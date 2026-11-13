"""Command line interface: init, run, passwd, canaries."""

from __future__ import annotations

import argparse
import asyncio
import getpass
import logging
import signal
import sys
from pathlib import Path

from tr4p import __version__
from tr4p.config import CONFIG_FILE, DATABASE_FILE, SEED_FILE, Config, ConfigError
from tr4p.dashboard.app import PASSWORD_SETTING
from tr4p.dashboard.auth import hash_password, password_problem
from tr4p.fsutil import default_home, ensure_private_dir, is_private
from tr4p.seed import Seed
from tr4p.store import Store

NOTICE = (
    "Use TR4P only on infrastructure you own or are explicitly authorized to protect."
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="tr4p",
        description="Self-hosted deception layer for sites you own or are authorized to protect.",
    )
    parser.add_argument("--version", action="version", version=f"tr4p {__version__}")
    parser.add_argument("--home", type=Path, default=None,
                        help="state directory (default: TR4P_HOME or the per-user config dir)")
    commands = parser.add_subparsers(dest="command", required=True)

    init = commands.add_parser("init", help="create config and secrets (guided)")
    init.add_argument("--yes", action="store_true", help="accept defaults, ask nothing")
    init.add_argument("--force", action="store_true", help="replace an existing config")
    init.add_argument("--mode", choices=("proxy", "standalone"))
    init.add_argument("--upstream", help="URL of the site to protect (proxy mode)")
    init.add_argument("--profile", choices=("generic", "php", "wordpress", "api"),
                      help="what the decoy pretends to be")
    init.add_argument("--public-host")
    init.add_argument("--public-port", type=int)
    init.add_argument("--dashboard-host")
    init.add_argument("--dashboard-port", type=int)
    init.add_argument("--trusted-proxy", action="append", default=None,
                      help="address/network of your TLS proxy or CDN (repeatable)")
    init.add_argument("--whitelist", action="append", default=None,
                      help="address/network that bypasses detection (repeatable)")

    commands.add_parser("run", help="start the trap and the dashboard")
    commands.add_parser("passwd", help="set or reset the dashboard password")
    commands.add_parser("canaries", help="show the currently armed canary paths")
    schema = commands.add_parser(
        "schema", help="give the decoy your table and column names (never any data)")
    schema.add_argument("file", type=Path, help="SQL schema dump without data rows")

    args = parser.parse_args(argv)
    home = (args.home or default_home()).expanduser()
    try:
        if args.command == "init":
            return _init(home, args)
        if args.command == "run":
            return _run(home)
        if args.command == "passwd":
            return _passwd(home)
        if args.command == "schema":
            return _schema(home, args.file)
        return _canaries(home)
    except ConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print()
        return 130


# ----------------------------------------------------------------------- init

def _ask(prompt: str, default: str) -> str:
    answer = input(f"{prompt} [{default}]: ").strip()
    return answer or default


def _ask_list(prompt: str) -> list[str]:
    answer = input(f"{prompt} (comma separated, empty for none): ").strip()
    return [item.strip() for item in answer.split(",") if item.strip()]


def _init(home: Path, args: argparse.Namespace) -> int:
    config_path = home / CONFIG_FILE
    if config_path.exists() and not args.force:
        print(f"A config already exists in {home}. Use --force to replace it.", file=sys.stderr)
        return 1

    interactive = not args.yes and sys.stdin.isatty()
    config = Config()
    public, dash = config.public, config.dashboard

    print(f"TR4P {__version__} setup\n{NOTICE}\n")
    if interactive:
        print("Press Enter to accept the value in [brackets].\n")

    public.mode = args.mode or (
        _ask("Mode: 'proxy' sits in front of your site, 'standalone' serves a built-in site",
             public.mode) if interactive else public.mode
    )
    if public.mode == "proxy":
        public.upstream = args.upstream or (
            _ask("Address of the site to protect", public.upstream) if interactive
            else public.upstream
        )
    config.decoy.profile = args.profile or (
        _ask("Decoy profile (generic, php, wordpress, api): pick what resembles your site",
             config.decoy.profile) if interactive else config.decoy.profile
    )
    public.host = args.public_host or (
        _ask("Public listen address", public.host) if interactive else public.host
    )
    public.port = args.public_port or (
        int(_ask("Public listen port", str(public.port))) if interactive else public.port
    )
    dash.host = args.dashboard_host or dash.host
    dash.port = args.dashboard_port or (
        int(_ask("Dashboard port (dashboard listens on 127.0.0.1 only)", str(dash.port)))
        if interactive else dash.port
    )
    if args.trusted_proxy is not None:
        public.trusted_proxies = args.trusted_proxy
    elif interactive:
        public.trusted_proxies = _ask_list(
            "Addresses of your own TLS proxy or CDN that may report client addresses"
        )
    if args.whitelist is not None:
        config.whitelist = args.whitelist
    elif interactive:
        config.whitelist = _ask_list("Your own testing addresses that should bypass detection")

    config.validate()
    ensure_private_dir(home)
    seed_path = home / SEED_FILE
    if args.force or not seed_path.exists():
        Seed.generate().save(seed_path)
    config.save(config_path)

    if interactive:
        print("\nCreate the dashboard password (there is no default).")
        password = _prompt_password()
        if password:
            _store_password(home, password)

    print(f"\nWritten to {home}")
    print("Next: tr4p run")
    if dash.host not in ("127.0.0.1", "::1", "localhost"):
        print("warning: the dashboard is not bound to loopback. Put it behind a "
              "firewall or VPN.", file=sys.stderr)
    return 0


def _prompt_password() -> str | None:
    for _ in range(3):
        first = getpass.getpass("Password (min 10 characters, empty to do this later): ")
        if not first:
            print("Skipped. The dashboard will ask for a setup code shown by `tr4p run`.")
            return None
        problem = password_problem(first)
        if problem:
            print(problem)
            continue
        if getpass.getpass("Repeat password: ") != first:
            print("The two passwords do not match.")
            continue
        return first
    print("Skipped after three attempts.")
    return None


def _store_password(home: Path, password: str) -> None:
    store = Store(home / DATABASE_FILE)
    store.open()
    try:
        store.set_setting(PASSWORD_SETTING, hash_password(password))
    finally:
        store.close()


# ------------------------------------------------------------------------ run

def _run(home: Path) -> int:
    from tr4p.runtime import Runtime

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    logging.getLogger("aiohttp.server").setLevel(logging.CRITICAL)
    runtime = Runtime.load(home)
    for name in (CONFIG_FILE, SEED_FILE):
        if not is_private(home / name):
            print(f"warning: {home / name} is readable by other users; run chmod 600 on it.",
                  file=sys.stderr)
    try:
        asyncio.run(_serve(runtime))
    except KeyboardInterrupt:
        pass
    except OSError as exc:
        print(f"error: could not start: {exc}", file=sys.stderr)
        return 1
    return 0


async def _serve(runtime) -> None:
    await runtime.start()
    config = runtime.config
    target = f"proxy -> {config.public.upstream}" if config.public.mode == "proxy" else "standalone"
    print(f"TR4P {__version__} running. {NOTICE}")
    print(f"  public     http://{config.public.host}:{runtime.public.port}  ({target})")
    print(f"  dashboard  http://{config.dashboard.host}:{runtime.dashboard.port}")
    if runtime.dashboard.setup_code:
        print(f"  first run  open the dashboard and enter setup code {runtime.dashboard.setup_code}")
    sys.stdout.flush()

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for name in ("SIGINT", "SIGTERM"):
        try:
            loop.add_signal_handler(getattr(signal, name), stop.set)
        except (NotImplementedError, RuntimeError, AttributeError):
            pass   # Windows: Ctrl+C arrives as KeyboardInterrupt instead
    try:
        await stop.wait()
    finally:
        await runtime.stop()


# -------------------------------------------------------------- small commands

def _passwd(home: Path) -> int:
    Config.load(home / CONFIG_FILE)
    password = _prompt_password()
    if not password:
        return 1
    _store_password(home, password)
    print("Dashboard password updated. Restart the service to sign out existing sessions.")
    return 0


def _schema(home: Path, source: Path) -> int:
    from tr4p.schema import SchemaError, import_schema

    Config.load(home / CONFIG_FILE)
    try:
        schema = import_schema(source, home)
    except (SchemaError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    columns = sum(len(table["columns"]) for table in schema["tables"])
    print(f"Imported {len(schema['tables'])} tables and {columns} columns (names and types only).")
    print("Restart the service for the decoy to use them.")
    return 0


def _canaries(home: Path) -> int:
    from tr4p.canary import Canaries

    config = Config.load(home / CONFIG_FILE)
    canaries = Canaries(Seed.load(home / SEED_FILE), config.canary.rotation_hours,
                        config.canary.keep_rotations)
    current = canaries.current()
    print(f"Rotation {current.rotation}. Do not link to or publish these paths.")
    print("Hidden links:")
    for path in current.link_paths:
        print(f"  {path}")
    print("Comment lures:")
    for path in current.comment_paths:
        print(f"  {path}")
    print(f"robots.txt only:    {current.robots_only_path}")
    print(f"Agent instruction:  {current.instruction_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
