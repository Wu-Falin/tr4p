"""`tr4p doctor`: check an installation and say plainly what is wrong.

Each check prints one line: ok, warn or FAIL. The command exits with 1 when
anything failed, so it can be used in scripts.
"""

from __future__ import annotations

import asyncio
import ipaddress
from pathlib import Path

from tr4p.config import CONFIG_FILE, DATABASE_FILE, SEED_FILE, Config, ConfigError
from tr4p.fsutil import is_private


class Report:
    def __init__(self) -> None:
        self.failed = 0
        self.warned = 0

    def ok(self, text: str) -> None:
        print(f"  ok    {text}")

    def warn(self, text: str) -> None:
        self.warned += 1
        print(f"  warn  {text}")

    def fail(self, text: str) -> None:
        self.failed += 1
        print(f"  FAIL  {text}")


def run_doctor(home: Path) -> int:
    report = Report()
    print(f"Checking {home}")
    try:
        config = Config.load(home / CONFIG_FILE)
        report.ok("config file is valid")
    except ConfigError as exc:
        report.fail(f"config: {exc}")
        return 1
    _files(home, report)
    _dashboard(home, config, report)
    _proxy_trust(config, report)
    _settings(config, report)
    try:
        asyncio.run(_live(home, config, report))
    except Exception as exc:   # a doctor must not crash on the patient
        report.fail(f"live checks could not run: {exc}")
    print(f"{report.failed} failed, {report.warned} warnings.")
    return 1 if report.failed else 0


def _files(home: Path, report: Report) -> None:
    for name in (CONFIG_FILE, SEED_FILE, DATABASE_FILE, "smtp.secret"):
        path = home / name
        if not path.exists():
            if name == SEED_FILE:
                report.fail(f"{name} is missing; run `tr4p init`")
            continue
        if is_private(path):
            report.ok(f"{name} is readable by its owner only")
        else:
            report.fail(f"{name} is readable by other users; run: chmod 600 {path}")
    if not is_private(home):
        report.warn(f"the home directory is open to other users; run: chmod 700 {home}")


def _dashboard(home: Path, config: Config, report: Report) -> None:
    host = config.dashboard.host
    if host in ("127.0.0.1", "::1", "localhost"):
        report.ok("dashboard listens on loopback only")
    else:
        report.warn(f"dashboard listens on {host}: make sure only you can reach it "
                    "(in a container, publish its port on 127.0.0.1 only)")
    database = home / DATABASE_FILE
    has_password = False
    if database.exists():
        from tr4p.dashboard.app import PASSWORD_SETTING
        from tr4p.store import Store

        store = Store(database)
        store.open()
        try:
            has_password = store.get_setting(PASSWORD_SETTING) is not None
        finally:
            store.close()
    if has_password:
        report.ok("dashboard password is set")
    else:
        report.warn("no dashboard password yet: run `tr4p passwd`, or use the setup code "
                    "printed by `tr4p run`")


def _proxy_trust(config: Config, report: Report) -> None:
    public = config.public
    trusted = public.trusted_proxies
    for entry in trusted:
        if ipaddress.ip_network(entry, strict=False).prefixlen == 0:
            report.fail(f"public.trusted_proxies contains {entry}: anyone could then fake "
                        "their address. List only your own proxy.")
            return
    loopback_only = public.host in ("127.0.0.1", "::1", "localhost")
    if trusted:
        report.ok(f"client addresses are taken from {public.client_ip_header} sent by "
                  f"{len(trusted)} trusted proxy entr{'y' if len(trusted) == 1 else 'ies'}")
    elif loopback_only:
        report.warn("the public listener is on loopback, so a proxy sits in front of it, but "
                    "public.trusted_proxies is empty: every visitor will appear to come from "
                    "the proxy and be treated as one client. Add the proxy's address.")
    else:
        report.ok("no trusted proxies: client addresses are the connecting addresses "
                  "(correct only if nothing sits in front)")


def _settings(config: Config, report: Report) -> None:
    if config.block.enforce:
        report.warn("block.enforce is on: listed clients are refused. Remember that an "
                    "address can be shared by many people.")
    if config.maze.external_targets:
        report.warn("maze.external_targets is set: trapped clients are sent to third parties. "
                    "Only list sites you run or have permission to use.")
    if config.alerts.webhook_allow_private:
        report.warn("alerts.webhook_allow_private is on: alerts may go to internal addresses")
    report.ok(f"events and sessions are kept for {config.storage.retention_days:g} days")
    if not config.decoy.enabled:
        report.warn("the decoy is off: high-tier sessions stay on the real site (tarpit only)")


async def _live(home: Path, config: Config, report: Report) -> None:
    """Checks that need the network: the protected site and the decoy."""
    import aiohttp

    from tr4p.canary import Canaries
    from tr4p.seed import Seed

    seed_path = home / SEED_FILE
    if not seed_path.exists():
        return
    seed = Seed.load(seed_path)
    timeout = aiohttp.ClientTimeout(total=5)
    if config.public.mode == "proxy":
        base = config.public.upstream.rstrip("/")
        try:
            async with aiohttp.ClientSession(timeout=timeout) as client:
                async with client.get(base + "/", allow_redirects=False) as response:
                    report.ok(f"protected site answers ({response.status})")
                current = Canaries(seed, config.canary.rotation_hours,
                                   config.canary.keep_rotations).current()
                clash = []
                for path in current.disallow:
                    async with client.get(base + path, allow_redirects=False) as response:
                        if response.status == 200:
                            clash.append(path)
                if clash:
                    report.warn("the protected site answers 200 on canary paths (a catch-all "
                                "page?). Those paths are served by the trap instead: " + ", ".join(clash))
                else:
                    report.ok("canary paths do not collide with the protected site")
        except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as exc:
            report.fail(f"protected site at {base} is not reachable: {exc}")
    if not config.decoy.enabled:
        return
    if config.decoy.url:
        try:
            async with aiohttp.ClientSession(timeout=timeout) as client:
                async with client.get(config.decoy.url.rstrip("/") + "/__control/ping") as response:
                    if response.status == 204:
                        report.ok("decoy service answers")
                    else:
                        report.fail(f"decoy service answered {response.status}")
        except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as exc:
            report.fail(f"decoy service at {config.decoy.url} is not reachable "
                        f"(high-tier sessions get an error page): {exc}")
        return
    from tr4p.decoylink import DecoyLink
    from tr4p.honeytoken import Honeytokens
    from tr4p.persona import Persona

    link = DecoyLink(home, config, seed, Persona.from_seed(seed), Honeytokens(seed))
    await link.start()
    try:
        if link.running:
            report.ok(f"decoy process starts and answers (profile: {config.decoy.profile})")
        else:
            report.fail("the decoy process does not start (high-tier sessions get an error page)")
    finally:
        await link.stop()
