"""Operations: doctor, retention and purge, the decoy as a separate service,
and that the documented quickstart is what CI runs."""

import asyncio
import os
import subprocess
import sys
import time
import unittest
from pathlib import Path

import pytest
from aiohttp import web

from tests.helpers import make_seed
from tests.test_store import make_event
from tr4p.cli import main
from tr4p.config import Config, ConfigError
from tr4p.decoy.__main__ import build
from tr4p.decoylink import HANDOFF_FILE, DecoyDown, DecoyLink
from tr4p.honeytoken import Honeytokens
from tr4p.persona import Persona
from tr4p.store import Store

ROOT = Path(__file__).resolve().parent.parent


def init(home, *extra):
    return main(["--home", str(home), "init", "--yes", "--mode", "standalone",
                 "--public-host", "127.0.0.1", *extra])


# ------------------------------------------------------------------ retention

def test_purge_by_age_and_everything(tmp_path):
    store = Store(tmp_path / "events.db")
    store.open()
    try:
        now = time.time()
        store.add_event(make_event(ts=now - 40 * 86400))
        store.add_event(make_event(ts=now))
        store.save_session({"key": "old", "last_seen": now - 40 * 86400, "tier": "low"})
        store.save_session({"key": "new", "last_seen": now, "tier": "low"})
        store.flush()
        assert store.purge(now - 30 * 86400) == (1, 1)
        assert len(store.events()) == 1 and [s["key"] for s in store.sessions()] == ["new"]
        assert store.purge() == (1, 1) and store.events() == []
    finally:
        store.close()


def test_purge_command_and_retention_setting(tmp_path, capsys):
    home = tmp_path / "home"
    init(home)
    assert Config.load(home / "config.json").storage.retention_days == 30.0
    with pytest.raises(ConfigError, match="retention_days"):
        Config.from_dict({"storage": {"retention_days": 0}})
    store = Store(home / "events.db")
    store.open()
    store.add_event(make_event(ts=time.time() - 10 * 86400))
    store.add_event(make_event(ts=time.time()))
    store.flush()
    store.close()
    capsys.readouterr()
    assert main(["--home", str(home), "purge", "--days", "5"]) == 0
    assert "Deleted 1 events" in capsys.readouterr().out
    assert main(["--home", str(home), "purge", "--all"]) == 0
    assert "Deleted 1 events" in capsys.readouterr().out
    with pytest.raises(SystemExit):
        main(["--home", str(home), "purge"])                 # must say what to delete


def test_runtime_applies_retention(tmp_path):
    from tr4p.runtime import Runtime

    config = Config()
    config.decoy.enabled = False
    config.storage.retention_days = 1.0
    runtime = Runtime(tmp_path, config, make_seed())
    runtime.store.open()
    try:
        runtime.store.add_event(make_event(ts=time.time() - 3 * 86400))
        runtime.store.add_event(make_event(ts=time.time()))
        runtime.store.flush()
        runtime._apply_retention()
        assert len(runtime.store.events()) == 1
    finally:
        runtime.store.close()


# --------------------------------------------------------------------- doctor

def test_doctor_passes_on_a_fresh_install(tmp_path, capsys):
    home = tmp_path / "home"
    init(home)
    capsys.readouterr()
    assert main(["--home", str(home), "doctor"]) == 0
    out = capsys.readouterr().out
    assert "config file is valid" in out and "dashboard listens on loopback only" in out
    assert "decoy process starts and answers" in out
    assert "no dashboard password yet" in out and "0 failed" in out


def test_doctor_reports_real_problems(tmp_path, capsys):
    home = tmp_path / "home"
    init(home, "--trusted-proxy", "0.0.0.0/0", "--dashboard-host", "0.0.0.0")
    if sys.platform != "win32":
        os.chmod(home / "secret.key", 0o644)
    capsys.readouterr()
    assert main(["--home", str(home), "doctor"]) == 1
    out = capsys.readouterr().out
    assert "anyone could then fake" in out
    assert "dashboard listens on 0.0.0.0" in out
    if sys.platform != "win32":
        assert "FAIL  secret.key is readable by other users" in out


def test_doctor_flags_unreachable_site_and_missing_config(tmp_path, capsys):
    home = tmp_path / "home"
    assert main(["--home", str(home), "init", "--yes", "--mode", "proxy",
                 "--upstream", "http://127.0.0.1:9", "--public-host", "127.0.0.1"]) == 0
    capsys.readouterr()
    assert main(["--home", str(home), "doctor"]) == 1
    out = capsys.readouterr().out
    assert "is not reachable" in out
    assert "public.trusted_proxies is empty" in out          # loopback listener, no proxy listed
    assert main(["--home", str(tmp_path / "nothing"), "doctor"]) == 1


# ------------------------------------------------- decoy as a separate service

class RemoteDecoy(unittest.IsolatedAsyncioTestCase):
    async def test_handoff_health_and_fail_closed(self):
        import json
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            home, handoff = Path(tmp) / "home", Path(tmp) / "handoff"
            home.mkdir()
            seed = make_seed()
            config = Config()
            config.decoy.handoff_dir = str(handoff)
            config.decoy.url = "http://127.0.0.1:1"            # placeholder until the port is known
            link = DecoyLink(home, config, seed, Persona.from_seed(seed), Honeytokens(seed))
            path = link.write_handoff()
            self.assertEqual(path.name, HANDOFF_FILE)
            settings = json.loads(path.read_text(encoding="utf-8"))
            self.assertNotIn(seed.digest("x").hex(), path.read_text())
            self.assertEqual(set(settings), {"profile", "seed", "look", "tokens", "port", "key", "schema"})
            self.assertNotEqual(settings["seed"], (b"\x07" * 32).hex())   # derived, not the install secret

            runner = web.AppRunner(build(settings), access_log=None)
            await runner.setup()
            await web.TCPSite(runner, "127.0.0.1", 0).start()
            link._remote = f"http://127.0.0.1:{runner.addresses[0][1]}"
            await link.start()
            try:
                self.assertTrue(link.running)
                self.assertEqual(link.stats()["placement"], "separate service")
                reply = await link.fetch("GET", "/", {"user-agent": "x"}, None, "session-1")
                self.assertEqual(reply.status, 200)
                await runner.cleanup()
                await link._check_remote()
                self.assertFalse(link.running)
                with self.assertRaises(DecoyDown):
                    await link.fetch("GET", "/", {}, None, "session-1")
            finally:
                await link.stop()

    async def test_decoy_service_starts_from_a_settings_file(self):
        import json
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            settings = {"profile": "api", "seed": "05" * 32, "key": "k" * 12, "tokens": {},
                        "look": {"name": "N", "accent": "#000", "tagline": "t", "year": 2025}}
            path = Path(tmp) / "decoy.json"
            path.write_text(json.dumps(settings), encoding="utf-8")
            process = await asyncio.create_subprocess_exec(
                sys.executable, "-m", "tr4p.decoy", "--settings", str(path), "--port", "0",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
            try:
                line = await asyncio.wait_for(process.stdout.readline(), 20)
                self.assertTrue(line.startswith(b"ready "))
                import aiohttp
                port = int(line.split()[1])
                async with aiohttp.ClientSession() as client:
                    async with client.get(f"http://127.0.0.1:{port}/__control/ping") as response:
                        self.assertEqual(response.status, 204)
                    async with client.get(f"http://127.0.0.1:{port}/") as response:
                        self.assertEqual(response.status, 403)     # no key, no answer
            finally:
                process.kill()
                await process.wait()


def test_remote_decoy_settings_are_validated():
    with pytest.raises(ConfigError, match="handoff_dir"):
        Config.from_dict({"decoy": {"url": "http://decoy:8081"}})
    with pytest.raises(ConfigError, match="decoy.url"):
        Config.from_dict({"decoy": {"url": "ftp://decoy", "handoff_dir": "/handoff"}})


# ----------------------------------------------------------------------- docs

QUICKSTART = ("pip install .", "tr4p init --yes --mode standalone", "tr4p doctor", "tr4p run")


def test_documented_quickstart_is_what_ci_runs():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    for command in QUICKSTART:
        assert f"\n{command}\n" in readme, command
        assert command in workflow, command
    assert "docker compose up" in readme and "docker compose up" in workflow


def test_required_documents_exist_and_carry_the_notices():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    for name in ("ARCHITECTURE.md", "CONTRIBUTING.md", "SECURITY.md", "docs/GUIDE.md"):
        assert (ROOT / name).is_file(), name
    for phrase in ("own or are", "Limitations", "Threat model", "not a clone", "container"):
        assert phrase in readme, phrase
    security = (ROOT / "SECURITY.md").read_text(encoding="utf-8")
    assert "private vulnerability reporting" in " ".join(security.lower().split())
    assert "@" not in security                                # no personal contact details
