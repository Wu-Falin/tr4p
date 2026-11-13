import asyncio
import json
import sys
import unittest

import aiohttp

from tr4p.cli import main
from tr4p.config import Config
from tr4p.crawlers import CrawlerVerifier, crawler_name
from tr4p.fsutil import is_private
from tr4p.runtime import Runtime
from tr4p.seed import Seed


def init(home, *extra):
    return main(["--home", str(home), "init", "--yes", "--mode", "standalone",
                 "--public-host", "127.0.0.1", "--public-port", "18081",
                 "--dashboard-port", "18788", *extra])


def test_init_writes_private_state_and_refuses_to_overwrite(tmp_path, capsys):
    home = tmp_path / "state"
    assert init(home) == 0
    assert "authorized" in capsys.readouterr().out
    for name in ("config.json", "secret.key"):
        assert is_private(home / name)
        if sys.platform != "win32":
            assert ((home / name).stat().st_mode & 0o777) == 0o600
    config = Config.load(home / "config.json")
    assert config.public.mode == "standalone" and config.dashboard.host == "127.0.0.1"
    secret = (home / "secret.key").read_text()

    assert init(home) == 1                                   # no silent overwrite
    assert (home / "secret.key").read_text() == secret
    assert init(home, "--force") == 0
    assert (home / "secret.key").read_text() != secret


def test_init_stores_no_password_by_default(tmp_path):
    home = tmp_path / "state"
    init(home)
    assert not (home / "events.db").exists()                 # nothing preset, no default


def test_init_rejects_bad_values(tmp_path, capsys):
    code = main(["--home", str(tmp_path / "s"), "init", "--yes", "--mode", "proxy",
                 "--upstream", "not-a-url"])
    assert code == 2
    assert "public.upstream" in capsys.readouterr().err
    assert not (tmp_path / "s" / "config.json").exists()


def test_init_flags_for_proxy_mode(tmp_path):
    home = tmp_path / "state"
    assert main(["--home", str(home), "init", "--yes", "--mode", "proxy",
                 "--upstream", "http://127.0.0.1:3000", "--trusted-proxy", "192.0.2.1",
                 "--whitelist", "198.51.100.0/24", "--whitelist", "203.0.113.4"]) == 0
    config = Config.load(home / "config.json")
    assert config.public.trusted_proxies == ["192.0.2.1"]
    assert config.whitelist == ["198.51.100.0/24", "203.0.113.4"]


def test_commands_without_config_explain_what_to_do(tmp_path, capsys):
    assert main(["--home", str(tmp_path / "none"), "canaries"]) == 2
    assert "tr4p init" in capsys.readouterr().err


def test_canaries_command_lists_current_paths(tmp_path, capsys):
    home = tmp_path / "state"
    init(home)
    capsys.readouterr()
    assert main(["--home", str(home), "canaries"]) == 0
    out = capsys.readouterr().out
    assert "robots.txt only" in out and "Agent instruction" in out


class RuntimeCase(unittest.IsolatedAsyncioTestCase):
    async def test_full_stack_starts_detects_and_restores(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            config = Config()
            config.public.mode = "standalone"
            config.public.host = "127.0.0.1"
            config.public.port = 0
            config.dashboard.port = 0
            seed = Seed.generate()               # port 0 = any free port (tests only)

            runtime = Runtime(home, config, seed)
            await runtime.start()
            try:
                self.assertTrue(runtime.dashboard.setup_code)
                base = f"http://127.0.0.1:{runtime.public.port}"
                agent = {"User-Agent": "curl/8.5.0", "Accept": "*/*"}
                async with aiohttp.ClientSession() as client:
                    async with client.get(base + "/", headers=agent) as response:
                        self.assertEqual(response.status, 200)
                    async with client.get(base + "/.env", headers=agent) as response:
                        self.assertEqual(response.status, 200)
                status = runtime.status()
                self.assertTrue(status["running"])
                self.assertEqual(status["level"], 3)
                self.assertEqual(status["tarpit"]["completed"], 1)      # the probe was held
                self.assertEqual(status["connections"]["limit"], 4096)
                config.public.port = runtime.public.port
                config.dashboard.port = runtime.dashboard.port
                await runtime.apply_settings({"tarpit": {"max_delay": 20.0}}, "test change")
                self.assertEqual(runtime.config.tarpit.level, 0)       # custom now
                from tr4p.config import Config as Saved
                self.assertEqual(Saved.load(home / "config.json").tarpit.max_delay, 20.0)
                from tr4p.config import ConfigError
                with self.assertRaises(ConfigError):
                    await runtime.apply_settings({"tarpit": {"max_delay": -1.0}}, "bad")
                self.assertEqual(runtime.config.tarpit.max_delay, 20.0)
                self.assertEqual(status["stats"]["tiers"]["medium"], 1)
                self.assertGreater(status["canary"]["next_rotation_in"], 0)
                json.dumps(status)                           # must be serialisable
            finally:
                await runtime.stop()
            self.assertFalse(runtime.running)
            self.assertTrue(is_private(home / "events.db"))

            config.public.port = config.dashboard.port = 0
            again = Runtime(home, config, seed)
            await again.start()
            try:
                self.assertEqual(again.engine.stats()["tiers"]["medium"], 1)
                self.assertGreaterEqual(len(again.store.events()), 3)
            finally:
                await again.stop()


class CrawlerCase(unittest.IsolatedAsyncioTestCase):
    async def test_forward_confirmed_reverse_lookup(self):
        calls = []

        async def resolver(address):
            calls.append(address)
            if address == "192.0.2.10":
                return "crawl-1.googlebot.com.", ["192.0.2.10"]
            if address == "192.0.2.11":
                return "crawl-1.googlebot.com", ["192.0.2.99"]      # forward mismatch
            if address == "192.0.2.12":
                return "googlebot.com.attacker.example", ["192.0.2.12"]
            raise OSError("no reverse record")

        verifier = CrawlerVerifier(resolver=resolver)
        agent = "Mozilla/5.0 (compatible; Googlebot/2.1)"
        self.assertTrue(await verifier.verify("192.0.2.10", agent))
        self.assertTrue(await verifier.verify("192.0.2.10", agent))
        self.assertEqual(calls.count("192.0.2.10"), 1)               # cached
        self.assertFalse(await verifier.verify("192.0.2.11", agent))
        self.assertFalse(await verifier.verify("192.0.2.12", agent))
        self.assertFalse(await verifier.verify("192.0.2.13", agent))
        self.assertFalse(await verifier.verify("192.0.2.10", "curl/8"))

    async def test_slow_lookup_counts_as_unverified(self):
        import tr4p.crawlers

        async def resolver(address):
            await asyncio.sleep(5)

        original = tr4p.crawlers.LOOKUP_TIMEOUT
        tr4p.crawlers.LOOKUP_TIMEOUT = 0.05
        try:
            verifier = CrawlerVerifier(resolver=resolver)
            self.assertFalse(await verifier.verify("192.0.2.10", "bingbot/2.0"))
        finally:
            tr4p.crawlers.LOOKUP_TIMEOUT = original


def test_crawler_names():
    assert crawler_name("Mozilla/5.0 (compatible; bingbot/2.0)") == "bingbot"
    assert crawler_name("curl/8.5") is None
