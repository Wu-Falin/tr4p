"""Blocklist: high tier only, expiring, reversible, never for the exempt."""

import json
import unittest

from tests.helpers import BROWSER_HEADERS, OTHER_IP, SCRIPT_HEADERS, Clock, make_engine
from tests.http_helpers import BROWSER, ListenerCase
from tests.test_engine import visit, with_cookie
from tests.test_engine_tarpit import trap_high
from tr4p.blocklist import Blocklist
from tr4p.config import BlockConfig, Config


def enforcing():
    config = Config()
    config.block.enforce = True
    return config


def test_entries_expire_and_the_list_is_bounded():
    clock = Clock()
    blocks = Blocklist(BlockConfig(ttl_hours=1, max_entries=10), clock)
    for n in range(12):
        blocks.add(f"g:{n}", f"203.0.113.{n}", "fp")
        clock.tick(1)
    assert len(blocks) == 10 and "g:0" not in {b.key for b in blocks.entries()}
    blocks.add("", "203.0.113.1", "fp")                       # nothing to key on: ignored
    assert len(blocks) == 10
    clock.tick(3600)
    assert blocks.entries() == [] and blocks.changed


def test_hit_only_counts_when_enforcement_is_on():
    clock = Clock()
    off = Blocklist(BlockConfig(), clock)
    off.add("g:1", "203.0.113.1", "fp")
    assert off.hit("g:1") is None
    on = Blocklist(BlockConfig(enforce=True, ttl_hours=1), clock)
    on.add("g:1", "203.0.113.1", "fp")
    assert on.hit("g:1").hits == 1 and on.hit("g:2") is None
    assert on.remove("g:1") and not on.remove("g:1") and on.hit("g:1") is None
    on.add("g:1", "203.0.113.1", "fp")
    clock.tick(3601)
    assert on.hit("g:1") is None


def test_export_lists_addresses_once_with_a_warning_and_round_trips():
    clock = Clock()
    blocks = Blocklist(BlockConfig(), clock)
    blocks.add("g:1", "203.0.113.7", "fp-a")
    blocks.add("g:2", "203.0.113.7", "fp-b")                  # same address, another client
    blocks.add("g:3", "198.51.100.2", "fp-c")
    text = blocks.export_text()
    assert "shared by many people" in text
    lines = [line for line in text.splitlines() if line and not line.startswith("#")]
    assert [line.split()[0] for line in lines] == ["198.51.100.2", "203.0.113.7"]
    copy = Blocklist(BlockConfig(), clock)
    copy.load(json.loads(json.dumps(blocks.dump())) + [{"broken": 1}])
    assert copy.export_text() == text


def test_only_the_high_tier_is_listed():
    engine, _, _ = make_engine()
    visit(engine, "/")
    visit(engine, engine.canaries.current().link_paths[0], ip=OTHER_IP)          # low
    medium = visit(engine, "/.env", status=404, headers=SCRIPT_HEADERS)
    assert medium.tier == "medium" and len(engine.blocklist) == 0
    high = trap_high(engine, headers=dict(BROWSER_HEADERS, **{"User-Agent": "Mozilla/5.0 Chrome/9"}))
    entries = engine.blocklist.entries()
    assert [entry.key for entry in entries] == [high.session.group_key]
    assert entries[0].ip and entries[0].fingerprint               # never an address alone
    assert engine.stats()["blocklist"] == 1


def test_listed_client_is_refused_only_with_enforcement_and_only_that_client():
    engine, sink, _ = make_engine()
    trap_high(engine)
    assert not visit(engine, "/").blocked                          # default: not enforced

    engine, sink, _ = make_engine(enforcing())
    trap_high(engine)
    refused = visit(engine, "/")
    assert refused.blocked and refused.session is None and refused.new_cookie is None
    assert visit(engine, "/", cookie=engine.mint_cookie()).blocked  # a new cookie does not help
    assert not visit(engine, "/", headers=SCRIPT_HEADERS).blocked   # same address, other client
    assert not visit(engine, "/", ip=OTHER_IP).blocked              # same browser, other address
    for _ in range(150):
        visit(engine, "/")
    assert engine.stats()["blocked"] == 152
    assert len(sink.kinds("blocked")) == 2                          # first and every 100th


def test_release_reverses_and_rearm_restores():
    engine, _, _ = make_engine(enforcing())
    cookie = with_cookie(engine)
    trapped = trap_high(engine, cookie=cookie)
    assert visit(engine, "/", cookie=cookie).blocked
    assert engine.release(trapped.session.key)
    assert len(engine.blocklist) == 0
    assert not visit(engine, "/", cookie=cookie).blocked
    assert engine.release(trapped.session.key, released=False)
    assert visit(engine, "/", cookie=cookie).blocked


def test_entries_expire_by_themselves():
    engine, _, clock = make_engine(enforcing())
    trap_high(engine)
    clock.tick(23 * 3600)
    assert visit(engine, "/").blocked
    clock.tick(2 * 3600)
    assert not visit(engine, "/").blocked


def test_whitelist_and_verified_crawlers_are_never_listed():
    config = enforcing()
    config.whitelist = ["203.0.113.0/24"]
    engine, _, _ = make_engine(config)
    assert trap_high(engine).whitelisted and len(engine.blocklist) == 0

    engine, _, _ = make_engine(enforcing())
    asked = []
    engine.crawler_hook = asked.append
    headers = {"Host": "x.example",
               "User-Agent": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"}
    trap_high(engine, headers=headers)
    assert asked and len(engine.blocklist) == 0                     # check still open: not listed
    engine.crawler_result(asked[0].key, True)
    assert len(engine.blocklist) == 0 and not visit(engine, "/", headers=headers).blocked

    engine.crawler_hook = asked.append
    trap_high(engine, headers=headers, ip=OTHER_IP)
    engine.crawler_result(asked[1].key, False)                      # an impostor is listed
    assert len(engine.blocklist) == 1


class Enforced(ListenerCase):
    def configure(self, config):
        config.block.enforce = True

    async def test_listed_client_gets_a_plain_forbidden_page(self):
        secret = self.engine.honeytokens.value("api_key")
        await self.get("/", headers=dict(BROWSER, Authorization=f"Bearer {secret}"))
        response, body = await self.get("/")
        self.assertEqual(response.status, 403)
        self.assertNotIn("Set-Cookie", response.headers)
        self.assert_anonymous(response, body)
        other, _ = await self.get("/", headers={"User-Agent": "curl/8.5.0", "Accept": "*/*"})
        self.assertEqual(other.status, 200)


class Export(unittest.IsolatedAsyncioTestCase):
    async def test_runtime_writes_and_restores_the_blocklist(self):
        import tempfile
        from pathlib import Path

        import aiohttp

        from tr4p.fsutil import is_private
        from tr4p.runtime import BLOCKLIST_FILE, Runtime
        from tr4p.seed import Seed

        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            config = Config()
            config.public.mode = "standalone"
            config.public.host = "127.0.0.1"
            config.public.port = config.dashboard.port = 0
            config.tarpit.enabled = False
            config.decoy.enabled = False
            seed = Seed.generate()
            runtime = Runtime(home, config, seed)
            await runtime.start()
            try:
                secret = runtime.engine.honeytokens.value("api_key")
                async with aiohttp.ClientSession() as client:
                    async with client.get(f"http://127.0.0.1:{runtime.public.port}/",
                                          headers={"Authorization": f"Bearer {secret}"}) as response:
                        await response.read()
                runtime._save_blocklist()
                export = home / BLOCKLIST_FILE
                self.assertIn("127.0.0.1  # until", export.read_text())
                self.assertTrue(is_private(export))
                self.assertFalse(runtime.alerts.stats()["configured"])
            finally:
                await runtime.stop()
            again = Runtime(home, config, seed)
            await again.start()
            try:
                self.assertEqual(len(again.engine.blocklist), 1)
            finally:
                await again.stop()
