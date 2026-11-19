"""Bait library, noindex headers, friction pages, decoy themes and canned
errors, adaptive depth, accounting, incident reports, and a scan for secrets
in the repository. All fake secrets here come from the code under test at
run time; none is written out in this file."""

import asyncio
import json
import re
import tempfile
import time
import unittest
from pathlib import Path
from urllib.parse import quote

import pytest
from aiohttp import web

from tests.helpers import SCRIPT_HEADERS, Clock, MemorySink, make_engine, make_seed, request
from tests.http_helpers import BROWSER, ListenerCase
from tests.test_decoy import app as decoy_app, get as decoy_get, TOKENS
from tests.test_engine_tarpit import trap_high
from tests.test_maze import ask, build, segment
from tr4p.canary import CanaryHit
from tr4p.config import Config
from tr4p.engine import Engine, Verdict
from tr4p.honeytoken import Honeytokens
from tr4p.persona import Persona
from tr4p.report import (ESTIMATE_NOTE, TIMELINE_LIMIT, build_report, clean_text, md_escape,
                         to_json, to_markdown)

ROOT = Path(__file__).resolve().parent.parent


# ----------------------------------------------- steady pace is on in production

def test_cadence_is_enabled_in_the_default_production_config(tmp_path):
    from tr4p.cli import main

    assert Config().detection.cadence_min_gaps == 15
    home = tmp_path / "home"
    assert main(["--home", str(home), "init", "--yes", "--mode", "standalone"]) == 0
    assert Config.load(home / "config.json").detection.cadence_min_gaps == 15
    clock = Clock()
    engine = Engine(Config(), make_seed(), MemorySink(), clock)          # no test-only overrides
    for n in range(25):
        clock.tick(2.0)
        info = request(f"/p/{n}")
        verdict = engine.begin(info)
        engine.finish(info, verdict, 200, "text/html")
        engine.end(verdict)
    assert engine.stats()["by_type"].get("cadence") == 1


# ------------------------------------------------------------- bait library

LIBRARY = ("docker-compose.yml", ".gitlab-ci.yml", "Jenkinsfile", "azure-pipelines.yml", "package.json",
           "postman_collection.json", "terraform.tfstate", "terraform.tfstate.backup", "error_log",
           "actuator/env", "phpinfo.php", "static/app.min.js", "static/app.min.js.map")


@pytest.mark.parametrize("name", LIBRARY)
def test_each_bait_family_plants_secrets_issued_to_the_session(name):
    made, engine, _ = build()
    path = f"/{segment(engine, 'link')}/{name}"
    first, again, other = (ask(made, path, key=key) for key in ("session-a", "session-a", "session-b"))
    assert first.status == 200 and first.body
    found = engine.honeytokens.find(first.body.decode())
    assert found is not None and found.origin == "session-a" and not found.install
    assert first.body == again.body != other.body


def test_status_pages_and_the_bundle_describe_the_made_up_api():
    made, engine, _ = build()
    link = f"/{segment(engine, 'link')}"
    assert b"Status" in ask(made, f"{link}/server-status").body or b"Active connections" in ask(made, f"{link}/server-status").body
    assert json.loads(ask(made, f"{link}/health").body)["status"] == "UP"
    bundle = ask(made, f"{link}/static/app.min.js")
    assert bundle.content_type == "application/javascript"
    assert all(path.encode() in bundle.body for path in engine.canaries.current().api_paths)
    assert b"sourceMappingURL=app.min.js.map" in bundle.body
    source_map = json.loads(ask(made, f"{link}/static/app.min.js.map").body)
    assert source_map["version"] == 3 and len(source_map["sources"]) == len(source_map["sourcesContent"])


class Noindex(ListenerCase):
    mode = "standalone"

    async def test_every_kind_of_bait_response_says_noindex(self):
        current = self.engine.canaries.current()
        paths = ["/.env", "/docker-compose.yml", "/Jenkinsfile", "/terraform.tfstate", "/error_log",
                 "/server-status", "/phpinfo.php", "/openapi.json", "/llms.txt", "/graphql",
                 current.link_paths[0], current.bundle_path, current.bundle_path + ".map",
                 current.api_paths[0], current.doc_paths[0], current.robots_only_path,
                 f"/{current.segments['robots']}/m/0000abc1"]
        for path in paths:
            response, body = await self.get(path)
            self.assertEqual(response.headers.get("X-Robots-Tag"), "noindex, nofollow", path)
            self.assert_anonymous(response, body)
        home, _ = await self.get("/")
        self.assertNotIn("X-Robots-Tag", home.headers)


def test_no_secret_shaped_strings_are_committed():
    patterns = [re.compile(p) for p in (
        r"AKIA[0-9A-Z]{16}", r"sk_live_[0-9A-Za-z]{16,}", r"gh[pousr]_[0-9A-Za-z]{30,}",
        r"xox[abp]-[0-9A-Za-z-]{10,}", r"-----BEGIN [A-Z ]*PRIVATE KEY-----", r"AIza[0-9A-Za-z_-]{35}")]
    checked = 0
    for path in ROOT.rglob("*"):
        if (not path.is_file() or ".venv" in path.parts or ".git" in path.parts
                or "node_modules" in path.parts or path.suffix in (".png", ".pyc", ".db")):
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        checked += 1
        for pattern in patterns:
            assert not pattern.search(text), f"{path.relative_to(ROOT)} contains {pattern.pattern}"
    assert checked > 80


# ------------------------------------------------------------------ friction

def test_friction_is_deterministic_rare_and_never_on_trap_content():
    engine, _, _ = make_engine(Config())
    session = trap_high(engine).session
    seen = set()
    for n in range(300):
        session.requests += 1
        page = request(f"/p/{n}?id=1")
        first, second = Verdict(), Verdict()
        first.payload = second.payload = "sqli" if n % 2 else ""
        engine._plan_friction(session, page, first)
        engine._plan_friction(session, page, second)
        assert first.friction == second.friction                       # same draw, same answer
        seen.add(first.friction)
        for blocked in (Verdict(canary=CanaryHit("link", 0)), Verdict(bait="always")):
            engine._plan_friction(session, page, blocked)
            assert blocked.friction == ""                              # never on trap content
        asset = Verdict()
        engine._plan_friction(session, request("/s.css", is_asset=True), asset)
        assert asset.friction == ""
    assert seen == {"", "waf", "rate"}


def test_friction_needs_the_high_tier_and_can_be_switched_off():
    engine, _, _ = make_engine(Config())
    medium = visit_medium(engine)
    for n in range(200):
        medium.requests += 1
        verdict = Verdict()
        engine._plan_friction(medium, request(f"/p/{n}"), verdict)
        assert verdict.friction == ""
    config = Config()
    config.maze.friction = False
    engine, _, _ = make_engine(config)
    session = trap_high(engine).session
    for n in range(200):
        session.requests += 1
        verdict = Verdict()
        engine._plan_friction(session, request(f"/p/{n}"), verdict)
        assert verdict.friction == ""


def visit_medium(engine):
    from tests.test_engine import visit

    verdict = visit(engine, engine.canaries.current().link_paths[0], headers=SCRIPT_HEADERS)
    assert verdict.tier == "medium"
    return verdict.session


def test_block_pages_are_canned_and_consistent_within_a_session():
    made, engine, _ = build()
    listed = set(engine.canaries.current().api_paths)
    pages = [made.friction("rate", "text/html", "session-a") for _ in range(5)]
    assert {p.status for p in pages} == {429} and len({p.headers["Retry-After"] for p in pages}) == 1
    hints = {m for p in pages for m in re.findall(r"/[\w.\-]+/v1/\w+", p.body.decode())}
    assert len(hints) == 1 and hints <= listed                          # a hint to an emulated endpoint
    blocks = [json.loads(made.friction("waf", "application/json", "session-a").body) for _ in range(3)]
    assert {b["error"] for b in blocks} == {"request_blocked"}
    assert len({re.search(r"rule (\d+)", b["message"]).group(1) for b in blocks}) == 1     # the rule is stable
    assert len({re.search(r"Reference (\w+)", b["message"]).group(1) for b in blocks}) == 3  # the reference varies


class FrictionOverHttp(ListenerCase):
    def configure(self, config):
        config.maze.friction = True

    async def test_a_high_tier_session_can_meet_a_block_page(self):
        self.engine._plan_friction = lambda session, info, verdict: setattr(verdict, "friction", "rate")
        secret = self.engine.honeytokens.value("api_key")
        response, body = await self.get("/", headers=dict(BROWSER, Authorization=f"Bearer {secret}"))
        self.assertEqual(response.status, 429)
        self.assertIn("Retry-After", response.headers)
        self.assertEqual(response.headers["X-Robots-Tag"], "noindex, nofollow")
        self.assertIn(b"Too many requests", body)
        self.assert_anonymous(response, body)
        ordinary, body = await self.get("/", headers=dict(BROWSER, **{"User-Agent": "Mozilla/5.0 Firefox/130"}))
        self.assertEqual(ordinary.status, 200)


# ------------------------------------------------------------ decoy and themes

def themed(decoy, theme, path, sid="s1", method="GET", body=b""):
    path, _, query = path.partition("?")
    return decoy.handle(method, path, query, body, sid, theme)


def test_theme_follows_what_the_session_tried_and_is_chosen_once():
    for intent, theme in (("sqli", "database"), ("operator", "database"), ("traversal", "files"),
                          ("command", "files"), ("xss", "portal"), ("", "generic")):
        engine, sink, _ = make_engine()
        session = trap_high(engine).session
        session.intent = intent
        assert engine.decoy_theme(session) == theme
        session.intent = "xss" if theme != "portal" else "sqli"
        assert engine.decoy_theme(session) == theme                      # kept
        assert bool(sink.kinds("decoy")) == (theme != "generic")
    engine, _, _ = make_engine()
    session = trap_high(engine).session
    session.signals["auth_burst"] = 1
    assert engine.decoy_theme(session) == "portal"
    assert session.snapshot()["theme"] == "portal"


def test_themes_add_surfaces_without_changing_facts():
    decoy = decoy_app("generic")
    assert themed(decoy, "generic", "/db").status == 404
    db = themed(decoy, "database", "/db?sql=select+*+from+users")
    assert db.touch == "database console" and b"user001" in db.body
    assert b"<script>" not in themed(decoy, "database", "/db?sql=" + quote("<script>alert(1)</script>")).body
    assert themed(decoy, "files", "/files").touch == "file manager"
    assert themed(decoy, "files", "/files/download?name=../../etc/passwd").status == 404
    assert themed(decoy, "files", "/files/download?name=db-dump.sql").touch == "database dump"
    notes = themed(decoy, "files", "/files/download?name=notes.txt").body.decode()
    assert TOKENS["admin_password"] in notes
    csv = themed(decoy, "files", "/files/download?name=users-export.csv")
    first = decoy._data.people[0].name
    assert first in csv.body.decode()
    assert b"Sign in" in themed(decoy, "portal", "/account").body
    decoy.handle("POST", "/login", "", f"username=a&password={TOKENS['admin_password']}".encode(), "s1")
    account = themed(decoy, "portal", "/account")
    assert account.touch == "customer profile" and first in account.body.decode()   # the same person


def test_canned_sql_errors_one_partial_win_and_sleeps_that_can_be_timed():
    decoy = decoy_app("generic")
    error = decoy_get(decoy, "/search?q=a%27b")
    assert error.status == 500 and error.canned and b"SQL syntax" in error.body and not error.touch
    hostile = decoy_get(decoy, "/search?q=" + quote("x'<script>alert(1)</script>"))
    assert b"<script>" not in hostile.body
    assert decoy_get(decoy, "/s?id=1'+order+by+9--").canned
    assert decoy_get(decoy, "/s?id=1'+order+by+2--").status == 404       # plausible: falls through
    win = decoy_get(decoy, "/s?id=1'+union+select+1,2,3,4--")
    assert win.status == 200 and win.touch == "injected query result" and b"user001" in win.body
    assert b"different number of columns" in decoy_get(decoy, "/s?id=1'+union+select+1,2--").body
    assert decoy_get(decoy, "/s?id=1+and+sleep(5)").delay == 5.0
    assert decoy_get(decoy, "/s?id=sleep(99)").delay == 8.0                # capped
    assert decoy_get(decoy, "/s?id=1").delay == 0


class CannedErrorsOverTheLink(unittest.IsolatedAsyncioTestCase):
    async def test_chosen_error_pages_are_not_a_failure(self):
        from tr4p.decoy.__main__ import build as build_decoy
        from tr4p.decoylink import DecoyLink

        seed = make_seed()
        with tempfile.TemporaryDirectory() as tmp:
            config = Config()
            config.decoy.handoff_dir, config.decoy.url = tmp + "/h", "http://127.0.0.1:1"
            link = DecoyLink(Path(tmp), config, seed, Persona.from_seed(seed), Honeytokens(seed))
            settings = json.loads(link.write_handoff().read_text())
            runner = web.AppRunner(build_decoy(settings), access_log=None)
            await runner.setup()
            await web.TCPSite(runner, "127.0.0.1", 0).start()
            link._remote = f"http://127.0.0.1:{runner.addresses[0][1]}"
            await link.start()
            try:
                error = await link.fetch("GET", "/s?q=a%27b", {}, None, "session-1")
                self.assertEqual(error.status, 500)
                self.assertIn(b"SQL syntax", error.body)
                self.assertEqual((await link.fetch("GET", "/s?id=sleep(99)", {}, None, "session-1")).delay, 8.0)
                page = await link.fetch("GET", "/db?sql=show+tables", {}, None, "session-1", theme="database")
                self.assertEqual(page.touch, "database console")
                self.assertEqual((await link.fetch("GET", "/db", {}, None, "session-1")).status, 404)
            finally:
                await link.stop()
                await runner.cleanup()


def test_the_tree_goes_deeper_as_the_session_phase_grows():
    made, engine, _ = build(rabbit_depth=2)
    root = f"/{segment(engine, 'link')}/"

    def links_down(bonus):
        return any(re.search(r'href="[^".][^"]*/"',
                             made.respond("GET", f"{root}d{n}/e/", "", None, "shop.example", "s", True,
                                          depth_bonus=bonus).body.decode()) for n in range(30))

    assert not links_down(0) and links_down(2)


# ----------------------------------------------------------------- accounting

class Accounting(ListenerCase):
    def configure(self, config):
        config.tarpit.enabled = True
        config.tarpit.base_delay = config.tarpit.max_delay = config.tarpit.light_max_delay = 0.2
        config.tarpit.jitter = 0.0

    async def test_bytes_and_hold_time_are_counted_for_trapped_sessions(self):
        secret = self.engine.honeytokens.value("api_key")
        canary = self.engine.canaries.current().link_paths[0]
        response, body = await self.get(canary, headers=dict(BROWSER, Authorization=f"Bearer {secret}"))
        session = next(s for s in self.engine.sessions.flagged() if s.tier == "high")
        self.assertEqual(session.served_bytes, len(body))
        self.assertGreaterEqual(session.held_seconds, 0.15)
        stats = self.engine.stats()
        self.assertEqual(stats["trap_bytes"], len(body))
        self.assertGreaterEqual(stats["trap_seconds"], 0.15)
        self.assertEqual(session.snapshot()["served_bytes"], len(body))


# -------------------------------------------------------------------- reports

HOSTILE = ("<script>alert(1)</script> [x](javascript:alert(1)) `rm -rf /` @everyone ‮evil"
           "\r\nINJECTED: yes\x00\x1b[31m | * _ # ~")


def hostile_inputs(events=3):
    session = {"key": "abc123", "ip": HOSTILE, "user_agent": HOSTILE, "tier": "high", "score": 88.4,
               "phase": 3, "campaign": HOSTILE, "theme": "database", "created": 1.7e9,
               "last_seen": 1.7e9 + 90, "requests": 41, "held_seconds": 63.2, "served_bytes": 40960,
               "signals": {"canary_path": 2, "attack_payload": 3, "honeytoken": 1, "generic_client": 1,
                           "follow_through": 1}}
    log = [{"ts": 1.7e9 + n, "kind": "signal", "signal": "canary_path" if n % 2 else "attack_payload",
            "tier": "medium", "detail": HOSTILE, "method": "GET", "path": "/x" + HOSTILE}
           for n in range(events)]
    return session, log


def strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from strings(item)


def test_attacker_text_cannot_come_alive_in_a_markdown_report():
    session, log = hostile_inputs()
    markdown = to_markdown(build_report(session, log, 1.7e9 + 100))
    assert "<" not in markdown and ">" not in markdown and "@" not in markdown
    assert all(ch == "\n" or ch.isprintable() for ch in markdown)
    assert "\nINJECTED" not in markdown and "‮" not in markdown
    assert not re.search(r"(?<!\\)\]\(", markdown) and "`" not in markdown.replace("\\`", "")
    assert "&lt;script&gt;" in markdown


def test_the_json_report_is_clean_and_the_estimate_is_labelled():
    session, log = hostile_inputs()
    report = json.loads(to_json(build_report(session, log, 1.7e9 + 100)))
    assert all(ch.isprintable() for text in strings(report) for ch in text)
    assert report["metrics"] == {"requests": 41, "held_seconds": 63.2, "bytes_sent": 40960,
                                 "estimated_tokens": 10240}
    assert ESTIMATE_NOTE in report["notes"] and "personal data" in " ".join(report["notes"])
    markdown = to_markdown(build_report(session, log, 1.7e9 + 100))
    assert "Estimated tokens: about 10240 (estimate)" in markdown and "(measured)" in markdown
    assert "divided by 4" in markdown and "No price is assumed" in markdown
    assert [s["stage"] for s in report["stages"]] == [
        "Reconnaissance", "Mapping", "Probing", "Access attempts", "Automation traits"]


def test_report_text_helpers_and_the_timeline_cap():
    assert clean_text("a\r\nb\x00‮c") == "a??b??c"
    assert len(clean_text("x" * 999, 50)) == 50
    assert md_escape("<a href=x>[y](z)*_`#") == "&lt;a href=x&gt;\\[y\\]\\(z\\)\\*\\_\\`\\#"
    session, log = hostile_inputs(events=TIMELINE_LIMIT + 300)
    assert len(build_report(session, log, 1.7e9)["timeline"]) == TIMELINE_LIMIT


def test_report_command(tmp_path, capsys):
    from tests.test_store import make_event
    from tr4p.cli import main
    from tr4p.store import Store

    home = tmp_path / "home"
    assert main(["--home", str(home), "init", "--yes", "--mode", "standalone"]) == 0
    store = Store(home / "events.db")
    store.open()
    store.save_session({"key": "abcdef123456", "last_seen": time.time(), "tier": "high", "ip": "203.0.113.9",
                        "user_agent": "x", "signals": {"canary_path": 1}, "requests": 3})
    store.add_event(make_event(session="abcdef123456"))
    store.flush()
    store.close()
    capsys.readouterr()
    assert main(["--home", str(home), "report", "abcdef"]) == 0
    assert "Incident report: session abcdef123456" in capsys.readouterr().out
    assert main(["--home", str(home), "report", "abcdef", "--format", "json"]) == 0
    assert json.loads(capsys.readouterr().out)["session"]["id"] == "abcdef123456"
    assert main(["--home", str(home), "report", "zzz"]) == 1
