import asyncio
import json
import unittest

import aiohttp

from tests.helpers import MemorySink, make_seed, request
from tr4p.bus import EventBus
from tr4p.config import Config
from tr4p.dashboard import auth
from tr4p.dashboard.app import Dashboard
from tr4p.engine import Engine
from tr4p.store import Store

PASSWORD = "correct horse battery"
POST = {"X-Requested-With": "dashboard", "Content-Type": "application/json"}


# ------------------------------------------------------------------ primitives

def test_password_hash_round_trip():
    stored = auth.hash_password(PASSWORD)
    assert stored.startswith("scrypt$") and PASSWORD not in stored
    assert auth.verify_password(PASSWORD, stored)
    assert not auth.verify_password(PASSWORD + "x", stored)
    assert auth.hash_password(PASSWORD) != stored            # fresh salt every time
    assert not auth.verify_password(PASSWORD, "garbage")
    assert not auth.verify_password(PASSWORD, "scrypt$1$2$3$!!$!!")


def test_password_rules():
    assert auth.password_problem("short")
    assert auth.password_problem("aaaaaaaaaaaaaa")
    assert auth.password_problem("x" * 300)
    assert auth.password_problem(PASSWORD) is None


def test_login_limiter_locks_out_and_recovers():
    now = [0.0]
    limiter = auth.LoginLimiter(max_failures=3, window=60, clock=lambda: now[0])
    for _ in range(3):
        assert limiter.retry_after("203.0.113.1") == 0
        limiter.failure("203.0.113.1")
    assert limiter.retry_after("203.0.113.1") > 0
    assert limiter.retry_after("203.0.113.2") == 0          # others unaffected
    now[0] = 61
    assert limiter.retry_after("203.0.113.1") == 0
    limiter.failure("203.0.113.1")
    limiter.success("203.0.113.1")
    assert limiter.retry_after("203.0.113.1") == 0


def test_login_limiter_global_cap_and_bounded_memory():
    limiter = auth.LoginLimiter(max_failures=3, global_max=10, max_tracked=5, clock=lambda: 0.0)
    for n in range(10):
        limiter.failure(f"203.0.113.{n}")
    assert limiter.retry_after("198.51.100.1") > 0           # spread attack slows everyone
    assert len(limiter._failures) <= 5


def test_session_store_expiry_and_cap():
    now = [0.0]
    sessions = auth.SessionStore(ttl_seconds=100, max_sessions=2, clock=lambda: now[0])
    token, session = sessions.create()
    assert sessions.get(token) is session
    assert sessions.get("nope") is None and sessions.get(None) is None
    now[0] = 101
    assert sessions.get(token) is None
    first, _ = sessions.create()
    sessions.create()
    sessions.create()
    assert sessions.get(first) is None                       # oldest evicted
    last, _ = sessions.create()
    sessions.drop(last)
    assert sessions.get(last) is None


def test_setup_code_shape():
    code = auth.new_setup_code()
    assert len(code) == 14 and code.count("-") == 2
    assert code != auth.new_setup_code()


# ----------------------------------------------------------------- application

class DashboardCase(unittest.IsolatedAsyncioTestCase):
    preset_password = True

    async def asyncSetUp(self):
        import tempfile
        from pathlib import Path

        self.tmp = tempfile.TemporaryDirectory()
        self.config = Config()
        self.config.dashboard.port = 0
        self.store = Store(Path(self.tmp.name) / "events.db")
        self.store.open()
        if self.preset_password:
            self.store.set_setting("dashboard_password", auth.hash_password(PASSWORD))
        self.bus = EventBus()
        store, bus = self.store, self.bus

        class Sink(MemorySink):
            def event(self, event):
                store.add_event(event)
                bus.publish(event)

        self.engine = Engine(self.config, make_seed(), Sink())
        self.dashboard = Dashboard(
            self.config, self.engine, self.store, self.bus, "instance-1",
            status=lambda: {"running": True, "mode": "proxy", "uptime": 5.0,
                            "stats": self.engine.stats()},
        )
        await self.dashboard.start()
        self.base = f"http://127.0.0.1:{self.dashboard.port}"
        self.client = aiohttp.ClientSession(cookie_jar=aiohttp.CookieJar(unsafe=True))

    async def asyncTearDown(self):
        await self.client.close()
        await self.dashboard.stop()
        self.store.close()
        self.tmp.cleanup()

    async def call(self, method, path, body=None, headers=None, **kwargs):
        data = json.dumps(body) if body is not None else None
        async with self.client.request(method, self.base + path, data=data,
                                       headers=headers, allow_redirects=False, **kwargs) as response:
            raw = await response.read()
            try:
                return response, json.loads(raw)
            except ValueError:
                return response, raw

    async def login(self):
        response, data = await self.call("POST", "/api/v1/login", {"password": PASSWORD}, POST)
        self.assertEqual(response.status, 200, data)
        _, session = await self.call("GET", "/api/v1/session")
        return dict(POST, **{"X-CSRF-Token": session["csrf"]})

    def trap_someone(self):
        info = request(self.engine.canaries.current().link_paths[0],
                       headers={"Host": "x.example", "User-Agent": "curl/8.5"})
        verdict = self.engine.begin(info)
        self.engine.finish(info, verdict, 200, "text/html")
        self.store.flush()
        return verdict.session


class Access(DashboardCase):
    async def test_everything_needs_sign_in(self):
        page, _ = await self.call("GET", "/")
        self.assertEqual(page.status, 302)
        self.assertEqual(page.headers["Location"], "/login")
        for path in ("/api/v1/status", "/api/v1/events", "/api/v1/sessions",
                     "/api/v1/session", "/api/v1/stream", "/static/app.js", "/static/app.css"):
            response, _ = await self.call("GET", path)
            self.assertIn(response.status, (401, 302), path)
        response, _ = await self.call("POST", "/api/v1/sessions/release", {"key": "x"}, POST)
        self.assertEqual(response.status, 401)

    async def test_login_page_is_neutral_and_hardened(self):
        response, body = await self.call("GET", "/login")
        self.assertEqual(response.status, 200)
        self.assertNotIn(b"tr4p", body.lower())
        self.assertIn("default-src 'none'", response.headers["Content-Security-Policy"])
        self.assertEqual(response.headers["X-Frame-Options"], "DENY")
        self.assertEqual(response.headers["Cache-Control"], "no-store")
        self.assertNotIn("aiohttp", response.headers["Server"].lower())
        for name in ("auth.js", "auth.css"):
            asset, _ = await self.call("GET", f"/static/{name}")
            self.assertEqual(asset.status, 200)
        missing, _ = await self.call("GET", "/static/../auth.py")
        self.assertIn(missing.status, (401, 404, 302))

    async def test_unknown_host_header_is_refused(self):
        response, _ = await self.call("GET", "/login", headers={"Host": "attacker.example"})
        self.assertEqual(response.status, 421)
        ok, _ = await self.call("GET", "/login", headers={"Host": "localhost:9999"})
        self.assertEqual(ok.status, 200)

    async def test_cross_site_posts_are_refused(self):
        body = {"password": PASSWORD}
        no_header, _ = await self.call("POST", "/api/v1/login", body,
                                       {"Content-Type": "application/json"})
        self.assertEqual(no_header.status, 403)
        foreign, _ = await self.call("POST", "/api/v1/login", body,
                                     dict(POST, Origin="https://attacker.example"))
        self.assertEqual(foreign.status, 403)
        same, _ = await self.call("POST", "/api/v1/login", body,
                                  dict(POST, Origin=self.base))
        self.assertEqual(same.status, 200)

    async def test_other_methods_are_refused(self):
        response, _ = await self.call("DELETE", "/api/v1/status")
        self.assertEqual(response.status, 405)


class Login(DashboardCase):
    async def test_wrong_password_then_lockout(self):
        for _ in range(5):
            response, data = await self.call("POST", "/api/v1/login", {"password": "nope-nope-nope"}, POST)
            self.assertEqual(response.status, 401)
        locked, _ = await self.call("POST", "/api/v1/login", {"password": PASSWORD}, POST)
        self.assertEqual(locked.status, 429)
        self.assertIn("Retry-After", locked.headers)

    async def test_session_cookie_flags_and_logout(self):
        response, _ = await self.call("POST", "/api/v1/login", {"password": PASSWORD}, POST)
        cookie = response.headers["Set-Cookie"]
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Strict", cookie)
        headers = await self.login()
        status, data = await self.call("GET", "/api/v1/status")
        self.assertEqual(status.status, 200)
        self.assertEqual(data["instance"]["id"], "instance-1")
        out, _ = await self.call("POST", "/api/v1/logout", {}, headers)
        self.assertEqual(out.status, 200)
        after, _ = await self.call("GET", "/api/v1/status")
        self.assertEqual(after.status, 401)

    async def test_signed_in_posts_need_the_csrf_token(self):
        headers = await self.login()
        session = self.trap_someone()
        missing, _ = await self.call("POST", "/api/v1/sessions/release", {"key": session.key}, POST)
        self.assertEqual(missing.status, 403)
        wrong, _ = await self.call("POST", "/api/v1/sessions/release", {"key": session.key},
                                   dict(POST, **{"X-CSRF-Token": "guess"}))
        self.assertEqual(wrong.status, 403)
        self.assertEqual(session.tier, "medium")
        ok, _ = await self.call("POST", "/api/v1/sessions/release", {"key": session.key}, headers)
        self.assertEqual(ok.status, 200)
        self.assertEqual(session.tier, "none")

    async def test_bad_json_and_unknown_session(self):
        headers = await self.login()
        async with self.client.post(self.base + "/api/v1/sessions/release", data="{nope",
                                    headers=headers) as response:
            self.assertEqual(response.status, 400)
        unknown, _ = await self.call("POST", "/api/v1/sessions/release", {"key": "nobody"}, headers)
        self.assertEqual(unknown.status, 404)


class Data(DashboardCase):
    async def test_sessions_events_and_release_round_trip(self):
        headers = await self.login()
        session = self.trap_someone()
        _, data = await self.call("GET", "/api/v1/sessions")
        row = next(r for r in data["sessions"] if r["key"] == session.key)
        self.assertEqual(row["tier"], "medium")
        self.assertEqual(row["groups"], ["client", "hidden_path"])
        _, events = await self.call("GET", "/api/v1/events?limit=10")
        kinds = {event["kind"] for event in events["events"]}
        self.assertEqual(kinds, {"signal", "tier"})
        self.assertTrue(any(event["alert"] for event in events["events"]))

        await self.call("POST", "/api/v1/sessions/release", {"key": session.key}, headers)
        _, data = await self.call("GET", "/api/v1/sessions")
        row = next(r for r in data["sessions"] if r["key"] == session.key)
        self.assertTrue(row["released"])
        await self.call("POST", "/api/v1/sessions/release",
                        {"key": session.key, "released": False}, headers)
        self.assertEqual(session.tier, "medium")

    async def test_hostile_strings_come_back_as_plain_json(self):
        await self.login()
        nasty = '<img src=x onerror=alert(1)>"\'</script>'
        info = request("/.env?" + nasty, headers={"Host": "x.example", "User-Agent": nasty})
        self.engine.finish(info, self.engine.begin(info), 404, "")
        self.store.flush()
        response, data = await self.call("GET", "/api/v1/events")
        self.assertTrue(response.headers["Content-Type"].startswith("application/json"))
        self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
        self.assertTrue(any(nasty in event["user_agent"] for event in data["events"]))

    async def test_live_stream_sends_status_then_activity(self):
        await self.login()
        async with self.client.get(self.base + "/api/v1/stream") as response:
            self.assertEqual(response.status, 200)
            self.assertTrue(response.headers["Content-Type"].startswith("text/event-stream"))
            first = await asyncio.wait_for(response.content.readuntil(b"\n\n"), 5)
            self.assertTrue(first.startswith(b"event: status\n"))
            self.trap_someone()
            seen = b""
            while b"event: activity" not in seen:
                seen += await asyncio.wait_for(response.content.readuntil(b"\n\n"), 5)
            payload = json.loads(seen.split(b"event: activity\ndata: ")[1].split(b"\n")[0])
            self.assertIn(payload["kind"], ("signal", "tier"))

    async def test_stream_count_is_capped(self):
        await self.login()
        self.dashboard._streams = 8
        response, _ = await self.call("GET", "/api/v1/stream")
        self.assertEqual(response.status, 503)
        self.dashboard._streams = 0


class FirstRun(DashboardCase):
    preset_password = False

    async def test_no_default_credentials_and_setup_needs_the_console_code(self):
        self.assertTrue(self.dashboard.setup_code)
        page, _ = await self.call("GET", "/")
        self.assertEqual(page.headers["Location"], "/setup")
        login, _ = await self.call("POST", "/api/v1/login", {"password": ""}, POST)
        self.assertEqual(login.status, 401)
        for guess in ("admin", "password"):
            login, _ = await self.call("POST", "/api/v1/login", {"password": guess}, POST)
            self.assertEqual(login.status, 401)

        wrong, _ = await self.call("POST", "/api/v1/setup",
                                   {"code": "AAAA-AAAA-AAAA", "password": PASSWORD}, POST)
        self.assertEqual(wrong.status, 403)
        weak, data = await self.call("POST", "/api/v1/setup",
                                     {"code": self.dashboard.setup_code, "password": "short"}, POST)
        self.assertEqual(weak.status, 400)
        done, _ = await self.call("POST", "/api/v1/setup",
                                  {"code": self.dashboard.setup_code.lower(), "password": PASSWORD}, POST)
        self.assertEqual(done.status, 200)
        self.assertIsNone(self.dashboard.setup_code)
        status, _ = await self.call("GET", "/api/v1/status")
        self.assertEqual(status.status, 200)                 # setup signs you in
        again, _ = await self.call("POST", "/api/v1/setup",
                                   {"code": "x", "password": PASSWORD}, POST)
        self.assertEqual(again.status, 409)
        stored = self.store.get_setting("dashboard_password")
        self.assertTrue(stored.startswith("scrypt$") and PASSWORD not in stored)

    async def test_setup_code_guessing_is_rate_limited(self):
        for _ in range(5):
            await self.call("POST", "/api/v1/setup", {"code": "nope", "password": PASSWORD}, POST)
        locked, _ = await self.call("POST", "/api/v1/setup",
                                    {"code": self.dashboard.setup_code, "password": PASSWORD}, POST)
        self.assertEqual(locked.status, 429)
