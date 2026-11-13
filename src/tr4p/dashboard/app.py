"""Dashboard web application.

The dashboard is an attack surface of its own, so it is deliberately strict:

* listens on loopback unless configured otherwise, on its own port;
* no default credentials: first run requires creating a password, and that
  step needs a one-time code shown only on the server console;
* Host header allow-list (stops DNS rebinding against a loopback service);
* state-changing requests need a same-origin Origin, a custom header that
  cross-site forms cannot send, and for signed-in actions a per-session
  CSRF token;
* login and setup attempts are rate limited;
* a tight content security policy, and all event data is rendered as text.

Every payload carries the instance id, so a later multi-instance view can
aggregate several of these APIs without changing them.
"""

from __future__ import annotations

import asyncio
import hmac
import json
import logging
import time
from importlib import resources
from typing import Any, Awaitable, Callable

from aiohttp import web

from tr4p import __version__, scoring
from tr4p.bus import EventBus
from tr4p.config import Config, ConfigError
from tr4p.dashboard.auth import (
    LoginLimiter,
    SessionStore,
    hash_password,
    new_setup_code,
    password_problem,
    verify_password,
)
from tr4p.engine import Engine
from tr4p.levels import PRESETS, level_of, preset_changes
from tr4p.store import Store

log = logging.getLogger("tr4p.dashboard")

PASSWORD_SETTING = "dashboard_password"
COOKIE_NAME = "dash_session"
CLIENT_HEADER = "X-Requested-With"
CLIENT_HEADER_VALUE = "dashboard"
CSRF_HEADER = "X-CSRF-Token"
MAX_STREAMS = 8
STATUS_INTERVAL = 2.0
MAX_JSON_BYTES = 8192

_SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
        "connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Server": "web",
}

# file name -> (content type, needs sign-in)
_STATIC = {
    "auth.css": ("text/css", False),
    "auth.js": ("application/javascript", False),
    "app.css": ("text/css", True),
    "app.js": ("application/javascript", True),
}
_OPEN_PATHS = frozenset({
    "/login", "/setup", "/api/v1/state", "/api/v1/login", "/api/v1/setup",
})
_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "[::1]"})

# The only settings the dashboard may change, by config section.
EDITABLE = {
    "tarpit": ("enabled", "adaptive", "base_delay", "max_delay", "light_max_delay",
               "max_sessions"),
    "detection": ("medium_threshold", "trap_threshold"),
    "maze": ("rabbit_depth", "redirect_chance"),
}
TIMELINE_LIMIT = 500


def _asset(name: str) -> bytes:
    return (resources.files("tr4p.dashboard") / "static" / name).read_bytes()


class Dashboard:
    def __init__(
        self,
        config: Config,
        engine: Engine,
        store: Store,
        bus: EventBus,
        instance_id: str,
        status: Callable[[], dict[str, Any]],
        apply_settings: Callable[[dict[str, Any], str], Awaitable[None]] | None = None,
    ) -> None:
        self._config = config
        self._engine = engine
        self._store = store
        self._bus = bus
        self._instance_id = instance_id
        self._status = status
        self._apply_settings = apply_settings
        self._sessions = SessionStore(config.dashboard.session_hours * 3600.0)
        self._limiter = LoginLimiter()
        self._streams = 0
        self._runner: web.AppRunner | None = None
        self.port = config.dashboard.port
        self.setup_code: str | None = None
        hosts = set(_LOOPBACK_HOSTS) | {h.lower() for h in config.dashboard.allowed_hosts}
        bind = config.dashboard.host.lower()
        if bind not in ("0.0.0.0", "::", ""):
            hosts.add(f"[{bind}]" if ":" in bind else bind)
        self._hosts = frozenset(hosts)

    # ---------------------------------------------------------------- lifecycle

    def setup_required(self) -> bool:
        return self._store.get_setting(PASSWORD_SETTING) is None

    def build(self) -> web.Application:
        app = web.Application(middlewares=[self._guard], client_max_size=MAX_JSON_BYTES)
        add = app.router
        add.add_get("/", self._page_index)
        add.add_get("/login", self._page_login)
        add.add_get("/setup", self._page_setup)
        add.add_get("/static/{name}", self._static)
        add.add_get("/api/v1/state", self._api_state)
        add.add_post("/api/v1/setup", self._api_setup)
        add.add_post("/api/v1/login", self._api_login)
        add.add_post("/api/v1/logout", self._api_logout)
        add.add_get("/api/v1/session", self._api_session)
        add.add_get("/api/v1/status", self._api_status)
        add.add_get("/api/v1/events", self._api_events)
        add.add_get("/api/v1/sessions", self._api_sessions)
        add.add_post("/api/v1/sessions/release", self._api_release)
        add.add_get("/api/v1/sessions/timeline", self._api_timeline)
        add.add_get("/api/v1/settings", self._api_settings)
        add.add_post("/api/v1/settings", self._api_settings_update)
        add.add_get("/api/v1/stream", self._api_stream)
        return app

    async def start(self) -> None:
        if self.setup_required():
            self.setup_code = new_setup_code()
        self._runner = web.AppRunner(self.build(), access_log=None, handle_signals=False)
        await self._runner.setup()
        site = web.TCPSite(self._runner, self._config.dashboard.host, self._config.dashboard.port)
        await site.start()
        if self._runner.addresses:
            self.port = self._runner.addresses[0][1]

    async def stop(self) -> None:
        if self._runner is not None:
            await self._runner.cleanup()
            self._runner = None

    # --------------------------------------------------------------- middleware

    @web.middleware
    async def _guard(
        self, request: web.Request, handler: Callable[[web.Request], Awaitable[web.StreamResponse]]
    ) -> web.StreamResponse:
        try:
            response = await self._guarded(request, handler)
        except web.HTTPException as exc:
            exc.headers.update(_SECURITY_HEADERS)
            raise
        if not response.prepared:
            response.headers.update(_SECURITY_HEADERS)
        return response

    async def _guarded(self, request: web.Request, handler) -> web.StreamResponse:
        if not self._host_allowed(request):
            return web.Response(status=421, text="Unknown host")
        if request.method not in ("GET", "POST"):
            return web.Response(status=405, text="Method not allowed")

        session = self._session(request)
        path = request.path
        is_api = path.startswith("/api/")

        if request.method == "POST":
            if not self._same_origin(request) or (
                request.headers.get(CLIENT_HEADER) != CLIENT_HEADER_VALUE
            ):
                return _json({"error": "cross-site request refused"}, 403)

        if path in _OPEN_PATHS or (
            path.startswith("/static/") and not _STATIC.get(path[8:], ("", True))[1]
        ):
            return await handler(request)

        if session is None:
            if is_api:
                return _json({"error": "sign in required"}, 401)
            raise web.HTTPFound("/setup" if self.setup_required() else "/login")
        if request.method == "POST":
            sent = request.headers.get(CSRF_HEADER, "")
            if not hmac.compare_digest(sent.encode(), session.csrf.encode()):
                return _json({"error": "invalid request token"}, 403)
        return await handler(request)

    def _session(self, request: web.Request):
        return self._sessions.get(request.cookies.get(COOKIE_NAME))

    def _host_allowed(self, request: web.Request) -> bool:
        host = request.headers.get("Host", "").lower()
        if host.startswith("["):
            name = host[: host.find("]") + 1]
        else:
            name = host.rsplit(":", 1)[0] if ":" in host else host
        return name in self._hosts

    @staticmethod
    def _same_origin(request: web.Request) -> bool:
        origin = request.headers.get("Origin")
        if origin is None:
            # Non-browser clients send no Origin; the custom header and the
            # session token still apply to them.
            return True
        host = request.headers.get("Host", "")
        return origin in (f"http://{host}", f"https://{host}")

    # -------------------------------------------------------------------- pages

    async def _page_index(self, request: web.Request) -> web.StreamResponse:
        return _html(_asset("index.html"))

    async def _page_login(self, request: web.Request) -> web.StreamResponse:
        if self.setup_required():
            raise web.HTTPFound("/setup")
        if self._session(request) is not None:
            raise web.HTTPFound("/")
        return _html(_asset("login.html"))

    async def _page_setup(self, request: web.Request) -> web.StreamResponse:
        if not self.setup_required():
            raise web.HTTPFound("/login")
        return _html(_asset("setup.html"))

    async def _static(self, request: web.Request) -> web.StreamResponse:
        name = request.match_info["name"]
        entry = _STATIC.get(name)
        if entry is None:
            raise web.HTTPNotFound()
        return web.Response(body=_asset(name), content_type=entry[0], charset="utf-8")

    # --------------------------------------------------------------------- auth

    async def _api_state(self, request: web.Request) -> web.StreamResponse:
        return _json({
            "setup_required": self.setup_required(),
            "authenticated": self._session(request) is not None,
        })

    async def _api_setup(self, request: web.Request) -> web.StreamResponse:
        if not self.setup_required():
            return _json({"error": "setup is already complete"}, 409)
        address = request.remote or ""
        wait = self._limiter.retry_after(address)
        if wait > 0:
            return _too_many(wait)
        data = await _read_json(request)
        code = str(data.get("code", "")).strip().upper()
        password = str(data.get("password", ""))
        expected = self.setup_code or ""
        if not expected or not hmac.compare_digest(code.encode(), expected.encode()):
            self._limiter.failure(address)
            return _json({"error": "Setup code is not correct. It is printed on the "
                                   "server console when the service starts."}, 403)
        problem = password_problem(password)
        if problem:
            return _json({"error": problem}, 400)
        hashed = await asyncio.to_thread(hash_password, password)
        await asyncio.to_thread(self._store.set_setting, PASSWORD_SETTING, hashed)
        self.setup_code = None
        log.info("dashboard password created")
        return self._sign_in(request)

    async def _api_login(self, request: web.Request) -> web.StreamResponse:
        address = request.remote or ""
        wait = self._limiter.retry_after(address)
        if wait > 0:
            return _too_many(wait)
        data = await _read_json(request)
        password = str(data.get("password", ""))
        stored = self._store.get_setting(PASSWORD_SETTING)
        valid = False
        if stored and 0 < len(password) <= 1024:
            valid = await asyncio.to_thread(verify_password, password, stored)
        if not valid:
            self._limiter.failure(address)
            log.warning("failed dashboard login from %s", address)
            return _json({"error": "Wrong password."}, 401)
        self._limiter.success(address)
        return self._sign_in(request)

    def _sign_in(self, request: web.Request) -> web.StreamResponse:
        token, _ = self._sessions.create()
        response = _json({"ok": True})
        response.set_cookie(
            COOKIE_NAME, token,
            httponly=True, samesite="Strict", path="/",
            secure=request.headers.get("X-Forwarded-Proto", "").lower() == "https",
            max_age=int(self._config.dashboard.session_hours * 3600),
        )
        return response

    async def _api_logout(self, request: web.Request) -> web.StreamResponse:
        self._sessions.drop(request.cookies.get(COOKIE_NAME))
        response = _json({"ok": True})
        response.del_cookie(COOKIE_NAME, path="/")
        return response

    async def _api_session(self, request: web.Request) -> web.StreamResponse:
        return _json({"csrf": self._session(request).csrf, "instance": self._instance()})

    # --------------------------------------------------------------------- data

    def _instance(self) -> dict[str, str]:
        return {
            "id": self._instance_id,
            "name": self._config.instance_name,
            "version": __version__,
        }

    def _status_payload(self) -> dict[str, Any]:
        payload = self._status()
        payload["instance"] = self._instance()
        payload["streams"] = self._streams
        return payload

    async def _api_status(self, request: web.Request) -> web.StreamResponse:
        return _json(self._status_payload())

    async def _api_events(self, request: web.Request) -> web.StreamResponse:
        query = request.query
        events = await self._store.events_async(
            limit=_int(query.get("limit"), 100),
            before=_int(query.get("before"), 0),
            session=query.get("session", "")[:80],
        )
        return _json({"instance": self._instance(), "events": events})

    async def _api_sessions(self, request: web.Request) -> web.StreamResponse:
        rows = []
        for session in self._engine.sessions.flagged():
            row = session.snapshot()
            row["groups"] = sorted(scoring.evidence_groups(session.signals))
            rows.append(row)
        rows.sort(key=lambda row: row["last_seen"], reverse=True)
        return _json({"instance": self._instance(), "sessions": rows[:300]})

    async def _api_release(self, request: web.Request) -> web.StreamResponse:
        data = await _read_json(request)
        key = str(data.get("key", ""))[:80]
        released = data.get("released", True) is not False
        if not key or not self._engine.release(key, released):
            return _json({"error": "unknown session"}, 404)
        return _json({"ok": True, "released": released})

    async def _api_timeline(self, request: web.Request) -> web.StreamResponse:
        """Everything recorded about one session, oldest first."""
        key = request.query.get("key", "")[:80]
        session = self._engine.sessions.get(key) if key else None
        if session is None:
            return _json({"error": "unknown session"}, 404)
        events = await self._store.events_async(limit=TIMELINE_LIMIT, session=key)
        events.reverse()
        row = session.snapshot()
        row["groups"] = sorted(scoring.evidence_groups(session.signals))
        return _json({"instance": self._instance(), "session": row, "events": events,
                      "truncated": len(events) >= TIMELINE_LIMIT})

    # ----------------------------------------------------------------- settings

    def _settings_payload(self) -> dict[str, Any]:
        values = {
            section: {name: getattr(getattr(self._config, section), name) for name in names}
            for section, names in EDITABLE.items()
        }
        return {
            "instance": self._instance(),
            "level": level_of(self._config),
            "presets": {str(level): preset for level, preset in PRESETS.items()},
            "values": values,
        }

    async def _api_settings(self, request: web.Request) -> web.StreamResponse:
        return _json(self._settings_payload())

    async def _api_settings_update(self, request: web.Request) -> web.StreamResponse:
        if self._apply_settings is None:
            return _json({"error": "settings cannot be changed here"}, 409)
        data = await _read_json(request)
        changes: dict[str, dict[str, Any]] = {}
        note = "settings changed"
        if "level" in data:
            try:
                changes = preset_changes(int(data["level"]))
            except (TypeError, ValueError):
                return _json({"error": "level must be 1-5"}, 400)
            note = f"tiring level set to {data['level']}"
        values = data.get("values", {})
        if not isinstance(values, dict):
            return _json({"error": "values must be an object"}, 400)
        for section, entries in values.items():
            if section not in EDITABLE or not isinstance(entries, dict):
                return _json({"error": f"unknown settings section: {section}"}, 400)
            for name, value in entries.items():
                if name not in EDITABLE[section]:
                    return _json({"error": f"{section}.{name} cannot be changed here"}, 400)
                changes.setdefault(section, {})[name] = value
        if not changes:
            return _json({"error": "nothing to change"}, 400)
        try:
            await self._apply_settings(changes, note)
        except ConfigError as exc:
            return _json({"error": str(exc)}, 400)
        return _json(self._settings_payload())

    async def _api_stream(self, request: web.Request) -> web.StreamResponse:
        """Server-sent events: live activity plus a status tick."""
        if self._streams >= MAX_STREAMS:
            return _json({"error": "too many live views open"}, 503)
        response = web.StreamResponse(headers={
            "Content-Type": "text/event-stream",
            "X-Accel-Buffering": "no",
        })
        response.headers.update(_SECURITY_HEADERS)
        await response.prepare(request)
        subscriber = self._bus.subscribe()
        self._streams += 1
        token = request.cookies.get(COOKIE_NAME)
        try:
            await _send(response, "status", self._status_payload())
            next_status = time.monotonic() + STATUS_INTERVAL
            while self._sessions.get(token) is not None:   # ends on sign-out or expiry
                timeout = max(0.05, next_status - time.monotonic())
                try:
                    event = await asyncio.wait_for(subscriber.get(), timeout)
                    await _send(response, "activity", event)
                except asyncio.TimeoutError:
                    pass
                if time.monotonic() >= next_status:
                    await _send(response, "status", self._status_payload())
                    next_status = time.monotonic() + STATUS_INTERVAL
        except (ConnectionError, asyncio.CancelledError):
            pass
        finally:
            self._streams -= 1
            self._bus.unsubscribe(subscriber)
        return response


async def _send(response: web.StreamResponse, name: str, payload: dict[str, Any]) -> None:
    data = json.dumps(payload, separators=(",", ":"))
    await response.write(f"event: {name}\ndata: {data}\n\n".encode("utf-8"))


async def _read_json(request: web.Request) -> dict[str, Any]:
    try:
        data = json.loads(await request.read())
    except (ValueError, UnicodeDecodeError):
        raise web.HTTPBadRequest(text="invalid JSON") from None
    if not isinstance(data, dict):
        raise web.HTTPBadRequest(text="invalid JSON")
    return data


def _json(payload: dict[str, Any], status: int = 200) -> web.Response:
    return web.json_response(payload, status=status)


def _html(body: bytes) -> web.Response:
    return web.Response(body=body, content_type="text/html", charset="utf-8")


def _too_many(wait: float) -> web.Response:
    response = _json({"error": "Too many attempts. Try again later."}, 429)
    response.headers["Retry-After"] = str(int(wait) + 1)
    return response


def _int(value: str | None, default: int) -> int:
    try:
        return int(value) if value is not None else default
    except ValueError:
        return default
