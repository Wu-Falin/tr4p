"""Harness for listener tests: a fake protected site plus the public listener."""

from __future__ import annotations

import gzip
import json
import unittest

import aiohttp
from aiohttp import web

from tests.helpers import MemorySink, make_seed
from tr4p.config import Config
from tr4p.engine import Engine
from tr4p.persona import Persona
from tr4p.public import PublicApp

HOME_PAGE = (
    b"<!doctype html><html><head><title>Shop</title></head>"
    b"<body><h1>Welcome</h1><p>Real content.</p></body></html>"
)
BROWSER = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/126.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "identity",
}
FORBIDDEN_WORDS = ("tr4p", "honeypot", "aiohttp", "python", "decoy", "tarpit")


def fake_site(hits: list[str]) -> web.Application:
    """A small stand-in for the protected application."""

    @web.middleware
    async def record(request, handler):
        hits.append(request.path)
        response = await handler(request)
        response.headers["Server"] = "gunicorn"
        return response

    async def home(request):
        return web.Response(body=HOME_PAGE, content_type="text/html", charset="utf-8",
                            headers={"ETag": '"abc123"'})

    async def data(request):
        return web.json_response({"ok": True, "items": [1, 2, 3]})

    async def css(request):
        return web.Response(text="body{}", content_type="text/css",
                            headers={"Cache-Control": "public, max-age=3600"})

    async def cached_page(request):
        return web.Response(body=HOME_PAGE, content_type="text/html",
                            headers={"Cache-Control": "public, s-maxage=600"})

    async def big(request):
        filler = b"<p>" + b"x" * 5000 + b"</p>"
        return web.Response(body=b"<html><body>" + filler * 10 + b"</body></html>",
                            content_type="text/html")

    async def fragment(request):
        return web.Response(body=b"<div>partial</div>", content_type="text/html")

    async def gzipped(request):
        return web.Response(body=gzip.compress(HOME_PAGE), content_type="text/html",
                            headers={"Content-Encoding": "gzip"})

    async def wide(request):
        return web.Response(body=HOME_PAGE.decode().encode("utf-16"),
                            headers={"Content-Type": "text/html; charset=utf-16"})

    async def echo(request):
        body = await request.read()
        return web.json_response({
            "method": request.method,
            "size": len(body),
            "headers": {k.lower(): v for k, v in request.headers.items()},
            "raw_path": request.raw_path,
        })

    async def robots(request):
        return web.Response(text="User-agent: *\nDisallow: /private/\n\nUser-agent: other\nDisallow: /\n")

    async def redirect(request):
        raise web.HTTPFound("/elsewhere")

    async def cookies(request):
        response = web.Response(body=HOME_PAGE, content_type="text/html")
        response.headers.add("Set-Cookie", "app_session=one; Path=/")
        response.headers.add("Set-Cookie", "theme=dark; Path=/")
        return response

    async def login_page(request):
        return web.Response(body=HOME_PAGE, content_type="text/html")

    async def socket(request):
        ws = web.WebSocketResponse(protocols=("chat",))
        await ws.prepare(request)
        async for message in ws:
            if message.type == aiohttp.WSMsgType.TEXT:
                await ws.send_str("echo:" + message.data)
            elif message.type == aiohttp.WSMsgType.BINARY:
                await ws.send_bytes(message.data[::-1])
        return ws

    async def missing(request):
        return web.Response(status=404, text='{"error":"no such thing"}',
                            content_type="application/json")

    app = web.Application(middlewares=[record], client_max_size=64 * 1024 * 1024)
    app.router.add_get("/", home)
    app.router.add_get("/api/data", data)
    app.router.add_get("/static/app.css", css)
    app.router.add_get("/cached", cached_page)
    app.router.add_get("/big", big)
    app.router.add_get("/fragment", fragment)
    app.router.add_get("/gz", gzipped)
    app.router.add_get("/wide", wide)
    app.router.add_route("*", "/echo", echo)
    app.router.add_get("/robots.txt", robots)
    app.router.add_get("/redirect", redirect)
    app.router.add_get("/cookies", cookies)
    app.router.add_get("/wp-login.php", login_page)
    app.router.add_get("/ws", socket)
    app.router.add_route("*", "/{tail:.*}", missing)
    return app


class ListenerCase(unittest.IsolatedAsyncioTestCase):
    """Starts a fake site and the public listener in front of it."""

    mode = "proxy"
    with_robots = True

    def configure(self, config: Config) -> None:
        """Override to adjust the config before start."""

    async def asyncSetUp(self) -> None:
        self.hits: list[str] = []
        self.config = Config()
        self.config.public.host = "127.0.0.1"
        self.config.public.port = 0
        self.config.public.mode = self.mode
        self.upstream_runner = None
        if self.mode == "proxy":
            self.upstream_runner = web.AppRunner(fake_site(self.hits), access_log=None)
            await self.upstream_runner.setup()
            site = web.TCPSite(self.upstream_runner, "127.0.0.1", 0)
            await site.start()
            port = self.upstream_runner.addresses[0][1]
            self.config.public.upstream = f"http://127.0.0.1:{port}"
        self.configure(self.config)
        self.seed = make_seed()
        self.sink = MemorySink()
        self.engine = Engine(self.config, self.seed, self.sink)
        self.persona = Persona.from_seed(self.seed)
        self.app = PublicApp(self.config, self.seed, self.engine, self.persona)
        await self.app.start()
        self.base = f"http://127.0.0.1:{self.app.port}"
        self.client = aiohttp.ClientSession(
            cookie_jar=aiohttp.DummyCookieJar(), auto_decompress=False,
            skip_auto_headers=("User-Agent", "Accept", "Accept-Encoding"),
        )

    async def asyncTearDown(self) -> None:
        await self.client.close()
        await self.app.stop()
        if self.upstream_runner is not None:
            await self.upstream_runner.cleanup()

    async def get(self, path: str, headers: dict | None = None, **kwargs):
        """GET returning (response, body bytes)."""
        async with self.client.get(
            self.base + path, headers=BROWSER if headers is None else headers,
            allow_redirects=False, **kwargs,
        ) as response:
            return response, await response.read()

    def signals(self) -> list[str]:
        return [event["signal"] for event in self.sink.kinds("signal")]

    def assert_anonymous(self, response, body: bytes) -> None:
        """A response must never reveal what produced it."""
        text = body.decode("utf-8", "replace").lower()
        header_text = json.dumps(dict(response.headers)).lower()
        for word in FORBIDDEN_WORDS:
            self.assertNotIn(word, text)
            self.assertNotIn(word, header_text)
