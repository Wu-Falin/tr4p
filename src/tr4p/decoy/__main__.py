"""Decoy process entry point.

Started by the main service with an empty environment. Reads one JSON
document from standard input, binds to loopback, prints "ready <port>" and
serves until its input closes or it is told to stop. Every request must
carry the shared key, so nothing else on the machine can talk to it.
"""

from __future__ import annotations

import asyncio
import hmac
import json
import sys

from aiohttp import web

from tr4p.decoy.app import DecoyApp

KEY_HEADER = "X-Decoy-Key"
SESSION_HEADER = "X-Decoy-Session"
TOUCH_HEADER = "X-Decoy-Touch"
MAX_BODY = 64 * 1024


def build(settings: dict) -> web.Application:
    decoy = DecoyApp(
        settings["profile"], bytes.fromhex(settings["seed"]), settings["look"],
        settings.get("tokens", {}), settings.get("schema"),
    )
    key = str(settings["key"]).encode("ascii")

    async def serve(request: web.Request) -> web.StreamResponse:
        if not hmac.compare_digest(request.headers.get(KEY_HEADER, "").encode("ascii", "replace"), key):
            return web.Response(status=403)
        sid = request.headers.get(SESSION_HEADER, "")[:64]
        path = request.path
        if path == "/__control/health":
            return web.json_response(decoy.stats())
        if path == "/__control/wipe":
            return web.json_response({"wiped": decoy.wipe(sid)})
        body = await request.content.read(MAX_BODY) if request.can_read_body else b""
        try:
            reply = decoy.handle(request.method, path, request.query_string, body, sid)
        except Exception:
            return web.Response(status=500)
        headers = dict(reply.headers)
        headers["Content-Type"] = reply.content_type
        if reply.touch:
            headers[TOUCH_HEADER] = reply.touch.encode("ascii", "replace").decode("ascii")[:80]
        return web.Response(status=reply.status, body=reply.body, headers=headers)

    app = web.Application(client_max_size=MAX_BODY)
    app.router.add_route("*", "/{tail:.*}", serve)
    return app


async def run(settings: dict) -> None:
    runner = web.AppRunner(build(settings), access_log=None, handle_signals=False)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", int(settings.get("port", 0)))
    await site.start()
    print(f"ready {runner.addresses[0][1]}", flush=True)
    loop = asyncio.get_running_loop()
    try:
        # The parent keeps our input open. When it closes, the parent is gone.
        await loop.run_in_executor(None, sys.stdin.read)
    finally:
        await runner.cleanup()


def main() -> int:
    settings = json.loads(sys.stdin.readline())
    try:
        asyncio.run(run(settings))
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
