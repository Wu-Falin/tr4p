"""Decoy process entry point.

Two ways to start it:

* As a child of the main service (the default): settings arrive as one JSON
  line on standard input, the process binds to loopback and stops when its
  input closes.
* As its own service in a container: `--settings FILE` names a hand-over
  file written by the main service into a directory both can see. That file
  is the only thing this process ever reads.

Every request except the bare liveness ping must carry the shared key.
"""

from __future__ import annotations

import argparse
import asyncio
import hmac
import json
import sys
import time
from pathlib import Path

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
        path = request.path
        if path == "/__control/ping":
            return web.Response(status=204)       # liveness only, says nothing
        if not hmac.compare_digest(request.headers.get(KEY_HEADER, "").encode("ascii", "replace"), key):
            return web.Response(status=403)
        sid = request.headers.get(SESSION_HEADER, "")[:64]
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


async def run(settings: dict, host: str, port: int, follow_input: bool) -> None:
    runner = web.AppRunner(build(settings), access_log=None, handle_signals=not follow_input)
    await runner.setup()
    site = web.TCPSite(runner, host, port)
    await site.start()
    print(f"ready {runner.addresses[0][1]}", flush=True)
    try:
        if follow_input:
            # The parent keeps our input open. When it closes, the parent is gone.
            await asyncio.get_running_loop().run_in_executor(None, sys.stdin.read)
        else:
            await asyncio.Event().wait()
    finally:
        await runner.cleanup()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="tr4p.decoy")
    parser.add_argument("--settings", type=Path, help="hand-over file written by the main service")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=0)
    args = parser.parse_args(argv)
    if args.settings is None:
        settings = json.loads(sys.stdin.readline())
        host, port, follow = "127.0.0.1", int(settings.get("port", 0)), True
    else:
        while not args.settings.is_file():        # the main service writes it at start
            time.sleep(1.0)
        settings = json.loads(args.settings.read_text(encoding="utf-8"))
        host, port, follow = args.host, args.port, False
    try:
        asyncio.run(run(settings, host, port, follow))
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
