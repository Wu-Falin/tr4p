"""Starts, watches and talks to the decoy process.

Isolation at this level:

* the decoy is a separate process with an empty environment and an empty
  working directory;
* it is handed a seed derived for it alone, never the install secret, and
  none of the real configuration;
* it listens on loopback only and answers only requests carrying a key made
  up at start;
* it gets no upstream address and contains no client code.

Process isolation is not a sandbox. Container and network isolation come
with the Docker setup.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import secrets
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

import aiohttp
from multidict import CIMultiDict

from tr4p.config import Config
from tr4p.decoy.__main__ import KEY_HEADER, SESSION_HEADER, TOUCH_HEADER
from tr4p.fsutil import ensure_private_dir, write_private
from tr4p.honeytoken import Honeytokens
from tr4p.persona import Persona
from tr4p.schema import load_schema
from tr4p.seed import Seed
from tr4p.site import site_look

log = logging.getLogger("tr4p.decoy")

RUN_DIR = "decoy-run"
HANDOFF_FILE = "decoy.json"
HEALTH_SECONDS = 5.0
START_TIMEOUT = 20.0
RESTART_DELAYS = (1.0, 2.0, 5.0, 15.0, 60.0)
_FORWARD = ("user-agent", "accept", "accept-language", "content-type", "referer")
_PASS_BACK = ("Location", "Content-Disposition", "X-Powered-By")


class DecoyDown(Exception):
    """The decoy cannot answer. Callers must fail closed."""


@dataclass
class DecoyReply:
    status: int
    content_type: str
    body: bytes
    headers: dict[str, str]
    cookies: list[str]
    touch: str


class DecoyLink:
    def __init__(self, home: Path, config: Config, seed: Seed, persona: Persona,
                 honeytokens: Honeytokens) -> None:
        self._home = home
        self._config = config
        self._seed = seed
        self._settings = {
            "profile": config.decoy.profile,
            "seed": seed.digest("decoy").hex(),
            "look": site_look(persona, seed),
            "tokens": {token.name: token.value for token in honeytokens.all()},
            "port": 0,
        }
        self._key = ""
        self._port = 0
        # Remote mode: the decoy is another service (a container).
        self._remote = config.decoy.url.rstrip("/")
        self._healthy = False
        self._process: asyncio.subprocess.Process | None = None
        self._session: aiohttp.ClientSession | None = None
        self._watcher: asyncio.Task[None] | None = None
        self._stopping = False
        self.restarts = 0
        self.served = 0
        self.failures = 0
        self.touches = 0
        self.started_at = 0.0

    # ---------------------------------------------------------------- process

    @property
    def running(self) -> bool:
        if self._remote:
            return self._healthy
        return self._process is not None and self._process.returncode is None and self._port > 0

    def _base(self) -> str:
        return self._remote or f"http://127.0.0.1:{self._port}"

    def write_handoff(self) -> Path:
        """Write what a separately running decoy needs to know. The key is
        derived from the seed so both sides agree across restarts."""
        self._key = self._seed.hex("decoy-key", length=48)
        settings = dict(self._settings, key=self._key, schema=load_schema(self._home))
        path = Path(self._config.decoy.handoff_dir) / HANDOFF_FILE
        write_private(path, json.dumps(settings).encode("utf-8"))
        return path

    async def _check_remote(self) -> None:
        try:
            response = await self._call("GET", "/__control/health", "", force=True)
            async with response:
                self._healthy = response.status == 200
        except DecoyDown:
            self._healthy = False

    async def _watch_remote(self) -> None:
        while not self._stopping:
            await self._check_remote()
            await asyncio.sleep(1.0 if not self._healthy else HEALTH_SECONDS)

    def session_id(self, session_key: str) -> str:
        return self._seed.hex("decoy-session", session_key, length=32)

    async def start(self) -> None:
        self._session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self._config.decoy.timeout),
            cookie_jar=aiohttp.DummyCookieJar(), auto_decompress=False,
            skip_auto_headers=("User-Agent", "Accept", "Accept-Encoding", "Content-Type"),
        )
        if self._remote:
            self.write_handoff()
            await self._check_remote()
            self.started_at = time.time()
            self._watcher = asyncio.ensure_future(self._watch_remote())
            return
        try:
            await self._spawn()
        except (OSError, DecoyDown) as exc:
            log.error("decoy did not start: %s", exc)
        self._watcher = asyncio.ensure_future(self._watch())

    async def _spawn(self) -> None:
        run_dir = self._home / RUN_DIR
        ensure_private_dir(run_dir)
        self._key = secrets.token_hex(24)
        settings = dict(self._settings, key=self._key, schema=load_schema(self._home))
        # Empty environment: nothing of ours leaks in. Windows needs
        # SYSTEMROOT for sockets to work at all.
        environment = {name: os.environ[name] for name in ("SYSTEMROOT",) if name in os.environ}
        self._port = 0
        self._process = await asyncio.create_subprocess_exec(
            sys.executable, "-m", "tr4p.decoy",
            stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL, cwd=str(run_dir), env=environment,
        )
        assert self._process.stdin is not None and self._process.stdout is not None
        self._process.stdin.write(json.dumps(settings).encode("utf-8") + b"\n")
        await self._process.stdin.drain()
        try:
            line = await asyncio.wait_for(self._process.stdout.readline(), START_TIMEOUT)
        except asyncio.TimeoutError as exc:
            self._process.kill()
            raise DecoyDown("no answer from the decoy process") from exc
        words = line.decode("ascii", "replace").split()
        if len(words) != 2 or words[0] != "ready" or not words[1].isdigit():
            raise DecoyDown("the decoy process did not come up")
        self._port = int(words[1])
        self.started_at = time.time()

    async def _watch(self) -> None:
        """Restart the decoy when it exits, backing off if it keeps dying."""
        attempt = 0
        while not self._stopping:
            if self._process is not None and self._process.returncode is None:
                await self._process.wait()
                self._port = 0
                if self._stopping:
                    return
                log.warning("decoy process exited; restarting")
            await asyncio.sleep(RESTART_DELAYS[min(attempt, len(RESTART_DELAYS) - 1)])
            if self._stopping:
                return
            try:
                await self._spawn()
                self.restarts += 1
                attempt = 0
            except (OSError, DecoyDown) as exc:
                attempt += 1
                log.error("decoy restart failed: %s", exc)

    async def stop(self) -> None:
        self._stopping = True
        if self._watcher is not None:
            self._watcher.cancel()
            await asyncio.gather(self._watcher, return_exceptions=True)
        process = self._process
        if process is not None and process.returncode is None:
            if process.stdin is not None:
                process.stdin.close()         # the decoy stops when its input closes
            try:
                await asyncio.wait_for(process.wait(), 5)
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
        self._port = 0
        if self._session is not None:
            await self._session.close()

    # --------------------------------------------------------------- requests

    async def _call(self, method: str, target: str, sid: str,
                    headers: Mapping[str, str] | None = None, body: bytes = b"",
                    force: bool = False):
        if self._session is None or not (force or self.running):
            raise DecoyDown("decoy is not running")
        send: CIMultiDict[str] = CIMultiDict(headers or {})
        send[KEY_HEADER] = self._key
        send[SESSION_HEADER] = sid
        try:
            return await self._session.request(
                method, f"{self._base()}{target}", headers=send,
                data=body or None, allow_redirects=False,
            )
        except (aiohttp.ClientError, asyncio.TimeoutError, OSError, ValueError) as exc:
            raise DecoyDown(str(exc)) from exc

    async def fetch(self, method: str, target: str, headers: Mapping[str, str],
                    body: bytes | None, session_key: str) -> DecoyReply:
        """Ask the decoy for an answer. Raises DecoyDown on any failure."""
        forward = {name: headers[name] for name in _FORWARD if name in headers}
        try:
            response = await self._call(method, target, self.session_id(session_key), forward, body or b"")
            async with response:
                data = await response.read()
                if response.status >= 500:
                    raise DecoyDown(f"decoy answered {response.status}")
                touch = response.headers.get(TOUCH_HEADER, "")
                reply = DecoyReply(
                    response.status, response.headers.get("Content-Type", "text/html"), data,
                    {name: response.headers[name] for name in _PASS_BACK if name in response.headers},
                    response.headers.getall("Set-Cookie", []), touch,
                )
        except DecoyDown:
            self.failures += 1
            raise
        except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as exc:
            self.failures += 1
            raise DecoyDown(str(exc)) from exc
        self.served += 1
        if touch:
            self.touches += 1
        return reply

    async def wipe(self, session_key: str) -> bool:
        """Forget everything the decoy holds about a session."""
        try:
            response = await self._call("POST", "/__control/wipe", self.session_id(session_key))
            async with response:
                return bool((await response.json()).get("wiped"))
        except (DecoyDown, aiohttp.ClientError, asyncio.TimeoutError, ValueError):
            return False

    def stats(self) -> dict[str, Any]:
        return {
            "enabled": True, "running": self.running, "profile": self._config.decoy.profile,
            "placement": "separate service" if self._remote else "child process",
            "served": self.served, "touches": self.touches, "failures": self.failures,
            "restarts": self.restarts,
            "uptime": time.time() - self.started_at if self.running else 0.0,
        }
