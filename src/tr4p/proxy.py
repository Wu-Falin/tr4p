"""Reverse proxy to the protected site.

Requests and responses are streamed through unchanged apart from standard
proxy housekeeping. The proxy never follows redirects, never stores cookies
and never decompresses on the site's behalf.
"""

from __future__ import annotations

import asyncio
from typing import Mapping

import aiohttp
from aiohttp import web
from multidict import CIMultiDict
from yarl import URL

from tr4p.config import PublicConfig

HOP_BY_HOP = frozenset({
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailer", "trailers", "transfer-encoding", "upgrade", "proxy-connection",
})
_WEBSOCKET_HEADERS = frozenset({
    "sec-websocket-key", "sec-websocket-version", "sec-websocket-extensions",
    "sec-websocket-protocol", "sec-websocket-accept",
})
# Headers the HTTP client library would otherwise add on its own.
_NO_AUTO_HEADERS = ("User-Agent", "Accept", "Accept-Encoding", "Content-Type")

WEBSOCKET_MAX_MESSAGE = 8 * 1024 * 1024


class UpstreamError(Exception):
    """The protected site could not be reached. `status` is 502 or 504."""

    def __init__(self, status: int) -> None:
        super().__init__(f"upstream error {status}")
        self.status = status


class Upstream:
    def __init__(self, config: PublicConfig) -> None:
        self._config = config
        self._base = config.upstream.rstrip("/")
        self._host = URL(config.upstream).authority
        self._session: aiohttp.ClientSession | None = None

    async def start(self) -> None:
        connector = aiohttp.TCPConnector(limit=self._config.upstream_connections)
        timeout = aiohttp.ClientTimeout(
            total=None, sock_connect=10, sock_read=self._config.upstream_timeout
        )
        self._session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            auto_decompress=False,
            cookie_jar=aiohttp.DummyCookieJar(),
            skip_auto_headers=_NO_AUTO_HEADERS,
        )

    async def close(self) -> None:
        if self._session is not None:
            await self._session.close()
            self._session = None

    def request_headers(
        self,
        headers: Mapping[str, str],
        client_ip: str,
        secure: bool,
        strip_cookie: str = "",
        identity: bool = False,
    ) -> CIMultiDict[str]:
        """Headers to send upstream for a client request."""
        named = {
            token.strip().lower()
            for token in headers.get("connection", "").split(",") if token.strip()
        }
        forwarded: CIMultiDict[str] = CIMultiDict()
        for name, value in headers.items():
            lowered = name.lower()
            if lowered in HOP_BY_HOP or lowered in named or lowered in _WEBSOCKET_HEADERS:
                continue
            if lowered == "host":
                continue
            if lowered == "cookie" and strip_cookie:
                value = _without_cookie(value, strip_cookie)
                if not value:
                    continue
            forwarded.add(name, value)
        original_host = headers.get("host", "")
        forwarded["Host"] = original_host if self._config.preserve_host and original_host else self._host
        previous = headers.get("x-forwarded-for")
        forwarded["X-Forwarded-For"] = f"{previous}, {client_ip}" if previous else client_ip
        forwarded["X-Forwarded-Proto"] = "https" if secure else "http"
        if original_host:
            forwarded["X-Forwarded-Host"] = original_host
        if identity:
            forwarded["Accept-Encoding"] = "identity"
        return forwarded

    async def fetch(
        self,
        method: str,
        raw_path: str,
        headers: CIMultiDict[str],
        body: object = None,
    ) -> aiohttp.ClientResponse:
        """Send one request upstream. The caller must release the response."""
        assert self._session is not None, "upstream not started"
        try:
            return await self._session.request(
                method,
                URL(self._base + raw_path, encoded=True),
                headers=headers,
                data=body,
                allow_redirects=False,
            )
        except asyncio.TimeoutError as exc:
            raise UpstreamError(504) from exc
        except (aiohttp.ClientError, OSError, ValueError) as exc:
            raise UpstreamError(502) from exc

    async def websocket(
        self, request: web.BaseRequest, headers: CIMultiDict[str], server_header: str
    ) -> web.StreamResponse:
        """Relay a WebSocket connection in both directions."""
        assert self._session is not None, "upstream not started"
        offered = [
            item.strip()
            for item in request.headers.get("sec-websocket-protocol", "").split(",")
            if item.strip()
        ]
        try:
            remote = await self._session.ws_connect(
                URL(self._base + request.raw_path, encoded=True),
                headers=headers,
                protocols=offered,
                autoclose=False,
                autoping=False,
                max_msg_size=WEBSOCKET_MAX_MESSAGE,
            )
        except aiohttp.WSServerHandshakeError as exc:
            raise UpstreamError(exc.status if 400 <= exc.status < 600 else 502) from exc
        except asyncio.TimeoutError as exc:
            raise UpstreamError(504) from exc
        except (aiohttp.ClientError, OSError, ValueError) as exc:
            raise UpstreamError(502) from exc

        local = web.WebSocketResponse(
            protocols=[remote.protocol] if remote.protocol else (),
            autoclose=False,
            autoping=False,
            max_msg_size=WEBSOCKET_MAX_MESSAGE,
        )
        local.headers["Server"] = server_header
        try:
            await local.prepare(request)
            pumps = [
                asyncio.ensure_future(_pump(local, remote)),
                asyncio.ensure_future(_pump(remote, local)),
            ]
            _, pending = await asyncio.wait(pumps, return_when=asyncio.FIRST_COMPLETED)
            for task in pending:
                task.cancel()
            await asyncio.gather(*pending, return_exceptions=True)
        finally:
            await remote.close()
            await local.close()
        return local


async def _pump(source, target) -> None:
    """Copy WebSocket messages one way until either side closes."""
    async for message in source:
        kind = message.type
        if kind == aiohttp.WSMsgType.TEXT:
            await target.send_str(message.data)
        elif kind == aiohttp.WSMsgType.BINARY:
            await target.send_bytes(message.data)
        elif kind == aiohttp.WSMsgType.PING:
            await target.ping(message.data)
        elif kind == aiohttp.WSMsgType.PONG:
            await target.pong(message.data)
        elif kind == aiohttp.WSMsgType.CLOSE:
            await target.close(code=message.data or 1000, message=(message.extra or "").encode())
            return
        else:
            return


def response_headers(headers: Mapping[str, str]) -> CIMultiDict[str]:
    """Headers from an upstream response that are safe to pass to the client."""
    named = {
        token.strip().lower()
        for token in headers.get("connection", "").split(",") if token.strip()
    }
    passed: CIMultiDict[str] = CIMultiDict()
    for name, value in headers.items():
        lowered = name.lower()
        if lowered in HOP_BY_HOP or lowered in named:
            continue
        passed.add(name, value)
    return passed


def _without_cookie(header: str, name: str) -> str:
    """Remove one cookie from a Cookie header value."""
    kept = [
        part.strip() for part in header.split(";")
        if part.strip() and part.strip().split("=", 1)[0] != name
    ]
    return "; ".join(kept)
