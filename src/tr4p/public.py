"""The public listener: what real users and attackers connect to.

For every request it asks the detection engine for a verdict, then either
serves bait (for canary paths), passes the request to the protected site, or
answers from the built-in site in standalone mode. HTML pages from the
protected site get hidden tripwires added on the way out.

Rule of the house: anything this layer adds must fail open. If injection or
bookkeeping breaks, the visitor still gets the original page.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
from typing import Any

from aiohttp import web
from aiohttp.web_protocol import RequestHandler
from multidict import CIMultiDict

from tr4p.clients import is_asset_request
from tr4p.config import Config, parse_networks
from tr4p.engine import Engine, RequestInfo, Verdict
from tr4p.inject import build_snippet, can_inject, inject, merge_robots
from tr4p.loot import Loot, LootFactory
from tr4p.persona import Persona, reason_phrase
from tr4p.proxy import Upstream, UpstreamError, response_headers
from tr4p.seed import Seed
from tr4p.site import BuiltinSite

log = logging.getLogger("tr4p.public")

_INSPECTABLE_TYPES = (
    "application/x-www-form-urlencoded", "application/json", "text/",
    "application/xml", "multipart/form-data", "application/graphql",
)
_COMPRESSIBLE_TYPES = (
    "text/", "application/json", "application/javascript", "application/xml",
    "image/svg+xml", "application/xhtml+xml",
)
_SHARED_CACHE_MARKS = ("public", "s-maxage", "immutable")
_BODY_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
_ROBOTS_LIMIT = 256 * 1024
_LEARN_LIMIT = 64 * 1024
_INTEGRITY_HEADERS = ("Content-Length", "Content-MD5", "Digest", "Accept-Ranges")


class PublicApp:
    def __init__(self, config: Config, seed: Seed, engine: Engine, persona: Persona) -> None:
        self._config = config
        self._seed = seed
        self._engine = engine
        self._persona = persona
        self._trusted = parse_networks(config.public.trusted_proxies, "public.trusted_proxies")
        self._loot = LootFactory(seed, engine.honeytokens, persona)
        self._upstream: Upstream | None = None
        self._site: BuiltinSite | None = None
        if config.public.mode == "proxy":
            self._upstream = Upstream(config.public)
        else:
            self._site = BuiltinSite(persona, seed)
        self._runner: web.ServerRunner | None = None
        self.port = config.public.port

    # ---------------------------------------------------------------- lifecycle

    async def start(self) -> None:
        if self._upstream is not None:
            await self._upstream.start()
        server = _Server(
            self.handle,
            _protocol_class(self._render_parse_error),
            access_log=None,
        )
        self._runner = web.ServerRunner(server, handle_signals=False)
        await self._runner.setup()
        site = web.TCPSite(self._runner, self._config.public.host, self._config.public.port)
        await site.start()
        addresses = self._runner.addresses
        if addresses:
            self.port = addresses[0][1]

    async def stop(self) -> None:
        if self._runner is not None:
            await self._runner.cleanup()
            self._runner = None
        if self._upstream is not None:
            await self._upstream.close()

    # ------------------------------------------------------------------ handler

    async def handle(self, request: web.BaseRequest) -> web.StreamResponse:
        try:
            return await self._handle(request)
        except UpstreamError as exc:
            return self._error(request, exc.status)
        except (asyncio.CancelledError, ConnectionError):
            raise
        except Exception:
            log.exception("unhandled error while serving a request")
            return self._error(request, 500)

    async def _handle(self, request: web.BaseRequest) -> web.StreamResponse:
        headers = request.headers
        peer = _peer_address(request)
        trusted = self._is_trusted(peer)
        client_ip = self._client_ip(headers, peer) if trusted else peer
        secure = trusted and headers.get("x-forwarded-proto", "").lower() == "https"

        length = request.content_length
        limit = self._config.public.max_body_bytes
        if length is not None and limit and length > limit:
            return self._error(request, 413)

        if headers.get("expect", "").lower() == "100-continue" and request.version >= (1, 1):
            await request.writer.write(b"HTTP/1.1 100 Continue\r\n\r\n")
            request.writer.output_size = 0

        raw_path, _, query = request.raw_path.partition("?")
        path = request.path
        body = await self._small_body(request, length)
        info = RequestInfo(
            ip=client_ip,
            method=request.method,
            path=path,
            target=request.raw_path,
            query=query,
            headers=headers,
            http_version=(request.version.major, request.version.minor),
            cookie=request.cookies.get(self._persona.cookie_name),
            body=body,
            is_asset=is_asset_request(path, headers),
        )
        verdict = self._engine.begin(info)
        cookie = self._cookie_header(verdict, secure)

        if verdict.canary is not None:
            loot = self._canary_loot(request, info, verdict)
            status = loot.status if loot else 403
            self._engine.finish(info, verdict, status, loot.content_type if loot else "")
            return self._loot_response(request, loot, cookie)

        if self._upstream is None:
            return self._standalone(request, info, verdict, cookie)
        if path == "/robots.txt" and request.method == "GET" and not verdict.whitelisted:
            return await self._robots(request, info, verdict, client_ip, secure, cookie)
        return await self._proxy(request, info, verdict, client_ip, secure, body, cookie)

    async def _small_body(self, request: web.BaseRequest, length: int | None) -> bytes | None:
        """Read a request body only when it is small and worth inspecting.
        Large or unknown-length bodies are streamed through unread."""
        if (
            request.method not in _BODY_METHODS
            or not length
            or length > self._config.detection.inspect_body_bytes
            or not request.headers.get("content-type", "").lower().startswith(_INSPECTABLE_TYPES)
        ):
            return None
        try:
            return await request.content.readexactly(length)
        except asyncio.IncompleteReadError as exc:
            return exc.partial

    # --------------------------------------------------------------- standalone

    def _standalone(
        self, request: web.BaseRequest, info: RequestInfo, verdict: Verdict, cookie: str | None
    ) -> web.StreamResponse:
        assert self._site is not None
        if info.path == "/robots.txt":
            text = merge_robots(None, self._engine.canaries.current().disallow)
            self._engine.finish(info, verdict, 200, "text/plain")
            return self._own(request, 200, "text/plain", text.encode("ascii"), cookie)
        result = self._site.respond(request.method, info.path)
        if result is None:
            self._engine.finish(info, verdict, 404, "")
            if verdict.bait:
                loot = self._loot.render(info.path, request.host)
                if loot is not None:
                    return self._loot_response(request, loot, cookie)
            return self._error(request, 404, cookie)
        status, content_type, body = result
        self._engine.finish(info, verdict, status, content_type)
        if self._wants_injection(request, info, verdict):
            body = self._inject(body, content_type, info, verdict) or body
        return self._own(
            request, status, content_type, body,
            None if info.is_asset else cookie, compress=True,
        )

    # -------------------------------------------------------------------- proxy

    async def _proxy(
        self,
        request: web.BaseRequest,
        info: RequestInfo,
        verdict: Verdict,
        client_ip: str,
        secure: bool,
        body: bytes | None,
        cookie: str | None,
    ) -> web.StreamResponse:
        assert self._upstream is not None
        candidate = self._wants_injection(request, info, verdict)
        forward = self._upstream.request_headers(
            request.headers, client_ip, secure,
            strip_cookie=self._persona.cookie_name, identity=candidate,
        )
        if request.method == "GET" and request.headers.get("upgrade", "").lower() == "websocket":
            self._engine.finish(info, verdict, 101, "")
            return await self._upstream.websocket(request, forward, self._server_header())

        data: Any = body
        if data is None and request.body_exists:
            data = request.content
        upstream = await self._upstream.fetch(request.method, request.raw_path, forward, data)
        try:
            status = upstream.status
            content_type = upstream.headers.get("content-type", "")
            self._persona.learn_banner(upstream.headers.get("server"))
            self._engine.finish(info, verdict, status, content_type)

            if status == 404 and verdict.bait:
                loot = self._loot.render(info.path, request.host)
                if loot is not None:
                    upstream.close()
                    return self._loot_response(request, loot, cookie)

            headers = response_headers(upstream.headers)
            headers["Server"] = upstream.headers.get("server") or self._server_header()
            if cookie and self._may_set_cookie(info, headers):
                headers.add("Set-Cookie", cookie)
            encoded = "content-encoding" in upstream.headers
            compress = (
                candidate and not encoded
                and content_type.lower().startswith(_COMPRESSIBLE_TYPES)
            )

            if candidate and not encoded and status == 200 and can_inject(content_type, b""):
                return await self._relay_html(request, upstream, headers, info, verdict)
            if (
                candidate and not encoded and status == 404
                and self._persona.learned_not_found is None
            ):
                return await self._relay_learning(request, upstream, headers, content_type)
            return await self._relay(request, upstream, headers, compress=compress)
        except BaseException:
            upstream.close()
            raise
        finally:
            upstream.release()

    async def _relay(
        self,
        request: web.BaseRequest,
        upstream,
        headers: CIMultiDict[str],
        prefix: list[bytes] | None = None,
        compress: bool = False,
    ) -> web.StreamResponse:
        """Stream an upstream response to the client as it arrives."""
        response = web.StreamResponse(status=upstream.status, reason=upstream.reason, headers=headers)
        if compress:
            response.enable_compression()
        await response.prepare(request)
        for chunk in prefix or ():
            await response.write(chunk)
        async for chunk in upstream.content.iter_any():
            await response.write(chunk)
        await response.write_eof()
        return response

    async def _relay_html(
        self, request, upstream, headers: CIMultiDict[str], info: RequestInfo, verdict: Verdict
    ) -> web.StreamResponse:
        """Buffer a page (up to the configured cap), add tripwires, send it.
        Anything that does not fit or does not parse goes out untouched."""
        limit = self._config.inject.max_body_bytes
        declared = upstream.content_length
        if declared is not None and declared > limit:
            return await self._relay(request, upstream, headers, compress=True)
        chunks, complete = await _buffer(upstream, limit)
        if not complete:
            return await self._relay(request, upstream, headers, prefix=chunks, compress=True)
        body = b"".join(chunks)
        content_type = upstream.headers.get("content-type", "")
        changed = self._inject(body, content_type, info, verdict)
        if changed is not None:
            body = changed
            etag = headers.get("ETag")
            if etag and not etag.startswith("W/"):
                headers["ETag"] = "W/" + etag   # no longer byte-identical
        for name in _INTEGRITY_HEADERS:
            headers.popall(name, None)
        response = web.Response(status=upstream.status, reason=upstream.reason,
                                body=body, headers=headers)
        response.enable_compression()
        return response

    async def _relay_learning(
        self, request, upstream, headers: CIMultiDict[str], content_type: str
    ) -> web.StreamResponse:
        """Pass a "not found" page through while remembering what the real
        site's looks like, so our own can match it."""
        chunks, complete = await _buffer(upstream, _LEARN_LIMIT)
        if complete:
            self._persona.learn_not_found(upstream.status, content_type, b"".join(chunks))
        return await self._relay(request, upstream, headers, prefix=chunks, compress=True)

    async def _robots(
        self, request, info: RequestInfo, verdict: Verdict,
        client_ip: str, secure: bool, cookie: str | None,
    ) -> web.StreamResponse:
        """Serve the site's robots.txt with the canary directories added."""
        assert self._upstream is not None
        disallow = self._engine.canaries.current().disallow
        forward = self._upstream.request_headers(
            request.headers, client_ip, secure,
            strip_cookie=self._persona.cookie_name, identity=True,
        )
        upstream = await self._upstream.fetch("GET", request.raw_path, forward)
        try:
            status = upstream.status
            content_type = upstream.headers.get("content-type", "")
            self._engine.finish(info, verdict, 200 if status == 404 else status, "text/plain")
            headers = response_headers(upstream.headers)
            headers["Server"] = upstream.headers.get("server") or self._server_header()
            if status == 404:
                upstream.close()
                text = merge_robots(None, disallow)
                return self._own(request, 200, "text/plain", text.encode("ascii"), None)
            plain = content_type.lower().startswith("text/plain")
            if status != 200 or not plain or "content-encoding" in upstream.headers:
                return await self._relay(request, upstream, headers)
            chunks, complete = await _buffer(upstream, _ROBOTS_LIMIT)
            if not complete:
                return await self._relay(request, upstream, headers, prefix=chunks)
            try:
                merged = merge_robots(b"".join(chunks).decode("utf-8"), disallow).encode("utf-8")
            except Exception:  # fail open: the site's own file, untouched
                log.exception("could not merge robots.txt")
                merged = b"".join(chunks)
            for name in _INTEGRITY_HEADERS:
                headers.popall(name, None)
            headers.popall("ETag", None)
            return web.Response(status=200, body=merged, headers=headers)
        except BaseException:
            upstream.close()
            raise
        finally:
            upstream.release()

    # ---------------------------------------------------------------- injection

    def _wants_injection(self, request, info: RequestInfo, verdict: Verdict) -> bool:
        """Decide before the request goes out whether its answer is a page we
        would add tripwires to."""
        if (
            not self._config.inject.enabled
            or verdict.whitelisted
            or request.method != "GET"
            or info.is_asset
            or "range" in request.headers
            or request.headers.get("upgrade")
        ):
            return False
        accept = request.headers.get("accept", "").lower()
        return not accept or "text/html" in accept or "*/*" in accept

    def _inject(
        self, body: bytes, content_type: str, info: RequestInfo, verdict: Verdict
    ) -> bytes | None:
        """Return the page with tripwires added, or None to leave it alone."""
        try:
            if verdict.session is None or not can_inject(content_type, body):
                return None
            canaries = self._engine.canaries
            current = canaries.current()
            snippet = build_snippet(
                current,
                canaries.instruction_token(verdict.session.key),
                self._seed.rng("inject", current.rotation, info.path),
                self._config.canary.links_per_page,
            )
            return inject(body, snippet)
        except Exception:
            log.exception("tripwire injection failed; serving the original page")
            return None

    # ---------------------------------------------------------------- responses

    def _canary_loot(self, request, info: RequestInfo, verdict: Verdict) -> Loot | None:
        current = self._engine.canaries.current()
        if info.path == current.instruction_path:
            return self._loot.agent_notice(current)
        return self._loot.render(info.path, request.host)

    def _loot_response(self, request, loot: Loot | None, cookie: str | None) -> web.StreamResponse:
        if loot is None:
            return self._error(request, 403, cookie)
        extra = None
        if loot.static_file:
            stamp, etag = self._loot.file_headers(request.path, len(loot.body))
            extra = {"Last-Modified": stamp, "ETag": etag, "Accept-Ranges": "bytes"}
        return self._own(request, loot.status, loot.content_type, loot.body, cookie, extra)

    def _error(self, request, status: int, cookie: str | None = None) -> web.StreamResponse:
        content_type, body = self._persona.error_page(status, request.headers.get("host", ""))
        return self._own(request, status, content_type, body, cookie)

    def _render_parse_error(self, request, status: int) -> web.StreamResponse:
        """Answer malformed requests in the persona's style, not the HTTP
        library's."""
        content_type, body = self._persona.error_page(status)
        return self._own(request, status, content_type, body, None)

    def _own(
        self,
        request,
        status: int,
        content_type: str,
        body: bytes,
        cookie: str | None,
        extra: dict[str, str] | None = None,
        compress: bool = False,
    ) -> web.StreamResponse:
        headers: CIMultiDict[str] = CIMultiDict()
        headers["Server"] = self._server_header()
        headers["Content-Type"] = content_type
        if extra:
            headers.update(extra)
        if cookie:
            headers["Set-Cookie"] = cookie
        response = web.Response(status=status, reason=reason_phrase(status) if status >= 400 else None,
                                body=body, headers=headers)
        if compress and len(body) >= 512 and content_type.lower().startswith(_COMPRESSIBLE_TYPES):
            response.enable_compression()
        return response

    def _server_header(self) -> str:
        return self._persona.server_header or self._persona.banner

    # ----------------------------------------------------------------- identity

    def _cookie_header(self, verdict: Verdict, secure: bool) -> str | None:
        if not verdict.new_cookie:
            return None
        value = f"{self._persona.cookie_name}={verdict.new_cookie}; Path=/; HttpOnly; SameSite=Lax"
        return value + "; Secure" if secure else value

    @staticmethod
    def _may_set_cookie(info: RequestInfo, headers: CIMultiDict[str]) -> bool:
        """Never attach a session cookie to something a shared cache may
        store: one cached cookie would be handed to many visitors."""
        if info.is_asset:
            return False
        cache_control = headers.get("Cache-Control", "").lower()
        return not any(mark in cache_control for mark in _SHARED_CACHE_MARKS)

    def _is_trusted(self, peer: str) -> bool:
        if not self._trusted:
            return False
        try:
            address = ipaddress.ip_address(peer)
        except ValueError:
            return False
        return any(address.version == net.version and address in net for net in self._trusted)

    def _client_ip(self, headers, peer: str) -> str:
        """Real client address as reported by a trusted proxy: the right-most
        entry that is not itself a trusted proxy."""
        value = headers.get(self._config.public.client_ip_header, "")
        for part in reversed(value.split(",")):
            candidate = part.strip()
            if not candidate:
                continue
            try:
                ipaddress.ip_address(candidate)
            except ValueError:
                break
            if not self._is_trusted(candidate):
                return candidate
        return peer


async def _buffer(upstream, limit: int) -> tuple[list[bytes], bool]:
    """Read a response body up to `limit` bytes. Returns the chunks read and
    whether the body ended within the limit."""
    chunks: list[bytes] = []
    size = 0
    async for chunk in upstream.content.iter_any():
        chunks.append(chunk)
        size += len(chunk)
        if size > limit:
            return chunks, False
    return chunks, True


def _peer_address(request: web.BaseRequest) -> str:
    transport = request.transport
    peer = transport.get_extra_info("peername") if transport is not None else None
    if isinstance(peer, (tuple, list)) and peer:
        return str(peer[0])
    return ""


class _Server(web.Server):
    """Low-level server whose connections use our protocol class."""

    def __init__(self, handler, protocol_class, **kwargs: Any) -> None:
        super().__init__(handler, **kwargs)
        self._protocol_class = protocol_class
        self._protocol_kwargs = kwargs

    def __call__(self) -> RequestHandler:
        return self._protocol_class(
            self, loop=asyncio.get_running_loop(), **self._protocol_kwargs
        )


def _protocol_class(render_error):
    class Protocol(RequestHandler):
        __slots__ = ()

        def handle_error(self, request, status=500, exc=None, message=None):
            if status >= 500:
                log.error("request failed with status %s", status, exc_info=exc)
            if request.writer.output_size > 0:
                raise ConnectionError("response already started")
            response = render_error(request, status)
            response.force_close()
            return response

    return Protocol
