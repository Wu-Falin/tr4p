"""Verification of search engine crawlers.

A user agent claiming to be a well-known crawler proves nothing. The major
engines document a check that does: the address must reverse-resolve to the
engine's domain, and that name must resolve back to the same address.
Verified crawlers are exempt from tiers so indexing is never disturbed.
"""

from __future__ import annotations

import asyncio
import socket
import time
from collections import OrderedDict
from typing import Awaitable, Callable

# user-agent marker -> domain suffixes its addresses reverse-resolve to
KNOWN_CRAWLERS: dict[str, tuple[str, ...]] = {
    "googlebot": (".googlebot.com", ".google.com"),
    "google-inspectiontool": (".googlebot.com", ".google.com"),
    "bingbot": (".search.msn.com",),
    "yandex": (".yandex.ru", ".yandex.net", ".yandex.com"),
    "baiduspider": (".baidu.com", ".baidu.jp"),
    "applebot": (".applebot.apple.com",),
    "slurp": (".crawl.yahoo.net",),
    "seznambot": (".seznam.cz",),
}

Resolver = Callable[[str], Awaitable[tuple[str, list[str]]]]

LOOKUP_TIMEOUT = 4.0


def crawler_name(user_agent: str) -> str | None:
    lowered = user_agent.lower()
    for name in KNOWN_CRAWLERS:
        if name in lowered:
            return name
    return None


async def system_resolver(address: str) -> tuple[str, list[str]]:
    """Reverse-resolve an address, then resolve that name forward again."""
    loop = asyncio.get_running_loop()
    host, _ = await loop.getnameinfo((address, 0), socket.NI_NAMEREQD)
    infos = await loop.getaddrinfo(host, None)
    return host, [info[4][0] for info in infos]


class CrawlerVerifier:
    def __init__(
        self,
        resolver: Resolver = system_resolver,
        ttl: float = 86400.0,
        max_cached: int = 2048,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._resolver = resolver
        self._ttl = ttl
        self._max = max_cached
        self._clock = clock
        self._cache: OrderedDict[tuple[str, str], tuple[bool, float]] = OrderedDict()

    async def verify(self, address: str, user_agent: str) -> bool:
        name = crawler_name(user_agent)
        if name is None:
            return False
        key = (address, name)
        cached = self._cache.get(key)
        now = self._clock()
        if cached is not None and now - cached[1] < self._ttl:
            return cached[0]
        result = await self._lookup(address, KNOWN_CRAWLERS[name])
        self._cache[key] = (result, now)
        self._cache.move_to_end(key)
        while len(self._cache) > self._max:
            self._cache.popitem(last=False)
        return result

    async def _lookup(self, address: str, suffixes: tuple[str, ...]) -> bool:
        try:
            host, forward = await asyncio.wait_for(self._resolver(address), LOOKUP_TIMEOUT)
        except (OSError, asyncio.TimeoutError, UnicodeError):
            return False
        host = host.rstrip(".").lower()
        return host.endswith(suffixes) and address in forward
