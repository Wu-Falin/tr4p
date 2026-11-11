"""Shared test helpers."""

from __future__ import annotations

from typing import Any

from multidict import CIMultiDict

from tr4p.config import Config
from tr4p.engine import Engine, RequestInfo
from tr4p.seed import Seed

# 203.0.113.0/24 and 198.51.100.0/24 are reserved for documentation.
CLIENT_IP = "203.0.113.10"
OTHER_IP = "198.51.100.7"

BROWSER_HEADERS = {
    "Host": "shop.example",
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/126.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate",
}
SCRIPT_HEADERS = {"Host": "shop.example", "User-Agent": "python-requests/2.32", "Accept": "*/*"}


class Clock:
    def __init__(self, start: float = 1_700_000_000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def tick(self, seconds: float) -> None:
        self.now += seconds


class MemorySink:
    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []
        self.sessions: dict[str, dict[str, Any]] = {}

    def event(self, event: dict[str, Any]) -> None:
        self.events.append(event)

    def session(self, snapshot: dict[str, Any]) -> None:
        self.sessions[snapshot["key"]] = snapshot

    def kinds(self, kind: str) -> list[dict[str, Any]]:
        return [event for event in self.events if event["kind"] == kind]


def make_seed(byte: int = 7) -> Seed:
    return Seed(bytes([byte]) * 32)


def make_engine(config: Config | None = None, seed: Seed | None = None):
    clock = Clock()
    sink = MemorySink()
    engine = Engine(config or Config(), seed or make_seed(), sink, clock)
    return engine, sink, clock


def request(
    path: str = "/",
    *,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    ip: str = CLIENT_IP,
    cookie: str | None = None,
    body: bytes | None = None,
    is_asset: bool = False,
) -> RequestInfo:
    target = path
    bare, _, query = path.partition("?")
    return RequestInfo(
        ip=ip,
        method=method,
        path=bare,
        target=target,
        query=query,
        headers=CIMultiDict(BROWSER_HEADERS if headers is None else headers),
        cookie=cookie,
        body=body,
        is_asset=is_asset,
    )
