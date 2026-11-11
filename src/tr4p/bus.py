"""In-process fan-out of events to live dashboard streams."""

from __future__ import annotations

import asyncio
from typing import Any

SUBSCRIBER_BACKLOG = 256


class EventBus:
    """Slow or stuck subscribers lose events; they never slow the trap down."""

    def __init__(self) -> None:
        self._subscribers: set[asyncio.Queue[dict[str, Any]]] = set()

    def subscribe(self) -> asyncio.Queue[dict[str, Any]]:
        subscriber: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=SUBSCRIBER_BACKLOG)
        self._subscribers.add(subscriber)
        return subscriber

    def unsubscribe(self, subscriber: asyncio.Queue[dict[str, Any]]) -> None:
        self._subscribers.discard(subscriber)

    def publish(self, event: dict[str, Any]) -> None:
        for subscriber in self._subscribers:
            try:
                subscriber.put_nowait(event)
            except asyncio.QueueFull:
                pass

    def __len__(self) -> int:
        return len(self._subscribers)
