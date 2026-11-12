"""Tarpit: holding back answers to trapped sessions, cheaply.

A held request costs the defender one idle connection and a timer. It costs
the client a worker that is stuck until the answer completes. Nothing here
runs anywhere but on this server: the client simply waits for bytes.

How an answer is held
---------------------
Short delays are a plain pause before the request is even passed on. Longer
ones use a slow drip: after a short pause the answer is fetched, the backend
connection is released at once, and the answer is then sent in small pieces
spread over the rest of the delay, with the last piece arriving at the very
end. The steady trickle keeps the client's read timeout from firing, so it
cannot give up early without knowing it gave up.

What keeps this from hurting the defender
-----------------------------------------
* The protected site's connection is never held during a delay.
* Each trapped session may run only a few requests at once; more wait in a
  short queue, and beyond that are refused straight away.
* The number of sessions held at once is capped. Past the cap, the oldest
  session's connections are dropped.
* Memory spent on held answers is capped. Past the cap, new holds fall back
  to the plain pause, which buffers nothing.
"""

from __future__ import annotations

import asyncio
import random
import time
from collections import OrderedDict, deque
from typing import Any, Awaitable, Callable

from aiohttp import web

from tr4p.config import TarpitConfig

Produce = Callable[[bool], Awaitable[web.StreamResponse]]
Refuse = Callable[[], web.StreamResponse]

# Statuses that never carry a body, so there is nothing to drip.
_BODYLESS = frozenset({204, 304})
REFUSAL_PAUSE = 1.0


class _Hold:
    """One request currently being held."""

    __slots__ = ("task", "transport", "started", "buffered", "dropped")

    def __init__(self, task: asyncio.Task[Any] | None, transport: Any, started: float) -> None:
        self.task = task
        self.transport = transport
        self.started = started
        self.buffered = 0
        self.dropped = False


class _Gate:
    """Per-session bookkeeping: running holds and requests waiting for a slot."""

    __slots__ = ("holds", "waiters")

    def __init__(self) -> None:
        self.holds: set[_Hold] = set()
        self.waiters: deque[asyncio.Future[None]] = deque()


class Tarpit:
    def __init__(
        self,
        config: TarpitConfig,
        bump: Callable[[str, str], bool] | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._config = config
        self._bump = bump or (lambda key, reason: False)
        self._clock = clock
        self._random = random.Random()
        # Oldest session first, so dropping "the oldest" is O(1).
        self._gates: OrderedDict[str, _Gate] = OrderedDict()
        self.held = 0
        self.queued = 0
        self.buffered_bytes = 0
        self.dropped = 0
        self.abandoned = 0
        self.refused = 0
        self.completed = 0
        self.burned_seconds = 0.0

    # -------------------------------------------------------------------- stats

    def stats(self) -> dict[str, Any]:
        return {
            "sessions": len(self._gates),
            "held": self.held,
            "queued": self.queued,
            "buffered_bytes": self.buffered_bytes,
            "dropped": self.dropped,
            "abandoned": self.abandoned,
            "refused": self.refused,
            "completed": self.completed,
            "burned_seconds": round(self.burned_seconds, 1),
        }

    # --------------------------------------------------------------------- run

    async def run(
        self,
        request: web.BaseRequest,
        key: str,
        delay: float,
        produce: Produce,
        refuse: Refuse,
    ) -> web.StreamResponse:
        """Answer a trapped request, taking `delay` seconds over it.

        `produce(buffered)` builds the answer. With buffered=True it should
        return an unsent response whenever the body is small enough to hold
        in memory, which is what makes the slow drip possible.
        """
        hold = await self._enter(key, request)
        if hold is None:
            await asyncio.sleep(min(delay, REFUSAL_PAUSE))
            return refuse()
        try:
            response = await self._held(request, hold, delay, produce)
            self.completed += 1
            return response
        except asyncio.CancelledError:
            if not hold.dropped:
                # The client hung up rather than wait: it is ignoring delays.
                self.abandoned += 1
                self._bump(key, "gave up waiting")
            raise
        finally:
            self._leave(key, hold)

    async def _held(
        self, request: web.BaseRequest, hold: _Hold, delay: float, produce: Produce
    ) -> web.StreamResponse:
        config = self._config
        drip = (
            delay > config.drip_interval * 1.5
            and config.buffer_bytes > 0
            and self.buffered_bytes < config.buffer_total_bytes
        )
        if not drip:
            await asyncio.sleep(delay)
            return await produce(False)

        await asyncio.sleep(min(config.drip_interval, delay * 0.4))
        response = await produce(True)
        remaining = delay - (self._clock() - hold.started)
        if response.prepared or remaining <= 0:
            return response   # too large to hold; it has been streamed already
        body = response.body if isinstance(response, web.Response) else None
        if (
            not isinstance(body, (bytes, bytearray))
            or not body
            or request.method == "HEAD"
            or response.status in _BODYLESS
        ):
            await asyncio.sleep(remaining)
            return response
        hold.buffered = len(body)
        self.buffered_bytes += hold.buffered
        return await self._drip(request, response, bytes(body), remaining)

    async def _drip(
        self, request: web.BaseRequest, response: web.Response, body: bytes, remaining: float
    ) -> web.StreamResponse:
        """Send a held answer in pieces; the final piece lands at the end."""
        interval = self._config.drip_interval
        pieces = min(len(body), int(remaining / interval) + 1)
        if pieces <= 1:
            await asyncio.sleep(remaining)
            return response
        gap = remaining / (pieces - 1)
        size = -(-len(body) // pieces)
        stream = web.StreamResponse(
            status=response.status, reason=response.reason, headers=response.headers
        )
        stream.content_length = len(body)
        await stream.prepare(request)
        for index in range(pieces):
            chunk = body[index * size:(index + 1) * size]
            if index:
                await asyncio.sleep(gap * self._random.uniform(0.9, 1.1))
            if chunk:
                await stream.write(chunk)
        await stream.write_eof()
        return stream

    # ----------------------------------------------------------------- gating

    async def _enter(self, key: str, request: web.BaseRequest) -> _Hold | None:
        """Take a slot for this session, waiting in its queue if needed.
        Returns None when the request should be refused."""
        config = self._config
        gate = self._gates.get(key)
        if gate is None:
            while len(self._gates) >= config.max_sessions and self.drop_oldest():
                pass
            gate = self._gates[key] = _Gate()
        if len(gate.holds) >= config.session_concurrency:
            self._bump(key, "parallel requests")
            if len(gate.waiters) >= config.session_queue:
                self.refused += 1
                return None
            waiter: asyncio.Future[None] = asyncio.get_running_loop().create_future()
            gate.waiters.append(waiter)
            self.queued += 1
            try:
                await waiter
            except asyncio.CancelledError:
                if waiter in gate.waiters:
                    gate.waiters.remove(waiter)
                elif not self._wake_next(gate):
                    # It had been handed a slot it will never use.
                    self._forget_if_idle(key, gate)
                raise
            finally:
                self.queued -= 1
            if self._gates.get(key) is not gate:
                return None   # the session was dropped while this request waited
        hold = _Hold(asyncio.current_task(), request.transport, self._clock())
        gate.holds.add(hold)
        self.held += 1
        return hold

    def _leave(self, key: str, hold: _Hold) -> None:
        self.held -= 1
        self.buffered_bytes -= hold.buffered
        self.burned_seconds += self._clock() - hold.started
        gate = self._gates.get(key)
        if gate is None or hold not in gate.holds:
            return   # the session was dropped; nothing left to hand over
        gate.holds.discard(hold)
        if not self._wake_next(gate):
            self._forget_if_idle(key, gate)

    @staticmethod
    def _wake_next(gate: _Gate) -> bool:
        """Hand the freed slot to the next waiting request, if any. The gate
        stays alive for it even though it holds nothing for a moment."""
        while gate.waiters:
            waiter = gate.waiters.popleft()
            if not waiter.done():
                waiter.set_result(None)
                return True
        return False

    def _forget_if_idle(self, key: str, gate: _Gate) -> None:
        if not gate.holds and not gate.waiters and self._gates.get(key) is gate:
            del self._gates[key]

    def drop_oldest(self) -> bool:
        """Drop every held connection of the longest-held session. Returns
        False when nothing is being held."""
        if not self._gates:
            return False
        key, gate = next(iter(self._gates.items()))
        del self._gates[key]
        self.dropped += 1
        for hold in gate.holds:
            hold.dropped = True
            if hold.transport is not None:
                hold.transport.close()
            if hold.task is not None:
                hold.task.cancel()
        for waiter in gate.waiters:
            if not waiter.done():
                waiter.set_result(None)   # wakes up, sees its gate is gone, is refused
        return True
