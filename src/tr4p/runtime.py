"""Wires the pieces together and runs them: storage, detection engine,
public listener and dashboard."""

from __future__ import annotations

import asyncio
import logging
import time
from pathlib import Path
from typing import Any

from tr4p.bus import EventBus
from tr4p.config import CONFIG_FILE, DATABASE_FILE, SEED_FILE, Config
from tr4p.crawlers import CrawlerVerifier
from tr4p.dashboard.app import Dashboard
from tr4p.engine import Engine
from tr4p.persona import Persona
from tr4p.public import PublicApp
from tr4p.seed import Seed
from tr4p.session import Session
from tr4p.store import Store

log = logging.getLogger("tr4p")

SWEEP_SECONDS = 60.0


class _Sink:
    """Receives everything the engine reports: persist it, then fan it out."""

    def __init__(self, store: Store, bus: EventBus) -> None:
        self._store = store
        self._bus = bus

    def event(self, event: dict[str, Any]) -> None:
        self._store.add_event(event)
        self._bus.publish(event)

    def session(self, snapshot: dict[str, Any]) -> None:
        self._store.save_session(snapshot)


class Runtime:
    def __init__(self, home: Path, config: Config, seed: Seed) -> None:
        self.home = home
        self.config = config
        self.seed = seed
        self.store = Store(home / DATABASE_FILE, config.storage.max_events)
        self.bus = EventBus()
        self.persona = Persona.from_seed(seed)
        self.engine = Engine(config, seed, _Sink(self.store, self.bus))
        self.public = PublicApp(config, seed, self.engine, self.persona)
        self.dashboard = Dashboard(
            config, self.engine, self.store, self.bus,
            instance_id=seed.hex("instance-id", length=16),
            status=self.status,
        )
        self._crawlers = CrawlerVerifier()
        self._tasks: set[asyncio.Task[Any]] = set()
        self._started = 0.0
        self.running = False

    @classmethod
    def load(cls, home: Path) -> "Runtime":
        config = Config.load(home / CONFIG_FILE)
        seed = Seed.load(home / SEED_FILE)
        return cls(home, config, seed)

    async def start(self) -> None:
        self.store.open()
        horizon = time.time() - self.config.session.flagged_days * 86400.0
        restored = self.engine.restore(self.store.sessions(since=horizon))
        if restored:
            log.info("restored %d flagged session(s) from the previous run", restored)
        self.engine.crawler_hook = self._verify_crawler
        await self.public.start()
        await self.dashboard.start()
        self._started = time.time()
        self.running = True
        self._spawn(self._housekeeping())

    async def stop(self) -> None:
        self.running = False
        for task in list(self._tasks):
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        await self.dashboard.stop()
        await self.public.stop()
        await asyncio.to_thread(self.store.close)

    def status(self) -> dict[str, Any]:
        canaries = self.engine.canaries
        period = self.config.canary.rotation_hours * 3600.0
        now = time.time()
        return {
            "running": self.running,
            "mode": self.config.public.mode,
            "started": self._started,
            "uptime": now - self._started if self._started else 0.0,
            "public": {"host": self.config.public.host, "port": self.public.port},
            "stats": self.engine.stats(),
            "dropped_events": self.store.dropped,
            "canary": {
                "rotation": canaries.rotation(),
                "next_rotation_in": period - (now % period),
            },
        }

    def _spawn(self, coroutine) -> None:
        task = asyncio.ensure_future(coroutine)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _housekeeping(self) -> None:
        while True:
            await asyncio.sleep(SWEEP_SECONDS)
            try:
                self.engine.sweep()
            except Exception:
                log.exception("session sweep failed")

    def _verify_crawler(self, session: Session) -> None:
        async def check(key: str, address: str, agent: str) -> None:
            verified = await self._crawlers.verify(address, agent)
            self.engine.crawler_result(key, verified)

        self._spawn(check(session.key, session.ip, session.user_agent))
