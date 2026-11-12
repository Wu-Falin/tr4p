"""Session tracking.

A session is identified by a signed cookie. Clients that send no cookie are
tracked as a group keyed by address *and* header fingerprint together, never
by address alone, so people sharing one NAT address are not lumped together.

Clean sessions live only in memory, in a bounded LRU. Nothing about ordinary
visitors is written to disk.
"""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any, Iterable

GROUP_PREFIX = "g:"


@dataclass(slots=True)
class Session:
    key: str
    created: float
    last_seen: float
    ip: str = ""
    fingerprint: str = ""
    user_agent: str = ""
    group_key: str = ""
    signals: dict[str, int] = field(default_factory=dict)
    # Evidence carried over from a session with the same address and header
    # fingerprint. Weighted lower and forgotten sooner than own signals.
    inherited: dict[str, int] = field(default_factory=dict)
    inherited_at: float = 0.0
    last_signal: float = 0.0
    score: float = 0.0
    tier: str = "none"
    released: bool = False
    # Tarpit state: current phase, delayed requests so far, and the cached
    # head of the cookie hash chain for that phase.
    phase: int = 0
    hits: int = 0
    chain: bytes | None = None
    chain_phase: int = -1
    crawler: str = ""          # "", "pending", "verified" or "unverified"
    agent_class: str = ""      # cached user-agent category
    agent_name: str = ""
    requests: int = 0
    pages: int = 0
    assets: int = 0
    rate_start: float = 0.0
    rate_count: int = 0
    not_found_start: float = 0.0
    not_found_count: int = 0
    auth_start: float = 0.0
    auth_count: int = 0

    @property
    def is_group(self) -> bool:
        return self.key.startswith(GROUP_PREFIX)

    @property
    def flagged(self) -> bool:
        return bool(self.signals) or bool(self.inherited)

    def snapshot(self) -> dict[str, Any]:
        """Plain data for storage and the dashboard."""
        return {
            "key": self.key,
            "created": self.created,
            "last_seen": self.last_seen,
            "ip": self.ip,
            "fingerprint": self.fingerprint,
            "user_agent": self.user_agent,
            "group_key": self.group_key,
            "signals": dict(self.signals),
            "inherited": dict(self.inherited),
            "inherited_at": self.inherited_at,
            "last_signal": self.last_signal,
            "phase": self.phase,
            "hits": self.hits,
            "score": self.score,
            "tier": self.tier,
            "released": self.released,
            "crawler": self.crawler,
            "requests": self.requests,
        }

    @classmethod
    def restore(cls, data: dict[str, Any]) -> "Session":
        return cls(
            key=str(data["key"]),
            created=float(data.get("created", 0.0)),
            last_seen=float(data.get("last_seen", 0.0)),
            ip=str(data.get("ip", "")),
            fingerprint=str(data.get("fingerprint", "")),
            user_agent=str(data.get("user_agent", "")),
            group_key=str(data.get("group_key", "")),
            signals={str(k): int(v) for k, v in dict(data.get("signals", {})).items()},
            inherited={str(k): int(v) for k, v in dict(data.get("inherited", {})).items()},
            inherited_at=float(data.get("inherited_at", 0.0)),
            last_signal=float(data.get("last_signal", data.get("last_seen", 0.0))),
            phase=max(0, int(data.get("phase", 0))),
            hits=max(0, int(data.get("hits", 0))),
            score=float(data.get("score", 0.0)),
            tier=str(data.get("tier", "none")),
            released=bool(data.get("released", False)),
            crawler=str(data.get("crawler", "")),
            requests=int(data.get("requests", 0)),
        )


class SessionTable:
    """Bounded in-memory session store.

    Clean sessions are evicted least-recently-used first. Flagged sessions
    are kept separately so a flood of new clients cannot push them out.
    """

    def __init__(self, max_tracked: int, idle_seconds: float, flagged_seconds: float) -> None:
        self._max = max_tracked
        self._idle = idle_seconds
        self._flagged_ttl = flagged_seconds
        self._clean: OrderedDict[str, Session] = OrderedDict()
        self._flagged: dict[str, Session] = {}

    def __len__(self) -> int:
        return len(self._clean) + len(self._flagged)

    def get(self, key: str) -> Session | None:
        session = self._flagged.get(key)
        if session is not None:
            return session
        session = self._clean.get(key)
        if session is not None:
            self._clean.move_to_end(key)
        return session

    def create(self, key: str, now: float) -> Session:
        session = Session(key=key, created=now, last_seen=now)
        self._clean[key] = session
        if len(self._clean) > self._max:
            self._clean.popitem(last=False)
        return session

    def add(self, session: Session) -> None:
        """Insert a restored session."""
        if session.flagged or session.released:
            self._flagged[session.key] = session
        else:
            self._clean[session.key] = session

    def promote(self, session: Session) -> None:
        """Move a session to the flagged set once it has a signal."""
        if session.key in self._flagged:
            return
        self._clean.pop(session.key, None)
        self._flagged[session.key] = session
        if len(self._flagged) > self._max:
            oldest = min(self._flagged.values(), key=lambda item: item.last_seen)
            del self._flagged[oldest.key]

    def flagged(self) -> Iterable[Session]:
        return self._flagged.values()

    def sweep(self, now: float) -> int:
        """Drop idle sessions. Returns how many were removed."""
        removed = 0
        while self._clean:
            key, session = next(iter(self._clean.items()))
            if now - session.last_seen < self._idle:
                break
            del self._clean[key]
            removed += 1
        stale = [key for key, item in self._flagged.items()
                 if now - item.last_seen >= self._flagged_ttl]
        for key in stale:
            del self._flagged[key]
        return removed + len(stale)

    def tier_counts(self) -> dict[str, int]:
        counts = {"low": 0, "medium": 0, "high": 0, "released": 0}
        for session in self._flagged.values():
            if session.released:
                counts["released"] += 1
            elif session.tier in counts:
                counts[session.tier] += 1
        return counts
