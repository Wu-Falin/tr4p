"""Blocklist of clients confirmed in the high tier.

An entry is an address together with a header fingerprint, never an address
alone and never a fingerprint alone: a browser fingerprint is shared by
millions of people, and an address can be shared by a whole office or mobile
carrier. Entries expire by themselves, and releasing a session removes its
entry. Whitelisted addresses and verified crawlers never reach this code.

Enforcement (refusing listed clients) is off unless the defender turns it
on. The exported file lists addresses only, for tools that cannot match
fingerprints. Treat it with care for exactly that reason.
"""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass
from typing import Any, Callable

from tr4p.config import BlockConfig

EXPORT_HEADER = (
    "# Addresses of clients confirmed in the high tier. Rewritten automatically.\n"
    "# Entries expire. One address can be shared by many people (offices,\n"
    "# mobile carriers, VPNs): blocking by address alone can lock them out too.\n"
)


@dataclass
class Block:
    key: str            # address-and-fingerprint group key
    ip: str
    fingerprint: str
    expires: float
    hits: int = 0


class Blocklist:
    def __init__(self, config: BlockConfig, clock: Callable[[], float] = time.time) -> None:
        self._config = config
        self._clock = clock
        self._entries: dict[str, Block] = {}
        self.changed = False

    def __len__(self) -> int:
        return len(self._entries)

    def add(self, key: str, ip: str, fingerprint: str) -> None:
        """List a client, or extend its entry."""
        if not key or not ip:
            return
        now = self._clock()
        expires = now + self._config.ttl_hours * 3600.0
        entry = self._entries.get(key)
        if entry is not None:
            entry.expires = expires
        else:
            if len(self._entries) >= self._config.max_entries:
                self.expire(now)
            if len(self._entries) >= self._config.max_entries:
                oldest = min(self._entries.values(), key=lambda item: item.expires)
                del self._entries[oldest.key]
            self._entries[key] = Block(key, ip, fingerprint, expires)
        self.changed = True

    def remove(self, key: str) -> bool:
        if self._entries.pop(key, None) is None:
            return False
        self.changed = True
        return True

    def hit(self, key: str) -> Block | None:
        """Return the live entry for a client when enforcement is on."""
        if not self._config.enforce:
            return None
        entry = self._entries.get(key)
        if entry is None:
            return None
        if entry.expires <= self._clock():
            del self._entries[key]
            self.changed = True
            return None
        entry.hits += 1
        return entry

    def expire(self, now: float | None = None) -> int:
        now = self._clock() if now is None else now
        stale = [key for key, entry in self._entries.items() if entry.expires <= now]
        for key in stale:
            del self._entries[key]
        if stale:
            self.changed = True
        return len(stale)

    def entries(self) -> list[Block]:
        self.expire()
        return sorted(self._entries.values(), key=lambda item: item.expires)

    def export_text(self) -> str:
        """Plain list of addresses with their latest expiry."""
        latest: dict[str, float] = {}
        for entry in self.entries():
            latest[entry.ip] = max(latest.get(entry.ip, 0.0), entry.expires)
        lines = [
            f"{ip}  # until {time.strftime('%Y-%m-%dT%H:%MZ', time.gmtime(expires))}"
            for ip, expires in sorted(latest.items())
        ]
        return EXPORT_HEADER + "\n".join(lines) + ("\n" if lines else "")

    def dump(self) -> list[dict[str, Any]]:
        return [asdict(entry) for entry in self.entries()]

    def load(self, rows: list[dict[str, Any]]) -> None:
        now = self._clock()
        for row in rows:
            try:
                entry = Block(str(row["key"]), str(row["ip"]), str(row.get("fingerprint", "")),
                              float(row["expires"]), int(row.get("hits", 0)))
            except (KeyError, TypeError, ValueError):
                continue
            if entry.expires > now:
                self._entries[entry.key] = entry
