"""SQLite storage for events and flagged sessions.

All writes go through one background thread that commits in batches, so the
request path never waits on disk. The queue is bounded: under a flood,
events are dropped (and counted) rather than allowed to eat memory.
"""

from __future__ import annotations

import asyncio
import json
import os
import queue
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

from tr4p.fsutil import ensure_private_dir

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY,
    ts REAL NOT NULL,
    kind TEXT NOT NULL,
    session TEXT NOT NULL DEFAULT '',
    ip TEXT NOT NULL DEFAULT '',
    method TEXT NOT NULL DEFAULT '',
    path TEXT NOT NULL DEFAULT '',
    signal TEXT NOT NULL DEFAULT '',
    detail TEXT NOT NULL DEFAULT '',
    score REAL NOT NULL DEFAULT 0,
    tier TEXT NOT NULL DEFAULT '',
    user_agent TEXT NOT NULL DEFAULT '',
    alert INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS events_session ON events (session, id);
CREATE TABLE IF NOT EXISTS sessions (
    key TEXT PRIMARY KEY,
    last_seen REAL NOT NULL,
    tier TEXT NOT NULL,
    data TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS sessions_seen ON sessions (last_seen);
CREATE TABLE IF NOT EXISTS settings (
    name TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""

_EVENT_COLUMNS = (
    "id", "ts", "kind", "session", "ip", "method", "path", "signal",
    "detail", "score", "tier", "user_agent", "alert",
)
_INSERT_EVENT = (
    f"INSERT OR REPLACE INTO events ({', '.join(_EVENT_COLUMNS)}) "
    f"VALUES ({', '.join('?' for _ in _EVENT_COLUMNS)})"
)

MAX_QUEUE = 20000
BATCH_SIZE = 500
FLUSH_SECONDS = 0.5
PRUNE_EVERY = 2000

_STOP = object()


class Store:
    def __init__(self, path: Path, max_events: int = 200000) -> None:
        self._path = path
        self._max_events = max_events
        self._queue: queue.SimpleQueue[Any] = queue.SimpleQueue()
        self._pending = 0
        self._lock = threading.Lock()
        self._read_lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._reader: sqlite3.Connection | None = None
        self._next_id = 1
        self._since_prune = 0
        self.dropped = 0

    # ---------------------------------------------------------------- lifecycle

    def open(self) -> None:
        ensure_private_dir(self._path.parent)
        if not self._path.exists():
            # Create the file owner-only before SQLite touches it.
            os.close(os.open(self._path, os.O_WRONLY | os.O_CREAT, 0o600))
        setup = self._connect()
        try:
            setup.executescript(_SCHEMA)
            row = setup.execute("SELECT COALESCE(MAX(id), 0) FROM events").fetchone()
            self._next_id = int(row[0]) + 1
            setup.commit()
        finally:
            setup.close()
        self._reader = self._connect(check_same_thread=False)
        self._thread = threading.Thread(target=self._run, name="store-writer", daemon=True)
        self._thread.start()

    def close(self) -> None:
        if self._thread is not None:
            self._queue.put(_STOP)
            self._thread.join(timeout=10)
            self._thread = None
        if self._reader is not None:
            self._reader.close()
            self._reader = None

    def _connect(self, check_same_thread: bool = True) -> sqlite3.Connection:
        connection = sqlite3.connect(self._path, check_same_thread=check_same_thread)
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=NORMAL")
        return connection

    # ------------------------------------------------------------------- writes

    def add_event(self, event: dict[str, Any]) -> int:
        """Queue an event. Returns its id, or 0 if it had to be dropped."""
        with self._lock:
            if self._pending >= MAX_QUEUE:
                self.dropped += 1
                return 0
            self._pending += 1
            event_id = self._next_id
            self._next_id += 1
        event["id"] = event_id
        row = tuple(
            int(event.get(name, 0)) if name == "alert" else event.get(name, "")
            for name in _EVENT_COLUMNS
        )
        self._queue.put(("event", row))
        return event_id

    def save_session(self, snapshot: dict[str, Any]) -> None:
        with self._lock:
            if self._pending >= MAX_QUEUE:
                self.dropped += 1
                return
            self._pending += 1
        row = (
            snapshot["key"],
            float(snapshot.get("last_seen", 0.0)),
            str(snapshot.get("tier", "none")),
            json.dumps(snapshot, separators=(",", ":")),
        )
        self._queue.put(("session", row))

    def _run(self) -> None:
        connection = self._connect()
        try:
            stopping = False
            while not stopping:
                batch: list[Any] = []
                try:
                    batch.append(self._queue.get(timeout=FLUSH_SECONDS))
                    while len(batch) < BATCH_SIZE:
                        batch.append(self._queue.get_nowait())
                except queue.Empty:
                    pass
                if not batch:
                    continue
                events, sessions = [], {}
                for item in batch:
                    if item is _STOP:
                        stopping = True
                    elif item[0] == "event":
                        events.append(item[1])
                    else:
                        sessions[item[1][0]] = item[1]  # last write per key wins
                try:
                    if events:
                        connection.executemany(_INSERT_EVENT, events)
                    if sessions:
                        connection.executemany(
                            "INSERT OR REPLACE INTO sessions (key, last_seen, tier, data) "
                            "VALUES (?, ?, ?, ?)",
                            list(sessions.values()),
                        )
                    self._since_prune += len(events)
                    if self._since_prune >= PRUNE_EVERY:
                        self._since_prune = 0
                        connection.execute(
                            "DELETE FROM events WHERE id <= "
                            "(SELECT MAX(id) FROM events) - ?",
                            (self._max_events,),
                        )
                    connection.commit()
                except sqlite3.Error:
                    connection.rollback()
                finally:
                    done = sum(1 for item in batch if item is not _STOP)
                    with self._lock:
                        self._pending -= done
        finally:
            connection.close()

    def flush(self, timeout: float = 5.0) -> None:
        """Block until queued writes are on disk (used by tests and shutdown)."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self._lock:
                if self._pending <= 0:
                    return
            time.sleep(0.01)

    # -------------------------------------------------------------------- reads

    def _query(self, sql: str, args: tuple = ()) -> list[tuple]:
        if self._reader is None:
            raise RuntimeError("store is not open")
        with self._read_lock:
            return self._reader.execute(sql, args).fetchall()

    def events(
        self, limit: int = 100, before: int = 0, session: str = ""
    ) -> list[dict[str, Any]]:
        limit = max(1, min(int(limit), 500))
        clauses, args = [], []
        if before > 0:
            clauses.append("id < ?")
            args.append(before)
        if session:
            clauses.append("session = ?")
            args.append(session)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        rows = self._query(
            f"SELECT {', '.join(_EVENT_COLUMNS)} FROM events {where} "
            "ORDER BY id DESC LIMIT ?",
            (*args, limit),
        )
        result = []
        for row in rows:
            item = dict(zip(_EVENT_COLUMNS, row))
            item["alert"] = bool(item["alert"])
            result.append(item)
        return result

    def sessions(self, since: float = 0.0, limit: int = 5000) -> list[dict[str, Any]]:
        rows = self._query(
            "SELECT data FROM sessions WHERE last_seen >= ? ORDER BY last_seen DESC LIMIT ?",
            (since, limit),
        )
        result = []
        for (data,) in rows:
            try:
                result.append(json.loads(data))
            except json.JSONDecodeError:
                continue
        return result

    def get_setting(self, name: str) -> str | None:
        rows = self._query("SELECT value FROM settings WHERE name = ?", (name,))
        return rows[0][0] if rows else None

    def set_setting(self, name: str, value: str) -> None:
        """Small, rare, synchronous write (dashboard password and the like)."""
        connection = self._connect()
        try:
            connection.execute(
                "INSERT OR REPLACE INTO settings (name, value) VALUES (?, ?)", (name, value)
            )
            connection.commit()
        finally:
            connection.close()

    def purge(self, before: float | None = None) -> tuple[int, int]:
        """Delete events and saved sessions older than `before` (a
        timestamp), or everything when it is None. Returns the two counts."""
        connection = self._connect()
        try:
            if before is None:
                events = connection.execute("DELETE FROM events").rowcount
                sessions = connection.execute("DELETE FROM sessions").rowcount
            else:
                events = connection.execute("DELETE FROM events WHERE ts < ?", (before,)).rowcount
                sessions = connection.execute(
                    "DELETE FROM sessions WHERE last_seen < ?", (before,)).rowcount
            connection.commit()
            return events, sessions
        finally:
            connection.close()

    async def events_async(self, **kwargs: Any) -> list[dict[str, Any]]:
        return await asyncio.to_thread(self.events, **kwargs)
