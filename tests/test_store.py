import sys

from tr4p.fsutil import is_private
from tr4p.store import Store


def make_event(n=0, **extra):
    event = {
        "ts": 1000.0 + n, "kind": "signal", "session": "abc", "ip": "203.0.113.5",
        "method": "GET", "path": f"/p/{n}", "signal": "canary_path", "detail": "x",
        "score": 45.0, "tier": "low", "user_agent": "ua", "alert": False,
    }
    event.update(extra)
    return event


def open_store(tmp_path, **kwargs):
    store = Store(tmp_path / "home" / "events.db", **kwargs)
    store.open()
    return store


def test_events_round_trip_newest_first(tmp_path):
    store = open_store(tmp_path)
    try:
        ids = [store.add_event(make_event(n)) for n in range(5)]
        store.flush()
        events = store.events(limit=3)
        assert [e["id"] for e in events] == ids[:1:-1][:3]
        assert events[0]["path"] == "/p/4" and events[0]["alert"] is False
        assert [e["id"] for e in store.events(before=ids[2])] == [ids[1], ids[0]]
        assert store.events(session="nobody") == []
    finally:
        store.close()


def test_ids_continue_after_reopen(tmp_path):
    store = open_store(tmp_path)
    last = [store.add_event(make_event(n)) for n in range(3)][-1]
    store.close()
    store = open_store(tmp_path)
    try:
        assert store.add_event(make_event(9)) == last + 1
    finally:
        store.close()


def test_database_file_is_private(tmp_path):
    store = open_store(tmp_path)
    store.close()
    path = tmp_path / "home" / "events.db"
    assert is_private(path)
    if sys.platform != "win32":
        assert (path.parent.stat().st_mode & 0o777) == 0o700


def test_sessions_last_write_wins_and_filter_by_age(tmp_path):
    store = open_store(tmp_path)
    try:
        store.save_session({"key": "a", "last_seen": 10.0, "tier": "low", "signals": {"rate": 1}})
        store.save_session({"key": "a", "last_seen": 20.0, "tier": "high", "signals": {"rate": 2}})
        store.save_session({"key": "b", "last_seen": 5.0, "tier": "low", "signals": {}})
        store.flush()
        assert [s["key"] for s in store.sessions()] == ["a", "b"]
        assert store.sessions()[0]["tier"] == "high"
        assert [s["key"] for s in store.sessions(since=6.0)] == ["a"]
    finally:
        store.close()


def test_settings(tmp_path):
    store = open_store(tmp_path)
    try:
        assert store.get_setting("missing") is None
        store.set_setting("name", "one")
        store.set_setting("name", "two")
        assert store.get_setting("name") == "two"
    finally:
        store.close()


def test_old_events_are_pruned(tmp_path, monkeypatch):
    monkeypatch.setattr("tr4p.store.PRUNE_EVERY", 50)
    store = open_store(tmp_path, max_events=100)
    try:
        for n in range(400):
            store.add_event(make_event(n))
        store.flush()
        events = store.events(limit=500)
        assert 100 <= len(events) <= 150
        assert events[0]["path"] == "/p/399"
    finally:
        store.close()


def test_queue_is_bounded_under_flood(tmp_path, monkeypatch):
    monkeypatch.setattr("tr4p.store.MAX_QUEUE", 10)
    store = Store(tmp_path / "events.db")
    # Writer thread not started: nothing drains the queue.
    results = [store.add_event(make_event(n)) for n in range(25)]
    assert results.count(0) == 15
    assert store.dropped == 15


def test_hostile_text_is_stored_verbatim(tmp_path):
    store = open_store(tmp_path)
    try:
        nasty = "/x'); DROP TABLE events;--<script>alert(1)</script>\x00‮"
        store.add_event(make_event(path=nasty, user_agent=nasty))
        store.flush()
        assert store.events()[0]["path"] == nasty
    finally:
        store.close()
