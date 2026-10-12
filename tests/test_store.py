from datetime import datetime, timedelta

from minisiem.models import Event, event_id
from minisiem.store.db import Store
from minisiem.timeutil import UTC, iso, timestamp


def make(raw="hello", **kw):
    now = datetime.now(UTC)
    return Event(
        id=event_id("test", raw),
        timestamp=now,
        ingested_at=now,
        source="test",
        dataset="generic",
        raw=raw,
        message=raw,
        **kw,
    )


def test_wal_fts_dedup_retention(tmp_path):
    with Store(tmp_path / "s.db") as s:
        e = make()
        with s.transaction():
            s.insert([e, e])
        assert s.counts()["events"] == 1
        assert s.db.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
        assert len(s.bounded("SELECT * FROM event_fts WHERE event_fts MATCH ?", ["hello"])) == 1
        assert s.retain(iso(e.timestamp + timedelta(seconds=1))) == 1
        assert s.bounded("SELECT * FROM event_fts WHERE event_fts MATCH ?", ["hello"]) == []
        assert s.db.execute("PRAGMA foreign_key_check").fetchall() == []


def test_time():
    a = timestamp("2025-01-01T05:30:00+05:30")
    assert a[0] == timestamp("2025-01-01T00:00:00Z")[0]
    assert a[2] == "UTC+05:30"
    assert timestamp("bad")[3]
    assert "very_old_timestamp" in timestamp("1970-01-01T00:00:00Z")[3]
    assert "future_timestamp" in timestamp("2099-01-01T00:00:00Z")[3]
    assert event_id("a", "x") != event_id("b", "x")
