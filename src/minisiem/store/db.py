"""Transactional SQLite, bounded reads, RE2, FTS and durable checkpoints."""

import json
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, Sequence

import re2

from minisiem.config import LIMITS
from minisiem.models import Event

DDL = """
CREATE TABLE IF NOT EXISTS schema_version(version INTEGER PRIMARY KEY);
INSERT OR IGNORE INTO schema_version VALUES(1);
CREATE TABLE IF NOT EXISTS events(
 ingest_seq INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT UNIQUE NOT NULL, timestamp TEXT NOT NULL, original_timestamp TEXT NOT NULL,
 original_timezone TEXT NOT NULL, ingested_at TEXT NOT NULL, source TEXT NOT NULL,
 dataset TEXT NOT NULL, host TEXT, user TEXT, source_ip TEXT, source_port INTEGER,
 destination_ip TEXT, destination_port INTEGER, transport TEXT, community_id TEXT,
 message TEXT NOT NULL, action TEXT, outcome TEXT, process_name TEXT, command_line TEXT,
 dns_question TEXT, http_url TEXT, http_status INTEGER, tls_server_name TEXT, event_code TEXT, channel TEXT, original_file_name TEXT,
 fields TEXT NOT NULL CHECK(json_valid(fields)), raw TEXT NOT NULL, warnings TEXT NOT NULL);
CREATE VIRTUAL TABLE IF NOT EXISTS event_fts USING fts5(message, content=events, content_rowid=rowid);
CREATE TRIGGER IF NOT EXISTS events_ai AFTER INSERT ON events BEGIN
 INSERT INTO event_fts(rowid,message) VALUES(new.rowid,new.message); END;
CREATE TRIGGER IF NOT EXISTS events_ad AFTER DELETE ON events BEGIN
 INSERT INTO event_fts(event_fts,rowid,message) VALUES('delete',old.rowid,old.message); END;
CREATE INDEX IF NOT EXISTS ix_time ON events(timestamp);
CREATE INDEX IF NOT EXISTS ix_host ON events(host,timestamp);
CREATE INDEX IF NOT EXISTS ix_dataset ON events(dataset,timestamp);
CREATE INDEX IF NOT EXISTS ix_src ON events(source_ip,timestamp);
CREATE INDEX IF NOT EXISTS ix_dst ON events(destination_ip,timestamp);
CREATE INDEX IF NOT EXISTS ix_ingested ON events(ingested_at);
CREATE INDEX IF NOT EXISTS ix_community ON events(community_id,timestamp);
CREATE TABLE IF NOT EXISTS quarantine(id INTEGER PRIMARY KEY, source TEXT, raw TEXT, reason TEXT, created_at TEXT);
CREATE TABLE IF NOT EXISTS checkpoints(path TEXT PRIMARY KEY, device INTEGER, inode INTEGER, offset INTEGER, prefix TEXT, owner_path TEXT, draining INTEGER DEFAULT 0, source TEXT, kind TEXT);
CREATE TABLE IF NOT EXISTS ingest_runs(id INTEGER PRIMARY KEY, source TEXT, started TEXT, finished TEXT,
 accepted INTEGER, duplicates INTEGER, quarantined INTEGER, lag_seconds REAL, elapsed_seconds REAL);
CREATE TABLE IF NOT EXISTS links(left_id TEXT REFERENCES events(id) ON DELETE CASCADE,
 right_id TEXT REFERENCES events(id) ON DELETE CASCADE, method TEXT, PRIMARY KEY(left_id,right_id));
CREATE TABLE IF NOT EXISTS alerts(id TEXT PRIMARY KEY, rule_id TEXT, title TEXT, host TEXT, window TEXT,
 severity TEXT, tags TEXT, author TEXT, license TEXT, status TEXT DEFAULT 'new', notes TEXT DEFAULT '', count INTEGER DEFAULT 0,
 created_at TEXT, updated_at TEXT, suppressed_until TEXT, suppression_reason TEXT);
CREATE TABLE IF NOT EXISTS evidence(alert_id TEXT REFERENCES alerts(id) ON DELETE CASCADE,
 event_id TEXT REFERENCES events(id) ON DELETE CASCADE, PRIMARY KEY(alert_id,event_id));
CREATE TABLE IF NOT EXISTS detections(rule_id TEXT, occurrence TEXT, created_at TEXT, PRIMARY KEY(rule_id,occurrence));
CREATE TABLE IF NOT EXISTS watermarks(rule_id TEXT PRIMARY KEY, cursor INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS rule_catalog(id TEXT PRIMARY KEY, document TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS rule_stats(rule_id TEXT PRIMARY KEY, title TEXT, status TEXT, reason TEXT,
 hits INTEGER, duration REAL, updated_at TEXT);
"""


def regexp(pattern: str, value: Any) -> int:
    """Linear-time regex with a length cap and no backtracking fallback."""
    if len(pattern) > LIMITS.regex_chars:
        raise ValueError("regex pattern limit")
    if value is None:
        return 0
    return int(re2.search(pattern, str(value)) is not None)


class Store:
    """One connection per command/request, with transactions for atomic offsets."""

    def __init__(self, path: Path | str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(self.path, timeout=5)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA secure_delete=ON")
        self.db.create_function("regexp", 2, regexp, deterministic=True)
        existing_version = self.db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='schema_version'"
        ).fetchone()
        if existing_version:
            version = self.db.execute("SELECT MAX(version) FROM schema_version").fetchone()[0]
            if version not in (1, 2, 3):
                self.db.close()
                raise ValueError("unsupported database schema")
        self.db.executescript(DDL)
        from minisiem.store.migrations import upgrade

        upgrade(self.db)

    def __enter__(self) -> "Store":
        return self

    def __exit__(self, *args: Any) -> None:
        self.db.close()

    @contextmanager
    def transaction(self) -> Iterator[None]:
        """Commit event writes and checkpoint together or roll both back."""
        try:
            self.db.execute("BEGIN IMMEDIATE")
            yield
            self.db.commit()
        except BaseException:
            self.db.rollback()
            raise

    def insert(self, events: Sequence[Event]) -> int:
        """Deduplicating fixed-column batch insert."""
        if not events:
            return 0
        values = [e.sql_values() for e in events]
        cols = list(values[0])
        sql = (
            "INSERT OR IGNORE INTO events("
            + ",".join(cols)
            + ") VALUES("
            + ",".join("?" for _ in cols)
            + ")"
        )
        return self.db.executemany(sql, [[v[c] for c in cols] for v in values]).rowcount

    def bounded(
        self,
        sql: str,
        params: Sequence[Any] = (),
        *,
        seconds: float | None = None,
        rows: int | None = None,
    ) -> list[dict[str, Any]]:
        """Read-only SQL for internally compiled rules; authorizer denies writes."""
        deadline = time.monotonic() + (seconds or LIMITS.query_seconds)
        denied = {
            sqlite3.SQLITE_INSERT,
            sqlite3.SQLITE_UPDATE,
            sqlite3.SQLITE_DELETE,
            sqlite3.SQLITE_ATTACH,
            sqlite3.SQLITE_DETACH,
            sqlite3.SQLITE_ALTER_TABLE,
            sqlite3.SQLITE_DROP_TABLE,
            sqlite3.SQLITE_CREATE_TABLE,
            sqlite3.SQLITE_PRAGMA,
        }
        self.db.set_authorizer(
            lambda action, a, b, c, d: (
                sqlite3.SQLITE_OK
                if action == sqlite3.SQLITE_PRAGMA and a == "data_version"
                else sqlite3.SQLITE_DENY
                if action in denied or (action == sqlite3.SQLITE_FUNCTION and b == "load_extension")
                else sqlite3.SQLITE_OK
            )
        )
        self.db.set_progress_handler(lambda: int(time.monotonic() > deadline), 100)
        try:
            cur = self.db.execute(sql, tuple(params))
            result = cur.fetchmany((rows or LIMITS.rows) + 1)
            if len(result) > (rows or LIMITS.rows):
                raise ValueError(
                    "row limit exceeded; narrow range or increase bounded configuration"
                )
            return [dict(r) for r in result]
        finally:
            self.db.set_progress_handler(None, 0)
            self.db.set_authorizer(None)

    def counts(self) -> dict[str, int]:
        """Health counts, without exposing raw data."""
        return {
            t: self.db.execute("SELECT COUNT(*) FROM " + t).fetchone()[0]
            for t in ("events", "quarantine", "alerts", "links")
        }

    def retain(self, before: str) -> int:
        """Remove events, evidence, context and FTS entries, then truncate WAL."""
        with self.transaction():
            n = self.db.execute("DELETE FROM events WHERE timestamp < ?", (before,)).rowcount
            self.db.execute("DELETE FROM quarantine WHERE created_at < ?", (before,))
            self.db.execute("DELETE FROM ingest_runs WHERE finished < ?", (before,))
            self.db.execute(
                "DELETE FROM alerts WHERE NOT EXISTS (SELECT 1 FROM evidence WHERE alert_id=alerts.id)"
            )
        if n:
            self.db.execute("INSERT INTO event_fts(event_fts) VALUES('optimize')")
            self.db.commit()
            self.db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            self.db.execute("VACUUM")
        return n

    def event(self, event_id: str) -> dict[str, Any] | None:
        row = self.db.execute("SELECT * FROM events WHERE id=?", (event_id,)).fetchone()
        if not row:
            return None
        d = dict(row)
        d["fields"] = json.loads(d["fields"])
        d["warnings"] = json.loads(d["warnings"])
        return d
