"""Micro-batches, bounded queries, ingest watermarks and persistent hit identity."""

import hashlib
import sqlite3
import time
from datetime import datetime
from typing import Any

from minisiem.alerts.workflow import add_alert, expire
from minisiem.config import LIMITS
from minisiem.detect.correlation import occurrences
from minisiem.detect.sigma_loader import Rule
from minisiem.store.db import Store
from minisiem.timeutil import UTC, iso


def run(
    store: Store, rules: list[Rule], now: datetime | None = None, group_seconds: int | None = None
) -> list[dict[str, Any]]:
    """Bound each rule independently; a failure never advances its watermark.

    Correlations rescan event-time windows around new ingest sequences and
    deduplicate occurrences in SQLite. Arbitrarily late offline events remain
    eligible while retained; input/time caps fail visibly without advancing the
    cursor. No wall-clock-age cutoff silently drops historical imports.
    """
    expire(store, now)
    now = now or datetime.now(UTC)
    maximum = store.db.execute("SELECT MAX(ingest_seq) FROM events").fetchone()[0]
    if maximum is None:
        return []
    by_name = {r.name: r for r in rules}
    by_name.update({r.id: r for r in rules})
    diagnostics = []
    for rule in rules:
        if rule.document.get("x-minisiem-evidence-only"):
            continue
        t0 = time.monotonic()
        hits = 0
        late = 0
        prior = store.db.execute(
            "SELECT cursor FROM watermarks WHERE rule_id=?", (rule.id,)
        ).fetchone()
        previous = prior[0] if prior else 0
        batch_rows = store.db.execute(
            "SELECT ingest_seq,timestamp FROM events WHERE ingest_seq>? ORDER BY ingest_seq LIMIT ?",
            (previous, LIMITS.batch_size),
        ).fetchall()
        if not batch_rows:
            continue
        upper = batch_rows[-1]["ingest_seq"]
        try:
            if rule.correlation:
                for dependency in rule.dependencies:
                    if dependency not in by_name:
                        raise ValueError("missing correlation dependency: " + dependency)
                groups = occurrences(store, rule, batch_rows, previous, upper)
            else:
                found = []
                for sql, params in rule.queries:
                    found.extend(
                        store.bounded(
                            "SELECT * FROM ("
                            + sql
                            + ") WHERE ingest_seq>? AND ingest_seq<=? ORDER BY timestamp,id",
                            params + [previous, upper],
                        )
                    )
                groups = [[e] for e in {e["id"]: e for e in found}.values()]
            # Time limit covers SQL and window processing, not just the query VM.
            if time.monotonic() - t0 > LIMITS.query_seconds:
                raise TimeoutError("rule time limit")
            with store.transaction():
                for events in groups:
                    identity = hashlib.sha256(
                        "|".join(sorted(e["id"] for e in events)).encode()
                    ).hexdigest()
                    fresh = store.db.execute(
                        "INSERT OR IGNORE INTO detections VALUES(?,?,?)",
                        (rule.id, identity, iso(now)),
                    ).rowcount
                    if fresh:
                        add_alert(store, rule, events, now, group_seconds)
                        hits += 1
                store.db.execute(
                    "INSERT INTO watermarks VALUES(?,?) ON CONFLICT(rule_id) DO UPDATE SET cursor=excluded.cursor",
                    (rule.id, upper),
                )
            status = "ok"
            reason = ""
        except (sqlite3.Error, ValueError, TimeoutError) as exc:
            status = "failed"
            reason = type(exc).__name__ + ": " + str(exc)[:200]
        duration = time.monotonic() - t0
        with store.transaction():
            store.db.execute(
                "INSERT INTO rule_stats VALUES(?,?,?,?,?,?,?) ON CONFLICT(rule_id) DO UPDATE SET status=excluded.status,reason=excluded.reason,hits=rule_stats.hits+excluded.hits,duration=excluded.duration,updated_at=excluded.updated_at",
                (rule.id, rule.title, status, reason, hits, duration, iso(now)),
            )
        diagnostics.append(
            {
                "id": rule.id,
                "status": status,
                "reason": reason,
                "hits": hits,
                "duration": duration,
                "late_excluded": late,
            }
        )
    return diagnostics
