"""Alerts are hypotheses with auditable evidence and expiring suppression."""

import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Any

from minisiem.config import LIMITS
from minisiem.store.db import Store
from minisiem.timeutil import UTC, iso

STATUSES = frozenset({"new", "triaged", "true_positive", "false_positive", "suppressed"})


def add_alert(
    store: Store,
    rule: Any,
    events: list[dict[str, Any]],
    now: datetime,
    group_seconds: int | None = None,
) -> str:
    """Group by rule, host and fixed event-time window, dedup evidence."""
    first = events[-1]
    host = first.get("host") or first.get("source_ip") or "unknown"
    dt = datetime.fromisoformat(first["timestamp"])
    width = group_seconds or LIMITS.grouping_seconds
    window = str(int(dt.timestamp()) // width * width)
    identity = hashlib.sha256((rule.id + "\0" + host + "\0" + window).encode()).hexdigest()
    stamp = iso(now)
    store.db.execute(
        "INSERT OR IGNORE INTO alerts(id,rule_id,title,host,window,severity,tags,author,license,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
        (
            identity,
            rule.id,
            rule.title,
            host,
            window,
            rule.level,
            json.dumps(rule.tags),
            str(rule.document.get("author", "unspecified")),
            str(rule.document.get("license", "MIT (original rules); verify imported rule terms")),
            stamp,
            stamp,
        ),
    )
    store.db.executemany(
        "INSERT OR IGNORE INTO evidence VALUES(?,?)", [(identity, e["id"]) for e in events]
    )
    store.db.execute(
        "UPDATE alerts SET count=(SELECT COUNT(*) FROM evidence WHERE alert_id=?),updated_at=? WHERE id=?",
        (identity, stamp, identity),
    )
    return identity


def expire(store: Store, now: datetime | None = None) -> int:
    with store.transaction():
        return store.db.execute(
            "UPDATE alerts SET status='new',suppressed_until=NULL WHERE status='suppressed' AND suppressed_until<=?",
            (iso(now or datetime.now(UTC)),),
        ).rowcount


def transition(
    store: Store,
    identity: str,
    status: str,
    notes: str,
    until: str | None = None,
    reason: str | None = None,
    now: datetime | None = None,
) -> None:
    now = now or datetime.now(UTC)
    if status not in STATUSES:
        raise ValueError("unknown status")
    if not notes.strip() or len(notes) > 4096:
        raise ValueError("bounded analyst note required")
    if status == "suppressed":
        if not reason or not reason.strip() or len(reason) > 1024 or not until:
            raise ValueError("justification and expiry required")
        dt = datetime.fromisoformat(until.replace("Z", "+00:00"))
        if dt.tzinfo is None or dt <= now:
            raise ValueError("future timezone-aware expiry required")
        until = iso(dt)
    else:
        until = None
        reason = None
    with store.transaction():
        n = store.db.execute(
            "UPDATE alerts SET status=?,notes=?,suppressed_until=?,suppression_reason=?,updated_at=? WHERE id=?",
            (status, notes, until, reason, iso(now), identity),
        ).rowcount
        if n != 1:
            raise ValueError("alert not found")


def detail(store: Store, identity: str) -> dict[str, Any] | None:
    row = store.db.execute("SELECT * FROM alerts WHERE id=?", (identity,)).fetchone()
    if not row:
        return None
    d = dict(row)
    d["evidence"] = store.bounded(
        "SELECT e.* FROM events e JOIN evidence v ON e.id=v.event_id WHERE v.alert_id=? ORDER BY e.timestamp,e.id LIMIT ?",
        [identity, LIMITS.rows],
    )
    d["context"] = store.bounded(
        "SELECT DISTINCT e.* FROM events e JOIN links l ON e.id=l.left_id OR e.id=l.right_id WHERE l.left_id IN (SELECT event_id FROM evidence WHERE alert_id=?) OR l.right_id IN (SELECT event_id FROM evidence WHERE alert_id=?) LIMIT ?",
        [identity, identity, LIMITS.rows],
    )
    return d


def notify_local(store: Store, path: Path) -> int:
    """Only a local JSONL file; no URL destinations or secret-bearing evidence."""
    alerts = store.bounded(
        "SELECT id,rule_id,title,author,license,severity,count FROM alerts WHERE status='new' LIMIT ?",
        [LIMITS.rows],
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a") as f:
        for alert in alerts:
            f.write(json.dumps(alert) + "\n")
    return len(alerts)
