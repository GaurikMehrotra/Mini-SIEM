"""Execute pinned backend correlation SQL over bounded event-time/ingest windows."""

import json
from datetime import datetime, timedelta
from typing import Any

from minisiem.detect.sigma_loader import Rule
from minisiem.store.db import Store
from minisiem.timeutil import iso


def occurrences(
    store: Store, rule: Rule, batch: list[Any], cursor: int, upper: int
) -> list[list[dict[str, Any]]]:
    """Native backend windows return evidence IDs, not fabricated single rows."""
    if not rule.correlation:
        return []
    span = rule.correlation["timespan"]
    seconds = int(span[:-1]) * {"s": 1, "m": 60, "h": 3600}[span[-1]]
    low = iso(
        min(datetime.fromisoformat(e["timestamp"]) for e in batch) - timedelta(seconds=seconds)
    )
    high = iso(
        max(datetime.fromisoformat(e["timestamp"]) for e in batch) + timedelta(seconds=seconds)
    )
    groups = []
    for sql, params in rule.queries:
        if not sql.startswith("WITH "):
            raise ValueError("unexpected pinned correlation SQL format")
        scoped = (
            "WITH events AS (SELECT * FROM main.events WHERE timestamp>=? AND timestamp<=? AND ingest_seq<=?), "
            + sql[5:]
        )
        for occurrence in store.bounded(scoped, [low, high, upper] + params):
            ids = json.loads(occurrence["event_ids"])
            if not isinstance(ids, list):
                raise ValueError("invalid backend evidence")
            evidence = []
            for identity in ids:
                # Backend encodes source table and leaf-event prefixes before the configured id.
                key = str(identity).rsplit(":", 1)[-1]
                e = store.event(key)
                if e is None:
                    raise ValueError("backend evidence missing from event store")
                evidence.append(e)
            if evidence and any(cursor < e["ingest_seq"] <= upper for e in evidence):
                groups.append(sorted(evidence, key=lambda e: (e["timestamp"], e["id"])))
    return groups
