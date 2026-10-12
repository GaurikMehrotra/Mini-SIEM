"""Finite file ingestion with checkpoint transactions and bounded memory."""

import hashlib
import shutil
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from minisiem.config import LIMITS
from minisiem.parsers.registry import parse
from minisiem.store.db import Store
from minisiem.timeutil import UTC, iso


def ingest(
    store: Store, path: Path, kind: str, source: str, pseudonym_key: bytes | None = None
) -> dict[str, Any]:
    """Ingest complete lines, drain renamed inode, and detect truncate/rewrite.

    Copytruncate has an inherent race: bytes removed before any reader sees them
    cannot be recovered. Prefer rename rotation and keep the rotated file.
    """
    if shutil.disk_usage(store.path.parent).free < LIMITS.minimum_disk_bytes:
        raise ValueError("insufficient free disk for ingestion")
    path = path.resolve()
    start = datetime.now(UTC)
    t0 = time.monotonic()
    totals = {"accepted": 0, "duplicates": 0, "quarantined": 0, "lag_seconds": 0.0}
    prior = store.db.execute("SELECT * FROM checkpoints WHERE path=?", (str(path),)).fetchone()
    stat = path.stat()
    if prior and (
        (prior["source"] and prior["source"] != source) or (prior["kind"] and prior["kind"] != kind)
    ):
        raise ValueError("checkpoint source/parser binding changed; use a separate stream/database")
    pending = list(
        store.db.execute(
            "SELECT * FROM checkpoints WHERE owner_path=? AND path<>?", (str(path), str(path))
        )
    )
    if prior and (prior["inode"], prior["device"]) != (stat.st_ino, stat.st_dev):
        pending.append(prior)
    candidates = list(path.parent.iterdir()) if pending else []
    for old in pending:
        for candidate in candidates:
            cs = candidate.stat()
            if candidate.is_file() and (cs.st_ino, cs.st_dev) == (old["inode"], old["device"]):
                _consume(
                    store,
                    candidate,
                    kind,
                    source,
                    pseudonym_key,
                    old["offset"],
                    str(candidate),
                    totals,
                    str(path),
                    bool(old["draining"]),
                )
                if old["path"] not in (str(path), str(candidate)):
                    with store.transaction():
                        store.db.execute("DELETE FROM checkpoints WHERE path=?", (old["path"],))
                break
    offset = 0
    draining = False
    if (
        prior
        and (prior["inode"], prior["device"]) == (stat.st_ino, stat.st_dev)
        and stat.st_size >= prior["offset"]
    ):
        with path.open("rb") as f:
            old_prefix = hashlib.sha256(f.read(min(256, prior["offset"]))).hexdigest()
        if prior["prefix"] == old_prefix:
            offset = prior["offset"]
            draining = bool(prior["draining"])
    _consume(
        store, path, kind, source, pseudonym_key, offset, str(path), totals, str(path), draining
    )
    elapsed = time.monotonic() - t0
    finish = iso(datetime.now(UTC))
    with store.transaction():
        store.db.execute(
            "INSERT INTO ingest_runs(source,started,finished,accepted,duplicates,quarantined,lag_seconds,elapsed_seconds) VALUES(?,?,?,?,?,?,?,?)",
            (
                source,
                iso(start),
                finish,
                totals["accepted"],
                totals["duplicates"],
                totals["quarantined"],
                totals["lag_seconds"],
                elapsed,
            ),
        )
    return dict(
        totals, elapsed_seconds=elapsed, events_per_second=totals["accepted"] / max(elapsed, 1e-9)
    )


def _consume(
    store: Store,
    path: Path,
    kind: str,
    source: str,
    key: bytes | None,
    offset: int,
    checkpoint: str,
    totals: dict[str, Any],
    owner: str,
    draining: bool = False,
) -> None:
    with path.open("rb") as f:
        stat = path.stat()
        f.seek(offset)
        exhausted = False
        while not exhausted:
            with store.transaction():
                events = []
                errors = []
                end = offset
                for _ in range(LIMITS.batch_size):
                    begin = f.tell()
                    line = f.readline(LIMITS.line_bytes + 1)
                    if not line:
                        exhausted = True
                        break
                    oversized = len(line) > LIMITS.line_bytes
                    if draining or oversized:
                        # Drain with bounded memory, never store the whole hostile line.
                        while line and not line.endswith(b"\n"):
                            line = f.readline(LIMITS.line_bytes + 1)
                        if not draining:
                            errors.append(("[oversized line omitted]", "line exceeds byte limit"))
                        draining = not line.endswith(b"\n")
                    elif not line.endswith(b"\n"):
                        f.seek(begin)
                        exhausted = True
                        break
                    else:
                        try:
                            text = line.decode("utf-8", errors="strict")
                            result = parse(text, kind, source, pseudonym_key=key)
                            if result.reason:
                                errors.append(
                                    (
                                        "[redacted]"
                                        if key or result.reason == "credential content rejected"
                                        else text.rstrip("\r\n"),
                                        result.reason,
                                    )
                                )
                            else:
                                events.extend(result.events)
                                for e in result.events:
                                    totals["lag_seconds"] = max(
                                        totals["lag_seconds"],
                                        max(0.0, (e.ingested_at - e.timestamp).total_seconds()),
                                    )
                        except UnicodeDecodeError:
                            errors.append(("[non-UTF8 line omitted]", "invalid UTF-8"))
                    end = f.tell()
                added = store.insert(events)
                totals["accepted"] += added
                totals["duplicates"] += len(events) - added
                totals["quarantined"] += len(errors)
                now = iso(datetime.now(UTC))
                store.db.executemany(
                    "INSERT INTO quarantine(source,raw,reason,created_at) VALUES(?,?,?,?)",
                    [(source, raw, reason, now) for raw, reason in errors],
                )
                position = f.tell()
                f.seek(0)
                prefix = hashlib.sha256(f.read(min(256, end))).hexdigest()
                f.seek(position)
                store.db.execute(
                    "INSERT INTO checkpoints(path,device,inode,offset,prefix,owner_path,draining,source,kind) VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(path) DO UPDATE SET device=excluded.device,inode=excluded.inode,offset=excluded.offset,prefix=excluded.prefix,owner_path=excluded.owner_path,draining=excluded.draining,source=excluded.source,kind=excluded.kind",
                    (
                        checkpoint,
                        stat.st_dev,
                        stat.st_ino,
                        end,
                        prefix,
                        owner,
                        int(draining),
                        source,
                        kind,
                    ),
                )
                offset = end
