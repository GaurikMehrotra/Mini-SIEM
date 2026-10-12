"""Regressions for credential, chunked-body, backend evidence and migration boundaries."""

import json
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from test_api import KEY

from minisiem.detect.runner import run
from minisiem.detect.sigma_loader import compile_rules, parameterize
from minisiem.ingest.pipeline import ingest
from minisiem.parsers.registry import parse
from minisiem.store.db import Store
from minisiem.timeutil import UTC, iso


def test_chunked_body_limit(client):
    def chunks():
        for _ in range(5):
            yield b"x" * 65536

    response = client.post(
        "/v1/ingest",
        content=chunks(),
        headers={"X-API-Key": KEY, "Content-Type": "application/json"},
    )
    assert response.status_code == 413


def test_unknown_keys_cannot_evade_rate(client):
    from minisiem.config import LIMITS

    for i in range(LIMITS.requests_per_minute):
        response = client.get("/v1/health", headers={"X-API-Key": str(i).zfill(48)})
        assert response.status_code == 401
    assert (
        client.get(
            "/v1/health", headers={"X-API-Key": "different-invalid-key".zfill(48)}
        ).status_code
        == 429
    )


def test_secret_content_quarantine_is_redacted(tmp_path, monkeypatch):
    key = "test-only-sentinel-not-a-real-key-abcdef"
    monkeypatch.setenv("MINISIEM_API_KEY", key)
    line = json.dumps({"message": key})
    assert parse(line).reason == "credential content rejected"
    path = tmp_path / "input"
    path.write_text(line + "\n")
    with Store(tmp_path / "s.db") as store:
        assert ingest(store, path, "jsonl", "test")["quarantined"] == 1
        assert key not in json.dumps(
            [dict(r) for r in store.db.execute("SELECT * FROM quarantine")]
        )


def test_late_correlation_native_ids_and_replay(tmp_path):
    # Success is ingested first; the earlier failure arrives later and completes ordered evidence.
    now = datetime.now(UTC)
    records = [
        {
            "timestamp": iso(now),
            "dataset": "syslog",
            "source_ip": "192.0.2.1",
            "outcome": "success",
        },
        {
            "timestamp": iso(now - timedelta(seconds=30)),
            "dataset": "syslog",
            "source_ip": "192.0.2.1",
            "outcome": "failure",
        },
    ]
    rules_path = Path("rules/custom/ssh_sequence.yml")
    with Store(tmp_path / "s.db") as store:
        first = parse(json.dumps(records[0])).events
        with store.transaction():
            store.insert(first)
        rules, report = compile_rules([rules_path], store)
        assert all(r["status"] == "compiled" for r in report)
        assert run(store, rules)[0]["hits"] == 0
        second = parse(json.dumps(records[1])).events
        with store.transaction():
            store.insert(second)
        assert run(store, rules)[0]["hits"] == 1
        assert store.db.execute("SELECT COUNT(*) FROM evidence").fetchone()[0] == 2
        assert run(store, rules) == []
        sql, params = parameterize("SELECT 1.7976931348623157e308 AS n")
        assert sql == "SELECT ? AS n" and params[0] > 1e308


def test_unknown_schema_rejected_without_mutation(tmp_path):
    path = tmp_path / "s.db"
    with Store(path) as store:
        store.db.execute("INSERT INTO schema_version VALUES(999)")
        store.db.commit()
    import sqlite3

    before = sqlite3.connect(path).execute("SELECT COUNT(*) FROM sqlite_master").fetchone()[0]
    with pytest.raises(ValueError):
        Store(path)
    after = sqlite3.connect(path).execute("SELECT COUNT(*) FROM sqlite_master").fetchone()[0]
    assert before == after
