import hashlib
import json
from datetime import datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from test_store import make

from minisiem.api.main import create_app
from minisiem.config import LIMITS
from minisiem.store.db import Store
from minisiem.timeutil import UTC, iso

KEY = "a" * 48
READ = "b" * 48


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv(
        "MINISIEM_KEYS",
        json.dumps(
            [
                {"sha256": hashlib.sha256(KEY.encode()).hexdigest(), "scopes": ["admin"]},
                {"sha256": hashlib.sha256(READ.encode()).hexdigest(), "scopes": ["read"]},
            ]
        ),
    )
    db = tmp_path / "s.db"
    with Store(db) as s:
        e = make("<img src=x onerror=alert(1)><script>alert(1)</script>")
        with s.transaction():
            s.insert([e])
    with TestClient(create_app(db)) as c:
        yield c


def test_auth_headers_xss_and_injection(client):
    assert client.get("/v1/health").status_code == 401
    assert client.get("/v1/health", headers={"X-API-Key": READ}).status_code == 200
    now = datetime.now(UTC)
    params = {"start": iso(now - timedelta(days=1)), "end": iso(now + timedelta(days=1))}
    r = client.get("/v1/dashboard", params=params, headers={"X-API-Key": KEY})
    assert r.status_code == 200 and "&lt;script&gt;" in r.text and "<script>alert" not in r.text
    assert "default-src 'none'" in r.headers["content-security-policy"]
    r = client.get(
        "/v1/events", params=dict(params, q='message = "\' OR 1=1 --"'), headers={"X-API-Key": KEY}
    )
    assert r.status_code == 200 and r.json()["events"] == []
    assert client.get("/v1/openapi.json", headers={"X-API-Key": KEY}).status_code == 200
    assert (
        client.patch(
            "/v1/alerts/x", json={"status": "triaged", "notes": "x"}, headers={"X-API-Key": READ}
        ).status_code
        == 403
    )
    assert (
        client.post("/v1/ingest", json={"lines": ["{}"]}, headers={"X-API-Key": READ}).status_code
        == 403
    )
    assert (
        client.post(
            "/v1/ingest", json={"lines": ['{"message":"' + KEY + '"}']}, headers={"X-API-Key": KEY}
        ).status_code
        == 400
    )


def test_body_limit_and_rate(client):
    assert (
        client.post(
            "/v1/ingest", content=b"x" * (LIMITS.request_bytes + 1), headers={"X-API-Key": KEY}
        ).status_code
        == 413
    )
    last = None
    for _ in range(LIMITS.requests_per_minute + 1):
        last = client.get("/v1/health", headers={"X-API-Key": KEY})
    assert last is not None and last.status_code == 429


def test_http_replay(client):
    payload = {
        "source": "test-http",
        "lines": ['{"timestamp":"2025-01-01T00:00:00Z","message":"test"}'],
    }
    assert (
        client.post("/v1/ingest", json=payload, headers={"X-API-Key": KEY}).json()["accepted"] == 1
    )
    assert (
        client.post("/v1/ingest", json=payload, headers={"X-API-Key": KEY}).json()["duplicates"]
        == 1
    )
    assert (
        client.post("/v1/ingest", json={"lines": ["{bad"]}, headers={"X-API-Key": KEY}).json()[
            "quarantined"
        ]
        == 1
    )
