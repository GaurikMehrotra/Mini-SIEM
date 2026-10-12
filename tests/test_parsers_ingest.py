import json
from datetime import datetime

from hypothesis import given, settings
from hypothesis import strategies as st

from minisiem.ingest.linking import link
from minisiem.ingest.pipeline import ingest
from minisiem.parsers.registry import parse
from minisiem.store.db import Store
from minisiem.timeutil import UTC

NOW = datetime(2025, 1, 1, tzinfo=UTC)


def test_parsers():
    assert parse("[]").reason
    assert parse("{bad").reason
    assert (
        parse("<34>1 2025-01-01T00:00:00Z lab sshd 1 ID - Failed password", "syslog", now=NOW)
        .events[0]
        .outcome
        == "failure"
    )
    p = parse("Jan  1 00:00:00 lab sshd: Accepted publickey", "syslog", now=NOW)
    assert p.events[0].outcome == "success" and p.warnings
    assert (
        parse('192.0.2.1 - - [01/Jan/2025:00:00:00 +0000] "GET / HTTP/1.1" 200 10 "-" "lab"', "web")
        .events[0]
        .http_status
        == 200
    )
    assert parse('{"message":"hi\\u001b[31mBAD\\nX"}').events[0].message == "hiBADX"
    assert parse('{"source_port":999999}').reason
    assert parse('{"dns":[]}', "suricata").reason


@given(st.text(max_size=2000), st.sampled_from(["jsonl", "syslog", "web", "zeek.conn", "suricata"]))
@settings(max_examples=300, deadline=None)
def test_total(line, kind):
    p = parse(line, kind)
    assert p.events or p.reason


def test_rotation_partial_and_replay(tmp_path):
    path = tmp_path / "input"
    db = tmp_path / "s.db"
    with Store(db) as s:
        path.write_text('{"message":"first"}\n{"message":"partial"')
        assert ingest(s, path, "jsonl", "x")["accepted"] == 1
        assert ingest(s, path, "jsonl", "x")["accepted"] == 0
        with path.open("a") as f:
            f.write("}\n")
        assert ingest(s, path, "jsonl", "x")["accepted"] == 1
        path.rename(tmp_path / "old")
        with (tmp_path / "old").open("a") as f:
            f.write('{"message":"rotated-tail"}\n')
        path.write_text('{"message":"replacement"}\n')
        assert ingest(s, path, "jsonl", "x")["accepted"] == 2
        path.write_text('{"message":"first"}\n')
        r = ingest(s, path, "jsonl", "x")
        assert r["accepted"] == 0 and r["duplicates"] == 1
        assert s.counts()["events"] == 4


def test_oversize_quarantine_and_privacy(tmp_path):
    path = tmp_path / "input"
    path.write_text(
        "x" * 100000
        + '\n{bad}\n{"host":"synthetic-alice","message":"synthetic-alice","source_ip":"192.0.2.1"}\n'
    )
    with Store(tmp_path / "s.db") as s:
        r = ingest(s, path, "jsonl", "x", b"test-only-pseudonym-key")
        assert r["quarantined"] == 2 and r["accepted"] == 1
        row = dict(s.db.execute("SELECT * FROM events").fetchone())
        assert "synthetic-alice" not in json.dumps(row)


def test_sensor_link(tmp_path):
    z = {
        "ts": 1735689600,
        "id.orig_h": "192.0.2.1",
        "id.resp_h": "198.51.100.2",
        "id.orig_p": 1234,
        "id.resp_p": 80,
        "proto": "tcp",
    }
    u = {
        "timestamp": "2025-01-01T00:00:00Z",
        "event_type": "flow",
        "src_ip": "192.0.2.1",
        "dest_ip": "198.51.100.2",
        "src_port": 1234,
        "dest_port": 80,
        "proto": "TCP",
    }
    a = parse(json.dumps(z), "zeek.conn").events[0]
    b = parse(json.dumps(u), "suricata").events[0]
    assert a.community_id == b.community_id
    with Store(tmp_path / "s.db") as s:
        with s.transaction():
            s.insert([a, b])
        assert link(s) == 1 and link(s) == 0


def test_rotated_partial_completed_on_later_poll(tmp_path):
    path = tmp_path / "active"
    path.write_text('{"message":"first"}\n{"message":"late-tail"')
    with Store(tmp_path / "s.db") as store:
        assert ingest(store, path, "jsonl", "stream")["accepted"] == 1
        old = tmp_path / "rotated"
        path.rename(old)
        path.write_text('{"message":"replacement"}\n')
        assert ingest(store, path, "jsonl", "stream")["accepted"] == 1
        with old.open("a") as f:
            f.write("}\n")
        assert ingest(store, path, "jsonl", "stream")["accepted"] == 1
        assert store.counts()["events"] == 3


def test_oversized_incomplete_line_remains_draining(tmp_path):
    from minisiem.config import LIMITS

    path = tmp_path / "active"
    path.write_text("x" * (LIMITS.line_bytes + 10))
    with Store(tmp_path / "s.db") as store:
        assert ingest(store, path, "jsonl", "stream")["quarantined"] == 1
        with path.open("a") as f:
            f.write('{"message":"suffix-not-an-event"}\n{"message":"real-next-line"}\n')
        result = ingest(store, path, "jsonl", "stream")
        assert result["accepted"] == 1 and result["quarantined"] == 0
        assert store.db.execute("SELECT message FROM events").fetchone()[0] == "real-next-line"
        import pytest

        with pytest.raises(ValueError):
            ingest(store, path, "jsonl", "different-stream")
