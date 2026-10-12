from datetime import datetime, timedelta

import pytest
from test_store import make

from minisiem.alerts.workflow import expire, transition
from minisiem.detect.runner import run
from minisiem.detect.sigma_loader import Rule, compile_rules, parameterize, yaml_documents
from minisiem.store.db import Store
from minisiem.timeutil import UTC, iso

RULE = """title: Harness Smoke
id: 12345678-1234-1234-1234-123456789012
name: smoke
logsource:
  product: minisiem
  service: generic
detection:
  selection:
    message|contains: test
  condition: selection
level: medium
tags: [attack.t1059]
"""


def test_harness_compile_run_and_suppression(tmp_path):
    path = tmp_path / "rule.yml"
    path.write_text(RULE)
    with Store(tmp_path / "s.db") as s:
        with s.transaction():
            s.insert([make("test positive"), make("benign")])
        rules, report = compile_rules([path], s)
        assert report[0]["status"] == "compiled", report
        assert run(s, rules)[0]["hits"] == 1
        assert run(s, rules) == []
        assert s.counts()["alerts"] == 1
        identity = s.db.execute("SELECT id FROM alerts").fetchone()[0]
        with pytest.raises(ValueError):
            transition(s, identity, "suppressed", "note")
        now = datetime.now(UTC)
        transition(
            s,
            identity,
            "suppressed",
            "lab tuning",
            iso(now + timedelta(seconds=2)),
            "synthetic exercise",
            now,
        )
        assert expire(s, now) == 0
        assert expire(s, now + timedelta(seconds=3)) == 1


def test_timeout_isolation(tmp_path):
    with Store(tmp_path / "s.db") as s:
        with s.transaction():
            s.insert([make("test")])
        path = tmp_path / "rule.yml"
        path.write_text(RULE)
        rules, _ = compile_rules([path], s)
        expensive = Rule(
            "bad",
            "bad",
            "Expensive",
            "low",
            [],
            [
                (
                    "WITH RECURSIVE n(x) AS (SELECT ? UNION ALL SELECT x+? FROM n WHERE x<?) SELECT e.* FROM events e WHERE (SELECT SUM(x) FROM n)>?",
                    [1, 1, 1000000000, 0],
                )
            ],
            {},
        )
        result = run(s, [expensive] + rules)
        assert result[0]["status"] == "failed" and "interrupt" in result[0]["reason"]
        assert result[1]["hits"] == 1
        assert not s.db.execute("SELECT * FROM watermarks WHERE rule_id=?", ("bad",)).fetchone()


def test_rule_rejections(tmp_path):
    with pytest.raises(ValueError):
        yaml_documents("a: &x [1,2]\nb: *x")
    p = tmp_path / "bad.yml"
    p.write_text(RULE.replace("message|contains", "UnknownField"))
    assert compile_rules([p])[1][0]["status"] == "not_applicable"
    p.write_text(RULE.replace("message|contains: test", 'message|re: "(a+)\\1"'))
    assert compile_rules([p])[1][0]["status"] != "compiled"
    sql, params = parameterize("SELECT * FROM events WHERE message='a''b' AND source_port=80")
    assert params == ["a'b", 80] and "a''b" not in sql
