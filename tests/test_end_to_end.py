"""Real sensor output from our generated benign PCAP, exercised without Docker."""

from pathlib import Path

from minisiem.detect.runner import run
from minisiem.detect.sigma_loader import compile_rules
from minisiem.ingest.linking import link
from minisiem.ingest.pipeline import ingest
from minisiem.store.db import Store

ROOT = Path(__file__).resolve().parents[1]


def test_fixture_e2e(tmp_path):
    with Store(tmp_path / "s.db") as store:
        for stem in ["conn", "dns", "http", "ssl", "notice"]:
            result = ingest(
                store,
                ROOT / "fixtures" / ("zeek_" + stem + ".jsonl"),
                "zeek." + stem,
                "fixture-zeek-" + stem,
            )
            assert result["accepted"] == 1 and result["quarantined"] == 0
        result = ingest(store, ROOT / "fixtures/suricata.jsonl", "suricata", "fixture-suricata")
        assert result["accepted"] == 3 and result["quarantined"] == 0
        assert link(store) >= 2
        assert (
            store.db.execute("SELECT COUNT(*) FROM links WHERE method='community_id'").fetchone()[0]
            >= 2
        )
        # jq-derived expectations in sensor generated output, not a PID-only test.
        rows = store.bounded("SELECT * FROM events WHERE dataset='suricata.alert'")
        assert rows[0]["message"] == "MINISIEM benign HTTP fixture"
        assert rows[0]["http_status"] == 200 and rows[0]["http_url"] == "/lab"
        rules, report = compile_rules(list((ROOT / "rules/custom").glob("*.yml")), store)
        assert all(x["status"] == "compiled" for x in report)
        results = run(store, rules)
        assert all(x["status"] == "ok" for x in results)
        alert = store.db.execute(
            "SELECT * FROM alerts WHERE title='Suricata sensor alert hypothesis'"
        ).fetchone()
        assert alert and alert["author"] == "Mini-SIEM contributors"
        assert (
            store.db.execute(
                "SELECT COUNT(*) FROM evidence WHERE alert_id=?", (alert["id"],)
            ).fetchone()[0]
            == 1
        )
