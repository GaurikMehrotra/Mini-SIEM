"""Measured synthetic evaluation with explicit denominators and limitations."""

import csv
import json
import platform
import random
import shutil
import sqlite3
import statistics
import tempfile
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import psutil

from minisiem.config import LIMITS
from minisiem.detect.runner import run
from minisiem.detect.sigma_loader import Rule, compile_rules
from minisiem.ingest.linking import link
from minisiem.ingest.pipeline import ingest
from minisiem.parsers.registry import parse
from minisiem.simulate.scenarios import generate
from minisiem.store.db import Store
from minisiem.timeutil import UTC, iso


def percentile(values: list[float], percent: float) -> float | None:
    return (
        sorted(values)[min(len(values) - 1, int((len(values) - 1) * percent))] if values else None
    )


def fuzz(seed: int = 42, count: int = 10000) -> dict[str, Any]:
    """Mutate valid JSON plus guaranteed invalid sentinels; test exact quarantine."""
    rng = random.Random(seed)
    accepted = quarantined = 0
    start = time.monotonic()
    kinds = [
        "jsonl",
        "syslog",
        "web",
        "zeek.conn",
        "zeek.dns",
        "zeek.http",
        "zeek.ssl",
        "zeek.notice",
        "suricata",
    ]
    bases = [
        '{"timestamp":"2025-01-01T00:00:00Z","message":"lab"}',
        "<34>1 2025-01-01T00:00:00Z lab app 1 ID - test",
        '192.0.2.1 - - [01/Jan/2025:00:00:00 +0000] "GET /lab HTTP/1.1" 200 3 "-" "fixture"',
    ]
    for i in range(count):
        text = rng.choice(bases)
        pos = rng.randrange(len(text) + 1)
        change = rng.choice(["\x00", "\x1b[31m", '"', "\\", "{", "\n", "a" * rng.randrange(10)])
        text = text[:pos] + change + text[pos:]
        result = parse(text, kinds[i % len(kinds)])
        if result.reason:
            quarantined += 1
        else:
            accepted += 1
    # Verify malformed/oversized inputs are not quietly accepted or dropped.
    with tempfile.TemporaryDirectory() as td, Store(Path(td) / "fuzz.db") as store:
        path = Path(td) / "invalid"
        path.write_text("{broken\n[]\n" + "x" * (LIMITS.line_bytes + 1) + "\n")
        ingest_result = ingest(store, path, "jsonl", "fuzz")
        assert ingest_result["quarantined"] == 3 and store.counts()["quarantine"] == 3
    return {
        "seed": seed,
        "mutated_lines": count,
        "accepted": accepted,
        "quarantined": quarantined,
        "uncaught_exceptions": 0,
        "known_invalid_quarantine_verified": True,
        "seconds": time.monotonic() - start,
    }


def parsing_agreement() -> dict[str, Any]:
    """Independent direct JSON field extraction vs normalized parser mappings."""
    import jq

    checks = []
    z = {
        "ts": 1735689600,
        "id.orig_h": "192.0.2.1",
        "id.resp_h": "198.51.100.2",
        "id.orig_p": 1234,
        "id.resp_p": 80,
        "query": "lab.invalid",
    }
    u = {
        "timestamp": "2025-01-01T00:00:00Z",
        "event_type": "dns",
        "src_ip": "192.0.2.1",
        "dest_ip": "198.51.100.2",
        "src_port": 1234,
        "dest_port": 53,
        "proto": "UDP",
        "dns": {"rrname": "lab.invalid"},
    }
    for kind, record, expressions in [
        (
            "zeek.dns",
            z,
            {
                "source_ip": '.["id.orig_h"]',
                "destination_ip": '.["id.resp_h"]',
                "destination_port": '.["id.resp_p"]',
                "dns_question": ".query",
            },
        ),
        (
            "suricata",
            u,
            {
                "source_ip": ".src_ip",
                "destination_ip": ".dest_ip",
                "destination_port": ".dest_port",
                "dns_question": ".dns.rrname",
            },
        ),
    ]:
        event = parse(json.dumps(record), kind).events[0]
        for field, expression in expressions.items():
            reference = jq.compile(expression).input_value(record).first()
            actual = getattr(event, field)
            checks.append(
                {
                    "parser": kind,
                    "field": field,
                    "reference": reference,
                    "actual": actual,
                    "agrees": reference == actual,
                }
            )
    return {
        "reference": "libjq direct extraction; actual sensor integration reported separately",
        "checks": checks,
        "agreement": sum(c["agrees"] for c in checks) / len(checks),
    }


def quality(truth: dict[str, Any], store: Store, rules: list[Rule], variant: str) -> dict[str, Any]:
    alerts = [dict(r) for r in store.db.execute("SELECT * FROM alerts")]
    evidence = {
        a["id"]: {
            r[0]
            for r in store.db.execute("SELECT event_id FROM evidence WHERE alert_id=?", (a["id"],))
        }
        for a in alerts
    }
    names = {r.id: r.name for r in rules}
    positive_ids = {e for t in truth["instances"] for e in t["event_ids"]}
    true_alerts = [a for a in alerts if evidence[a["id"]] & positive_ids]
    false = len(alerts) - len(true_alerts)
    per_rule = []
    errors = []
    delays = []
    event_delays = []
    for target in sorted({t["rule"] for t in truth["instances"]}):
        instances = [t for t in truth["instances"] if t["rule"] == target]
        matched = 0
        for inst in instances:
            candidates = [
                a
                for a in alerts
                if names.get(a["rule_id"]) == target and evidence[a["id"]] & set(inst["event_ids"])
            ]
            if candidates:
                matched += 1
                earliest = min(datetime.fromisoformat(a["created_at"]) for a in candidates)
                ids = evidence[candidates[0]["id"]]
                times = []
                for event_identity in ids:
                    event_row = store.event(event_identity)
                    if event_row:
                        times.append(datetime.fromisoformat(event_row["ingested_at"]))
                if times:
                    delays.append((earliest - min(times)).total_seconds())
                event_delays.append(
                    (earliest - datetime.fromisoformat(inst["scenario_start"])).total_seconds()
                )
            else:
                errors.append(
                    {
                        "variant": variant,
                        "instance": inst["instance"],
                        "rule": target,
                        "reason": "correlation intentionally disabled"
                        if variant == "without_correlation"
                        and target in ("ssh_burst", "port_spread", "sensor_pair", "ssh_sequence")
                        else "no evidence-bearing alert; inspect mapping, window and compile report",
                    }
                )
        own = [a for a in alerts if names.get(a["rule_id"]) == target]
        own_true = [a for a in own if evidence[a["id"]] & positive_ids]
        per_rule.append(
            {
                "rule": target,
                "instances": len(instances),
                "detected": matched,
                "recall": matched / len(instances),
                "precision": len(own_true) / len(own) if own else None,
                "alerts": len(own),
            }
        )
    return {
        "variant": variant,
        "precision": len(true_alerts) / len(alerts) if alerts else None,
        "recall": sum(r["detected"] for r in per_rule) / len(truth["instances"]),
        "alerts": len(alerts),
        "false_positive_alerts": false,
        "false_positive_alerts_per_day": false / truth["benign_observation_days"],
        "benign_observation_days": truth["benign_observation_days"],
        "ingest_to_alert_p50_seconds": percentile(delays, 0.5),
        "ingest_to_alert_p95_seconds": percentile(delays, 0.95),
        "offline_event_time_to_alert_p50_seconds": percentile(event_delays, 0.5),
        "per_rule": per_rule,
        "misses": errors,
        "rule_firings": sorted({a["rule_id"] for a in alerts}),
        "definition": "An alert is positive if its evidence intersects synthetic target records; scenario recall also requires intended rule identity. This is not real-world precision.",
    }


def performance(events: int, output: Path) -> dict[str, Any]:
    """Measured bounded workloads; size per million is explicitly extrapolated."""
    if shutil.disk_usage(output).free < events * 2048 + LIMITS.minimum_disk_bytes:
        raise ValueError("insufficient free disk for benchmark")
    process = psutil.Process()
    samples = []
    stop = threading.Event()

    def sample() -> None:
        while not stop.wait(0.01):
            samples.append(process.memory_info().rss)

    thread = threading.Thread(target=sample, daemon=True)
    thread.start()
    metrics = []
    now = datetime.now(UTC)
    try:
        with tempfile.TemporaryDirectory() as td:
            for kind in ["jsonl", "syslog", "web", "zeek.conn", "suricata"]:
                path = Path(td) / (kind + ".jsonl")
                db = Path(td) / (kind + ".db")
                with path.open("w") as f:
                    for i in range(events):
                        stamp = iso(now - timedelta(seconds=i % 3600))
                        if kind == "syslog":
                            line = f"<34>1 {stamp} lab app 1 ID - benign-{i}"
                        elif kind == "web":
                            line = f'192.0.2.1 - - [{now.strftime("%d/%b/%Y:%H:%M:%S %z")}] "GET /lab/{i} HTTP/1.1" 200 3 "-" "synthetic"'
                        elif kind == "zeek.conn":
                            line = json.dumps(
                                {
                                    "ts": now.timestamp() - i % 3600,
                                    "id.orig_h": "192.0.2.1",
                                    "id.resp_h": "198.51.100.2",
                                    "id.orig_p": 41000,
                                    "id.resp_p": 80,
                                    "proto": "tcp",
                                    "uid": f"C{i}",
                                }
                            )
                        elif kind == "suricata":
                            line = json.dumps(
                                {
                                    "timestamp": stamp,
                                    "event_type": "flow",
                                    "src_ip": "192.0.2.1",
                                    "dest_ip": "198.51.100.2",
                                    "src_port": 41000,
                                    "dest_port": 80,
                                    "proto": "TCP",
                                    "flow_id": i,
                                }
                            )
                        else:
                            line = json.dumps(
                                {
                                    "timestamp": stamp,
                                    "message": f"benign synthetic event {i}",
                                    "host": "lab",
                                    "source_ip": "192.0.2.1",
                                }
                            )
                        f.write(line + "\n")
                with Store(db) as store:
                    result = ingest(store, path, kind, "benchmark")
                    assert result["accepted"] == events and result["quarantined"] == 0
                    latency = {}
                    query = "SELECT COUNT(*) FROM events WHERE timestamp>=? AND timestamp<?"
                    params = [iso(now - timedelta(seconds=60)), iso(now + timedelta(seconds=1))]

                    def measure(sql: str, p: list[Any]) -> float:
                        timings = []
                        for _ in range(20):
                            start = time.perf_counter()
                            store.bounded(sql, p, seconds=5)
                            timings.append(time.perf_counter() - start)
                        return statistics.median(timings)

                    latency["indexed_seconds"] = measure(query, params)
                    store.db.execute("DROP INDEX ix_time")
                    latency["without_time_index_seconds"] = measure(query, params)
                    store.db.execute("CREATE INDEX ix_time ON events(timestamp)")
                    latency["fts_seconds"] = measure(
                        "SELECT COUNT(*) FROM event_fts WHERE event_fts MATCH ?", ['"synthetic"']
                    )
                    latency["like_seconds"] = measure(
                        "SELECT COUNT(*) FROM events WHERE message LIKE ?", ["%synthetic%"]
                    )
                    store.db.commit()
                    store.db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                    size = db.stat().st_size
                    metrics.append(
                        {
                            "source": kind,
                            "events": events,
                            "events_per_second": result["events_per_second"],
                            "seconds": result["elapsed_seconds"],
                            "database_bytes": size,
                            "bytes_per_million_extrapolated": size / events * 1000000,
                            **latency,
                        }
                    )
    finally:
        stop.set()
        thread.join()
    return {
        "host": platform.platform(),
        "python": platform.python_version(),
        "sqlite": sqlite3.sqlite_version,
        "cpu_logical": psutil.cpu_count(),
        "host_memory_bytes": psutil.virtual_memory().total,
        "peak_sampled_rss_bytes": max(samples + [process.memory_info().rss]),
        "peak_sample_interval_seconds": 0.01,
        "laptop_measurement": False,
        "sources": metrics,
        "limitations": "Finite synthetic batch throughput, not sustained live ingest; no sensors run concurrently. Index is removed only in disposable benchmark DB. Million-event size is extrapolated unless events=1000000.",
    }


def evaluate(output: Path, events: int = 10000) -> dict[str, Any]:
    """Persist reproducible JSON, CSV, matrix, error analysis and a plot."""
    output.mkdir(parents=True, exist_ok=True)
    config = {
        "seed": 42,
        "benchmark_events_per_source": events,
        "noise": 200,
        "repeats": 3,
        "generated_on": iso(datetime.now(UTC)),
        "limits": LIMITS.model_dump(),
    }
    (output / "config.json").write_text(json.dumps(config, indent=2) + "\n")
    parsed = parsing_agreement()
    mutated = fuzz()
    measured = performance(events, output)
    summaries = []
    coverage = []
    error_analysis = []
    with tempfile.TemporaryDirectory() as td:
        tdpath = Path(td)
        truth = generate(tdpath / "synthetic", Path("rules/tests"), noise=200, repeats=3)
        for variant in [
            "full",
            "without_correlation",
            "suricata_only",
            "keyword",
            "group_60s",
            "group_900s",
            "without_linking",
            "with_suppression",
        ]:
            with Store(tdpath / (variant + ".db")) as store:
                write_at = time.monotonic()
                ingest(store, tdpath / "synthetic/events.jsonl", "jsonl", "synthetic")
                rules, report = compile_rules(list(Path("rules/custom").glob("*.yml")), store)
                if any(r["status"] != "compiled" for r in report):
                    raise AssertionError(report)
                if variant != "without_linking":
                    link(store)
                selected = rules
                if variant == "without_correlation":
                    selected = [r for r in rules if not r.correlation]
                if variant == "suricata_only":
                    selected = [r for r in rules if r.name == "suricata_hypothesis"]
                if variant == "keyword":
                    selected = [
                        Rule(
                            "keyword",
                            "keyword",
                            "Naive keyword baseline",
                            "low",
                            [],
                            [
                                (
                                    "SELECT * FROM events WHERE message LIKE ? OR outcome=?",
                                    ["%MINISIEM%", "failure"],
                                )
                            ],
                            {},
                        )
                    ]
                results = run(
                    store,
                    selected,
                    group_seconds=60
                    if variant == "group_60s"
                    else 900
                    if variant == "group_900s"
                    else None,
                )
                if any(r["status"] == "failed" for r in results):
                    raise AssertionError(results)
                row = quality(truth, store, rules, variant)
                row["file_write_to_detection_seconds"] = time.monotonic() - write_at
                row["compile_report"] = report
                row["linked_pairs"] = store.counts()["links"]
                if variant == "with_suppression":
                    # Actual persisted workflow: suppress every low-value single SSH-failure hypothesis.
                    from minisiem.alerts.workflow import transition

                    rid = next(r.id for r in rules if r.name == "ssh_failure")
                    for a in store.db.execute(
                        "SELECT id FROM alerts WHERE rule_id=?", (rid,)
                    ).fetchall():
                        transition(
                            store,
                            a[0],
                            "suppressed",
                            "Synthetic tuning exercise",
                            iso(datetime.now(UTC) + timedelta(hours=1)),
                            "Retain burst correlation rather than single failures",
                        )
                    row["visible_alerts"] = store.db.execute(
                        "SELECT COUNT(*) FROM alerts WHERE status!='suppressed'"
                    ).fetchone()[0]
                else:
                    row["visible_alerts"] = row["alerts"]
                if variant == "keyword":
                    # Identity-independent baseline scenario recall: any positive evidence is a hit.
                    alert_ids = {r[0] for r in store.db.execute("SELECT event_id FROM evidence")}
                    row["recall"] = sum(
                        bool(set(t["event_ids"]) & alert_ids) for t in truth["instances"]
                    ) / len(truth["instances"])
                    row["misses"] = [
                        {
                            "variant": variant,
                            "instance": t["instance"],
                            "rule": t["rule"],
                            "reason": "keyword baseline has no matching keyword/field",
                        }
                        for t in truth["instances"]
                        if not set(t["event_ids"]) & alert_ids
                    ]
                if variant == "suricata_only":
                    row["misses"] = [
                        dict(x, reason="sensor-only baseline excludes non-Suricata scenarios")
                        for x in row["misses"]
                    ]
                summaries.append(row)
                error_analysis.extend(row["misses"])
                if variant == "full":
                    for rule in rules:
                        for tag in rule.tags:
                            coverage.append(
                                {
                                    "rule_id": rule.id,
                                    "rule": rule.name,
                                    "technique": tag,
                                    "exists": True,
                                    "compiled": True,
                                    "evidence_only": bool(
                                        rule.document.get("x-minisiem-evidence-only")
                                    ),
                                    "fired_on_synthetic": rule.id in row["rule_firings"],
                                }
                            )
    result = {
        "parsing": parsed,
        "fuzzing": mutated,
        "performance": measured,
        "detection": summaries,
        "limitations": [
            "Synthetic test data is easier than real telemetry.",
            "One synthetic benign hour does not estimate operational false positives reliably.",
            "Small original-rule suite, no SigmaHQ corpus accuracy claim.",
            "This synthetic run excludes public data; use the separate reviewed evaluate-public command.",
            "Linking adds context; it does not change rule decisions, so that ablation should have identical recall.",
            "Suppression changes visibility, not underlying evidence or classification.",
            "No DuckDB, live capture, distributed system or EVTX.",
        ],
    }
    for name, data in [
        ("results", result),
        ("attack_coverage", coverage),
        ("error_analysis", error_analysis),
    ]:
        (output / (name + ".json")).write_text(json.dumps(data, indent=2) + "\n")
    with (output / "detection.csv").open("w", newline="") as f:
        fields = [
            "variant",
            "precision",
            "recall",
            "alerts",
            "visible_alerts",
            "false_positive_alerts_per_day",
            "file_write_to_detection_seconds",
            "ingest_to_alert_p50_seconds",
            "ingest_to_alert_p95_seconds",
        ]
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(summaries)
    with (output / "performance.csv").open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(measured["sources"][0]))
        writer.writeheader()
        writer.writerows(measured["sources"])
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    fig, ax = plt.subplots(figsize=(10, 5))
    ax.bar([r["variant"] for r in summaries], [r["recall"] for r in summaries])
    ax.set_ylabel("Synthetic scenario recall")
    ax.set_ylim(0, 1.05)
    ax.tick_params(axis="x", rotation=35)
    fig.tight_layout()
    fig.savefig(output / "recall.png")
    plt.close(fig)
    return {
        "output": str(output),
        "fuzzed": mutated["mutated_lines"],
        "synthetic_recall": summaries[0]["recall"],
        "variants": len(summaries),
        "laptop_measurement": False,
    }
