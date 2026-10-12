"""Pinned, checksum-verified public lab telemetry and scientifically bounded evaluation."""

import csv
import hashlib
import json
import subprocess
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any

import yaml

from minisiem.config import LIMITS
from minisiem.detect.runner import run
from minisiem.detect.sigma_loader import compile_rules
from minisiem.parsers.registry import parse
from minisiem.parsers.windows_xml import split_records
from minisiem.store.db import Store

MANIFEST_PATH = Path("configs/public_dataset.json")


def manifest(path: Path = MANIFEST_PATH) -> dict[str, Any]:
    """Validate only the reviewed source; no arbitrary log-supplied download URL."""
    document = json.loads(path.read_text())
    if (
        document["repository"] != "https://github.com/splunk/attack_data.git"
        or document["commit"] != "4389fa7a4e74a7c083c0fbe448fa2c7c32378981"
    ):
        raise ValueError("public source differs from reviewed release")
    names = set()
    for case in document["cases"]:
        for file in case["files"]:
            if file["bytes"] > LIMITS.line_bytes or Path(file["path"]).name in names:
                raise ValueError("public fixture size or basename ambiguity")
            names.add(Path(file["path"]).name)
    return document


def verify(path: Path, expected: dict[str, Any]) -> None:
    """Never consume a partial download or silently replace an expected checksum."""
    if path.stat().st_size != expected["bytes"]:
        raise ValueError("public sample size mismatch")
    if hashlib.sha256(path.read_bytes()).hexdigest() != expected["sha256"]:
        raise ValueError("public sample SHA256 mismatch")


def fetch(destination: Path, document: dict[str, Any]) -> None:
    """Fetch three static exports only. Git LFS smudge avoids corpus-wide scanning."""
    destination.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="minisiem-public-") as td:
        checkout = Path(td) / "catalog"
        subprocess.run(
            [
                "git",
                "clone",
                "--depth",
                "1",
                "--filter=blob:none",
                "--no-checkout",
                document["repository"],
                str(checkout),
            ],
            check=True,
            timeout=120,
            capture_output=True,
        )
        # HEAD can advance; fetch and read the reviewed commit, never substitute a new one.
        subprocess.run(
            ["git", "-C", str(checkout), "fetch", "--depth", "1", "origin", document["commit"]],
            check=True,
            timeout=120,
            capture_output=True,
        )

        def blob(path: str) -> bytes:
            return subprocess.check_output(
                ["git", "-C", str(checkout), "show", document["commit"] + ":" + path], timeout=60
            )

        license_text = blob(document["license_path"])
        if b"Apache License" not in license_text or b"Version 2.0" not in license_text:
            raise ValueError("reviewed Apache license not present")
        (destination / "LICENSE.upstream.txt").write_bytes(license_text)
        for case in document["cases"]:
            metadata = blob(case["metadata_path"])
            obj = yaml.safe_load(metadata)
            if (
                obj["id"] != case["metadata_id"]
                or obj["environment"] != "attack_range"
                or obj["mitre_technique"] != case["techniques"]
            ):
                raise ValueError("public lab provenance/labels differ from reviewed metadata")
            (destination / (case["name"] + ".metadata.yaml")).write_bytes(metadata)
            for file in case["files"]:
                target = destination / Path(file["path"]).name
                if target.exists():
                    verify(target, file)
                    continue
                pointer = blob(file["path"])
                if ("oid sha256:" + file["sha256"]).encode() not in pointer or (
                    "size " + str(file["bytes"])
                ).encode() not in pointer:
                    raise ValueError("pinned Git LFS pointer differs from manifest")
                data = subprocess.check_output(
                    [
                        "git",
                        "-C",
                        str(checkout),
                        "-c",
                        "lfs.dialtimeout=15",
                        "-c",
                        "lfs.activitytimeout=15",
                        "lfs",
                        "smudge",
                    ],
                    input=pointer,
                    timeout=60,
                    stderr=subprocess.DEVNULL,
                )
                temporary = target.with_suffix(".download")
                temporary.write_bytes(data)
                try:
                    verify(temporary, file)
                    temporary.replace(target)
                finally:
                    temporary.unlink(missing_ok=True)
        (destination / "manifest.json").write_text(json.dumps(document, indent=2) + "\n")


def evaluate_public(destination: Path, output: Path, download: bool = True) -> dict[str, Any]:
    """Scenario-level technique recovery, with event precision/FPR explicitly unknown."""
    document = manifest()
    if download:
        fetch(destination, document)
    output.mkdir(parents=True, exist_ok=True)
    cases = []
    source_codes: Counter[str] = Counter()
    misses = []
    with tempfile.TemporaryDirectory(prefix="minisiem-public-eval-") as td:
        for case in document["cases"]:
            with Store(Path(td) / (case["name"] + ".db")) as store:
                input_records = duplicates = quarantined = accepted = 0
                agreement = 0
                checked = 0
                source = "public:splunk:" + case["name"]
                records = []
                for file in case["files"]:
                    path = destination / Path(file["path"]).name
                    verify(path, file)
                    for raw in split_records(path.read_text(encoding="utf-8-sig")):
                        input_records += 1
                        parsed = parse(raw, "windows_xml", source)
                        if parsed.reason:
                            quarantined += 1
                            # Retain bounded raw/reason only in an ignored/disposable database.
                            with store.transaction():
                                store.db.execute(
                                    "INSERT INTO quarantine(source,raw,reason,created_at) VALUES(?,?,?,?)",
                                    (source, raw, parsed.reason, "2026-10-12T00:00:00+00:00"),
                                )
                            continue
                        event = parsed.events[0]
                        source_codes[str(event.event_code)] += 1
                        # Invariants from the publisher's selected exported Sysmon records.
                        checked += 2
                        agreement += int(
                            event.channel == "Microsoft-Windows-Sysmon/Operational"
                        ) + int(event.event_code == "1")
                        with store.transaction():
                            n = store.insert(parsed.events)
                        accepted += n
                        duplicates += 1 - n
                        records.append(event)
                rules, report = compile_rules(list(Path("rules/custom").glob("*.yml")), store)
                if any(item["status"] != "compiled" for item in report):
                    raise ValueError("public evaluation rule compilation failed")
                diagnostics = []
                while True:
                    batch = run(store, rules)
                    diagnostics.extend(batch)
                    if not batch or any(item["status"] == "failed" for item in batch):
                        break
                failures = [item for item in diagnostics if item["status"] == "failed"]
                if failures:
                    raise ValueError("public evaluation bounded runner failed")
                by_id = {rule.id: rule for rule in rules}
                fired = [dict(row) for row in store.db.execute("SELECT rule_id,count FROM alerts")]
                fired_names = sorted({by_id[row["rule_id"]].name for row in fired})
                recovered = bool(set(case["expected_relevant_rules"]) & set(fired_names))
                if not recovered:
                    misses.append(
                        {
                            "case": case["name"],
                            "reason": "No expected technique-relevant rule fired; inspect channel/field mapping or rule applicability.",
                            "expected_rules": case["expected_relevant_rules"],
                        }
                    )
                # Replay must not add evidence or advance alert volume.
                with store.transaction():
                    replay = store.insert(records)
                if replay or run(store, rules):
                    raise AssertionError("public-data replay was not idempotent")
                cases.append(
                    {
                        "case": case["name"],
                        "upstream_metadata_id": case["metadata_id"],
                        "author": case["author"],
                        "techniques": case["techniques"],
                        "input_records": input_records,
                        "unique_events": accepted,
                        "duplicates": duplicates,
                        "quarantined": quarantined,
                        "field_invariants_checked": checked,
                        "field_invariants_agree": agreement,
                        "expected_relevant_rules": case["expected_relevant_rules"],
                        "fired_rules": fired_names,
                        "scenario_recovered": recovered,
                        "grouped_alerts": len(fired),
                        "unique_evidence_events": store.db.execute(
                            "SELECT COUNT(DISTINCT event_id) FROM evidence"
                        ).fetchone()[0],
                        "replay_verified": True,
                        "compile_report": report,
                    }
                )
    result = {
        "dataset": document,
        "cases": cases,
        "records_total": sum(c["input_records"] for c in cases),
        "scenarios_total": len(cases),
        "scenarios_recovered": sum(c["scenario_recovered"] for c in cases),
        "scenario_recovery_fraction": sum(c["scenario_recovered"] for c in cases) / len(cases),
        "input_event_codes": dict(source_codes),
        "event_precision": None,
        "event_recall": None,
        "false_positive_alerts_per_day": None,
        "time_to_detect": None,
        "misses": misses,
        "limitations": [
            "The publisher labels lab scenarios/techniques, not each event as malicious or benign.",
            "PowerShell process presence is a broad hypothesis, not proof of malicious encoded or RemoteSigned execution.",
            "No event-level precision, recall, false-positive/day or real-time time-to-detect can be inferred.",
            "Eight input records across two scenarios are a narrow parsing/applicability demonstration, not broad generalization.",
            "The two encoded exports overlap; source/raw ID deduplication accounts for that overlap.",
            "Non-Windows rules are out of scope for these samples; no SSH, DNS, Zeek, or Suricata public recall claim.",
        ],
    }
    (output / "public_results.json").write_text(json.dumps(result, indent=2) + "\n")
    (output / "public_error_analysis.json").write_text(json.dumps(misses, indent=2) + "\n")
    with (output / "public_cases.csv").open("w", newline="") as file:
        columns = [
            "case",
            "input_records",
            "unique_events",
            "duplicates",
            "quarantined",
            "scenario_recovered",
            "grouped_alerts",
            "unique_evidence_events",
        ]
        writer = csv.DictWriter(file, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(cases)
    (output / "public_config.json").write_text(
        json.dumps(
            {"limits": LIMITS.model_dump(), "manifest": document, "download_enabled": download},
            indent=2,
        )
        + "\n"
    )
    return {
        "output": str(output),
        "records": result["records_total"],
        "scenarios_recovered": result["scenarios_recovered"],
        "scenarios": len(cases),
        "event_precision": "unavailable: scenario labels only",
    }
