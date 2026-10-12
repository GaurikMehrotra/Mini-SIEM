"""The detection harness exists before original rule authoring."""

import json
from pathlib import Path
from tempfile import TemporaryDirectory

from minisiem.detect.sigma_loader import compile_rules
from minisiem.parsers.registry import parse
from minisiem.store.db import Store


def test_cases(rule_path: Path, cases_path: Path) -> dict[str, int]:
    """Each case has synthetic records and an exact expected set of rule names."""
    from minisiem.detect.runner import run

    passed = 0
    cases = json.loads(cases_path.read_text())
    if not cases:
        raise ValueError("empty detection test file")
    for case in cases:
        with TemporaryDirectory() as td, Store(Path(td) / "test.db") as store:
            for record in case["records"]:
                result = parse(json.dumps(record), "jsonl", "rule-test")
                if result.reason:
                    raise AssertionError(result.reason)
                with store.transaction():
                    store.insert(result.events)
            rules, report = compile_rules([rule_path], store)
            if any(r["status"] != "compiled" for r in report):
                raise AssertionError(report)
            run(store, rules)
            fired = {r[0] for r in store.db.execute("SELECT DISTINCT rule_id FROM alerts")}
            expected = {r.id for r in rules if r.name in case["expected"]}
            if fired != expected:
                raise AssertionError(
                    {"case": case["name"], "expected": sorted(expected), "actual": sorted(fired)}
                )
            passed += 1
    return {"passed": passed, "total": len(cases)}
