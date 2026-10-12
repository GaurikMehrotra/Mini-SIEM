from pathlib import Path

import pytest

from minisiem.detect.rule_tests import test_cases as run_cases

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize(
    "rule", sorted((ROOT / "rules/custom").glob("*.yml")), ids=lambda p: p.stem
)
def test_custom_rule(rule):
    outcome = run_cases(rule, ROOT / "rules/tests" / (rule.stem + ".json"))
    assert outcome["passed"] == outcome["total"] and outcome["total"] >= 2
