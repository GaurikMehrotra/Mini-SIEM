from pathlib import Path

from minisiem.evaluation import fuzz, parsing_agreement
from minisiem.simulate.scenarios import generate


def test_fixed_seed_fuzz_and_reference():
    result = fuzz(count=10000)
    assert result["mutated_lines"] == 10000 and result["uncaught_exceptions"] == 0
    assert result["accepted"] + result["quarantined"] == 10000
    assert parsing_agreement()["agreement"] == 1


def test_generator_repeatable(tmp_path):
    from datetime import datetime

    from minisiem.timeutil import UTC

    now = datetime(2025, 1, 1, tzinfo=UTC)
    a = generate(tmp_path / "a", Path("rules/tests"), now=now)
    b = generate(tmp_path / "b", Path("rules/tests"), now=now)
    assert (
        a == b
        and (tmp_path / "a/events.jsonl").read_bytes() == (tmp_path / "b/events.jsonl").read_bytes()
    )
