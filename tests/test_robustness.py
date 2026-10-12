import json

from test_detection import RULE
from test_store import make

from minisiem.config import LIMITS
from minisiem.detect.runner import run
from minisiem.detect.sigma_loader import compile_rules
from minisiem.parsers.registry import parse
from minisiem.store.db import Store


def test_microbatch_watermark_replay_and_retention(tmp_path):
    path = tmp_path / "rule.yml"
    path.write_text(RULE)
    with Store(tmp_path / "s.db") as store:
        with store.transaction():
            store.insert([make("test " + str(i)) for i in range(LIMITS.batch_size + 3)])
        rules, _ = compile_rules([path], store)
        assert run(store, rules)[0]["hits"] == LIMITS.batch_size
        assert run(store, rules)[0]["hits"] == 3
        assert run(store, rules) == []
        before = store.db.execute("SELECT COUNT(*) FROM evidence").fetchone()[0]
        with store.transaction():
            store.insert([make("test " + str(i)) for i in range(3)])
        assert run(store, rules) == []
        assert store.db.execute("SELECT COUNT(*) FROM evidence").fetchone()[0] == before
        store.retain("2099-01-01T00:00:00+00:00")
        with store.transaction():
            store.insert([make("test fresh")])
        assert run(store, rules)[0]["hits"] == 1


def test_redos_rejected_and_clock_skew():
    from minisiem.store.db import regexp

    assert regexp("(a+)+$", "a" * 4000 + "!") == 0
    assert parse(json.dumps({"timestamp": "2099-01-01T00:00:00Z"})).warnings == ["future_timestamp"]
    assert parse(json.dumps({"timestamp": "not-a-time"})).warnings
