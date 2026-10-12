import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from test_store import make

from minisiem.search.compile import Parser, compile_query, csv_cell
from minisiem.store.db import Store

START = "2025-01-01T00:00:00Z"
END = "2025-01-02T00:00:00Z"


def test_parameters():
    payload = "' OR 1=1; DROP TABLE events --"
    import json

    sql, p = compile_query("message = " + json.dumps(payload), START, END)
    assert payload not in sql and p[0] == payload
    with pytest.raises(ValueError):
        Parser('host = "x"; DELETE FROM events').run()
    with pytest.raises(ValueError):
        compile_query("", START, "2026-01-01T00:00:00Z")
    assert csv_cell("  =1+1").startswith("'")


@given(st.text(max_size=300))
@settings(max_examples=300, deadline=None)
def test_query_fuzz(s):
    try:
        sql, p = Parser(s).run()
        assert ";" not in sql
    except ValueError:
        pass


def test_fts_and_null_negation(tmp_path):
    from minisiem.timeutil import timestamp

    e = make("hello lab")
    e.timestamp = timestamp(START)[0]
    with Store(tmp_path / "s.db") as s:
        with s.transaction():
            s.insert([e])
        sql, p = compile_query('NOT host = "other"', START, END, fts="hello")
        assert len(s.bounded(sql, p)) == 1
