"""Synthetic exported XML only: these tests never fetch public telemetry or run Docker."""

import hashlib
import json

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from minisiem.parsers.registry import parse
from minisiem.parsers.windows_xml import split_records
from minisiem.public_data import evaluate_public, verify

XML = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>1</EventID><TimeCreated SystemTime="2025-01-01T00:00:00Z"/><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>synthetic-lab</Computer></System><EventData><Data Name="Image">C:\\Windows\\powershell.exe</Data><Data Name="User">synthetic-alice</Data><Data Name="CommandLine">powershell.exe -NoProfile</Data><Data Name="OriginalFileName">PowerShell.EXE</Data></EventData></Event>"""


def test_windows_export_normalizes_and_keeps_raw():
    parsed = parse(XML, "windows_xml", "synthetic-xml")
    assert not parsed.reason
    event = parsed.events[0]
    assert event.raw == XML and event.dataset == "windows.sysmon"
    assert event.host == "synthetic-lab" and event.user == "synthetic-alice"
    assert (
        event.process_name is not None
        and event.process_name.endswith("powershell.exe")
        and event.event_code == "1"
    )
    assert event.timestamp.year == 2025 and event.original_timezone == "UTC"
    assert split_records(XML + "\n\n" + XML) == [XML, XML]


def test_xml_entity_invalid_framing_and_duplicates_rejected():
    assert parse('<!DOCTYPE Event [<!ENTITY x "bad">]>' + XML, "windows_xml").reason
    assert parse(XML.replace("</Event>", ""), "windows_xml").reason
    assert parse(
        XML.replace("Microsoft-Windows-Sysmon/Operational", "Unsupported"), "windows_xml"
    ).reason
    assert parse(
        XML.replace("</EventData>", '<Data Name="Image">x</Data></EventData>'), "windows_xml"
    ).reason
    with pytest.raises(ValueError):
        split_records("junk" + XML)
    with pytest.raises(ValueError):
        split_records(XML[:-8])
    with pytest.raises(ValueError):
        split_records("x" * 65537)


@given(st.text(max_size=2048))
@settings(max_examples=200, deadline=None)
def test_exported_xml_parser_total(text):
    result = parse(text, "windows_xml")
    assert result.reason or result.events


def test_checksum_guards(tmp_path):
    path = tmp_path / "input.log"
    path.write_bytes(b"abc")
    expected = {"bytes": 3, "sha256": hashlib.sha256(b"abc").hexdigest()}
    verify(path, expected)
    path.write_bytes(b"abd")
    with pytest.raises(ValueError):
        verify(path, expected)
    path.write_bytes(b"abcde")
    with pytest.raises(ValueError):
        verify(path, expected)


def test_public_evaluation_uses_scenario_labels_without_inventing_precision(tmp_path, monkeypatch):
    # Replace only manifest lookup with an original synthetic case; no upstream fixture is committed.
    document = {
        "name": "synthetic adapter test",
        "cases": [
            {
                "name": "synthetic-case",
                "metadata_id": "test-case",
                "author": "Synthetic fixture",
                "techniques": ["T1059.001"],
                "expected_relevant_rules": ["process_shell"],
                "files": [
                    {
                        "path": "synthetic.log",
                        "bytes": len(XML.encode()),
                        "sha256": hashlib.sha256(XML.encode()).hexdigest(),
                    }
                ],
            }
        ],
    }
    monkeypatch.setattr("minisiem.public_data.manifest", lambda: document)
    (tmp_path / "synthetic.log").write_text(XML)
    summary = evaluate_public(tmp_path, tmp_path / "results", download=False)
    assert summary["scenarios_recovered"] == 1
    report = json.loads((tmp_path / "results/public_results.json").read_text())
    assert report["event_precision"] is None and report["event_recall"] is None
    assert report["false_positive_alerts_per_day"] is None and report["time_to_detect"] is None
    assert report["cases"][0]["replay_verified"]
    assert report["cases"][0]["field_invariants_agree"] == 2
    assert report["cases"][0]["grouped_alerts"] == 1
