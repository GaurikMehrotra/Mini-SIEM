"""Local joins annotate evidence without opening destinations."""

from minisiem.enrich.local import enrich, load


def test_local_enrichment(tmp_path):
    assets = {"192.0.2.1": {"criticality": "high"}}
    iocs = {"example.invalid": {"confidence": "low"}}
    findings = {"192.0.2.1": {"findings": ["synthetic finding"]}}
    event = {"source_ip": "192.0.2.1", "dns_question": "example.invalid"}
    result = enrich(event, assets, iocs, findings)
    assert result["assets"] == [{"criticality": "high"}]
    assert result["ioc_matches"] == ["example.invalid"]
    assert result["vulnerability_findings"] == [findings["192.0.2.1"]]
    path = tmp_path / "assets.yaml"
    path.write_text("192.0.2.1: {criticality: high}\n")
    assert load(path) == assets
