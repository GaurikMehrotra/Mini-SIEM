"""Optional local enrichment; never fetch an IOC URL or probe an asset."""

from pathlib import Path
from typing import Any

import yaml


def load(path: Path) -> dict[str, Any]:
    if path.stat().st_size > 1048576:
        raise ValueError("enrichment file size limit")
    d = yaml.safe_load(path.read_text())
    if not isinstance(d, dict):
        raise ValueError("mapping required")
    return d


def enrich(
    event: dict[str, Any], assets: dict[str, Any], iocs: dict[str, Any], findings: dict[str, Any]
) -> dict[str, Any]:
    """Annotate only with explicitly supplied local metadata."""
    ips = [event.get("source_ip"), event.get("destination_ip")]
    return {
        "assets": [assets[x] for x in ips if x in assets],
        "ioc_matches": [x for x in ips + [event.get("dns_question")] if x and x in iocs],
        "vulnerability_findings": [findings[x] for x in ips if x in findings],
    }
