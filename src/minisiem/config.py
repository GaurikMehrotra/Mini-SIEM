"""Bounded runtime configuration; secrets never enter reports."""

import os
from pathlib import Path

from pydantic import BaseModel, Field


class Limits(BaseModel):
    line_bytes: int = Field(default=65536, ge=1024, le=1048576)
    field_chars: int = Field(default=4096, ge=64, le=65536)
    batch_size: int = Field(default=500, ge=1, le=10000)
    rows: int = Field(default=500, ge=1, le=10000)
    query_seconds: float = Field(default=0.25, gt=0, le=10)
    regex_chars: int = Field(default=256, ge=1, le=1024)
    range_days: int = Field(default=31, ge=1, le=366)
    future_seconds: int = 300
    retention_days: int = Field(default=30, ge=1)
    minimum_disk_bytes: int = 100 * 1024 * 1024
    request_bytes: int = 262144
    requests_per_minute: int = 120
    correlation_seconds: int = 300
    grouping_seconds: int = 300
    late_seconds: int = 600


def configured_limits() -> Limits:
    """Load an optional local YAML override, without touching secret values."""
    import yaml

    selected = os.environ.get("MINISIEM_LIMITS")
    if not selected:
        return Limits()
    path = Path(selected)
    if path.stat().st_size > 65536:
        raise ValueError("limits configuration too large")
    doc = yaml.safe_load(path.read_text())
    if not isinstance(doc, dict) or set(doc) - set(Limits.model_fields):
        raise ValueError("unknown limits configuration fields")
    return Limits.model_validate(doc)


LIMITS = configured_limits()


def data_dir() -> Path:
    """Resolve a user-selected local data directory."""
    return Path(os.environ.get("MINISIEM_DATA", "data"))
