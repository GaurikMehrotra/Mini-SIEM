"""ECS-inspired names are flattened for storage, never presented as full ECS."""

import hashlib
import json
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from minisiem.timeutil import iso


class Event(BaseModel):
    id: str
    timestamp: datetime
    original_timestamp: str = ""
    original_timezone: str = ""
    ingested_at: datetime
    source: str
    dataset: str
    host: str | None = None
    user: str | None = None
    source_ip: str | None = None
    source_port: int | None = None
    destination_ip: str | None = None
    destination_port: int | None = None
    transport: str | None = None
    community_id: str | None = None
    message: str = ""
    action: str | None = None
    outcome: str | None = None
    process_name: str | None = None
    command_line: str | None = None
    dns_question: str | None = None
    http_url: str | None = None
    http_status: int | None = None
    tls_server_name: str | None = None
    event_code: str | None = None
    channel: str | None = None
    original_file_name: str | None = None
    fields: dict[str, Any] = Field(default_factory=dict)
    raw: str
    warnings: list[str] = Field(default_factory=list)

    def sql_values(self) -> dict[str, Any]:
        """Serialize only the fixed schema's values."""
        d = self.model_dump()
        d["timestamp"] = iso(self.timestamp)
        d["ingested_at"] = iso(self.ingested_at)
        d["fields"] = json.dumps(self.fields, ensure_ascii=True, allow_nan=False)
        d["warnings"] = json.dumps(self.warnings)
        return d


def event_id(source: str, raw: str) -> str:
    """Exact source + raw bytes identity; replay never changes it."""
    return hashlib.sha256((source + "\0" + raw).encode("utf-8", "surrogatepass")).hexdigest()
