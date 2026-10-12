"""Total, bounded parsers: bad records become quarantine entries."""

import hashlib
import hmac
import ipaddress
import json
import os
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from communityid import CommunityID, FlowTuple

from minisiem.config import LIMITS
from minisiem.models import Event, event_id
from minisiem.timeutil import UTC, timestamp

ANSI = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))")
CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")
WEB = re.compile(
    r'^(\S+) \S+ (\S+) \[([^\]]+)\] "(\S+) ([^" ]+) [^"]+" (\d{3}) (\d+|-) "([^"]*)" "([^"]*)"$'
)
RFC5424 = re.compile(r"^<(\d{1,3})>1 (\S+) (\S+) (\S+) (\S+) (\S+) (.*)$")
RFC3164 = re.compile(
    r"^(?:<\d{1,3}>)?([A-Z][a-z]{2} +\d{1,2} \d{2}:\d{2}:\d{2}) (\S+) ([^:]+): ?(.*)$"
)


@dataclass
class Parsed:
    events: list[Event] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    reason: str | None = None


def clean(value: str) -> str:
    """Strip terminal control characters; CR/LF never create rendered log lines."""
    return CONTROL.sub("", ANSI.sub("", value))[: LIMITS.field_chars]


def sanitize(value: Any, depth: int = 0) -> Any:
    """Bound JSON depth, container sizes, and strings."""
    if depth > 12:
        raise ValueError("maximum JSON depth")
    if isinstance(value, dict):
        if len(value) > 256:
            raise ValueError("maximum object members")
        return {clean(str(k)): sanitize(v, depth + 1) for k, v in value.items()}
    if isinstance(value, list):
        if len(value) > 256:
            raise ValueError("maximum array members")
        return [sanitize(v, depth + 1) for v in value]
    if isinstance(value, str):
        return clean(value)
    if isinstance(value, float) and (value != value or abs(value) == float("inf")):
        raise ValueError("nonfinite number")
    return value


def integer(v: Any) -> int | None:
    return None if v is None or v == "-" else int(v)


def address(v: Any) -> str | None:
    return str(ipaddress.ip_address(v)) if v else None


def normalized(
    d: dict[str, Any],
    source: str,
    dataset: str,
    raw: str,
    now: datetime,
    pseudonym_key: bytes | None,
) -> Event:
    dt, original, zone, warnings = timestamp(
        d.get("timestamp", d.get("@timestamp", d.get("ts"))), now
    )
    p: dict[str, Any] = {}
    mapping = {
        "host": "host",
        "user": "user",
        "source_ip": "source_ip",
        "destination_ip": "destination_ip",
        "source_port": "source_port",
        "destination_port": "destination_port",
        "transport": "transport",
        "community_id": "community_id",
        "message": "message",
        "action": "action",
        "outcome": "outcome",
        "process_name": "process_name",
        "command_line": "command_line",
        "dns_question": "dns_question",
        "http_url": "http_url",
        "http_status": "http_status",
        "tls_server_name": "tls_server_name",
        "event_code": "event_code",
        "channel": "channel",
        "original_file_name": "original_file_name",
    }
    for key, col in mapping.items():
        if key in d:
            p[col] = d[key]
    for col in ("source_ip", "destination_ip"):
        p[col] = address(p.get(col))
    for col in ("source_port", "destination_port", "http_status"):
        p[col] = integer(p.get(col))
    for col in ("source_port", "destination_port"):
        if p[col] is not None and not 0 <= p[col] <= 65535:
            raise ValueError("port out of range")
    if not p.get("community_id") and all(
        p.get(k) is not None
        for k in ("source_ip", "destination_ip", "source_port", "destination_port", "transport")
    ):
        protocols = {"tcp": 6, "udp": 17}
        if p["transport"] in protocols:
            p["community_id"] = CommunityID().calc(
                FlowTuple(
                    protocols[p["transport"]],
                    p["source_ip"],
                    p["destination_ip"],
                    p["source_port"],
                    p["destination_port"],
                )
            )
    fields = sanitize(d)
    # Pseudonym mode is irreversible: raw, message and unmapped fields may contain identifiers.
    # Preserve raw only in normal synthetic/lab mode; privacy mode explicitly redacts it.
    if pseudonym_key:
        for col in ("host", "user", "source_ip", "destination_ip"):
            if p.get(col):
                p[col] = (
                    "anon-"
                    + hmac.new(pseudonym_key, str(p[col]).encode(), hashlib.sha256).hexdigest()[:24]
                )
        p["community_id"] = None
        p["message"] = "[redacted in pseudonym mode]"
        p["command_line"] = p["http_url"] = p["dns_question"] = p["tls_server_name"] = None
        fields = {"privacy": "unmapped fields redacted"}
        warnings.append("pseudonymized_raw_redacted")
    return Event(
        id=event_id(source, raw),
        timestamp=dt,
        original_timestamp=original,
        original_timezone=zone,
        ingested_at=now,
        source=source,
        dataset=dataset,
        raw="[redacted in pseudonym mode]" if pseudonym_key else raw,
        fields=fields,
        warnings=warnings,
        **p,
    )


def parse(
    line: str,
    kind: str = "jsonl",
    source: str = "local",
    *,
    now: datetime | None = None,
    pseudonym_key: bytes | None = None,
) -> Parsed:
    """Never raises on malformed log content. Source identity is configured by operator."""
    now = now or datetime.now(UTC)
    try:
        if len(line.encode("utf-8", "surrogatepass")) > LIMITS.line_bytes:
            return Parsed(reason="line exceeds byte limit")
        # Reject known application secrets before storing raw, normalized or quarantine data.
        for secret_name in ("MINISIEM_API_KEY", "MINISIEM_PSEUDONYM_KEY"):
            secret_value = os.environ.get(secret_name)
            if secret_value and secret_value in line:
                return Parsed(reason="credential content rejected")
        raw = line.rstrip("\r\n")
        if kind == "syslog":
            m = RFC5424.match(raw)
            if m:
                _, ts, host, app, pid, msgid, tail = m.groups()
                # Basic RFC5424 SD parser: honor quoted escapes and brackets.
                if tail.startswith("- "):
                    msg = tail[2:]
                elif tail.startswith("["):
                    pos = 0
                    while pos < len(tail) and tail[pos] == "[":
                        quoted = False
                        escaped = False
                        end = pos + 1
                        while end < len(tail):
                            c = tail[end]
                            if escaped:
                                escaped = False
                            elif c == "\\":
                                escaped = True
                            elif c == '"':
                                quoted = not quoted
                            elif c == "]" and not quoted:
                                break
                            end += 1
                        if end == len(tail):
                            raise ValueError("malformed structured data")
                        pos = end + 1
                    msg = tail[pos:].lstrip()
                elif tail == "-":
                    msg = ""
                else:
                    raise ValueError("malformed structured data")
                d = {
                    "timestamp": ts,
                    "host": host,
                    "message": msg,
                    "app": app,
                    "pid": pid,
                    "event_code": msgid,
                }
            else:
                m = RFC3164.match(raw)
                if not m:
                    raise ValueError("invalid syslog basics")
                ts, host, app, msg = m.groups()
                dt = datetime.strptime(f"{now.year} {ts}", "%Y %b %d %H:%M:%S").replace(tzinfo=UTC)
                d = {
                    "timestamp": dt.isoformat(),
                    "host": host,
                    "app": app,
                    "message": msg,
                    "timestamp_inferred": "year and UTC",
                }
            if "Failed password" in d["message"]:
                d.update(action="ssh_login", outcome="failure")
            if "Accepted " in d["message"]:
                d.update(action="ssh_login", outcome="success")
            dataset = "syslog"
        elif kind == "web":
            m = WEB.match(raw)
            if not m:
                raise ValueError("invalid combined access log")
            ip, user, ts, method, url, status, size, ref, agent = m.groups()
            dt = datetime.strptime(ts, "%d/%b/%Y:%H:%M:%S %z")
            d = {
                "timestamp": dt.isoformat(),
                "source_ip": ip,
                "user": None if user == "-" else user,
                "http_url": url,
                "http_status": int(status),
                "message": method + " " + url,
                "method": method,
                "bytes": size,
                "referrer": ref,
                "user_agent": agent,
            }
            dataset = "web.access"
        elif kind == "windows_xml":
            from minisiem.parsers.windows_xml import fields

            d = fields(raw)
            dataset = "windows.sysmon"
        else:
            obj = json.loads(
                raw, parse_constant=lambda v: (_ for _ in ()).throw(ValueError("nonfinite JSON"))
            )
            if not isinstance(obj, dict):
                raise ValueError("JSON record must be an object")
            d = sanitize(obj)
            aliases = {
                "@timestamp": "timestamp",
                "host.name": "host",
                "user.name": "user",
                "source.ip": "source_ip",
                "destination.ip": "destination_ip",
                "process.name": "process_name",
                "process.command_line": "command_line",
                "event.code": "event_code",
                "winlog.channel": "channel",
                "Image": "process_name",
                "CommandLine": "command_line",
                "EventID": "event_code",
                "Channel": "channel",
                "OriginalFileName": "original_file_name",
                "process.pe.original_file_name": "original_file_name",
            }
            for original_key, mapped_key in aliases.items():
                if original_key in d:
                    d[mapped_key] = (
                        str(d[original_key]) if mapped_key == "event_code" else d[original_key]
                    )
            dataset = str(d.get("dataset", "generic"))
            if kind.startswith("zeek"):
                dataset = "zeek." + (
                    kind.split(".", 1)[1] if "." in kind else str(d.get("_path", "conn"))
                )
                d.update(
                    source_ip=d.get("id.orig_h"),
                    destination_ip=d.get("id.resp_h"),
                    source_port=d.get("id.orig_p"),
                    destination_port=d.get("id.resp_p"),
                    transport=d.get("proto", "tcp"),
                    community_id=d.get("community_id"),
                    dns_question=d.get("query"),
                    http_url=d.get("uri"),
                    http_status=d.get("status_code"),
                    tls_server_name=d.get("server_name"),
                    action=d.get("note"),
                    message=d.get("msg", str(d.get("uid", "Zeek event"))),
                )
            elif kind == "suricata":
                event_type = str(d.get("event_type", "unknown"))
                dataset = "suricata." + event_type
                alert = d.get("alert", {})
                http = d.get("http", {})
                tls = d.get("tls", {})
                dns = d.get("dns", {})
                for part in (alert, http, tls, dns):
                    if not isinstance(part, dict):
                        raise ValueError("nested sensor field must be an object")
                queries = dns.get("queries", [])
                query = (
                    queries[0].get("rrname")
                    if queries and isinstance(queries[0], dict)
                    else dns.get("rrname")
                )
                d.update(
                    source_ip=d.get("src_ip"),
                    destination_ip=d.get("dest_ip"),
                    source_port=d.get("src_port"),
                    destination_port=d.get("dest_port"),
                    transport=str(d.get("proto", "tcp")).lower(),
                    message=alert.get("signature", event_type),
                    action=alert.get("action"),
                    event_code=str(alert.get("signature_id", "")),
                    http_url=http.get("url"),
                    http_status=http.get("status"),
                    tls_server_name=tls.get("sni"),
                    dns_question=query,
                )
            elif kind != "jsonl":
                raise ValueError("unsupported parser; optional EVTX not installed")
        d = sanitize(d)
        e = normalized(d, source, dataset, raw, now, pseudonym_key)
        if kind == "syslog" and "timestamp_inferred" in d:
            e.warnings.append("RFC3164_year_and_timezone_assumed")
        return Parsed([e], e.warnings)
    except (
        ValueError,
        TypeError,
        KeyError,
        AttributeError,
        IndexError,
        OverflowError,
        RecursionError,
        OSError,
    ) as exc:
        # Error descriptions never include raw text or secrets.
        return Parsed(reason="invalid " + kind + " record: " + type(exc).__name__)
