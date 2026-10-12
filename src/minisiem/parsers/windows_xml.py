"""Bounded exported Sysmon XML, distinct from optional binary EVTX parsing."""

import re
import xml.etree.ElementTree as ET
from typing import Any

from minisiem.config import LIMITS

EVENT = re.compile(r"<Event\b[^>]*>.*?</Event>", re.DOTALL)


def split_records(text: str) -> list[str]:
    """Frame a small verified export; accept whitespace and a UTF-8 BOM only."""
    if len(text.encode("utf-8")) > LIMITS.line_bytes:
        raise ValueError("Windows export size limit")
    records = []
    position = 0
    for match in EVENT.finditer(text):
        if text[position : match.start()].strip("\ufeff \t\r\n"):
            raise ValueError("unexpected content outside Event records")
        records.append(match.group())
        position = match.end()
    if text[position:].strip("\ufeff \t\r\n") or not records:
        raise ValueError("incomplete or absent Event records")
    return records


def fields(raw: str) -> dict[str, Any]:
    """Extract fixed System/EventData names with DTD/entity declarations forbidden."""
    if len(raw.encode("utf-8")) > LIMITS.line_bytes:
        raise ValueError("Windows record size limit")
    if re.search(r"<!\s*(?:DOCTYPE|ENTITY)\b", raw, re.IGNORECASE):
        raise ValueError("XML DTD/entity declarations forbidden")
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as exc:
        raise ValueError("invalid exported XML") from exc

    def local(tag: str) -> str:
        return tag.rsplit("}", 1)[-1]

    if local(root.tag) != "Event":
        raise ValueError("Event root required")
    system = next((child for child in root if local(child.tag) == "System"), None)
    data = next((child for child in root if local(child.tag) == "EventData"), None)
    if system is None or data is None:
        raise ValueError("System and EventData required")
    native: dict[str, Any] = {}
    for child in data:
        if local(child.tag) != "Data" or len(child):
            raise ValueError("unsupported EventData child")
        name = child.attrib.get("Name")
        if not name or name in native:
            raise ValueError("unique named EventData fields required")
        native[name] = child.text or ""
    if len(native) > 256:
        raise ValueError("Windows field limit")
    system_fields = {local(child.tag): child for child in system}
    code = system_fields.get("EventID")
    channel = system_fields.get("Channel")
    computer = system_fields.get("Computer")
    created = system_fields.get("TimeCreated")
    if code is None or not code.text or channel is None or not channel.text:
        raise ValueError("EventID and Channel required")
    if channel.text != "Microsoft-Windows-Sysmon/Operational":
        raise ValueError("only exported Sysmon channel supported")
    stamp = created.attrib.get("SystemTime") if created is not None else None
    if not stamp and native.get("UtcTime"):
        # Sysmon explicitly names this field UTC even when its spelling has no offset.
        stamp = str(native["UtcTime"]).replace(" ", "T") + "Z"
    return dict(
        native,
        timestamp=stamp,
        event_code=code.text,
        channel=channel.text,
        host=computer.text if computer is not None else None,
        user=native.get("User"),
        process_name=native.get("Image"),
        command_line=native.get("CommandLine"),
        original_file_name=native.get("OriginalFileName"),
        message="Sysmon event " + code.text,
        dataset="windows.sysmon",
    )
