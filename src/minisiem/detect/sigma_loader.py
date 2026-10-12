"""Safe YAML, validated fields, real pySigma compilation, explicit coverage."""

import copy
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, cast

import re2
import yaml
from sigma.backends.sqlite import sqliteBackend
from sigma.collection import SigmaCollection
from sigma.pipelines.sysmon import sysmon_pipeline
from sigma.pipelines.windows import windows_logsource_pipeline
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import (
    AddConditionTransformation,
    FieldMappingTransformation,
    SetStateTransformation,
)

from minisiem.config import LIMITS
from minisiem.search.compile import FIELDS
from minisiem.store.db import Store

MAP: dict[str | None, str | list[str]] = {
    "Image": "process_name",
    "CommandLine": "command_line",
    "EventID": "event_code",
    "Channel": "channel",
    "OriginalFileName": "original_file_name",
    "Computer": "host",
    "User": "user",
    "SourceIp": "source_ip",
    "DestinationIp": "destination_ip",
    "DestinationPort": "destination_port",
    "SourcePort": "source_port",
    "query": "dns_question",
    "uri": "http_url",
    "status_code": "http_status",
    "note": "action",
    "signature": "message",
    "id.orig_h": "source_ip",
    "id.resp_h": "destination_ip",
    "id.resp_p": "destination_port",
    "id.orig_p": "source_port",
}
DATASETS = {
    "ssh": "syslog",
    "conn": "zeek.conn",
    "dns": "zeek.dns",
    "http": "zeek.http",
    "ssl": "zeek.ssl",
    "notice": "zeek.notice",
    "suricata": "suricata.alert",
    "web": "web.access",
    "process_creation": "windows.sysmon",
    "generic": "generic",
}
MODIFIERS = frozenset(
    {
        "contains",
        "startswith",
        "endswith",
        "all",
        "re",
        "cidr",
        "cased",
        "exists",
        "gt",
        "gte",
        "lt",
        "lte",
        "fieldref",
        "base64",
        "base64offset",
        "wide",
        "utf16",
        "utf16le",
        "utf16be",
        "windash",
    }
)


class NotApplicable(ValueError):
    """The selected normalized schema cannot represent this rule."""


@dataclass
class Rule:
    id: str
    name: str
    title: str
    level: str
    tags: list[str]
    queries: list[tuple[str, list[Any]]]
    document: dict[str, Any]
    correlation: dict[str, Any] | None = None
    dependencies: list[str] = field(default_factory=list)


def parameterize(sql: str) -> tuple[str, list[Any]]:
    """Bind converter-generated SQL literals; SQL never comes from API/logs."""
    out = []
    params: list[Any] = []
    i = 0
    while i < len(sql):
        c = sql[i]
        if c == "'":
            i += 1
            value = ""
            while i < len(sql):
                if sql[i] == "'":
                    if i + 1 < len(sql) and sql[i + 1] == "'":
                        value += "'"
                        i += 2
                        continue
                    i += 1
                    break
                value += sql[i]
                i += 1
            else:
                raise ValueError("unterminated compiled SQL literal")
            out.append("?")
            params.append(value)
        elif c == "`":
            j = sql.find("`", i + 1)
            if j < 0 or (
                sql[i + 1 : j] not in FIELDS | {"channel", "original_file_name", "rowid"}
                and not re.fullmatch(r"g[0-9]+", sql[i + 1 : j])
            ):
                raise ValueError("unsafe SQL identifier")
            out.append(sql[i : j + 1])
            i = j + 1
        elif c.isdigit() and (i == 0 or not (sql[i - 1].isalnum() or sql[i - 1] == "_")):
            match = re.match(r"\d+(?:\.\d*)?(?:[eE][+-]?\d+)?", sql[i:])
            if match is None:
                raise ValueError("invalid compiled number")
            num = match.group()
            params.append(float(num) if any(c in num for c in ".eE") else int(num))
            out.append("?")
            i += len(num)
        else:
            out.append(c)
            i += 1
    return "".join(out), params


def yaml_documents(text: str) -> list[dict[str, Any]]:
    """Disallow anchors, aliases, unsafe tags and excessive expansion."""
    if len(text.encode()) > 262144:
        raise ValueError("rule file too large")
    tokens = list(yaml.scan(text))
    if len(tokens) > 10000:
        raise ValueError("too many YAML tokens")
    if any(
        isinstance(t, (yaml.tokens.AliasToken, yaml.tokens.AnchorToken, yaml.tokens.TagToken))
        for t in tokens
    ):
        raise ValueError("YAML aliases/anchors/tags disabled")
    docs = list(yaml.safe_load_all(text))
    if not docs or len(docs) > 64 or any(not isinstance(d, dict) for d in docs):
        raise ValueError("rule documents required")
    return docs


def check_selection(value: Any, depth: int = 0) -> None:
    if depth > 12:
        raise ValueError("rule nesting limit")
    if isinstance(value, dict):
        for key, val in value.items():
            base, *mod = str(key).split("|")
            if base not in MAP and base not in FIELDS and base != "channel":
                raise NotApplicable("unmapped field: " + base)
            if any(m not in MODIFIERS for m in mod):
                raise ValueError("unsupported modifier: " + str(key))
            if "re" in mod:
                for pattern in val if isinstance(val, list) else [val]:
                    if not isinstance(pattern, str) or len(pattern) > LIMITS.regex_chars:
                        raise ValueError("regex length/type limit")
                    try:
                        re2.compile(pattern)
                    except Exception as exc:
                        raise ValueError("regex is outside RE2 subset") from exc
            if "fieldref" in mod and val not in MAP and val not in FIELDS:
                raise NotApplicable("unmapped field reference")
            if isinstance(val, (dict, list)):
                check_value(val, depth + 1)
    elif isinstance(value, list):
        for sub in value:
            if isinstance(sub, dict):
                check_selection(sub, depth + 1)
            else:
                raise ValueError("fieldless selections unsupported")
    else:
        raise ValueError("fieldless selections unsupported")


def check_value(value: Any, depth: int) -> None:
    if depth > 12:
        raise ValueError("rule nesting limit")
    if isinstance(value, (dict, list)) and len(value) > 256:
        raise ValueError("rule value count limit")
    if isinstance(value, list):
        for v in value:
            if isinstance(v, (dict, list)):
                check_value(v, depth + 1)


def pipeline(doc: dict[str, Any]) -> ProcessingPipeline:
    """Logsource constrains datasets; transformations map field names to columns."""
    log = doc.get("logsource", {})
    service = log.get("service", log.get("category"))
    if service not in DATASETS:
        raise NotApplicable("unmapped logsource: " + str(service))
    p = ProcessingPipeline()
    if log.get("product") == "windows":
        p = sysmon_pipeline() + windows_logsource_pipeline()
    return p + ProcessingPipeline(
        items=[
            ProcessingItem(FieldMappingTransformation(MAP)),
            *(
                [ProcessingItem(AddConditionTransformation({"dataset": DATASETS[service]}))]
                if service != "generic"
                else []
            ),
            ProcessingItem(SetStateTransformation("table", "events")),
        ],
        priority=100,
        name="minisiem_v1",
    )


def compile_rules(
    paths: list[Path], store: Store | None = None
) -> tuple[list[Rule], list[dict[str, Any]]]:
    """Compile independently, so rejected files cannot hide valid rules."""
    rules = []
    report = []
    seen: set[str] = set()
    for path in sorted(paths):
        try:
            docs = yaml_documents(path.read_text())
            for doc in docs:
                if "correlation" not in doc:
                    detection = doc.get("detection", {})
                    if "|" in str(detection.get("condition", "")):
                        raise ValueError(
                            "deprecated aggregation syntax unsupported; use correlation"
                        )
                    for key, value in detection.items():
                        if key not in ("condition", "timeframe"):
                            check_selection(value)
            collection = SigmaCollection.from_yaml(yaml.safe_dump_all(copy.deepcopy(docs)))
            # Individual collections avoid mutating rule objects more than once.
            base_docs = [d for d in docs if "correlation" not in d]
            if not base_docs:
                raise ValueError("correlation file must include referenced base documents")
            # Base rules in one correlation file must share a compatible logsource.
            # Cross-sensor rules use service generic and direct per-selection dataset filters.
            if any(d.get("logsource") != base_docs[0].get("logsource") for d in base_docs):
                raise ValueError(
                    "mixed logsource correlation: use minisiem generic with dataset selections"
                )
            backend = sqliteBackend(
                processing_pipeline=cast(Any, pipeline(base_docs[0])), event_id_field="id"
            )
            generated = backend.convert(collection)
            # pySigma associates generated output with collection.rules, including referenced rules.
            compiled_by_id: dict[str, list[tuple[str, list[Any]]]] = {}
            for sr in collection.rules:
                outputs = getattr(sr, "conversion_result", None) or []
                if outputs:
                    compiled_by_id[str(sr.id)] = [parameterize(q) for q in outputs]
            # Compile base rules separately to guarantee selectable evidence, regardless of generate flag.
            for doc in docs:
                identity = str(doc.get("id", ""))
                if not re.fullmatch(r"[0-9a-fA-F-]{36}", identity):
                    raise ValueError("UUID rule id required")
                if identity in seen:
                    raise ValueError("duplicate rule id")
                corr = doc.get("correlation")
                if not corr:
                    queries = [
                        parameterize(q)
                        for q in sqliteBackend(
                            processing_pipeline=cast(Any, pipeline(doc))
                        ).convert(SigmaCollection.from_yaml(yaml.safe_dump(copy.deepcopy(doc))))
                    ]
                    if store:
                        for sql, p in queries:
                            store.db.execute("EXPLAIN QUERY PLAN " + sql, p).fetchall()
                    deps = []
                else:
                    typ = corr.get("type")
                    if typ not in ("event_count", "value_count", "temporal", "temporal_ordered"):
                        raise ValueError("unsupported correlation type")
                    span = str(corr.get("timespan", ""))
                    if not re.fullmatch(r"\d+[smh]", span):
                        raise ValueError("invalid correlation timespan")
                    seconds = int(span[:-1]) * {"s": 1, "m": 60, "h": 3600}[span[-1]]
                    if not 1 <= seconds <= 3600:
                        raise ValueError("correlation timespan limit")
                    for col in corr.get("group-by", []):
                        if col not in FIELDS:
                            raise NotApplicable("unmapped correlation group: " + col)
                    if (
                        typ == "value_count"
                        and corr.get("condition", {}).get("field") not in FIELDS
                    ):
                        raise NotApplicable("unmapped value-count field")
                    deps = [str(x) for x in corr.get("rules", [])]
                    queries = compiled_by_id.get(identity, [])
                    if not queries:
                        # A single correlation output is returned even if base outputs are suppressed.
                        queries = [parameterize(generated[-1])]
                    if store:
                        for sql, p in queries:
                            store.db.execute("EXPLAIN QUERY PLAN " + sql, p).fetchall()
                rule = Rule(
                    identity,
                    str(doc.get("name", identity)),
                    str(doc["title"]),
                    str(doc.get("level", "medium")),
                    list(doc.get("tags", [])),
                    queries,
                    doc,
                    corr,
                    deps,
                )
                if "sigma_upstream" in path.parts:
                    doc["license"] = "DRL-1.1"
                    doc["source"] = "https://github.com/SigmaHQ/sigma"
                if store:
                    with store.transaction():
                        store.db.execute(
                            "INSERT INTO rule_catalog VALUES(?,?) ON CONFLICT(id) DO UPDATE SET document=excluded.document",
                            (identity, json.dumps(doc, default=str)),
                        )
                rules.append(rule)
                seen.add(identity)
                applies = bool(
                    store
                    and store.db.execute(
                        "SELECT 1 FROM events WHERE dataset=? LIMIT 1",
                        (
                            DATASETS[
                                base_docs[0]["logsource"].get(
                                    "service", base_docs[0]["logsource"].get("category")
                                )
                            ],
                        ),
                    ).fetchone()
                )
                report.append(
                    {
                        "file": str(path),
                        "id": identity,
                        "status": "compiled",
                        "applicable_to_loaded_data": applies,
                        "reason": "",
                        "correlation": bool(corr),
                    }
                )
        except Exception as exc:
            report.append(
                {
                    "file": str(path),
                    "status": "not_applicable"
                    if isinstance(exc, NotApplicable)
                    else "unsupported_or_invalid",
                    "reason": str(exc)[:512],
                }
            )
    return rules, report
