"""A small hand-written language: field op JSON-string/number, AND/OR/NOT."""

import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from minisiem.config import LIMITS
from minisiem.timeutil import UTC, iso

FIELDS = frozenset(
    {
        "id",
        "timestamp",
        "source",
        "dataset",
        "host",
        "user",
        "source_ip",
        "source_port",
        "destination_ip",
        "destination_port",
        "transport",
        "community_id",
        "message",
        "action",
        "outcome",
        "process_name",
        "command_line",
        "dns_question",
        "http_url",
        "http_status",
        "tls_server_name",
        "event_code",
    }
)
NUMERIC = frozenset({"source_port", "destination_port", "http_status"})


@dataclass(frozen=True)
class Token:
    kind: str
    value: Any


def lex(text: str) -> list[Token]:
    """Tokenize explicitly; quoted values use JSON escape rules."""
    if len(text) > 4096:
        raise ValueError("query too long")
    out = []
    i = 0
    while i < len(text):
        c = text[i]
        if c.isspace():
            i += 1
            continue
        if c in "()":
            out.append(Token(c, c))
            i += 1
        elif c in "=!<>":
            op = c
            i += 1
            if i < len(text) and text[i] == "=":
                op += "="
                i += 1
            if op not in ("=", "!=", "<", "<=", ">", ">="):
                raise ValueError("invalid operator")
            out.append(Token("OP", op))
        elif c == '"':
            try:
                value, used = json.JSONDecoder().raw_decode(text[i:])
            except ValueError as exc:
                raise ValueError("invalid quoted string") from exc
            out.append(Token("VALUE", value))
            i += used
        elif c.isdigit() or c == "-":
            end = i + 1
            while end < len(text) and text[end].isdigit():
                end += 1
            try:
                number = int(text[i:end])
            except ValueError as exc:
                raise ValueError("invalid integer") from exc
            if abs(number) > 2**63 - 1:
                raise ValueError("integer out of range")
            out.append(Token("VALUE", number))
            i = end
        elif c.isascii() and (c.isalpha() or c == "_"):
            end = i + 1
            while (
                end < len(text)
                and text[end].isascii()
                and (text[end].isalnum() or text[end] == "_")
            ):
                end += 1
            value = text[i:end]
            upper = value.upper()
            out.append(
                Token(upper if upper in ("AND", "OR", "NOT", "CONTAINS") else "FIELD", value)
            )
            i = end
        else:
            raise ValueError("invalid query character")
        if len(out) > 256:
            raise ValueError("too many tokens")
    out.append(Token("EOF", None))
    return out


class Parser:
    def __init__(self, text: str):
        self.tokens = lex(text)
        self.pos = 0
        self.params: list[Any] = []
        self.depth = 0

    def peek(self) -> str:
        return self.tokens[self.pos].kind

    def take(self, kind: str) -> Token:
        tok = self.tokens[self.pos]
        if tok.kind != kind:
            raise ValueError("expected " + kind)
        self.pos += 1
        return tok

    def expr(self) -> str:
        value = self.term()
        while self.peek() == "OR":
            self.take("OR")
            value = "(" + value + " OR " + self.term() + ")"
        return value

    def term(self) -> str:
        value = self.factor()
        while self.peek() == "AND":
            self.take("AND")
            value = "(" + value + " AND " + self.factor() + ")"
        return value

    def factor(self) -> str:
        self.depth += 1
        if self.depth > 32:
            raise ValueError("query nesting too deep")
        try:
            if self.peek() == "NOT":
                self.take("NOT")
                return "(NOT COALESCE(" + self.factor() + ",0))"
            if self.peek() == "(":
                self.take("(")
                value = self.expr()
                self.take(")")
                return "(" + value + ")"
            field = self.take("FIELD").value
            if field not in FIELDS:
                raise ValueError("field not allowed")
            contains = self.peek() == "CONTAINS"
            op = self.take("CONTAINS" if contains else "OP").value
            val = self.take("VALUE").value
            if field in NUMERIC and not isinstance(val, int):
                raise ValueError("numeric field requires integer")
            if contains:
                if not isinstance(val, str):
                    raise ValueError("CONTAINS requires a string")
                val = "%" + val.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
                sql = field + " LIKE ? ESCAPE '\\'"
            else:
                sql = field + " " + op + " ?"
            self.params.append(val)
            return sql
        finally:
            self.depth -= 1

    def run(self) -> tuple[str, list[Any]]:
        if self.peek() == "EOF":
            return "1", []
        sql = self.expr()
        self.take("EOF")
        return sql, self.params


def time_range(start: str, end: str) -> tuple[str, str]:
    """Reject invalid/naive/oversized ranges instead of imputing query times."""
    try:
        a = datetime.fromisoformat(start.replace("Z", "+00:00"))
        b = datetime.fromisoformat(end.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("invalid time range") from exc
    if a.tzinfo is None or b.tzinfo is None:
        raise ValueError("explicit timezones required")
    a = a.astimezone(UTC)
    b = b.astimezone(UTC)
    if b <= a or (b - a).total_seconds() > LIMITS.range_days * 86400:
        raise ValueError("range exceeds configured maximum")
    return iso(a), iso(b)


def compile_query(
    query: str, start: str, end: str, limit: int = 100, offset: int = 0, fts: str | None = None
) -> tuple[str, list[Any]]:
    """Mandatory bounded half-open UTC range and deterministic pagination."""
    if not 1 <= limit <= LIMITS.rows or not 0 <= offset <= 10000:
        raise ValueError("pagination limit")
    a, b = time_range(start, end)
    expr, params = Parser(query).run()
    sql = (
        "SELECT "
        + ",".join("e." + f for f in sorted(FIELDS))
        + " FROM events e WHERE ("
        + expr
        + ") AND timestamp>=? AND timestamp<?"
    )
    params.extend([a, b])
    if fts:
        if len(fts) > 256:
            raise ValueError("FTS expression too long")
        # A quoted phrase only: no FTS operators or wildcards exposed by the API.
        sql += " AND e.rowid IN (SELECT rowid FROM event_fts WHERE event_fts MATCH ?)"
        params.append('"' + fts.replace('"', '""') + '"')
    sql += " ORDER BY timestamp,id LIMIT ? OFFSET ?"
    params.extend([limit, offset])
    return sql, params


def csv_cell(value: Any) -> str:
    """Protect CSV spreadsheet formula injection, including leading whitespace."""
    s = "" if value is None else str(value)
    return "'" + s if s.lstrip().startswith(("=", "+", "-", "@")) else s
