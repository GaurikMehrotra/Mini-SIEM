"""Loopback FastAPI, scoped authentication, bounded bodies and escaped dashboard."""

import asyncio
import json
import sqlite3
import time
from collections import OrderedDict, deque
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, AsyncIterator

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from jinja2 import Environment, FileSystemLoader, select_autoescape
from pydantic import BaseModel, Field

from minisiem.alerts.workflow import detail, expire, transition
from minisiem.api.auth import authorize, bindings
from minisiem.config import LIMITS, data_dir
from minisiem.ingest.linking import link
from minisiem.parsers.registry import parse
from minisiem.search.compile import compile_query
from minisiem.store.db import Store
from minisiem.timeutil import UTC, iso

WEB = Path(__file__).resolve().parents[1] / "web"
ENV = Environment(
    loader=FileSystemLoader(WEB / "templates"),
    autoescape=select_autoescape(["html", "xml"], default_for_string=True),
)
CSP = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
HEADERS = {
    "Content-Security-Policy": CSP,
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}


class Guard:
    """ASGI receive limit enforces actual bytes, including chunked bodies."""

    def __init__(self, app: Any):
        self.app = app
        self.buckets: OrderedDict[str, deque[float]] = OrderedDict()

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def reject(status: int, message: str) -> None:
            response = JSONResponse({"detail": message}, status_code=status, headers=HEADERS)
            await response(scope, receive, send)

        headers = dict(scope.get("headers", []))
        # Bound anonymous callers by peer, and authenticated callers by SHA256 key hash.
        import hashlib

        supplied_digest = hashlib.sha256(headers.get(b"x-api-key", b"")).hexdigest()
        known_key = any(entry["sha256"] == supplied_digest for entry in bindings())
        who = supplied_digest if known_key else str(scope.get("client", ("local",))[0])
        now = time.monotonic()
        if who not in self.buckets and len(self.buckets) >= 4096:
            self.buckets.popitem(last=False)
        bucket = self.buckets.setdefault(who, deque())
        self.buckets.move_to_end(who)
        while bucket and bucket[0] < now - 60:
            bucket.popleft()
        if len(bucket) >= LIMITS.requests_per_minute:
            await reject(429, "rate limit")
            return
        bucket.append(now)
        origin = headers.get(b"origin")
        host = headers.get(b"host", b"")
        if host.split(b":")[0] not in (b"127.0.0.1", b"localhost", b"testserver"):
            await reject(400, "untrusted host")
            return
        if origin and origin not in (b"http://" + host, b"https://" + host):
            await reject(403, "cross-origin request denied")
            return
        try:
            if int(headers.get(b"content-length", b"0")) > LIMITS.request_bytes:
                await reject(413, "request body limit")
                return
        except ValueError:
            await reject(400, "invalid content length")
            return
        body = bytearray()
        # Buffer a bounded body before routing so no partial mutation occurs.
        while True:
            try:
                message = await asyncio.wait_for(receive(), timeout=10)
            except asyncio.TimeoutError:
                await reject(408, "request body timeout")
                return
            if message["type"] == "http.disconnect":
                return
            body.extend(message.get("body", b""))
            if len(body) > LIMITS.request_bytes:
                await reject(413, "request body limit")
                return
            if not message.get("more_body", False):
                break
        delivered = False

        async def bounded_receive() -> dict[str, Any]:
            nonlocal delivered
            if not delivered:
                delivered = True
                return {"type": "http.request", "body": bytes(body), "more_body": False}
            return await receive()

        async def secure_send(message: dict[str, Any]) -> None:
            if message["type"] == "http.response.start":
                message["headers"] += [(k.lower().encode(), v.encode()) for k, v in HEADERS.items()]
            await send(message)

        await self.app(scope, bounded_receive, secure_send)


class AlertUpdate(BaseModel):
    status: str
    notes: str = Field(min_length=1, max_length=4096)
    until: str | None = None
    reason: str | None = Field(default=None, max_length=1024)


class IngestBody(BaseModel):
    kind: str = Field(default="jsonl", max_length=32)
    source: str = Field(default="http-synthetic", max_length=128)
    lines: list[str] = Field(max_length=100)


def create_app(
    db_path: Path | None = None, rule_dir: Path | None = None, background: bool = False
) -> FastAPI:
    """Use create_app for tests; server entry explicitly enables periodic jobs."""
    db_path = db_path or data_dir() / "minisiem.db"
    rule_dir = rule_dir or Path("rules/custom")

    def tick() -> None:
        from minisiem.detect.runner import run
        from minisiem.detect.sigma_loader import compile_rules

        with Store(db_path) as store:
            rules, report = compile_rules(list(rule_dir.glob("*.yml")), store)
            for entry in report:
                if entry["status"] != "compiled":
                    identity = entry.get("id", Path(entry["file"]).stem)
                    with store.transaction():
                        store.db.execute(
                            "INSERT INTO rule_stats VALUES(?,?,?,?,?,?,?) ON CONFLICT(rule_id) DO UPDATE SET status=excluded.status,reason=excluded.reason,updated_at=excluded.updated_at",
                            (
                                identity,
                                Path(entry["file"]).stem,
                                entry["status"],
                                entry.get("reason", ""),
                                0,
                                0,
                                iso(datetime.now(UTC)),
                            ),
                        )
            run(store, rules)
            link(store)
            store.retain(iso(datetime.now(UTC) - timedelta(days=LIMITS.retention_days)))

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        if not bindings():
            raise RuntimeError("Configure scoped API keys before serving")
        task = None

        async def worker() -> None:
            while True:
                try:
                    await asyncio.to_thread(tick)
                    app.state.background_error = None
                except (sqlite3.Error, ValueError, OSError) as exc:
                    app.state.background_error = type(exc).__name__
                await asyncio.sleep(30)

        if background:
            task = asyncio.create_task(worker())
        try:
            yield
        finally:
            if task:
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass

    app = FastAPI(
        title="Mini-SIEM",
        version="1.0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )
    app.add_middleware(Guard)
    app.mount("/static", StaticFiles(directory=WEB / "static"), name="static")

    @app.exception_handler(RequestValidationError)
    async def invalid(request: Request, exc: RequestValidationError) -> JSONResponse:
        return JSONResponse({"detail": "invalid request"}, status_code=422)

    @app.exception_handler(sqlite3.Error)
    async def db_error(request: Request, exc: sqlite3.Error) -> JSONResponse:
        return JSONResponse({"detail": "bounded database query failed"}, status_code=400)

    @app.get("/v1/openapi.json")
    def openapi(request: Request) -> dict[str, Any]:
        authorize(request, "read")
        return app.openapi()

    @app.get("/v1/health")
    def health(request: Request) -> dict[str, Any]:
        authorize(request, "read")
        with Store(db_path) as s:
            return dict(
                schema_version=3,
                background_error=getattr(app.state, "background_error", None),
                **s.counts(),
                runs=s.bounded(
                    "SELECT source,finished,accepted,duplicates,quarantined,lag_seconds,elapsed_seconds FROM ingest_runs ORDER BY id DESC LIMIT 20"
                ),
            )

    @app.get("/v1/events")
    def events(
        request: Request,
        start: str,
        end: str,
        q: str = "",
        limit: int = 100,
        offset: int = 0,
        fts: str | None = None,
    ) -> dict[str, Any]:
        authorize(request, "read")
        try:
            sql, p = compile_query(q, start, end, limit, offset, fts)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        with Store(db_path) as s:
            rows = s.bounded(sql, p)
            return {
                "version": 1,
                "events": rows,
                "offset": offset,
                "next_offset": offset + len(rows) if len(rows) == limit else None,
            }

    @app.get("/v1/alerts")
    def alerts(
        request: Request, limit: int = 100, offset: int = 0, status: str | None = None
    ) -> dict[str, Any]:
        authorize(request, "read")
        if not 1 <= limit <= LIMITS.rows or not 0 <= offset <= 10000:
            raise HTTPException(400, "pagination limit")
        from minisiem.alerts.workflow import STATUSES

        if status and status not in STATUSES:
            raise HTTPException(400, "invalid status")
        with Store(db_path) as s:
            expire(s)
            rows = s.bounded(
                "SELECT * FROM alerts WHERE (? IS NULL OR status=?) ORDER BY created_at,id LIMIT ? OFFSET ?",
                [status, status, limit, offset],
            )
            return {
                "alerts": rows,
                "next_offset": offset + len(rows) if len(rows) == limit else None,
            }

    @app.get("/v1/alerts/{identity}")
    def alert_detail(request: Request, identity: str) -> dict[str, Any]:
        authorize(request, "read")
        with Store(db_path) as s:
            expire(s)
            item = detail(s, identity)
            if item is None:
                raise HTTPException(404, "alert not found")
            return item

    @app.patch("/v1/alerts/{identity}")
    def update(request: Request, identity: str, body: AlertUpdate) -> dict[str, str]:
        authorize(request, "alert-write")
        with Store(db_path) as s:
            try:
                transition(s, identity, body.status, body.notes, body.until, body.reason)
            except ValueError as exc:
                raise HTTPException(400, str(exc)) from exc
        return {"status": body.status}

    @app.get("/v1/rules")
    def stats(request: Request) -> dict[str, Any]:
        authorize(request, "read")
        with Store(db_path) as s:
            return {
                "rules": s.bounded(
                    "SELECT * FROM rule_stats ORDER BY hits DESC LIMIT ?", [LIMITS.rows]
                )
            }

    @app.get("/v1/rules/{identity}")
    def rule_document(request: Request, identity: str) -> dict[str, Any]:
        authorize(request, "read")
        with Store(db_path) as store:
            row = store.db.execute(
                "SELECT document FROM rule_catalog WHERE id=?", (identity,)
            ).fetchone()
            if row is None:
                raise HTTPException(404, "rule not found")
            return {"id": identity, "rule": json.loads(row["document"])}

    @app.post("/v1/ingest")
    def http_ingest(request: Request, body: IngestBody) -> dict[str, int]:
        authorize(request, "ingest")
        if body.kind not in (
            "jsonl",
            "syslog",
            "web",
            "suricata",
            "zeek.conn",
            "zeek.dns",
            "zeek.http",
            "zeek.ssl",
            "zeek.notice",
        ):
            raise HTTPException(400, "unknown parser")
        # Never let an API key become part of raw/evidence, even if echoed by a caller.
        supplied = request.headers.get("x-api-key", "")
        if any(supplied in line for line in body.lines):
            raise HTTPException(400, "credential content rejected")
        events = []
        rejected = 0
        with Store(db_path) as s:
            with s.transaction():
                for line in body.lines:
                    p = parse(line, body.kind, body.source)
                    if p.reason:
                        rejected += 1
                        s.db.execute(
                            "INSERT INTO quarantine(source,raw,reason,created_at) VALUES(?,?,?,?)",
                            (
                                body.source,
                                "[HTTP record omitted]",
                                p.reason,
                                iso(datetime.now(UTC)),
                            ),
                        )
                    else:
                        events.extend(p.events)
                accepted = s.insert(events)
        return {"accepted": accepted, "duplicates": len(events) - accepted, "quarantined": rejected}

    @app.get("/", response_class=HTMLResponse)
    def shell() -> str:
        # Shell exposes no log data. A key is kept only in JS memory, never in URL/storage.
        return ENV.get_template("index.html").render()

    @app.get("/v1/dashboard", response_class=HTMLResponse)
    def dashboard(request: Request, start: str, end: str, q: str = "") -> str:
        authorize(request, "read")
        try:
            sql, p = compile_query(q, start, end, 50)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        with Store(db_path) as s:
            expire(s)
            return ENV.get_template("dashboard.html").render(
                counts=s.counts(),
                events=s.bounded(sql, p),
                alerts=s.bounded("SELECT * FROM alerts ORDER BY updated_at DESC LIMIT 50"),
                rules=s.bounded("SELECT * FROM rule_stats ORDER BY hits DESC LIMIT 50"),
                runs=s.bounded("SELECT * FROM ingest_runs ORDER BY id DESC LIMIT 20"),
            )

    @app.get("/v1/dashboard/alerts/{identity}", response_class=HTMLResponse)
    def dashboard_alert(request: Request, identity: str) -> str:
        authorize(request, "read")
        with Store(db_path) as s:
            expire(s)
            item = detail(s, identity)
            if item is None:
                raise HTTPException(404, "alert not found")
            return ENV.get_template("alert.html").render(alert=item)

    return app
