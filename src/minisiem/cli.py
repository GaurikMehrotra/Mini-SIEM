"""Terminal-first reproducible commands. No implicit remote downloads."""

import csv
import hashlib
import json
import os
import secrets
from datetime import datetime, timedelta
from pathlib import Path

import typer
from dotenv import load_dotenv
from rich.console import Console

from minisiem.config import LIMITS, data_dir
from minisiem.detect.sigma_loader import compile_rules
from minisiem.ingest.pipeline import ingest as ingest_file
from minisiem.search.compile import compile_query, csv_cell
from minisiem.store.db import Store
from minisiem.timeutil import UTC, iso

app = typer.Typer(
    pretty_exceptions_show_locals=False,
    no_args_is_help=True,
    help="Defensive offline Mini-SIEM. Synthetic or approved lab data only.",
)
console = Console()
rules_app = typer.Typer(pretty_exceptions_show_locals=False)
app.add_typer(rules_app, name="rules")


def db_path() -> Path:
    return data_dir() / "minisiem.db"


@app.command()
def init() -> None:
    """Create WAL/FTS schema without a listener."""
    with Store(db_path()) as s:
        console.print(s.counts())


@app.command()
def keygen(env_file: Path = Path(".env")) -> None:
    """Create a private ignored env file exclusively; never print key values."""
    if env_file.exists():
        raise typer.BadParameter("env file exists; preserve it and select a new path")
    key = secrets.token_urlsafe(36)
    metadata = json.dumps(
        [{"sha256": hashlib.sha256(key.encode()).hexdigest(), "scopes": ["admin"]}],
        separators=(",", ":"),
    )
    fd = os.open(env_file, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write("MINISIEM_API_KEY=" + key + "\nMINISIEM_KEYS='" + metadata + "'\n")
    console.print(
        "Created private key file. Read it locally when needed; never paste it into chat or commit it."
    )


@app.command("ingest")
def ingest_cmd(
    path: Path, kind: str = "jsonl", source: str = "local", pseudonymize: bool = False
) -> None:
    """One finite read; rerun to resume a growing or rotated file."""
    load_dotenv()
    key = None
    if pseudonymize:
        load_dotenv()
        val = os.environ.get("MINISIEM_PSEUDONYM_KEY")
        if not val or len(val) < 32:
            raise typer.BadParameter("set MINISIEM_PSEUDONYM_KEY securely (at least 32 characters)")
        key = val.encode()
    with Store(db_path()) as s:
        console.print_json(json.dumps(ingest_file(s, path, kind, source, key)))


@app.command()
def search(
    start: str,
    end: str,
    q: str = "",
    limit: int = 100,
    offset: int = 0,
    fts: str | None = None,
    export: Path | None = None,
) -> None:
    """Only structured query text, never raw SQL."""
    sql, p = compile_query(q, start, end, limit, offset, fts)
    with Store(db_path()) as s:
        rows = s.bounded(sql, p)
    if export:
        with export.open("w", newline="") as f:
            if rows:
                writer = csv.DictWriter(f, fieldnames=list(rows[0]))
                writer.writeheader()
                writer.writerows([{k: csv_cell(v) for k, v in r.items()} for r in rows])
    else:
        console.print_json(
            json.dumps(
                {"events": rows, "next_offset": offset + len(rows) if len(rows) == limit else None}
            )
        )


@rules_app.command("compile")
def compile_cmd(
    directory: Path = Path("rules/custom"), output: Path = Path("results/compile.json")
) -> None:
    """Compile coverage with explicit invalid/unmapped reasons."""
    with Store(db_path()) as s:
        _, report = compile_rules(
            list(directory.rglob("*.yml")) + list(directory.rglob("*.yaml")), s
        )
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + "\n")
    console.print(
        {
            "compiled": sum(r["status"] == "compiled" for r in report),
            "reported": len(report),
            "report": str(output),
        }
    )


@rules_app.command("test")
def rules_test(directory: Path = Path("rules/custom"), cases: Path = Path("rules/tests")) -> None:
    """Run every original rule's positive and negative synthetic cases."""
    from minisiem.detect.rule_tests import test_cases

    total = 0
    for path in sorted(directory.glob("*.yml")):
        result = test_cases(path, cases / (path.stem + ".json"))
        total += result["passed"]
    if total == 0:
        raise typer.Exit(1)
    console.print({"passed_cases": total})


@app.command()
def detect(directory: Path = Path("rules/custom")) -> None:
    """Evaluate rules and print failures without hiding them."""
    from minisiem.detect.runner import run
    from minisiem.ingest.linking import link

    with Store(db_path()) as s:
        rules, report = compile_rules(list(directory.glob("*.yml")), s)
        bad = [r for r in report if r["status"] != "compiled"]
        link(s)
        results = []
        while True:
            batch = run(s, rules)
            results.extend(batch)
            if not batch or any(r["status"] == "failed" for r in batch):
                break
        console.print_json(
            json.dumps({"rules": results, "compile_failures": bad, "counts": s.counts()})
        )
        if bad or any(r["status"] == "failed" for r in results):
            raise typer.Exit(1)


@app.command()
def retain(days: int = LIMITS.retention_days) -> None:
    """Delete old records, evidence and FTS entries and compact the database."""
    if days < 1:
        raise typer.BadParameter("days must be positive")
    with Store(db_path()) as s:
        console.print({"deleted": s.retain(iso(datetime.now(UTC) - timedelta(days=days)))})


@app.command()
def simulate(
    seed: int = 42, repeats: int = 3, noise: int = 100, destination: Path = Path("data/synthetic")
) -> None:
    """Generate log patterns and ground truth only, never network traffic."""
    from minisiem.simulate.scenarios import generate

    if not 1 <= repeats <= 20 or not 0 <= noise <= 1000000:
        raise typer.BadParameter("generator bounds")
    result = generate(destination, Path("rules/tests"), seed, repeats, noise)
    console.print(
        {
            "records": result["records"],
            "instances": len(result["instances"]),
            "destination": str(destination),
        }
    )


@app.command()
def notify(output: Path = Path("data/notifications.jsonl")) -> None:
    """Append local hypothesis summaries; no webhook or email."""
    from minisiem.alerts.workflow import notify_local

    with Store(db_path()) as s:
        console.print({"written": notify_local(s, output)})


@app.command()
def serve(port: int = 8000) -> None:
    """Always bind loopback; no host override in this defensive CLI."""
    import uvicorn

    from minisiem.api.main import create_app

    load_dotenv()
    uvicorn.run(
        create_app(background=True),
        host="127.0.0.1",
        port=port,
        access_log=False,
        limit_concurrency=32,
    )


@app.command("enrich")
def enrich_cmd(
    identity: str,
    assets: Path = Path("configs/assets.yaml"),
    iocs: Path = Path("configs/iocs.yaml"),
    findings: Path = Path("configs/findings.yaml"),
) -> None:
    """Annotate an evidence ID using local files only."""
    from minisiem.enrich.local import enrich, load

    with Store(db_path()) as store:
        event = store.event(identity)
        if event is None:
            raise typer.BadParameter("event not found")
        console.print_json(
            json.dumps(
                {
                    "event_id": identity,
                    "enrichment": enrich(event, load(assets), load(iocs), load(findings)),
                }
            )
        )


@app.command()
def evaluate(output: Path = Path("results"), events: int = 10000) -> None:
    """Fixed-seed synthetic evaluation on THIS machine, not laptop results."""
    from minisiem.evaluation import evaluate as run_evaluation

    if not 100 <= events <= 1000000:
        raise typer.BadParameter("benchmark size bounds")
    console.print(run_evaluation(output, events))


@app.command("evaluate-public")
def evaluate_public_cmd(output: Path = Path("results/public"), offline: bool = False) -> None:
    """Review recorded terms, verify pinned public lab logs, and evaluate technique recovery."""
    from minisiem.public_data import evaluate_public

    console.print(evaluate_public(data_dir() / "public/splunk", output, download=not offline))


if __name__ == "__main__":
    app()
