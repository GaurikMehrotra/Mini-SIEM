"""Fixed-seed synthetic ground truth; no traffic generation or attack execution."""

import json
import random
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from minisiem.models import event_id
from minisiem.timeutil import UTC, iso


def generate(
    destination: Path,
    rule_tests: Path,
    seed: int = 42,
    repeats: int = 3,
    noise: int = 100,
    now: datetime | None = None,
) -> dict[str, Any]:
    rng = random.Random(seed)
    now = (now or datetime.now(UTC)).replace(microsecond=0)
    destination.mkdir(parents=True, exist_ok=True)
    records = []
    truth = []
    for rep in range(repeats):
        for idx, case_path in enumerate(sorted(rule_tests.glob("*.json"))):
            positive = json.loads(case_path.read_text())[0]
            instance = f"{case_path.stem}-{rep}"
            start = now - timedelta(minutes=(rep * 10 + idx + 1) * 10)
            ips = f"192.0.2.{1 + rep * 10 + idx}"
            ids = []
            for j, record in enumerate(positive["records"]):
                record = dict(
                    record,
                    timestamp=iso(start + timedelta(seconds=j * 30)),
                    source_ip=ips,
                    host="lab-" + str(idx),
                    scenario=instance,
                )
                raw = json.dumps(record, sort_keys=True)
                records.append(raw)
                ids.append(event_id("synthetic", raw))
            truth.append(
                {
                    "instance": instance,
                    "rule": case_path.stem,
                    "event_ids": ids,
                    "scenario_start": iso(start),
                    "expected": positive["expected"],
                }
            )
    for i in range(noise):
        r = {
            "timestamp": iso(now - timedelta(seconds=rng.randrange(60 * 60))),
            "dataset": rng.choice(["generic", "zeek.dns", "web.access", "zeek.conn"]),
            "message": "benign synthetic " + str(i),
            "source_ip": "198.51.100.10",
            "host": "benign-lab",
            "dns_question": "lab.invalid",
            "http_status": 200,
            "destination_port": 443,
        }
        records.append(json.dumps(r, sort_keys=True))
    rng.shuffle(records)
    (destination / "events.jsonl").write_text("\n".join(records) + "\n")
    ground = {
        "seed": seed,
        "source": "synthetic",
        "created_at": iso(now),
        "benign_observation_days": 1 / 24,
        "noise": noise,
        "instances": truth,
        "records": len(records),
    }
    (destination / "ground_truth.json").write_text(json.dumps(ground, indent=2) + "\n")
    return ground
