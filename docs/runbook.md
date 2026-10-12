# Exact terminal workflow

Use the existing checkout in each isolated cloud task. Do not create a Git worktree unless
explicitly requested. On your laptop use WSL2 with Python 3.12, Git, jq and Docker/Compose.
Run from the repository root. The following commands do not publish anything remotely.

## WSL2 and setup

In Windows `%UserProfile%\.wslconfig` set:

```ini
[wsl2]
memory=4GB
processors=4
swap=2GB
```

Run `wsl --shutdown` in PowerShell to apply. This reserves memory for Windows on an 8-GB
laptop. Docker Desktop must enable WSL integration. Do not run sensors during benchmarks.
Python 3.12 and SQLite >=3.38 are required; original requested 3.10+ is satisfied by
choosing a tested 3.12 toolchain. If your Ubuntu distro's Python is older, install Python
3.12 using its supported packaging before continuing. No GPU or Kaggle is involved.

```bash
python3.12 --version
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.lock
python -m pip install --no-build-isolation --no-deps -e .
python -m pip check
python -c 'import sqlite3; print(sqlite3.sqlite_version)'
make check
minisiem keygen
minisiem init
```

Expected: no broken requirements, ruff/mypy pass, fixture tests and 25 rule cases pass.
`keygen` creates a private ignored `.env` and does not print its contents. Rerunning keygen
refuses to overwrite it; rerun init safely. The application supports local directories
with MINISIEM_DATA; optional limits are selected with MINISIEM_LIMITS=configs/limits.yaml.
No credentials are required for synthetic simulation, search or detection.

## Full synthetic workflow (all milestones)

```bash
minisiem simulate --seed 42 --repeats 3 --noise 100
minisiem ingest data/synthetic/events.jsonl --source synthetic
minisiem detect
minisiem rules compile
minisiem rules test
minisiem notify
jq '.records, (.instances | length)' data/synthetic/ground_truth.json
python -m sqlite3 data/minisiem.db 'SELECT dataset,count(*) FROM events GROUP BY dataset;'
python -m sqlite3 data/minisiem.db 'SELECT title,count,status,author FROM alerts ORDER BY title;'
python -m sqlite3 data/minisiem.db 'PRAGMA journal_mode; PRAGMA foreign_key_check;'
minisiem ingest data/synthetic/events.jsonl --source synthetic
```

Expected: 148 synthetic records and 30 scenario instances; zero quarantine on valid data;
WAL mode; empty foreign-key check; replay ingests zero new events. Alerts are grouped, so
counts are not one alert per input. The CLI detect exits nonzero on any compile/runtime
failure; inspect the report instead of claiming a partial run passed. Source must stay
`synthetic` for ground-truth IDs to match. Do not regenerate timestamps to test an exact replay.

## Offline sensors, profile sensors

Both tools process one generated benign PCAP at a time, with no network and a 1-GiB cap.
No PCAP is committed. First pull the exact pinned image tags/digests from Compose, then:

```bash
mkdir -p data/pcaps data/zeek data/suricata
python lab/traffic/benign_pcap.py data/pcaps/benign.pcap
docker compose -f lab/docker-compose.lab.yml --profile sensors run --rm zeek
docker compose -f lab/docker-compose.lab.yml --profile sensors run --rm suricata
jq -s 'length' data/zeek/conn.log
jq -s '[.[] | select(.event_type=="alert")] | length' data/suricata/eve.json
jq 'select(.event_type=="stats") | .stats.decoder.pkts, .stats.decoder.invalid, .stats.detect.alert' data/suricata/eve.json
minisiem ingest data/zeek/conn.log --kind zeek.conn --source lab-zeek-conn
minisiem ingest data/zeek/http.log --kind zeek.http --source lab-zeek-http
minisiem ingest data/suricata/eve.json --kind suricata --source lab-suricata
minisiem detect
python -m sqlite3 data/minisiem.db 'SELECT method,count(*) FROM links GROUP BY method;'
```

Expected: one Zeek connection and HTTP record, one Suricata alert, eight decoded packets,
zero invalid packets, matching community IDs. The PCAP timestamp is 2025-01-01, so inspect
it before running the automatic current-date retention worker. Use separate archived-data
limits if you deliberately retain this fixture beyond the default 30 days.

Local bind mounts must be readable/writable to UID 1000. If your WSL UID differs, adjust
only the Compose sensor user to your owned lab UID, not permissions on real telemetry.
The cloud daemon cannot see checkout bind mounts; the verified alternative is:

```bash
python lab/sensors/run_offline.py zeek data/pcaps/benign.pcap data/zeek-run
python lab/sensors/run_offline.py suricata data/pcaps/benign.pcap data/suricata-run
jq -s 'length' data/zeek-run/conn.log
jq 'select(.event_type=="alert") | .community_id, .alert.signature' data/suricata-run/eve.json
```

The helper requires empty output directories and preserves prior output. It uses docker cp,
no network, memory/CPU limits and no capabilities. It detects the host UID/GID for owned files.
Never call sensors with live `-i` flags or a host network. Sensor names/options were checked
against official source documentation and the pinned binaries. Upgrades require repeating
this smoke test and recording new digests; never change a checksum to make a pull pass.

## API/dashboard, profile core

```bash
minisiem serve
```

The CLI binds 127.0.0.1:8000, disables access logs, starts periodic detection and retention,
and refuses to serve without key metadata. Open your local browser to that loopback address
on your laptop; cloud onboarding does not provide a web preview. Read the private `.env`
locally to use the dashboard key input; never paste it in chat. It stays only in JS memory.
The API can be queried without exposing the key in a command argument:

```bash
python - <<'PYCLIENT'
from datetime import datetime, timedelta, timezone
from dotenv import dotenv_values
import httpx
key = dotenv_values('.env')['MINISIEM_API_KEY']
now = datetime.now(timezone.utc)
with httpx.Client(base_url='http://127.0.0.1:8000') as client:
    response = client.get('/v1/events', headers={'X-API-Key': key}, params={
        'start': (now-timedelta(days=1)).isoformat(), 'end': now.isoformat(),
        'q': 'dataset = "syslog"', 'limit': 20})
    response.raise_for_status()
    print(response.json())
PYCLIENT
```

For local Linux/WSL Docker core, stop the CLI server first. Compose defaults to local UID/GID 1000 for the owned bind-mounted data directory.
Set LOCAL_UID and LOCAL_GID to your WSL UID/GID if they differ. Standalone images use UID 10001.
The core runs on host networking but its listener remains loopback. Do not use core alongside
sensors or performance evaluation on an 8-GB laptop.

```bash
docker compose -f lab/docker-compose.lab.yml --profile core up --build core
```

Corporate/cloud TLS interception may require the platform's trusted CA bundle during image
build. Dockerfile supports a temporary BuildKit CA mount without copying credentials or
weakening TLS. The tested cloud build command is:

```bash
BUILDX_CONFIG=/tmp/minisiem-buildx docker build --secret id=ca_bundle,src=/etc/ssl/certs/ca-certificates.crt -t minisiem:local .
```

Normal local builds use `docker build -t minisiem:local .` with public CA verification.
If certificate verification fails, fix trust using an authorized CA; do not use trusted-host,
insecure curl flags or disabled verification.

## Evaluation and retention

```bash
# Stop sensors first. Select a new results directory for each comparison.
MPLCONFIGDIR=/tmp/minisiem-mpl minisiem evaluate --events 10000 --output results/laptop
jq '.fuzzing, .performance.laptop_measurement, .detection[0].per_rule' results/laptop/results.json
python -m sqlite3 data/minisiem.db 'SELECT count(*) FROM event_fts WHERE event_fts MATCH "benign";'
minisiem retain --days 30
make check
```

The tool always labels its host rather than assuming it is your laptop. Add a reviewed note
with laptop hardware/WSL caps if actually running there. Increase toward a million events
only after checking `df -h` and free memory, with sensors stopped. Default size-per-million
is explicitly extrapolated and finite batch throughput is not claimed sustained throughput.
Public dataset review/evaluation is separate and now available as `minisiem evaluate-public`
for the recorded Apache-2.0 Splunk lab subset. See public_dataset.md for label limitations.

## Final Git audit and publication commands

Existing origin points at the requested GitHub repository;
its main branch was initially empty. Review every staged path before committing:

```bash
git status --short --untracked-files=all
git check-ignore .env data/pcaps/benign.pcap rules/sigma_upstream/proc_creation_win_cmdkey_recon.yml
git add .gitignore .dockerignore .env.example pyproject.toml requirements.lock README.md SAFETY.md LICENSE Makefile Dockerfile configs src tests rules/custom rules/tests fixtures lab eval docs .github
git diff --cached --check
git diff --cached --stat
git ls-files '*.pcap' '*.pcapng' '*.db' '*.sqlite' '.env' 'data/*' 'rules/sigma_upstream/*'
# Expected last output: empty. Inspect staged content locally for keys/personal identifiers.
git commit -m "Build defensive Mini-SIEM with offline sensors, Sigma evidence, API and evaluation"
git branch -M main
git push -u origin main
```

For a separate NEW repository only, after GitHub CLI authentication and your decision to
publish, `gh repo create minisiem --private --source=. --remote=portfolio --push` creates and
pushes a repository. Do not run it to replace the existing Mini-SIEM origin. GitHub Actions
fetches actions/dependencies during preparation; the checks themselves run with network
isolated and never invoke Docker/downloads. A hosted CI run is not claimed until it executes.
