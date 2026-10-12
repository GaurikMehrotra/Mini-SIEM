# Bundled phase map

All code is in the checkout; phases are not approval gates. Full commands and cross-checks
are in runbook.md. These optional individual commit commands are for local review; the initial implementation is published as one aggregate commit when authorized. They stage only explicit reviewed files,
not data or upstream rules. One aggregate commit is simpler for this empty repository.

| Phase | Implementation/check | Command | Suggested commit message |
| --- | --- | --- | --- |
| 1 | Safety/environment | `make install && minisiem init` | `git commit -m "scaffold defensive environment"` (after explicit reviewed staging) |
| 2 | Schema/time/FTS/retention | `pytest tests/test_store.py` | `git commit -m "add versioned UTC event storage"` (after explicit reviewed staging) |
| 3 | JSON/syslog/web parsers | `pytest tests/test_parsers_ingest.py` | `git commit -m "add bounded parsers and quarantine"` (after explicit reviewed staging) |
| 4 | File checkpoints/batching | `pytest tests/test_parsers_ingest.py` | `git commit -m "add transactional rotating file ingestion"` (after explicit reviewed staging) |
| 5 | Offline sensors/linking | `make sensors` | `git commit -m "add isolated offline sensor workflow"` (after explicit reviewed staging) |
| 6 | Safe query language | `pytest tests/test_search.py` | `git commit -m "add parameterized bounded search"` (after explicit reviewed staging) |
| 7 | Sigma foundations/coverage | `minisiem rules compile` | `git commit -m "add mapped Sigma compilation coverage"` (after explicit reviewed staging) |
| 8 | Detection test harness | `pytest tests/test_detection.py` | `git commit -m "add evidence-bearing rule harness"` (after explicit reviewed staging) |
| 9 | Bounded runner/watermarks | `pytest tests/test_robustness.py tests/test_detection.py` | `git commit -m "add isolated rule execution and cursors"` (after explicit reviewed staging) |
| 10 | Ten custom rules | `minisiem rules test` | `git commit -m "add original tested detection hypotheses"` (after explicit reviewed staging) |
| 11 | Four correlation types | `pytest tests/test_custom_rules.py` | `git commit -m "add native bounded Sigma correlations"` (after explicit reviewed staging) |
| 12 | Alerts/suppression/notifications | `minisiem notify && pytest tests/test_detection.py` | `git commit -m "add grouped alert analyst workflow"` (after explicit reviewed staging) |
| 13 | Synthetic scenarios/ground truth | `minisiem simulate` | `git commit -m "add seeded ground-truth scenarios"` (after explicit reviewed staging) |
| 14 | Versioned scoped API | `pytest tests/test_api.py` | `git commit -m "add scoped local query and alert API"` (after explicit reviewed staging) |
| 15 | Secure dashboard | `pytest tests/test_api.py` | `git commit -m "add escaped dashboard and timeline"` (after explicit reviewed staging) |
| 16 | Optional local enrichment | `pytest tests/test_enrichment.py` | `git commit -m "add local metadata enrichment"` (after explicit reviewed staging) |
| 17 | Parsing/fuzz/performance | `minisiem evaluate --events 10000` | `git commit -m "add measured parser and performance evaluation"` (after explicit reviewed staging) |
| 18 | Quality/baselines/ablations | `minisiem evaluate --events 10000` | `git commit -m "add synthetic coverage and ablations"` (after explicit reviewed staging) |
| 19 | Security/robustness | `pytest tests/test_api.py tests/test_robustness.py` | `git commit -m "verify hostile input and replay defenses"` (after explicit reviewed staging) |
| 20 | Quality/CI/packaging | `make check` | `git commit -m "package Mini-SIEM and offline checks"` (after explicit reviewed staging) |
| 21 | Docs/architecture/results | `git diff --check` | `git commit -m "document measured behavior and limits"` (after explicit reviewed staging) |
| 22 | Final audit | `git status --short --untracked-files=all` | `git commit -m "audit portfolio release inputs"` (after explicit reviewed staging) |

Public scenario-labeled dataset validation in phases 13/18 is now implemented and run;
public per-event precision/FPR cannot be inferred from those labels. Actual laptop/sustained
measurements in 17/18,
and hosted CI/publication in 20/22 require external actions. They are not marked passed.
Optional EVTX, syslog TCP/UDP, DuckDB and AI integration are excluded intentionally.
