# Evaluation entry point

Run `minisiem evaluate --events 10000` from the repository root. The tested implementation
is src/minisiem/evaluation.py; separate one-file wrappers are avoided so configurations
and metrics cannot drift. Outputs live in ignored results/: config.json, results.json,
detection.csv, performance.csv, attack_coverage.json, error_analysis.json and recall.png.
`pytest --junitxml=results/tests.xml` saves security/robustness test evidence.

Parsing compares fixed fields with independent libjq extraction and includes an actual
sensor-produced fixture end-to-end test. The 10,000-line seeded mutation campaign asserts
no uncaught exceptions and separately verifies malformed/oversized quarantine persistence.
Performance measures finite batches per source, sampled peak RSS, SQLite file size and
query medians with/without the time index and FTS versus LIKE. Million-event size is
explicitly extrapolated at the default run size. These are cloud-host figures; repeat
on the specified laptop, with sensors stopped, to claim laptop or sustained performance.

Detection compares full Sigma, correlation removed, Suricata-only, keyword baseline,
60/900-second grouping, context linking removed, and justified single-failure suppression.
The suppression variant changes visible volume and leaves underlying classification intact.
Linking is a context-only feature, so recall should not change. Reports do not pretend
otherwise. Precision is evidence-based synthetic precision, not adjudicated real-world
precision. The benign denominator is one synthetic hour, extrapolated to alerts/day;
zero on that small toy workload does not establish a safe false-positive rate.

Latency currently reports ingest-to-alert p50/p95 on synthetic targets and total finite
file-ingest/detection time. It does not claim sustained write-to-alert latency distribution
on a real concurrent log writer. The optional `minisiem evaluate-public` command now evaluates a reviewed, pinned Splunk
lab subset; see docs/public_dataset.md for scenario-label limits and results. Laptop runs
and independently labeled public event metrics remain outside the current evidence.
