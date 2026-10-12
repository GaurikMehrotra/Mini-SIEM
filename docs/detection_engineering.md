# Detection engineering

Ten original rule files: SSH failure, long DNS question, denied web request, shell process,
Suricata fixture signature, certificate notice, SSH burst, distinct destination ports,
Zeek/Suricata pair and ordered SSH failure/success. These are synthetic/lab hypotheses,
not production detections. Each has UUID, author, level, ATT&CK tags and positive/negative
cases in rules/tests. Correlations also test outside-window and reversed-order behavior.
The harness and timeout isolation checks were built before the custom rules.

Pinned compatible tooling: pySigma 1.5.1, SQLite backend 2.0.0, Sysmon pipeline 2.0.0,
Windows pipeline 2.0.1. The newer backend 2.1.0 requires pySigma 2; the Windows/Sysmon
packages still require <2. Do not mix those pins or force an unsupported installation.
The backend 2.0.0 supports native sliding correlations (event_count, value_count, temporal,
temporal_ordered); SQLite >=3.38 is required. Compilation and execution were tested against
SQLite 3.53.1 in the cloud environment. Check your local sqlite3.sqlite_version separately.

The custom pipeline runs after official Windows/Sysmon transforms when product=windows.
It maps native Sigma fields to normalized columns, adds a dataset restriction, and sets
pipeline state `table=events`. Generic correlation evidence selects dataset explicitly.
The backend constructor sets `event_id_field=id` for stable evidence. Generated base SQL
selects from events; generated correlation SQL uses bounded CTEs with event-time windows.
Literal strings and numbers (including scientific notation) are replaced with parameters.
Quoted identifiers are restricted to known columns and known generated aliases.

Supported ingestion logsource map: ssh->syslog, conn/dns/http/ssl/notice->zeek.*, web->web.access,
suricata->suricata.alert, process_creation->windows.sysmon; generic requires explicit
selection fields/datasets. Unmapped fields or log sources are `not_applicable` with reason.
Invalid or unsupported rules are `unsupported_or_invalid`. Compile coverage is not recall.
`applicable_to_loaded_data` reports presence of the corresponding dataset, not that a rule
has sufficient evidence or fires. Referenced evidence-only rules are counted separately
from the ten alerting rules. The rule catalog preserves author and imported license.

Supported bounded modifier subset: contains/startswith/endswith/all/re/cidr/cased/exists,
gt/gte/lt/lte/fieldref/base64/base64offset/wide/utf16/utf16le/utf16be/windash. Other modifiers
are reported rather than ignored. RE2 rejects backreferences/lookaround and runs linearly;
patterns are capped. Backend case handling is predominantly ASCII; do not infer full
Unicode/case-insensitive equivalence. CIDR expansion is text-based and should be checked
against your IP spelling. Keyword/fieldless selections, deprecated `condition: selection |
count(...)`, chained correlations, cross-file correlation references and aliases are not
supported by this bounded integration. A correlation YAML file must include its base
documents. Additional backend features do not imply Mini-SIEM supports them.

The runner reads at most 500 new ingest sequences per rule per micro-batch. The durable
cursor and persistent detection identity are committed with alerts/evidence. Failure does
not advance the cursor; it records the reason and lets other rules run. The CLI repeats
batches until done or a visible failure. SQL has a progress deadline (250 ms) and row cap
(500); the rule's overall evaluation also has that time budget. Dense windows that exceed
caps fail visibly; reduce batch/rule scope or tune bounded limits instead of discarding
matches. Backend correlation event IDs are resolved back to the event store.

Late policy: retained offline events remain eligible regardless of age. Correlation SQL
rescans an event-time window around new sequences, restricted to committed ingest sequences.
An arbitrarily late event can therefore complete an old hypothesis while its supporting
events remain retained. Results without a newly ingested evidence event are ignored.
A rule+sorted-evidence-set hash deduplicates re-evaluation; grouped evidence has a unique
key. An event may support multiple distinct correlation windows/rules. Changing a rule
under the same UUID does not automatically replay history; use a new UUID for an intentional
revision/backfill. An old cursor with exhausted retention is harmless because AUTOINCREMENT
sequence numbers never repeat.

Analyst statuses: new, triaged, true_positive, false_positive, suppressed. Notes are required
for a transition. Suppression requires a reason and timezone-aware future expiry; expired
suppression returns to new and retains its justification. Local JSONL notification summaries
preserve author attribution and can be re-emitted on repeated notify commands; delivery is
at-least-once, not a guaranteed exactly-once notification service.

Measure per-scenario recall, per-rule precision, benign alerts/day, grouped volume and
latency. A rule existing or compiling is not proof of ATT&CK detection ability. All original
rules are experimental. Asset or IOC enrichment is local annotation and does not establish
an attack. Never run upstream rule simulations or commands found in reference URLs.
