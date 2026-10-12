# Public contract and storage schema

API contract v1; current SQLite schema v3. This is ECS-inspired, not an ECS-compliant event
store. Official ECS definitions inspected: schemas/source.yml and schemas/event.yml in
elastic/ecs; flattened SQL names avoid quoting dotted fields. Windows/Zeek/Suricata native
fields are retained in `fields` and the bounded `raw` record.

| Column | ECS-inspired field or purpose |
| --- | --- |
| timestamp | @timestamp, UTC ISO text with six fractional digits |
| original_timestamp, original_timezone | Source spelling and offset/uncertainty |
| ingested_at, ingest_seq | Ingest time and monotonic SQLite AUTOINCREMENT sequence |
| id | SHA256 stable source/raw identity; unique independently of ingest_seq |
| dataset | event.dataset |
| source | Operator's stable input stream ID, not source.ip |
| host, user | host.name, user.name |
| source_ip, source_port | source.ip, source.port |
| destination_ip, destination_port | destination.ip, destination.port |
| transport, community_id | network.transport, network.community_id |
| action, outcome, event_code | event.action, event.outcome, event.code |
| process_name, command_line | process.name, process.command_line |
| original_file_name, channel | process.pe.original_file_name, winlog.channel |
| dns_question | dns.question.name |
| http_url, http_status | url.original, http.response.status_code |
| tls_server_name | tls.client.server_name |
| message | Searchable bounded message |
| fields, raw, warnings | JSON unmapped data, original record and uncertainty |

IP values are canonicalized; ports are in 0..65535. An invalid IP/port rejects the record.
Naive timestamps assume UTC with a warning. Numeric timestamps are Unix seconds, not
milliseconds. Missing/malformed/overflow time is imputed at ingest and flagged, never
silently represented as reliable event time. Future timestamps beyond 300 seconds and
pre-2000 timestamps are retained with warnings. RFC3164 lacks year/zone: current ingest
year and UTC are assumed explicitly. Supply JSON with explicit year/offset for archives.
Query timestamps never use imputation: explicit valid zones are mandatory. Time ranges
are half-open [start,end). API queries cap range, rows, input length and offset.

All inserts/checkpoints are transactional. WAL allows readers alongside the single writer.
FTS5 uses an external-content table and insert/delete triggers. Fixed indexes cover time,
host, dataset, source/destination IP, ingest time and community ID. Keep normal indexes
on for bounded application queries; the disposable benchmark drops only its time index
for an ablation. Batch_size is configurable; no unbounded queue exists.

`quarantine` records bounded invalid input and reason; `ingest_runs` records rate/lag/errors.
`checkpoints` stores path/device/inode/offset/prefix digest, source/parser binding, rotated
owner path and oversized-line drain state; same-inode rewrites/truncation
rewind and ID dedup prevents replays. Rename rotation drains the old inode if its file is
still in the same directory. Incomplete final lines wait for append, including tails completed after rename rotation.
Oversized partial lines retain drain state across restarts so their later suffix cannot
be treated as a new event. Changing a checkpointed stream source/parser is rejected. Copytruncate can lose
bytes deleted before any reader sees them: no file reader can guarantee recovery of those
bytes. Prefer rename rotation and retain the old file until drained. HTTP inputs do not
have file checkpoints and are deduplicated by source/raw identity.

`links` joins sensor evidence; `alerts`, `evidence`, `detections`, `watermarks`, `rule_stats`
and `rule_catalog` retain detection state, bounded rule metadata and analyst workflow.
Schema upgrades in store/migrations.py are transactional/additive, with an explicit version
check. Unknown versions are rejected. Retention cascades event deletion and cleans FTS,
orphan alerts, and old quarantine/run metadata; durable sequence IDs are not reused after
retention. Suppression expiry resurfaces during reads and detection ticks.

Search grammar (no raw SQL):

```text
expression := term (OR term)*
term       := factor (AND factor)*
factor     := NOT factor | '(' expression ')' | field operator JSON_string_or_integer
operator   := = | != | < | <= | > | >= | CONTAINS
```

FTS input is an escaped literal phrase; advanced FTS operators are intentionally unavailable.
`NOT` wraps missing/null values with COALESCE. Results sort by timestamp/id for stable
bounded offset pagination. Concurrent inserts can shift offsets; take a fixed time range
and deduplicate IDs downstream. No promise of snapshot pagination is made.
