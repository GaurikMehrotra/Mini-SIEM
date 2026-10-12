# Reviewed public-data evaluation

Source: [Splunk attack_data](https://github.com/splunk/attack_data), pinned commit
`4389fa7a4e74a7c083c0fbe448fa2c7c32378981`. [License at this revision](https://github.com/splunk/attack_data/blob/4389fa7a4e74a7c083c0fbe448fa2c7c32378981/LICENSE):
Apache-2.0. Reviewed 2026-10-12 at the user's request. Preserve the license, copyright/
attribution and any applicable notices; mark modifications when redistributing. This
project does not redistribute public telemetry. Upstream LICENSE and per-case provenance
metadata are saved only under ignored data/public/splunk/. Manifest hashes and aggregate
results reveal no raw users, hosts, commands, domains or credentials.

The publisher's YAML labels identify environment=attack_range and ATT&CK T1059.001.
The encoded PowerShell case is attributed to Patrick Bareiss; RemoteSigned to Teoderick
Contreras, Splunk. These are exported logs from controlled lab generation. No attack
commands, simulations, scripts or URLs from telemetry were executed or visited.

## Reproduce

Git and Git LFS must be available; Python dependencies are already pinned. From the root:

```bash
git lfs version
minisiem evaluate-public
jq '{records_total, scenarios_total, scenarios_recovered, event_precision, false_positive_alerts_per_day}' results/public/public_results.json
jq '.cases[] | {case,input_records,unique_events,duplicates,quarantined,fired_rules,grouped_alerts}' results/public/public_results.json
# Once cached, this reruns without network or downloads:
minisiem evaluate-public --offline
```

The downloader reads only the pinned repository license and case metadata, verifies their
lab labels, then downloads the three specific LFS objects using `git lfs smudge`. It checks
each pointer's SHA256/size against configs/public_dataset.json, then checks downloaded
bytes before consuming or reusing them. It never runs a corpus-wide `git lfs pull` or
updates to a newer commit silently. Partial/modified files fail; expected hashes are never
changed to make validation pass. GitHub read-only proxy authentication is reused. The
cloud policy blocks the GitHub media hostname, so the verified Git LFS route is used.
No new token, external secret or network allowlist change was required.

The public evaluation is explicitly requested through a separate command; default
`evaluate`, `make check`, and CI do not download or consume public records. Tests of this
adapter use original synthetic XML only. All public telemetry, local license copies,
metadata, temporary databases and generated reports remain outside Git.

## What the labels support

| Unit | Input records | Unique events | Duplicate records | Quarantine | Grouped alerts | Relevant rule fired |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| encoded_powershell | 7 | 4 | 3 | 0 | 3 | process_shell |
| powershell_remotesigned | 1 | 1 | 0 | 0 | 1 | process_shell |

Both labeled scenarios contained evidence that fired the existing `process_shell` rule.
This rule selects PowerShell process presence; it does not establish encoded-command
malice or RemoteSigned abuse. The scenario recovery fraction is 2/2 on this deliberately
narrow subset. The two encoded exports overlap; the stable scenario source/raw identity
accounts for that overlap. Other log-source rules are outside this Windows sample's scope.

All eight input records have EventID=1 and the Sysmon Operational channel; the report
checks those source invariants, stores exact bounded XML raw records/unmapped EventData,
and verifies replay adds no events or alerts. `windows_xml` handles exported XML, not
binary EVTX. The evaluation frames the small verified exports, skips only surrounding
whitespace/BOM, and rejects unknown outside content, malformed XML, DTD/entity declarations,
duplicate field names, wrong channels, and size-limit violations. Timestamps come from
SystemTime (or explicitly UTC-named UtcTime), not the wall clock. Archived records are
processed in disposable SQLite databases, preserving current production/demo retention.

**Not measurable from these labels:** per-event malicious/benign precision or recall,
false-positive alerts/day, real-time time-to-detect, or production generalization. JSON
uses null for these metrics, rather than fabricated zeroes or perfect precision. The
public run complements the independently labeled original synthetic evaluation; it does
not replace it. Eight records and two technique-labeled samples are not a benchmark of
broad ATT&CK coverage. Reports include compile coverage, case counts, replay, raw-file
checksums, config and miss analysis, plus CSV output.

An OTRF Security-Datasets candidate was considered but not used: its inspected revision's
README mentioned GPL-3.0 while LICENSE contained MIT. The unambiguous Splunk Apache-2.0
source was selected instead. This is a source/terms review, not legal advice.
