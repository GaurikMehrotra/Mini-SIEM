# License and source review

Reviewed 2026-10-12 using upstream repository documents and installed metadata. The original
Mini-SIEM implementation/rules/fixtures are MIT licensed. No upstream rule or dataset is
committed. Public telemetry was selected and reviewed at the user's explicit request. pySigma/backend are dynamically imported as separately installed Python packages.

| Component | Verified source / license | Handling |
| --- | --- | --- |
| SigmaHQ rules | [Sigma LICENSE](https://github.com/SigmaHQ/sigma/blob/master/LICENSE), [DRL 1.1](https://github.com/SigmaHQ/Detection-Rule-License/blob/main/LICENSE.Detection.Rules.md) | Keep authors, source URI and license; matched-alert views must retain authors. Download only into ignored rules/sigma_upstream. |
| pySigma | [LGPL 2.1](https://github.com/SigmaHQ/pySigma/blob/main/LICENSE) | Keep notices and license, provide source/modifications when redistributing, preserve recipient replacement/relinking rights. No vendored or modified pySigma. Verify obligations for your exact packaging; MIT on this app does not relicense dependencies. |
| SQLite backend | LGPL-3.0-only from installed package License-Expression and bundled license | Same separate-dependency review, no vendoring. |
| Sysmon/Windows pipelines | LGPL-2.1 from installed package metadata | Separate pinned packages with preserved notices. |
| Zeek | [COPYING](https://github.com/zeek/zeek/blob/master/COPYING), BSD-style 3-clause | Preserve copyright, conditions and disclaimer when redistributing. Use official zeek/zeek image. |
| Suricata | [LICENSE](https://github.com/OISF/suricata/blob/master/LICENSE), GPL-2.0 | Use separate executable/container; redistribution of binaries/images requires corresponding source and notices as applicable. |
| jasonish Docker build files | [README/license](https://github.com/jasonish/docker-suricata), MIT | The build-file license does not change Suricata's GPL license. |
| Suricata rule set | Original lab/sensors/local.rules, MIT | No ET, GPL-community or commercial rules downloaded or bundled. |
| RE2 / google-re2 | BSD-style upstream RE2 | Keep dependency notices; no backtracking fallback. |
| Public dataset | [Splunk attack_data Apache-2.0 license](https://github.com/splunk/attack_data/blob/4389fa7a4e74a7c083c0fbe448fa2c7c32378981/LICENSE) | Reviewed pinned lab subset; preserve attribution/license and mark modifications if distributing. No telemetry committed. See public_dataset.md. |

Docker distribution includes Python wheels and their `.dist-info` notices. Before publishing
an image, create a dependency SBOM and include relevant licenses and source-offer information
for copyleft dependencies; merely listing names here is not a complete legal assessment.
This is general information, not legal advice. Upstream URLs in logs/rules are never fetched
at runtime.

The tested upstream subset consists of `proc_creation_win_cmdkey_recon.yml` (jmallette,
Florian Roth, Nasreddine Bencherchali) and `proc_creation_win_net_user_add.yml` (Endgame,
JHasenbusch). Both compile under the Windows/Sysmon/custom mapping. No Windows dataset was
loaded during that coverage check: compiled=2, applicable datasets=0, fired=unmeasured.
Coverage report and downloaded content remain ignored. This is not a broad SigmaHQ audit.
