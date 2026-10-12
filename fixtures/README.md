# Original synthetic fixtures (MIT)

zeek_conn.jsonl, zeek_http.jsonl and suricata.jsonl were produced by pinned sensor images
from the project's own eight-packet benign HTTP PCAP generator. The PCAP is generated
locally and ignored. No network traffic is sent. The other Zeek DNS/SSL/notice records,
syslog/web/JSON and malformed examples are handcrafted synthetic records. They are tiny
fixtures, not collected logs. User `synthetic-alice`, hosts `synthetic-lab`/lab.invalid,
and RFC5737 IP addresses are deliberately fictional. UIDs are sensor-generated opaque
identifiers; do not compare them across Zeek runs. Community ID is deterministic.

Expected sensor output: one Zeek conn and one http record; Suricata EVE has one original
fixture alert, one http record, one flow and a stats record. The committed Suricata fixture
omits engine/runtime stats. Offline reference run decoded 8 packets, zero invalid packets,
one loaded rule and one alert. The normalized common flow ID is
`1:mZngVHYvXxnJn1EvvM/SV4l0dTU=`. No upstream PCAP, dataset or rule is included.
