.PHONY: install check test rules demo eval sensors clean
install:
	python -m pip install -r requirements.lock
	python -m pip install --no-deps -e .
check:
	ruff check .
	ruff format --check .
	mypy
	pytest --junitxml=results/tests.xml
	minisiem rules test
test:
	pytest
rules:
	minisiem rules compile
	minisiem rules test
demo:
	minisiem init
	minisiem simulate
	minisiem ingest data/synthetic/events.jsonl --source synthetic
	minisiem detect
eval:
	minisiem evaluate --events 10000
sensors:
	python lab/traffic/benign_pcap.py data/pcaps/benign.pcap
	python lab/sensors/run_offline.py zeek data/pcaps/benign.pcap data/zeek-run
	python lab/sensors/run_offline.py suricata data/pcaps/benign.pcap data/suricata-run
clean:
	rm -rf build dist .pytest_cache .mypy_cache .ruff_cache
