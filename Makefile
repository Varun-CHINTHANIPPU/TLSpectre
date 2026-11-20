SHELL := /bin/bash
.DEFAULT_GOAL := help
CONFIG ?= configs/server/P1.yaml
PYTHON ?= python3

.PHONY: help setup build pki ocsp server probe smoke test test-java bench clean tools e2-agent plan analyze figures tables E1 E2 E3 E4 E5 E6 E7 reproduce
setup:
	python3 -m pip install -e '.[dev]'
	$(MAKE) build
	$(MAKE) bench
help:
	@echo 'make build | pki | ocsp | server [CONFIG=...] | probe | smoke | test | test-java | bench'
build:
	cd java && mvn -B -ntp -DskipTests package
pki:
	bash pki/make_pki.sh
ocsp:
	bash pki/start_ocsp.sh
server:
	PYTHONPATH=harness $(PYTHON) -m tlslab.launch $(CONFIG)
smoke:
	PYTHONPATH=harness $(PYTHON) -m tlslab.smoke --config $(CONFIG)
probe:
	PYTHONPATH=harness $(PYTHON) -m tlslab.probe --config $(CONFIG)
test:
	PYTHONPATH=harness $(PYTHON) -m pytest -q tests
test-java:
	mvn -f java/pom.xml -B -ntp test
bench:
	mvn -f java/bench/pom.xml -B -ntp package
tools:
	bash scripts/install_tools.sh
e2-agent:
	bash scripts/install_e2_agent.sh
plan:
	PYTHONPATH=harness $(PYTHON) -m tlslab.run_experiment $(EXPERIMENT)
E1 E2 E3 E4 E5 E6 E7:
	PYTHONPATH=harness $(PYTHON) -m tlslab.run_experiment $@ --run $(RUN_FLAGS)
reproduce:
	@test "$(CONFIRM_FULL_EXPERIMENTS)" = yes || (echo "Set CONFIRM_FULL_EXPERIMENTS=yes to authorize lengthy local studies"; exit 2)
	$(MAKE) E1 E2 E3 E4 RUN_FLAGS="$(RUN_FLAGS)"
	@echo 'E5-E7 require explicit root isolation; execute individually with --isolated'
analyze:
	PYTHONPATH=harness $(PYTHON) -m tlslab.analysis.artifacts --figures --tables --strict
figures:
	PYTHONPATH=harness $(PYTHON) -m tlslab.analysis.artifacts --figures --strict
tables:
	PYTHONPATH=harness $(PYTHON) -m tlslab.analysis.artifacts --tables --strict
clean:
	rm -rf java/target
