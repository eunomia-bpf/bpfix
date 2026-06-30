# BPFix root Makefile.

SHELL := /bin/bash
CURDIR := $(shell pwd)
CARGO := cargo
EMPIRICAL_DIR := $(CURDIR)/bpfix-empirical
CASE ?= bpfix-empirical/cases/stackoverflow-60053570/replay-verifier.log
BPFIX_BENCH_AUDIT_ARGS :=
ifneq ($(strip $(SPLIT)),)
BPFIX_BENCH_AUDIT_ARGS += --split $(SPLIT)
endif
ifneq ($(strip $(MANIFEST)),)
BPFIX_BENCH_AUDIT_ARGS += --manifest $(MANIFEST)
endif
ifneq ($(strip $(SMOKE)),)
BPFIX_BENCH_AUDIT_ARGS += --smoke
endif

.DEFAULT_GOAL := help

.PHONY: help
help:
	@echo ""
	@echo "BPFix"
	@echo "====="
	@echo ""
	@echo "Rust"
	@echo "  make check             Run cargo check for the workspace"
	@echo "  make test              Run cargo test for the workspace"
	@echo "  make test-quick        Run bpfix CLI tests"
	@echo "  make fmt               Format Rust code"
	@echo "  make cli CASE=...      Run bpfix against a verifier/build/load log"
	@echo "  make empirical-smoke   Run the CLI against one empirical corpus case"
	@echo "  make empirical-eval    Run bpfix over bpfix-empirical and print metrics"
	@echo "  make bpfix-bench-audit  Audit bpfix-bench fixture structure and prompts"
	@echo "                          Optional: SPLIT=... MANIFEST=... SMOKE=1 for custom oracle checks"
	@echo "  make bpfix-bench-smoke  Validate bpfix-bench fixtures and buggy rejects"
	@echo "  make bpfix-bench-main-gate Run the frozen main75 bpfix-bench gate"
	@echo "  make bpfix-bench-dev40-gate   Run the full dev40 split quality gate"
	@echo "  make release-check     Run packaging, example, empirical, and object-analysis gates"
	@echo ""
	@echo "Utilities"
	@echo "  make clean             Remove generated Rust, empirical, and benchmark artifacts"
	@echo ""

.PHONY: check
check:
	@echo "[check] Running cargo check..."
	cd $(CURDIR) && $(CARGO) check --workspace

.PHONY: test
test:
	@echo "[test] Running cargo test..."
	cd $(CURDIR) && $(CARGO) test --workspace

.PHONY: test-quick
test-quick:
	@echo "[test-quick] Running bpfix tests..."
	cd $(CURDIR) && $(CARGO) test -p bpfix

.PHONY: fmt
fmt:
	@echo "[fmt] Formatting Rust code..."
	cd $(CURDIR) && $(CARGO) fmt --all

.PHONY: cli
cli:
	@echo "[cli] Running bpfix on $(CASE)..."
	cd $(CURDIR) && $(CARGO) run -p bpfix -- $(CASE)

.PHONY: empirical-smoke
empirical-smoke:
	@echo "[empirical-smoke] Running bpfix empirical corpus smoke case..."
	cd $(CURDIR) && $(CARGO) run -q -p bpfix -- bpfix-empirical/cases/stackoverflow-60053570/replay-verifier.log

.PHONY: empirical-eval
empirical-eval:
	@echo "[empirical-eval] Running bpfix diagnostic evaluation over bpfix-empirical..."
	cd $(CURDIR) && python3 bpfix-empirical/run-bpfix-eval.py --confusion --reject-fallback

.PHONY: bpfix-bench-smoke
bpfix-bench-smoke:
	@echo "[bpfix-bench-smoke] Validating LLM repair stress fixtures..."
	cd $(CURDIR) && python3 bpfix-bench/tools/run_suite.py --smoke

.PHONY: bpfix-bench-audit
bpfix-bench-audit:
	@echo "[bpfix-bench-audit] Auditing LLM repair stress fixtures..."
	cd $(CURDIR) && python3 bpfix-bench/tools/audit_cases.py $(BPFIX_BENCH_AUDIT_ARGS)

.PHONY: bpfix-bench-main-gate
bpfix-bench-main-gate:
	@echo "[bpfix-bench-main-gate] Auditing frozen bpfix-bench main75 suite..."
	cd $(CURDIR) && python3 bpfix-bench/tools/audit_cases.py \
		--split bpfix-bench/splits/main.txt \
		--manifest bpfix-bench/splits/main.manifest.json

.PHONY: bpfix-bench-dev40-gate
bpfix-bench-dev40-gate:
	@echo "[bpfix-bench-dev40-gate] Auditing dev40 split and buggy-reject smoke..."
	cd $(CURDIR) && python3 bpfix-bench/tools/audit_splits.py \
		--split bpfix-bench/splits/dev40.txt \
		--manifest bpfix-bench/splits/dev40.manifest.json \
		--profile dev \
		--expected-count 40 \
		--audit-cases --smoke

.PHONY: bpfix-bench-real-seed-candidate-gate
bpfix-bench-real-seed-candidate-gate:
	@echo "[bpfix-bench-real-seed-candidate-gate] Auditing historical real-project seed staging ledger..."
	cd $(CURDIR) && python3 bpfix-bench/tools/audit_splits.py \
		--split bpfix-bench/splits/real-seed-candidates.txt \
		--manifest bpfix-bench/splits/real-seed-candidates.manifest.json \
		--profile candidate \
		--disallow-overlap bpfix-bench/splits/dev40.txt \
		--audit-cases --smoke

.PHONY: release-check
release-check:
	@echo "[release-check] Running release readiness checks..."
	cd $(CURDIR) && scripts/check-release.sh

.PHONY: clean
clean:
	@echo "[clean] Removing Rust, empirical corpus, and benchmark build artifacts..."
	cd $(CURDIR) && $(CARGO) clean
	@rm -f $(EMPIRICAL_DIR)/replay-report.json
	@find $(EMPIRICAL_DIR)/cases -type f \( \
		-name '*.o' -o \
		-name 'replay-verifier.log' -o \
		-name 'verifier.log' -o \
		-name 'selftest_prog_loader' -o \
		-name 'verifier_load_result.json' -o \
		-name 'replay_load_result.json' \
	\) -delete
	@rm -rf $(CURDIR)/bpfix-bench/results
	@echo "[clean] Done."
