# BPFix root Makefile.

SHELL := /bin/bash
CURDIR := $(shell pwd)
CARGO := cargo
BENCH_DIR := $(CURDIR)/bpfix-bench
CASE ?= bpfix-bench/cases/stackoverflow-60053570/replay-verifier.log
BPFIX_TEST_AUDIT_ARGS :=
ifneq ($(strip $(SPLIT)),)
BPFIX_TEST_AUDIT_ARGS += --split $(SPLIT)
endif
ifneq ($(strip $(MANIFEST)),)
BPFIX_TEST_AUDIT_ARGS += --manifest $(MANIFEST)
endif
ifneq ($(strip $(SMOKE)),)
BPFIX_TEST_AUDIT_ARGS += --smoke
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
	@echo "  make bench-smoke       Run the CLI against one benchmark case"
	@echo "  make bench-eval        Run bpfix over bpfix-bench and print metrics"
	@echo "  make bpfix-test-audit  Audit bpfix-test fixture structure and prompts"
	@echo "                          Optional: SPLIT=... MANIFEST=... SMOKE=1 for custom clean oracles"
	@echo "  make bpfix-test-smoke  Validate bpfix-test fixtures and buggy rejects"
	@echo "  make bpfix-test-main-gate Run the combined 61-case bpfix-test gate"
	@echo "  make bpfix-test-real-seed-candidate-gate Audit real-project seed staging candidates"
	@echo "  make bpfix-test-dev40-gate   Run the full dev40 split quality gate"
	@echo "  make release-check     Run packaging, example, benchmark, and object-analysis gates"
	@echo ""
	@echo "Utilities"
	@echo "  make clean             Remove generated Rust and benchmark artifacts"
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

.PHONY: bench-smoke
bench-smoke:
	@echo "[bench-smoke] Running bpfix benchmark smoke case..."
	cd $(CURDIR) && $(CARGO) run -q -p bpfix -- bpfix-bench/cases/stackoverflow-60053570/replay-verifier.log

.PHONY: bench-eval
bench-eval:
	@echo "[bench-eval] Running bpfix diagnostic benchmark..."
	cd $(CURDIR) && python3 bpfix-bench/run-bpfix-eval.py --confusion --reject-fallback

.PHONY: bpfix-test-smoke
bpfix-test-smoke:
	@echo "[bpfix-test-smoke] Validating LLM repair stress fixtures..."
	cd $(CURDIR) && python3 bpfix-test/tools/run_suite.py --smoke

.PHONY: bpfix-test-audit
bpfix-test-audit:
	@echo "[bpfix-test-audit] Auditing LLM repair stress fixtures..."
	cd $(CURDIR) && python3 bpfix-test/tools/audit_cases.py $(BPFIX_TEST_AUDIT_ARGS)

.PHONY: bpfix-test-main-gate
bpfix-test-main-gate:
	@echo "[bpfix-test-main-gate] Auditing combined bpfix-test working suite..."
	cd $(CURDIR) && python3 bpfix-test/tools/audit_cases.py \
		--split bpfix-test/splits/main.txt

.PHONY: bpfix-test-dev40-gate
bpfix-test-dev40-gate:
	@echo "[bpfix-test-dev40-gate] Auditing dev40 split and buggy-reject smoke..."
	cd $(CURDIR) && python3 bpfix-test/tools/audit_splits.py \
		--split bpfix-test/splits/dev40.txt \
		--manifest bpfix-test/splits/dev40.manifest.json \
		--profile dev \
		--expected-count 40 \
		--audit-cases --smoke

.PHONY: bpfix-test-real-seed-candidate-gate
bpfix-test-real-seed-candidate-gate:
	@echo "[bpfix-test-real-seed-candidate-gate] Auditing real-project seed staging candidates..."
	cd $(CURDIR) && python3 bpfix-test/tools/audit_splits.py \
		--split bpfix-test/splits/real-seed-candidates.txt \
		--manifest bpfix-test/splits/real-seed-candidates.manifest.json \
		--profile candidate \
		--disallow-overlap bpfix-test/splits/dev40.txt \
		--audit-cases --smoke

.PHONY: bpfix-test-clean60-gate
bpfix-test-clean60-gate:
	@echo "[bpfix-test-clean60-gate] Auditing clean60 heldout split..."
	cd $(CURDIR) && python3 bpfix-test/tools/audit_splits.py \
		--split bpfix-test/splits/clean60.txt \
		--manifest bpfix-test/splits/clean60.manifest.json \
		--profile clean60 \
		--expected-count 60 \
		--disallow-overlap bpfix-test/splits/dev40.txt \
		--audit-cases --smoke

.PHONY: bpfix-test-prompt-gate
bpfix-test-prompt-gate:
	@test -n "$(PROMPT_MANIFEST)" || (echo "Set PROMPT_MANIFEST to the clean60 prompt manifest"; exit 2)
	@echo "[bpfix-test-prompt-gate] Verifying clean60 prompt manifest..."
	cd $(CURDIR) && python3 bpfix-test/tools/prompt_manifest.py \
		--split bpfix-test/splits/clean60.txt \
		--expected-count 60 \
		--verify $(PROMPT_MANIFEST)

.PHONY: bpfix-test-clean60-paper-gate
bpfix-test-clean60-paper-gate: bpfix-test-clean60-gate bpfix-test-prompt-gate

.PHONY: bpfix-test-result-gate
bpfix-test-result-gate:
	@test -n "$(RESULT_SUMMARIES)" || (echo "Set RESULT_SUMMARIES to legacy clean60 summary.json paths"; exit 2)
	@test -n "$(PROMPT_MANIFEST)" || (echo "Set PROMPT_MANIFEST to the legacy clean60 prompt manifest"; exit 2)
	@echo "[bpfix-test-result-gate] Running legacy clean60 admission, prompt, and result gates..."
	$(MAKE) bpfix-test-clean60-paper-gate PROMPT_MANIFEST=$(PROMPT_MANIFEST)
	cd $(CURDIR) && python3 bpfix-test/tools/audit_results.py \
		--split bpfix-test/splits/clean60.txt \
		--expected-count 60 \
		--prompt-manifest $(PROMPT_MANIFEST) \
		--required-mode source-only \
		--required-mode raw \
		--required-mode trimmed-raw \
		--required-mode bpfix \
		$(RESULT_SUMMARIES)

.PHONY: release-check
release-check:
	@echo "[release-check] Running release readiness checks..."
	cd $(CURDIR) && scripts/check-release.sh

.PHONY: clean
clean:
	@echo "[clean] Removing Rust and benchmark build artifacts..."
	cd $(CURDIR) && $(CARGO) clean
	@rm -f $(BENCH_DIR)/replay-report.json
	@find $(BENCH_DIR)/cases -type f \( \
		-name '*.o' -o \
		-name 'replay-verifier.log' -o \
		-name 'verifier.log' -o \
		-name 'selftest_prog_loader' -o \
		-name 'verifier_load_result.json' -o \
		-name 'replay_load_result.json' \
	\) -delete
	@rm -rf $(CURDIR)/bpfix-test/results
	@echo "[clean] Done."
