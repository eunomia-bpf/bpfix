# BPFix root Makefile.

SHELL := /bin/bash
CURDIR := $(shell pwd)
CARGO := cargo
BENCH_DIR := $(CURDIR)/bpfix-bench
CASE ?= bpfix-bench/cases/stackoverflow-60053570/replay-verifier.log

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
	cd $(CURDIR) && $(CARGO) run -p bpfix -- $(CASE) --format both

.PHONY: bench-smoke
bench-smoke:
	@echo "[bench-smoke] Running bpfix benchmark smoke case..."
	cd $(CURDIR) && $(CARGO) run -q -p bpfix -- bpfix-bench/cases/stackoverflow-60053570/replay-verifier.log --format json

.PHONY: bench-eval
bench-eval:
	@echo "[bench-eval] Running bpfix diagnostic benchmark..."
	cd $(CURDIR) && python3 bpfix-bench/run-bpfix-eval.py --confusion --reject-fallback

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
	@echo "[clean] Done."
