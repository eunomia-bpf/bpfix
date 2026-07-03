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
	@echo "  make bpfix-bench-published-results Audit tracked published main75 result summaries"
	@echo "  make release-check     Run packaging, example, empirical, and object-analysis gates"
	@echo "  make paper-arxiv       Build and validate paper/arxiv-submission.tar.gz"
	@echo "  make artifact-check    Run release, published-result, and paper artifact checks"
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

.PHONY: bpfix-bench-published-results
bpfix-bench-published-results:
	@echo "[bpfix-bench-published-results] Auditing tracked main75 result summaries..."
	cd $(CURDIR) && set -e; \
	base=bpfix-bench/published-results/main75; \
	common=(python3 bpfix-bench/tools/audit_results.py --split bpfix-bench/splits/main.txt --expected-count 75 --required-mode raw --required-mode bpfix --allow-missing-prompt-manifest --allow-dirty); \
	for spec in \
		"qwen36-one-shot||qwen36-27b/raw-one-shot|qwen36-27b/bpfix-one-shot" \
		"qwen36-retry2||qwen36-27b/raw-retry2|qwen36-27b/bpfix-retry2" \
		"glm52-one-shot|--allow-missing-model-digest|glm52/raw-one-shot|glm52/bpfix-one-shot" \
		"glm52-retry2|--allow-missing-model-digest|glm52/raw-retry2|glm52/bpfix-retry2" \
		"qwen25-one-shot||qwen25-3b/raw-one-shot|qwen25-3b/bpfix-one-shot" \
		"qwen25-retry2||qwen25-3b/raw-retry2|qwen25-3b/bpfix-retry2"; do \
		IFS='|' read -r name extra raw bpfix <<< "$$spec"; \
		args=("$${common[@]}"); \
		[[ -n "$$extra" ]] && args+=($$extra); \
		"$${args[@]}" "$$base/$$raw/summary.json" "$$base/$$bpfix/summary.json" >"/tmp/bpfix-bench-$$name-results-audit.json"; \
	done

.PHONY: release-check
release-check:
	@echo "[release-check] Running release readiness checks..."
	cd $(CURDIR) && scripts/check-release.sh

.PHONY: paper-arxiv
paper-arxiv:
	@echo "[paper-arxiv] Building arXiv package..."
	$(MAKE) -C $(CURDIR)/paper docker-arxiv

.PHONY: artifact-check
artifact-check: release-check bpfix-bench-published-results paper-arxiv

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
