# BPFix root Makefile.

SHELL := /bin/bash
CURDIR := $(shell pwd)

PYTHON := python3
PYTEST := $(PYTHON) -m pytest

BENCH_DIR := $(CURDIR)/bpfix-bench
PAPER_DIR := $(CURDIR)/docs/paper
TMP_DIR := $(CURDIR)/docs/tmp

.DEFAULT_GOAL := help

.PHONY: help
help:
	@echo ""
	@echo "BPFix"
	@echo "====="
	@echo ""
	@echo "Testing"
	@echo "  make test              Run the full pytest suite"
	@echo "  make test-quick        Run pytest quietly"
	@echo ""
	@echo "Benchmark"
	@echo "  make bench-validate    Replay and validate all bpfix-bench cases"
	@echo "  make bench-eval        Replay cases, then run BPFix/baseline/ablation eval"
	@echo "  make bench-raw-audit   Regenerate raw external audit index"
	@echo ""
	@echo "Paper"
	@echo "  make paper             Compile LaTeX paper once"
	@echo "  make paper-full        Compile paper with bibliography"
	@echo "  make paper-clean       Remove LaTeX build artifacts"
	@echo ""
	@echo "Utilities"
	@echo "  make lint              Run flake8 on active Python code"
	@echo "  make loc               Count lines of code in active Python modules"
	@echo "  make clean             Remove generated benchmark and paper artifacts"
	@echo ""

.PHONY: test
test:
	@echo "[test] Running full pytest suite..."
	cd $(CURDIR) && $(PYTEST) tests/ -v

.PHONY: test-quick
test-quick:
	@echo "[test-quick] Running pytest..."
	cd $(CURDIR) && $(PYTEST) tests/ -q

.PHONY: bench-validate
bench-validate:
	@echo "[bench-validate] Replaying bpfix-bench..."
	cd $(CURDIR) && $(PYTHON) tools/validate_benchmark.py --replay bpfix-bench --timeout-sec 60

.PHONY: bench-raw-audit
bench-raw-audit:
	@echo "[bench-raw-audit] Regenerating raw external audit index..."
	cd $(CURDIR) && $(PYTHON) tools/sync_external_raw_bench.py --apply

.PHONY: bench-eval
bench-eval:
	@echo "[bench-eval] Replaying bpfix-bench and running diagnostic eval..."
	cd $(CURDIR) && $(PYTHON) tools/evaluate_benchmark.py --benchmark bpfix-bench --timeout-sec 60

.PHONY: paper
paper:
	@echo "[paper] Compiling LaTeX paper..."
	cd $(PAPER_DIR) && pdflatex -interaction=nonstopmode main.tex
	@echo "[paper] Output: $(PAPER_DIR)/main.pdf"

.PHONY: paper-full
paper-full:
	@echo "[paper-full] Compiling paper with bibliography..."
	cd $(PAPER_DIR) && pdflatex -interaction=nonstopmode main.tex
	cd $(PAPER_DIR) && bibtex main || true
	cd $(PAPER_DIR) && pdflatex -interaction=nonstopmode main.tex
	cd $(PAPER_DIR) && pdflatex -interaction=nonstopmode main.tex
	@echo "[paper-full] Output: $(PAPER_DIR)/main.pdf"

.PHONY: paper-clean
paper-clean:
	@echo "[paper-clean] Removing LaTeX build artifacts..."
	cd $(PAPER_DIR) && rm -f *.aux *.bbl *.blg *.log *.out *.toc *.fls *.fdb_latexmk *.synctex.gz

.PHONY: lint
lint:
	@echo "[lint] Running flake8 on active Python code..."
	$(PYTHON) -m flake8 \
		--max-line-length=120 \
		--extend-ignore=E203,W503 \
		$(CURDIR)/bpfix/ $(CURDIR)/tools/ $(CURDIR)/tests/

.PHONY: loc
loc:
	@echo "[loc] Active Python modules:"
	@find bpfix tools tests -name '*.py' -print0 | xargs -0 wc -l | sort -rn | tail -1

.PHONY: clean
clean: paper-clean
	@echo "[clean] Removing generated benchmark artifacts..."
	@rm -f $(BENCH_DIR)/replay-report.json
	@find $(BENCH_DIR)/cases -type f \( \
		-name '*.o' -o \
		-name 'replay-verifier.log' -o \
		-name 'verifier.log' -o \
		-name 'selftest_prog_loader' -o \
		-name 'verifier_load_result.json' -o \
		-name 'replay_load_result.json' \
	\) -delete
	@rm -f $(TMP_DIR)/*.md
	@echo "[clean] Done."
