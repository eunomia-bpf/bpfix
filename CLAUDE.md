# CLAUDE.md

This file provides guidance to Claude Code when working with this repository.

## Project Overview

**BPFix** — userspace, Rust-style diagnostics for eBPF verifier failures.

BPFix analyzes eBPF verifier verbose logs to produce stable, structured diagnostics. The active product scope is a pure-userspace CLI/API that explains verifier rejections with stable error IDs, proof obligations, source/bytecode spans, and actionable help text. Automatic patch synthesis is not part of the current maintained scope.

### Core Thesis

The eBPF verifier at LOG_LEVEL2 already outputs rich per-instruction abstract state (register types, scalar bounds, pointer offsets, BTF source lines, backtracking info). When a program is rejected, this trace contains all the information needed to understand the failure — but it's buried in 500-1000+ lines of flat text. BPFix parses the complete proof trace to extract where the proof was lost, why, and how to fix it.

## Using Codex CLI as Subagent

OpenAI Codex CLI is available on this machine (`codex-cli 0.113.0`, default model: `gpt-5.4`).

### Division of Labor (IMPORTANT)
- **Codex handles**: ALL code implementation, data collection, data analysis, experiment scripts, literature search/summarization, prototype building, test writing
- **Claude Code handles**: scheduling/dispatching codex tasks, document writing (non-tmp), CLAUDE.md/memory updates, architectural decisions, reviewing codex output, paper framing
- **Claude Code must NEVER**: write analysis code directly, run experiments directly, or manually collect data — always delegate to codex

### Workflow Rules
- **Codex output goes to `docs/tmp/`** — codex writes analysis/research/design docs into `docs/tmp/`
- **Claude maintains non-tmp docs** — Claude directly edits `CLAUDE.md`, `docs/research-plan.md`, and other non-tmp documents
- **Codex runs in background** — use `run_in_background: true` for all codex tasks; Claude dispatches and moves on
- **Review cycle** — when codex produces a new document, dispatch another codex to review it; iterate until quality is sufficient
- **Never ask for confirmation** — just keep going, do all work, iterate multiple rounds autonomously
- **Single agent for build+code+test** — Do NOT split building, code modification, and testing/running into separate subagents. Use ONE agent that can iterate: write code → run tests → see failure → fix → rerun. Only split when tasks are truly independent (e.g., two unrelated eval scripts). This avoids the problem where a test agent finds bugs but can't fix them.

### Usage
```bash
# Non-interactive execution — no sandbox, no prompts
codex exec --dangerously-bypass-approvals-and-sandbox "your prompt here"

# With a specific working directory
codex exec --dangerously-bypass-approvals-and-sandbox -C /path/to/dir "your prompt here"
```

## Repository Structure

```
ebpf-verifier-agent/
├── CLAUDE.md                    # This file
├── README.md                    # Project overview
├── bpfix-bench/                 # Unified benchmark and raw external corpus
│   ├── manifest.yaml            # Single entry point for replayable cases
│   ├── taxonomy.yaml            # The 5-class benchmark failure taxonomy
│   ├── cases/                   # Self-contained local reproducers
│   └── raw/                     # SO/GH/commit records, reproduced and unreproduced
├── bpfix/                       # Public Python package and diagnostic engine
│   ├── api/                     # Public Python API
│   ├── baseline/                # Baseline diagnostic implementations
│   ├── catalogs/                # Error and obligation catalogs used by diagnostics
│   ├── extractor/               # Extract structured diagnostics from verifier output
│   │   ├── pipeline.py          # Main diagnostic pipeline
│   │   ├── trace_parser.py      # Public trace parser entry point
│   │   └── engine/              # Active trace analysis helpers
│   └── schema/                  # JSON schema for structured diagnostics
├── interface/                   # Compatibility alias for older imports
├── tools/                       # Benchmark replay, validation, audit, and eval tools
│   ├── validate_benchmark.py    # Rebuild/load replay validator
│   ├── replay_case.py           # Per-case replay helper
│   ├── evaluate_benchmark.py    # Fresh-replay diagnostic evaluation runner
│   └── sync_external_raw_bench.py # Raw external audit/index generator
├── docs/
│   ├── research-plan.md         # Master research plan (single hub)
│   ├── paper-outline.md         # Paper outline
│   └── tmp/                     # Codex-generated working documents
├── scripts/                     # Utility scripts
└── tests/                       # Test suite
```

## Research Phases

### Phase 1: Case Collection ✅
- Unified under `bpfix-bench/`
- 235 replayable verifier-reject cases currently admitted: 85 kernel selftests, 86 Stack Overflow, 18 GitHub issues, 46 GitHub commits
- 736 external SO/GH/commit raw records archived for reproduced/unreproduced audit, plus 201 kernel-selftest raw fixtures
- 5-class taxonomy with stable error IDs

### Phase 2: Proof Trace Analysis ✅ / CURRENT
- Parse verifier verbose logs (per-instruction register state traces)
- Detect critical state transitions (bounds collapse, type downgrade, provenance loss)
- Extract causal chains from error point back to root cause instruction
- Map to source code via BTF line_info annotations

### Phase 3: Open-Source Tool Hardening (CURRENT)
- Keep `bpfix` as the public package namespace
- Keep `interface` only as a compatibility alias
- Maintain README, benchmark docs, and evaluation docs as current fact sources
- Keep repair synthesis out of the active API until it is implemented and validated

## Key Design Decisions
- **Pure userspace** — verifier LOG_LEVEL2 already has complete abstract state; no kernel patch needed
- **Analyze full state trace, not just error message** — key difference from Pretty Verifier (regex on error line only)
- **Stable CLI/API first** — `python -m bpfix`, `bpfix` console script, and `from bpfix import build_diagnostic`
- **Benchmark facts come from manifests** — use `bpfix-bench/manifest.yaml` and `bpfix-bench/raw/index.yaml`, not historical `docs/tmp/` reports
