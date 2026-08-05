# Full repair-cost experiment artifacts

This directory is a complete snapshot of the local model-backed repair-cost and
prompt-ablation runs performed on the frozen `main75` split in August 2026. It
is intentionally larger than the compact summaries under `published-results/`.

The snapshot preserves the generated prompt and model response for every
attempt, extracted candidate source, executable-oracle result, compiled BPF
object, per-case result, run summary, experiment plan, and independent review.
Absolute local paths in the JSON metadata are retained as execution provenance.

## Valid headline runs

The success--cost experiment uses:

- `cost-main75-current-server/20260801T075920882474Z-pid3975799/raw/`
- `cost-main75-current-server/20260801T082437160849Z-pid4040619/bpfix/`

Its interpretation and independent review are in
`cost-main75-current-server/result-report.md` and
`cost-main75-current-server/result-review.md`.

The one-shot mechanism ablation uses:

- `ablation-main75-current-server/full/20260802T073105095759Z-pid1058068/source-only/`
- `ablation-main75-current-server/full/20260802T074345660111Z-pid1071164/matched-raw-tail/`
- `ablation-main75-current-server/full/20260802T075855562289Z-pid1092324/bpfix-no-help/`
- `ablation-main75-current-server/full/20260802T082035959683Z-pid1127965/bpfix-neutral/`

Its plan, plan review, result report, and independent result review are in
`ablation-main75-current-server/`.

## Retained development and invalid runs

Preflights and prompt-only development runs are retained to make the execution
history auditable. The first full-neutral run at
`ablation-main75-current-server/full/20260802T080952373002Z-pid1112388/` is
invalid because the model service exited after 60 usage-bearing calls; it must
not be used in the reported four-way comparison. The valid full-neutral rerun
is listed above and has 75/75 token-usage coverage.

## Integrity

`SHA256SUMS` covers every artifact in this directory except the checksum file
itself. From the repository root, verify the snapshot with:

```bash
sha256sum --check bpfix-bench/results/SHA256SUMS
```

