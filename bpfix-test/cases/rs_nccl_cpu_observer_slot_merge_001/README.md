# rs_nccl_cpu_observer_slot_merge_001

This candidate is a minimized real-project seed from
`nccl-eBPF/src/kernel_observer/nccl_cpu_observer.bpf.c`.

The upstream program is a `sched_switch` tracepoint observer for NCCL CPU
contention. It reads a target process from `config_map`, updates a per-CPU
rolling window in `percpu_slot_map`, classifies contention, and publishes the
result to an mmapable `state_map`. This minimized version uses a per-CPU hash
slot keyed by the configured target PID, which models the natural extension
from one watched NCCL process to several concurrent jobs.

This case keeps that observer workflow but injects a proof-lifecycle bug: the
non-null proof for the per-CPU slot is established only inside one
tracepoint-data branch. After the branch merge, the program reads and writes
`slot` on paths where the verifier still sees it as `map_value_or_null`.

A correct repair must move or duplicate the slot null check so the proof
dominates all later window accounting. The oracle requires the repair to load
as a `sched_switch` tracepoint, keep the config filter, preserve per-CPU slot
accounting, and keep publishing the computed contention state to `state_map`.
