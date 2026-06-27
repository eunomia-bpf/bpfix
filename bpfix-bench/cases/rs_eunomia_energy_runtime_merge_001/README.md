# rs_eunomia_energy_runtime_merge_001

This case is a minimized real-project seed from eunomia.dev's energy monitor.
The upstream program records process start timestamps, computes the previous
process runtime on `sched_switch`, updates a runtime map, and emits a ringbuf
event.

The harness keeps that workflow in an XDP program so `bpftool prog run` can
exercise deterministic inputs:

- `time_lookup` stores the last timestamp for a process.
- `runtime_lookup` accumulates runtime for the previous process.
- `rb` receives a runtime event.
- `stats` records the observable control-flow result for the oracle.

The injected verifier bug is a proof-lifecycle error. `old_ts` is returned by
`bpf_map_lookup_elem(&time_lookup, &prev_pid)`. The program proves it non-null
only under a packet-selected branch, then dereferences it after the branch
merge. The final verifier line is the dereference, but a repair must preserve
the timestamp lookup, runtime accumulation, next-process timestamp update, and
ringbuf emission workflow.

Upstream provenance:

- project: https://github.com/eunomia-bpf/eunomia.dev
- commit: `3b8626b1f7836dedfe295fe79070b170ba347e3f`
- path: `docs/tutorials/48-energy/energy_monitor.bpf.c`
- SPDX: `GPL-2.0 OR BSD-3-Clause`
- upstream file sha256:
  `913f95f408165b8b9998b37a7f00effa786ab1354bec17a7f2755ffe96c61047`
