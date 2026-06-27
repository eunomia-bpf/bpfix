# rs_bpftime_opensnoop_stack_wrong_prog_type_001

Source: real project seed from `bpftime` commit `fac864e`,
`example/tracing/opensnoop/opensnoop.bpf.c`, license `GPL-2.0`.

The upstream opensnoop tracing example stores open arguments, captures a user
stack with `bpf_get_stack(ctx, ..., BPF_F_USER_STACK)`, and emits the event
through `bpf_perf_event_output()`. This minimized candidate keeps that tracing
workflow but places the exit path in an XDP section, where `bpf_get_stack()` is
not available.

A correct repair must restore a tracepoint-compatible section and context while
preserving the stack capture and event output. Deleting the stack capture,
switching to an unrelated helper, or making the program load as XDP is not a
valid repair.
