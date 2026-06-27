# rs_tutorial_pidhide_tailcall_map_type_001

Real-project seed from the bpf-developer-tutorial `pidhide.bpf.c` tail-call
dispatch path.  The case preserves the multi-program prog-array dispatch shape
in a runnable XDP harness.

The buggy program declares the tail-call map as a normal array.  The intended
repair is to keep the tail-call workflow and declare the map as
`BPF_MAP_TYPE_PROG_ARRAY`, so slot 1 can dispatch to the drop target.
