# rs_actplane_taint_loop_count_bound_001

Real-project seed from ActPlane's taint-engine `bpf_loop` tokenizer.  The case
preserves the loop-callback scan shape, but the buggy harness asks the callback
to scan more entries than the stack scratch array contains.

The intended repair is to make the loop index proof match the scratch-slot
bound, while keeping the callback-driven scan and marker-drop behavior.
