# rs_actplane_cap_dynptr_payload_null_001

Real-project seed from ActPlane's `bpf/capability.bpf.h` capability request
drain path. The case preserves the tag-first dynptr payload parsing pattern in a
deterministic XDP harness so repairs can be checked with `bpftool prog run`.

The buggy program proves that the dynptr contains the 32-bit request tag, then
uses larger request structs returned by `bpf_dynptr_data()` without proving those
struct slices are non-null. A correct repair must preserve the tag-dispatched
payload workflow and prove each requested payload struct before reading its
fields.
