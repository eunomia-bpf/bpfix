# rs_cilium_fib_lookup_param_len_001

Source: real project seed from Cilium commit
`3a3646386538766d6edd5ada929b427728dbfafd`, `bpf/lib/fib.h`,
license `(GPL-2.0-only OR BSD-2-Clause)`.

Cilium's datapath uses FIB lookup parameters to decide whether a packet can be
forwarded directly and, on success, rewrites the Ethernet addresses before
redirecting to the selected interface.

The bug preserves that workflow but passes `sizeof(struct bpf_fib_lookup) + 4`
to `bpf_fib_lookup`. The stack object is only 64 bytes, so the verifier rejects
the helper call as an invalid indirect stack read.

A correct repair must pass the real struct size while preserving the FIB lookup,
the IPv4 packet parsing, the success-path L2 rewrite, and the redirect helper.
Simply deleting the helper or returning `XDP_PASS` is not a valid repair.
