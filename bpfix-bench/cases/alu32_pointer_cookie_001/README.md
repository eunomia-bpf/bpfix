# alu32_pointer_cookie_001

Canary bucket: proof lifecycle / lowering artifact.

The program parses Ethernet/IPv4/UDP and should drop UDP destination port 53
while passing other packets. The buggy source has an inline asm sequence that
shifts a verifier-tracked packet pointer as if it were an integer cookie before
rebuilding the UDP pointer.

The raw verifier log rejects the shift:

```text
R1 pointer arithmetic with <<= operator prohibited
```

A working repair must preserve packet semantics while keeping the UDP pointer as
a verifier-visible packet pointer. The oracle loads the candidate as XDP and
runs two packet tests:

- UDP destination port 53 returns `XDP_DROP`;
- UDP destination port 80 returns `XDP_PASS`.
