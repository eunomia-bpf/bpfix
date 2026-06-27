# packet_checked_wrong_base_001

The program checks that the Ethernet header is present at `data + 14`, but then
derives a shifted base (`data + 1`) and reads two bytes at `shifted + 12`. That
access needs 15 bytes and also reads the wrong bytes for `h_proto`.

This is a checked/use pointer mismatch case. A correct repair must use the
same checked packet base for the Ethernet type read, not merely widen the guard
while preserving the shifted-base read.
