# Repair Patterns

Use these patterns after reading the BPFix diagnostic. The repair target is the
missing verifier-visible proof, not the shortest edit that changes the terminal
error string.

## Bounds

Use for packet, map-value, dynptr-slice, and scalar length/range failures.

- Keep the same pointer expression checked against `data_end` and later used
  for the access. If the verifier sees a different register or scalarized
  pointer, rederive the pointer from the checked base immediately before use.
- Check `ptr + size > data_end` before the load/store and return on failure.
  Guard overflow-prone arithmetic by checking the base and size in verifier
  friendly steps.
- After helpers that can move packet data, such as `bpf_xdp_adjust_head` or
  `bpf_skb_pull_data`, reload `data`/`data_end` and redo packet checks.
- Bound indexes before using them for map-value or stack offsets:
  `if (idx >= MAX) return ...;`.
- Prefer constants or tightly bounded variables for helper lengths and dynptr
  slice lengths.

## Nullability

Use for map lookup, ringbuf reserve, kptr, kfunc, socket, task, and other
nullable pointer returns.

- Add a dominating null check on the exact nullable value before dereference or
  helper use.
- Keep the checked value in the same branch as the use. If a wrapper, callback,
  or branch merge hides the fact, move the use into the checked branch or pass a
  verifier-recognized non-null value.
- Do not store a nullable pointer in an integer or opaque container before the
  check.

## Initialization

Use for unread stack bytes, uninitialized registers, partial struct writes, and
helper output buffers.

- Zero-initialize stack structs before passing them to helpers or copying them
  to maps/ring buffers.
- Initialize every byte in the range the helper or memory access may read, not
  only the C fields the source appears to use.
- Keep helper writable stack regions as verifier-visible stack slots with the
  required size and alignment.
- Avoid reading fields from structs filled on only some branches.

## Reference And Lifetime

Use for ringbuf records, socket/task/cpumask references, kptr refs, and other
verifier-tracked ownership.

- Release or submit/discard every acquired reference on every exit path.
- Avoid carrying a reference across callback, sleepable, tail-call, or branch
  boundaries that the verifier forbids.
- After release, do not reuse the pointer except as dead data.
- For ringbuf reserve, pair each successful reserve with submit or discard in
  all branches.

## Provenance And Lowering

Use for scalarized pointers, stale packet pointers, branch-local pointer proofs,
compiler-lowering artifacts, and invalid pointer types.

- Recompute the pointer from a verifier-tracked base near the dereference.
- Duplicate small loads or stores inside branches when a merge would turn a
  packet/map/stack pointer into a scalar or lose range facts.
- Avoid pointer-to-integer casts, arithmetic through integer temporaries, and
  opaque helper calls around verifier-sensitive pointer values.
- Keep checked packet pointers paired with the same `data_end` generation. Any
  helper that mutates packet data makes old packet pointers stale.
- For stack-region proofs, pass the exact stack slot and size the verifier can
  see; avoid hiding the address in untracked arithmetic.

## Alignment

Use when the verifier cannot prove access alignment.

- Prefer naturally aligned struct fields and typed pointers after bounds checks.
- If packet layout can be unaligned, use byte loads or safe copy helpers rather
  than wide unaligned loads.
- Keep offset arithmetic simple enough for the verifier to prove alignment.

## Helper, Kfunc, Dynptr, Iterator, Lock, RCU, IRQ

Use for protocol-style verifier contracts.

- Read the helper/kfunc contract as a precondition list: pointer type,
  nullability, trusted/refcounted ownership, constness, stack slot, flags,
  context, and sleepability all matter.
- For dynptrs, initialize before use, use the right backing memory and mode,
  keep required stack slots exact, respect slice lifetime, and release once.
- For iterators, follow the verifier-approved new/next/destroy lifecycle and do
  not use iterator state after destroy or outside the allowed loop shape.
- For lock/RCU/IRQ discipline, keep acquire/release or save/restore balanced on
  every path and avoid calls that are forbidden in the current state.
- For modern object helpers, satisfy trusted pointer, RCU protection,
  reference ownership, and program-type requirements before changing unrelated
  source logic.

## Environment And Context

Use for unsupported helpers, kfuncs, attach types, BTF, program context fields,
privileges, and kernel feature gaps.

- Verify the program type and attach type match the helper/context/kfunc.
- Check kernel version and configuration before rewriting source.
- Confirm BTF and relocation metadata are present when the verifier message
  points at missing func_info, map relocation, CO-RE, or kfunc metadata.
- Treat privilege failures separately from verifier proof failures.

## Budget And Complexity

Use for loop bounds, state explosion, stack depth, instruction budget, and
verifier complexity limits.

- Add static loop bounds or convert unbounded loops to bounded loops.
- Reduce branch fanout, split large programs, or move non-critical work out of
  the hot verifier path.
- Reduce stack usage and deeply nested calls.
- Avoid data-dependent pointer/range relations that force excessive verifier
  state splits.
