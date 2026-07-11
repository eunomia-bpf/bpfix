# Repair Patterns

Use these patterns after identifying the missing verifier-visible proof from a
raw verifier log, BPFix diagnostic, or failed repair attempt. The repair target
is the proof the verifier cannot see, not the shortest edit that changes the
terminal error string.

## Bounds

Use for packet, map-value, dynptr-slice, and scalar length/range failures.

- Preserve the original packet/map/helper semantics while adding the missing
  proof. Do not clamp, skip, or truncate inputs unless that is already the
  program's intended behavior.
- Keep the same pointer expression checked against `data_end` and later used
  for the access. If the verifier sees a different register or scalarized
  pointer, rederive the pointer from the checked base immediately before use.
- When checked and used bases differ, determine whether the guard is too small
  or the use points at the wrong protocol field. Do not merely widen the guard
  if that would preserve an off-by-one or wrong-header read; use the intended
  typed base and field while keeping the original packet semantics.
- Check `ptr + size > data_end` before the load/store and return on failure.
  Guard overflow-prone arithmetic by checking the base and size in verifier
  friendly steps.
- After helpers that can move packet data, such as `bpf_xdp_adjust_head` or
  `bpf_skb_pull_data`, reload `data`/`data_end` and redo packet checks.
- Bound indexes before using them for map-value or stack offsets:
  `if (idx >= MAX) return ...;`.
- For signed indexes, prove the lower bound before converting or scaling. If
  valid business values include negatives, validate that domain first and map
  it to a separate nonnegative slot, for example `slot = (__u32)(idx + 1)`;
  never use the signed value directly as a pointer offset.
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
- Treat helper pointer/length pairs as one proof. Prefer a fully initialized
  struct or array and pass `sizeof(object)`; do not initialize 8 bytes and ask
  a helper to read 12. Include padding and protocol fields required by the
  helper's intended semantics rather than merely shrinking the length.
- When a helper accepts ordinary stack/map memory but not a live packet
  pointer for a data argument, bounds-check the packet range, copy the exact
  payload into initialized stack storage, and pass that stack object. Keep the
  payload size and contents unchanged.
- When a requested transfer can exceed a fixed destination, preserve the
  requested length and derive a separate verifier-bounded transfer length,
  such as `copy_len = min(requested, sizeof(dst))`, only when truncation is the
  intended policy. Do not erase the original request or silently change event
  metadata that reports it.
- Keep helper writable stack regions as verifier-visible stack slots with the
  required size and alignment.
- Avoid reading fields from structs filled on only some branches.

## Reference And Lifetime

Use for ringbuf records, socket/task/cpumask references, kptr refs, and other
verifier-tracked ownership.

- Release or submit/discard every acquired reference on every exit path.
- Prefer one release immediately after the reference's last required use and
  before later verdict-only branches. This creates a common post-dominator and
  avoids duplicating release calls across semantically unrelated returns.
- Avoid carrying a reference across callback, sleepable, tail-call, or branch
  boundaries that the verifier forbids.
- After release, do not reuse the pointer except as dead data.
- For ringbuf reserve, pair each successful reserve with submit or discard in
  all branches.
- Determine acquisition from verifier state (`ref_obj_id`, `refs=`, or the
  reported allocation instruction), not only from the helper's scalar return.
  If the verifier tracks a reference after the call, balance every subsequent
  error exit, including helper-error paths, with the protocol-approved release
  or discard.

## Provenance And Lowering

Use for scalarized pointers, stale packet pointers, branch-local pointer proofs,
compiler-lowering artifacts, and invalid pointer types.

- First identify where the proof is established, where it is lost, and which
  dereference/helper argument needs the proof. Repair that relation; do not
  rewrite unrelated control flow.
- Recompute the pointer from a verifier-tracked base near the dereference.
- Duplicate small loads or stores inside branches when a merge would turn a
  packet/map/stack pointer into a scalar or lose range facts.
- When policy requires distinct branch-local side effects, establish and
  null-check each candidate pointer before the branch, then perform the effects
  in mutually exclusive branches. This can preserve both verifier proofs and
  compiler-visible control flow; a no-op barrier or deleting the guarded path
  does neither.
- Avoid pointer-to-integer casts, arithmetic through integer temporaries, and
  opaque helper calls around verifier-sensitive pointer values.
- When the source intentionally carries an alias through a no-op cast or
  temporary and the verifier preserves its pointer type, remove only the
  operation that destroys provenance. Preserve surrounding assignments,
  aliases, branch structure, and the exact pointer passed to the helper unless
  evidence requires simplifying them too.
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
- Treat verifier-tracked objects such as dynptrs as non-copyable. Pass the exact
  initialized stack slot to later helpers; `memcpy`, assignment through raw
  bytes, or reconstructing another slot does not transfer verifier state.
- For dynptr slices backed by packet data, make the requested slice or fallback
  buffer at least as large as every later field access, check each nullable
  slice result, and preserve the short-packet path. Add a direct packet-length
  precheck when the full operation requires multiple slices or the loader/test
  contract requires malformed packets to return before dynptr operations.
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
- When a helper is valid for the intended workflow but not the current program
  type, repair the section, context type, context-field reads, and return
  convention as one contract. Do not simply delete the helper or change the
  workflow into an unrelated program type.
- When the verifier reports `cannot pass map_type ... into func`, match the map
  declaration to the helper's intended contract (for example perf-event output,
  XSK redirect, tail call, or queue/stack operation) while preserving key/value
  layout and loader expectations. Do not replace the helper with a generic map
  operation solely to gain acceptance.

## Budget And Complexity

Use for loop bounds, state explosion, stack depth, instruction budget, and
verifier complexity limits.

- Add static loop bounds or convert unbounded loops to bounded loops.
- Reduce branch fanout, split large programs, or move non-critical work out of
  the hot verifier path.
- Reduce stack usage and deeply nested calls.
- Avoid data-dependent pointer/range relations that force excessive verifier
  state splits.
