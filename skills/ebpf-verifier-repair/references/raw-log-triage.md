# Raw Verifier Log Triage

Use this procedure when no structured BPFix diagnostic is available. Work from
the end of the verifier rejection backward; loader preamble and the final errno
are context, not the root cause.

## Extract The Failure Slice

1. Find the last verifier error before `verification time`, then record the
   rejected instruction and its source annotation.
2. Record the rejected register or stack slot exactly as shown, including its
   type, id, offset, range, nullability, and initialization state.
3. Locate the instruction that created that value: a context load, map lookup,
   helper/kfunc return, pointer copy, stack spill, arithmetic operation, or
   branch merge.
4. Trace forward to the first instruction where the required fact is lost.
   Common loss points are a helper call, nullable lookup overwrite, pointer to
   integer conversion, 32-bit ALU operation, branch merge, or stale packet
   generation after packet mutation.
5. State one relation before editing:

   ```text
   use: <rejected source operation and PC>
   observed: <verifier type/range/state>
   required: <type/range/state the operation needs>
   origin: <where the value came from>
   loss: <where the required fact disappeared or was never established>
   ```

If the source annotation and rejected instruction disagree, trust the
instruction dataflow and inspect compiler output before changing nearby source.

## Route Terminal Signals

- `invalid mem access '*_or_null'`: find the exact nullable producer and add a
  dominating check on that same value. If a proven fallback pointer is
  overwritten by a nullable lookup, keep the fallback and assign the override
  only on success.
- `type=<actual> expected=<expected>`: map the rejected register to the helper
  argument number or memory operand. Repair the argument source or program
  contract; a cast cannot turn `fp`, `scalar`, or `ctx` into `map_ptr`, packet
  data, or another verifier pointer class.
- `invalid indirect read from stack` or `uninitialized stack`: identify the
  exact byte range consumed by the helper. Initialize every byte in that range
  and keep the size consistent with the initialized object.
- `min value is negative`, `unbounded memory access`, or an out-of-range
  variable offset: prove both lower and upper bounds before pointer arithmetic.
  For signed inputs, `if (idx < 0 || idx >= MAX)` is different from only an
  unsigned upper-bound check.
- `pointer arithmetic with ... prohibited` or a pointer shown as `scalar`:
  remove integer/ALU manipulation of the pointer and rederive a typed pointer
  from its tracked base near use.
- `R? offset is outside of the packet` or packet access beyond `data_end`:
  ensure the checked pointer expression, packet generation, and used pointer
  are identical. Reload and recheck after packet-mutating helpers.
- `Unreleased reference id=`, `reference has not been acquired`, or use after
  submit/discard/release: write down the acquire event and enumerate every exit
  path. Balance ownership once per successful acquire.
- `program of this type cannot use helper`, `unknown func`, or invalid context
  access: check section/program type, attach type, kernel support, and helper or
  kfunc availability before editing proof logic.
- complexity, stack-depth, or instruction-limit messages: treat the limit and
  its reported counters as the rejected condition; do not invent a pointer or
  bounds repair.

## Resist Misleading Nearby Fixes

- Do not patch the line nearest the terminal message until the rejected
  register is mapped back to a source value.
- Do not replace a nullable override with an early return when the source has
  fallback semantics.
- Do not clamp helper lengths or indexes unless truncation is intended runtime
  behavior; prefer rejecting the invalid path or proving the original range.
- Do not remove helper calls, map operations, packet parsing, or side effects
  that an accepted repair still needs to preserve.
