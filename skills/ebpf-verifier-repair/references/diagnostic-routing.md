# Diagnostic Routing

BPFix diagnostics are evidence for one repair workflow. Do not treat every
`BPFIX-E*` code as a separate skill. Route by `diagnostic_kind`,
`failure_class`, `help_safety`, `next_action`, and `required_proof`.

## Routing Order

1. `diagnostic_kind: unsupported_input`
   Collect a full verbose verifier log before editing source.

2. `diagnostic_kind: unsupported_verifier_message`
   Preserve the log and inspect the terminal verifier message manually. If this
   repo is being improved, add a corpus case and diagnostic support before
   promising an automated repair.

3. `failure_class: environment_or_configuration`
   Check kernel version, program type, attach type, privileges, helper/kfunc
   availability, BTF, JIT/support settings, object metadata, and loader flags.
   Avoid source patches until the environment boundary is clear.

4. `help_safety: triage_only`
   Do not present a source patch as proven. Simplify the verifier relation,
   collect object/kernel context, or compare against a kernel with a relevant
   verifier fix.

5. `failure_class: lowering_artifact`
   The source may contain the intended proof, but compiler lowering, branch
   merging, spills, casts, or helper boundaries made it invisible. Repair the
   verifier-visible bytecode shape.

6. `failure_class: verifier_limit`
   Reduce verifier state growth, stack use, loop uncertainty, or program size.

7. `failure_class: source_bug`
   Apply the local source repair pattern for `next_action` and verify by
   rerunning the original load path.

## Stable JSON Fields

- `error_id`: stable user-facing family such as `BPFIX-E001`.
- `failure_class`: source bug, lowering artifact, environment/configuration,
  verifier false positive, verifier limit, input error, or unsupported message.
- `next_action`: machine-readable repair family: `bounds`, `provenance`,
  `null`, `initialize`, `release`, `environment`, `budget`, `protocol`,
  `context`, or `other`.
- `required_proof`: the verifier-visible fact missing at the rejected
  instruction.
- `source_span`: primary source or PC location. Respect `span_confidence`.
- `related_spans`: proof establishment, proof loss, or nearby context labels.
- `evidence`: terminal verifier error, rejected PC, verifier state signal,
  lowering signal, or precision signal.
- `metadata.object_analysis_error`: object metadata was requested but could not
  be used; the log diagnostic can still be valid.

## Error Family Index

Use this table as an index into repair patterns, not as a skill taxonomy.

| Error ID | Primary meaning | Usual route |
| --- | --- | --- |
| `BPFIX-E000` | Missing verifier rejection region | collect log |
| `BPFIX-E001` | Packet bounds proof missing | `bounds` |
| `BPFIX-E002` | Nullable pointer proof missing | `null` |
| `BPFIX-E003` | Stack/register initialization proof missing | `initialize` |
| `BPFIX-E004` | Reference lifecycle violation | `release` |
| `BPFIX-E005` | Scalar/map-value range proof missing | `bounds` or `provenance` |
| `BPFIX-E006` | Pointer/stack-region proof missing | `provenance` |
| `BPFIX-E007` | Alignment proof missing | `bounds` or `provenance` |
| `BPFIX-E008` | Verifier type contract mismatch | `protocol` |
| `BPFIX-E009` | Environment capability unavailable | `environment` |
| `BPFIX-E010` | Helper/subprogram argument contract | `protocol` |
| `BPFIX-E011` | Invalid pointer/context access | `provenance` or `context` |
| `BPFIX-E012` | Dynptr protocol violation | `protocol` |
| `BPFIX-E013` | Kfunc/subprogram contract violation | `protocol` |
| `BPFIX-E014` | Iterator lifecycle violation | `protocol` |
| `BPFIX-E015` | Lock, RCU, IRQ state violation | `protocol` |
| `BPFIX-E016` | Unsupported instruction or execution context | `environment` or `context` |
| `BPFIX-E018` | Loop or verifier budget limit | `budget` |
| `BPFIX-E019` | Dynptr helper contract violation | `protocol` |
| `BPFIX-E020` | IRQ flag lifecycle violation | `protocol` |
| `BPFIX-E021` | Map relocation or metadata missing | `environment` or `protocol` |
| `BPFIX-E023` | Modern BPF object protocol violation | `protocol` |
| `BPFIX-E099` | Unsupported verifier message | manual triage |
