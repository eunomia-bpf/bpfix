# Failure-Directed Retry

Treat every candidate as an experiment on one proof hypothesis. Preserve the
candidate, command, and complete output, then route the next edit by the first
failing stage.

## Retry Matrix

| First failing stage | Meaning | Next action |
| --- | --- | --- |
| extraction or malformed output | No testable candidate exists | Restore one complete source file; make no verifier-logic change yet. |
| C/Rust compile | The hypothesis has not reached the verifier | Fix syntax, types, declarations, includes, and API signatures only; retain the intended proof change. |
| same verifier rejection | The proof was not established or did not survive lowering | Compare rejected PC/register states before and after; verify exact value identity, domination, range, pointer generation, and generated instructions. |
| different verifier rejection | The first proof may now hold and exposed another obligation | Confirm the old rejection is gone, state the new obligation, and add the smallest compatible proof without undoing the first. |
| verifier accepts, semantic oracle fails | The patch changed behavior | Reopen the semantic contract; restore data origins, branches, side effects, helper order, and return actions while retaining the accepted proof shape. |
| environment/setup failure | The candidate was not evaluated | Fix privileges, kernel feature, section/program type, loader flags, maps, BTF, or test setup before drawing a source conclusion. |

## Retry Discipline

- Use the new log, not the original terminal message, as retry evidence.
- Change one proof relation at a time. Do not stack unrelated guards after a
  failed attempt.
- If a source check exists but the same rejection remains, inspect generated
  BPF around the rejected PC; stronger prose or another duplicate check is not
  evidence that the verifier sees the relation.
- If load succeeds but an oracle fails, do not weaken the oracle or accept a
  constant return. Compare the candidate with the pre-edit semantic invariants.
- Stop only when compile, original load path, and available semantic checks all
  pass, or when the remaining privileged/environment step is explicitly named.
