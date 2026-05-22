# Lowering Artifact Candidate Audit

This audit tracks every case currently labelled `label.taxonomy_class:
lowering_artifact`. The goal is to separate confirmed lowering artifacts from
ordinary source obligations that happen to produce scalar-range or provenance
verifier errors.

## Decision Standard

A case remains `lowering_artifact` only when the evidence shows that the
source-level safety argument is present and the compiler/lowering path loses or
obscures that proof. Strong evidence includes source checks that dominate the
access, verifier trace showing proof loss after a spill/reload, CFG join,
ALU32 truncation, wide access lowering, code merging, or an accepted equivalent
rewrite that preserves the semantic precondition while changing bytecode shape.

Cases become `source_bug` when the fix adds a missing semantic precondition,
such as a packet/map bounds check, a clamp, initialization, or a valid helper
argument. Cases become `verifier_false_positive` when the bytecode-level
program is plausibly safe but the verifier loses a relation, range, or state
fact independent of compiler/lowering shape. Cases become
`environment_or_configuration` when the evidence points to loader/kernel feature
mismatch, unsupported context access, or target configuration rather than
source-to-bytecode proof loss. `verifier_limit` is reserved for explicit
resource, complexity, loop, state, instruction, or stack-budget failures.

## Reviewed Candidate Queue

- [x] `github-cilium-cilium-41522` (github_issue, BPFIX-E005, conf=medium, fix=bounds_check)
- [x] `github-commit-bcc-42c00adb4181` (github_commit, BPFIX-E005, conf=medium, fix=compiler_flags)
- [x] `github-commit-cilium-3740e9db8fef` (github_commit, BPFIX-E004, conf=medium, fix=initialization)
- [x] `github-commit-cilium-4853fb153410` (github_commit, BPFIX-E005, conf=medium, fix=stack_alignment)
- [x] `github-commit-cilium-489da3e3f924` (github_commit, BPFIX-E006, conf=medium, fix=align_stack)
- [x] `github-commit-cilium-4bb6b56b5c22` (github_commit, BPFIX-E006, conf=medium, fix=avoid_wide_context_access)
- [x] `github-commit-cilium-4d36cac2ee63` (github_commit, BPFIX-E006, conf=medium, fix=preserve_64bit_pointer_type)
- [x] `github-commit-cilium-4dc7d8047caf` (github_commit, BPFIX-E006, conf=high, fix=prevent_pointer_merge)
- [x] `github-commit-cilium-50c319d0cbfe` (github_commit, BPFIX-E006, conf=medium, fix=force_stack_materialization)
- [x] `github-commit-cilium-514825596e44` (github_commit, BPFIX-E006, conf=medium, fix=align_stack)
- [x] `github-commit-cilium-7e3115694f03` (github_commit, BPFIX-E005, conf=medium, fix=stack_alignment)
- [x] `github-commit-cilium-847014aa62f9` (github_commit, BPFIX-E006, conf=medium, fix=avoid_pointer_truncation)
- [x] `github-commit-cilium-86c904761b39` (github_commit, BPFIX-E006, conf=medium, fix=avoid_wide_context_access)
- [x] `github-commit-cilium-892316d8df68` (github_commit, BPFIX-E005, conf=medium, fix=stack_alignment)
- [x] `github-commit-cilium-8eb389403823` (github_commit, BPFIX-E006, conf=high, fix=type_signature)
- [x] `github-commit-cilium-9100ffbef979` (github_commit, BPFIX-E006, conf=medium, fix=align_stack)
- [x] `github-commit-cilium-b4a0fa7425c7` (github_commit, BPFIX-E006, conf=medium, fix=align_stack)
- [x] `github-commit-cilium-c3b65fce8b84` (github_commit, BPFIX-E006, conf=high, fix=initialize_output_register)
- [x] `github-commit-cilium-caf84595d9cb` (github_commit, BPFIX-E006, conf=high, fix=preserve_ctx_argument)
- [x] `github-iovisor-bcc-5062` (github_issue, BPFIX-E005, conf=medium, fix=bounds_check)
- [x] `github-orangeopensource-p4rt-ovs-5` (github_issue, BPFIX-E005, conf=medium, fix=bounds_check)
- [x] `stackoverflow-53136145` (stackoverflow, BPFIX-E006, conf=low, fix=inline)
- [x] `stackoverflow-60053570` (stackoverflow, BPFIX-E005, conf=medium, fix=bounds_check)
- [x] `stackoverflow-70729664` (stackoverflow, BPFIX-E005, conf=low, fix=reorder)
- [x] `stackoverflow-70750259` (stackoverflow, BPFIX-E005, conf=medium, fix=type_cast)
- [x] `stackoverflow-70760516` (stackoverflow, BPFIX-E005, conf=medium, fix=bounds_check)
- [x] `stackoverflow-70873332` (stackoverflow, BPFIX-E005, conf=medium, fix=clamp)
- [x] `stackoverflow-71522674` (stackoverflow, BPFIX-E005, conf=medium, fix=clamp)
- [x] `stackoverflow-72560675` (stackoverflow, BPFIX-E005, conf=medium, fix=clamp)
- [x] `stackoverflow-72575736` (stackoverflow, BPFIX-E005, conf=medium, fix=bounds_check)
- [x] `stackoverflow-73088287` (stackoverflow, BPFIX-E005, conf=medium, fix=bounds_check)
- [x] `stackoverflow-73282201` (stackoverflow, BPFIX-E005, conf=medium, fix=bounds_check)
- [x] `stackoverflow-73381767` (stackoverflow, BPFIX-E005, conf=medium, fix=bounds_check)
- [x] `stackoverflow-74178703` (stackoverflow, BPFIX-E005, conf=medium, fix=reorder)
- [x] `stackoverflow-76760635` (stackoverflow, BPFIX-E005, conf=medium, fix=bounds_check)
- [x] `stackoverflow-77713434` (stackoverflow, BPFIX-E005, conf=medium, fix=bounds_check)
- [x] `stackoverflow-77762365` (stackoverflow, BPFIX-E005, conf=medium, fix=clamp)
- [x] `stackoverflow-77967675` (stackoverflow, BPFIX-E005, conf=medium, fix=bounds_check)
- [x] `stackoverflow-78186253` (stackoverflow, BPFIX-E005, conf=medium, fix=bounds_check)
- [x] `stackoverflow-78196801` (stackoverflow, BPFIX-E005, conf=medium, fix=bounds_check)
- [x] `stackoverflow-78208591` (stackoverflow, BPFIX-E005, conf=medium, fix=bounds_check)
- [x] `stackoverflow-78591601` (stackoverflow, BPFIX-E005, conf=medium, fix=bounds_check)
- [x] `stackoverflow-78599154` (stackoverflow, BPFIX-E005, conf=medium, fix=bounds_check)
- [x] `stackoverflow-78958420` (stackoverflow, BPFIX-E005, conf=medium, fix=bounds_check)
- [x] `stackoverflow-79095876` (stackoverflow, BPFIX-E005, conf=medium, fix=bounds_check)
- [x] `stackoverflow-79485758` (stackoverflow, BPFIX-E005, conf=medium, fix=type_cast)

## Results

First manual pass over all 46 current lowering candidates:

| case_id | audit class | evidence strength | rationale |
| --- | --- | --- | --- |
| `github-cilium-cilium-41522` | `source_bug` | high | The case description says the packet access occurs before sufficient `data_end` proof; the fix adds the missing full-range proof. |
| `github-commit-bcc-42c00adb4181` | `lowering_artifact` | high | Same source compiled through the frontend with `-O2` instead of `-O0` avoids verifier-hostile noinline/optnone bytecode. |
| `github-commit-cilium-3740e9db8fef` | `lowering_artifact` | high | Clang 17 can spill a value from an error path where the source no longer uses it; initializing `*l4_off` is a verifier-visible workaround. |
| `github-commit-cilium-4853fb153410` | `lowering_artifact` | high | LLVM 18 emits 64-bit stack accesses to only 4-byte-aligned IPv6 stack objects; `__align_stack_8` preserves semantics while changing layout. |
| `github-commit-cilium-489da3e3f924` | `lowering_artifact` | high | A packed IPv6 CT tuple is lowered into an unaligned 8-byte stack copy; alignment annotation changes bytecode shape, not semantics. |
| `github-commit-cilium-4bb6b56b5c22` | `environment_or_configuration` | medium | UAPI/context layout update leads to target verifier context-access mismatch; evidence points more to target ABI/header compatibility than proof-loss lowering. |
| `github-commit-cilium-4d36cac2ee63` | `lowering_artifact` | high | `mattr=+alu32` lets LLVM materialize packet pointer state through 32-bit moves; the fix keeps pointer values verifier-visible as 64-bit. |
| `github-commit-cilium-4dc7d8047caf` | `lowering_artifact` | high | Clang 17 merges TCP/UDP socket-pointer paths into a shared dereference; `READ_ONCE` prevents the verifier-incompatible code merge. |
| `github-commit-cilium-50c319d0cbfe` | `lowering_artifact` | high | RHEL `mcpu=v3` lowering re-reads packet data through a hostile ctx-pointer path; an empty asm barrier forces stack materialization. |
| `github-commit-cilium-514825596e44` | `lowering_artifact` | high | Missing `__align_stack_8` causes LLVM-emitted wide loads from unaligned stack slots; alignment preserves source semantics. |
| `github-commit-cilium-7e3115694f03` | `lowering_artifact` | high | IPv6 stack key/address objects are semantically valid but lowered into 64-bit accesses requiring 8-byte stack alignment. |
| `github-commit-cilium-847014aa62f9` | `lowering_artifact` | high | LLVM lowers packet pointer reads into 32-bit assignments, destroying verifier pointer provenance before packet access. |
| `github-commit-cilium-86c904761b39` | `lowering_artifact` | medium | Adjacent IPv6 sock_addr fields are lowered as wide context accesses; barriers force verifier-compatible narrow operations. |
| `github-commit-cilium-892316d8df68` | `lowering_artifact` | high | A MAC byte array from neighbor state is lowered into wide word access despite possible unaligned stack layout; byte-wise/aligned helper path fixes shape. |
| `github-commit-cilium-8eb389403823` | `source_bug` | medium | The global subprogram signature uses `void *ctx`; the fix gives the verifier the concrete ctx type, which is a source/API type contract. |
| `github-commit-cilium-9100ffbef979` | `lowering_artifact` | high | `lb6_key` stack objects need explicit 8-byte alignment so verifier accepts LLVM-emitted wide stack accesses. |
| `github-commit-cilium-b4a0fa7425c7` | `lowering_artifact` | high | CT tuple stack object is semantically unchanged; `__align_stack_8` only changes verifier-visible stack layout. |
| `github-commit-cilium-c3b65fce8b84` | `lowering_artifact` | high | Inline asm output register can appear uninitialized on a verifier-visible branch even though source only uses it on the success path; masking rewrites the bytecode proof. |
| `github-commit-cilium-caf84595d9cb` | `lowering_artifact` | high | Clang drops an unused ctx argument at a BPF-to-BPF callsite; `volatile` forces the real ctx pointer to remain live. |
| `github-iovisor-bcc-5062` | `lowering_artifact` | medium | The optimizer uses a packet pointer register different from the one that received the verifier bounds proof. |
| `github-orangeopensource-p4rt-ovs-5` | `lowering_artifact` | medium | Generated P4/uBPF code widens a map-value access from 4 to 8 bytes; root cause is source-to-BPF generation, not handwritten C source intent. |
| `stackoverflow-53136145` | `lowering_artifact` | high | IPv4/IPv6 branch merge loses UDP pointer provenance before `udph->dest`; branch-preserving rewrite is semantically equivalent. |
| `stackoverflow-60053570` | `source_bug` | high | Accepted answer says the checksum helper is asked to read 64 bytes while source only checked `icmph + 1`. |
| `stackoverflow-70729664` | `verifier_false_positive` | high | Source carries bounds checks, but verifier rejects due `MAX_PACKET_OFF`/range precision while walking chunks; fix adds verifier-friendly clamp. |
| `stackoverflow-70750259` | `source_bug` | medium | The TLS extension length needs a new bound before pointer advance; available evidence does not show an already-established source proof. |
| `stackoverflow-70760516` | `verifier_false_positive` | medium | Source clamps `ext_len`, but verifier accumulates packet offset maxima across loop iterations and cannot preserve the intended bound. |
| `stackoverflow-70873332` | `verifier_false_positive` | high | Accepted answer explicitly calls it a verifier corner case: packet length check exists but is ignored due `MAX_PACKET_OFF` overflow risk. |
| `stackoverflow-71522674` | `source_bug` | high | Accepted answer identifies a real missing boundary check before reading `tcph->doff`. |
| `stackoverflow-72560675` | `verifier_false_positive` | medium | Older 4.14 verifier loses the range from `MIN()`; explicit clamp is a verifier workaround for the same semantic bound. |
| `stackoverflow-72575736` | `verifier_false_positive` | high | Accepted answer identifies a missing verifier bugfix in Linux 5.10 that is present in 5.13. |
| `stackoverflow-73088287` | `lowering_artifact` | high | Compiler likely emits separate registers for `payload + i + 1` and `payload[i]`; source check exists but bytecode expression equivalence is lost. |
| `stackoverflow-73282201` | `source_bug` | medium | Fix changes the loop index type/range so the verifier can prove it stays below the map-value bound; no independent lowering evidence. |
| `stackoverflow-73381767` | `source_bug` | high | Accepted answer says the program must prove it never reads past the 4096-byte map value. |
| `stackoverflow-74178703` | `lowering_artifact` | medium | Source checks `offset + i`, but lowered/rebuilt access loses that relation before the `memcpy` load/store. |
| `stackoverflow-76760635` | `source_bug` | low | External answer only explains how to obtain the verifier log; no evidence supports a lowering/proof-loss claim. |
| `stackoverflow-77713434` | `source_bug` | low | Available source shows a variable helper read into a 70-byte map value with no accepted-answer evidence for an existing proof. |
| `stackoverflow-77762365` | `verifier_false_positive` | high | Verifier cannot preserve the relation `event->len + read < MAX_READ_CONTENT_LENGTH` for helper destination bounds. |
| `stackoverflow-77967675` | `verifier_false_positive` | medium | Source bounds `index`, but verifier does not recognize the bound for packet pointer arithmetic inside `bpf_loop`. |
| `stackoverflow-78186253` | `lowering_artifact` | medium | Accepted answer says verifier loses track of `payload + i` between the check and use; making the checked expression its own variable should preserve bytecode proof. |
| `stackoverflow-78196801` | `lowering_artifact` | high | Accepted answer explicitly attributes the failure to unfortunate bytecode generation: compiler reloads `value->index`, so verifier cannot connect the checked and used values. |
| `stackoverflow-78208591` | `lowering_artifact` | low | Question reports equivalent logic and weird compiled code; no accepted answer, but the source shape resembles the `value->index` reload proof-loss pattern. |
| `stackoverflow-78591601` | `source_bug` | high | Accepted answer says the bounds check does not include the 4-byte access width. |
| `stackoverflow-78599154` | `source_bug` | low | Available evidence points to map-value offset beyond declared value size; no confirmed source proof-loss mechanism. |
| `stackoverflow-78958420` | `source_bug` | high | Program passes a packet-backed 254-byte map key after proving only one byte. |
| `stackoverflow-79095876` | `verifier_false_positive` | medium | Verifier cannot track relation between `total_len`, `to_read`, and map-value size; fix uses a verifier-friendly constant/clamp. |
| `stackoverflow-79485758` | `verifier_false_positive` | high | Accepted answer identifies a verifier corner-case limitation and requires an extra packet bound check workaround. |

First-pass counts:

| audit class | cases |
| --- | ---: |
| `lowering_artifact` | 24 |
| `verifier_false_positive` | 9 |
| `source_bug` | 12 |
| `environment_or_configuration` | 1 |
| `verifier_limit` | 0 |

The 24 `lowering_artifact` cases are the interesting set to preserve and
strengthen with `mechanism_tags` and `evidence_tags`. The 9
`verifier_false_positive` cases should not be mixed into lowering claims; they
are still valuable, but the claim is verifier precision/conservatism rather than
compiler-lowering proof loss.
