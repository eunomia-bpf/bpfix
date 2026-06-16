use std::collections::BTreeSet;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use serde_json::Value;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn run_json(path: &str) -> Value {
    run_json_path(workspace_root().join(path))
}

fn run_json_path(path: PathBuf) -> Value {
    let output = Command::new(env!("CARGO_BIN_EXE_bpfix"))
        .arg(path)
        .arg("--format")
        .arg("json")
        .output()
        .expect("bpfix should execute");
    assert!(
        output.status.success(),
        "bpfix failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("bpfix should emit JSON")
}

fn run_json_with_args(args: &[&str]) -> Value {
    let output = run_with_args(args);
    serde_json::from_slice(&output.stdout).expect("bpfix should emit JSON")
}

fn run_with_args(args: &[&str]) -> std::process::Output {
    let output = Command::new(env!("CARGO_BIN_EXE_bpfix"))
        .args(args)
        .output()
        .expect("bpfix should execute");
    assert!(
        output.status.success(),
        "bpfix failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn run_json_stdin(input: &str) -> Value {
    run_json_stdin_with_args(input, &["-", "--format", "json"])
}

fn assert_source_bug_without_verifier_state_signal(json: &Value, error_id: &str) {
    assert_eq!(json["error_id"], error_id);
    assert_eq!(json["failure_class"], "source_bug");
    assert!(!json["evidence"]
        .as_array()
        .unwrap()
        .iter()
        .any(|evidence| evidence["kind"] == "verifier_state_signal"));
}

fn evidence_contains(json: &Value, kind: &str, detail: &str) -> bool {
    json["evidence"].as_array().unwrap().iter().any(|evidence| {
        evidence["kind"] == kind && evidence["detail"].as_str().unwrap().contains(detail)
    })
}

fn assert_no_stale_pointer_invalidation_signal(json: &Value) {
    assert!(!evidence_contains(
        json,
        "verifier_state_signal",
        "packet-mutating helper invalidated"
    ));
    assert!(!evidence_contains(
        json,
        "verifier_state_signal",
        "dynptr data or slice helper result"
    ));
}

fn run_json_stdin_with_args(input: &str, args: &[&str]) -> Value {
    let mut child = Command::new(env!("CARGO_BIN_EXE_bpfix"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("bpfix should execute");
    {
        use std::io::Write;
        child
            .stdin
            .as_mut()
            .expect("stdin should be piped")
            .write_all(input.as_bytes())
            .expect("stdin write should succeed");
    }
    let output = child.wait_with_output().expect("bpfix should finish");
    assert!(
        output.status.success(),
        "bpfix failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("bpfix should emit JSON")
}

fn run_json_stdin_output(input: &str) -> std::process::Output {
    run_stdin_output(input, &["-", "--format", "json"])
}

fn run_stdin_output(input: &str, args: &[&str]) -> std::process::Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_bpfix"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("bpfix should execute");
    {
        use std::io::Write;
        child
            .stdin
            .as_mut()
            .expect("stdin should be piped")
            .write_all(input.as_bytes())
            .expect("stdin write should succeed");
    }
    child.wait_with_output().expect("bpfix should finish")
}

fn run_text(path: &str) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_bpfix"))
        .arg(workspace_root().join(path))
        .output()
        .expect("bpfix should execute");
    assert!(
        output.status.success(),
        "bpfix failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("bpfix should emit UTF-8")
}

#[test]
fn help_marks_object_analysis_as_experimental_and_feature_gated() {
    let output = Command::new(env!("CARGO_BIN_EXE_bpfix"))
        .arg("--help")
        .output()
        .expect("bpfix --help should execute");
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).expect("help should be UTF-8");
    assert!(help.contains("Experimental compiled BPF object metadata"));
    assert!(help.contains("Requires --features object-analysis"));
}

#[test]
fn diagnostic_schema_and_editor_example_track_json_contract() {
    let json = run_json("bpfix-bench/cases/stackoverflow-53136145/replay-verifier.log");
    let precision_json = run_json("bpfix-bench/cases/stackoverflow-77762365/replay-verifier.log");
    let verifier_state_signal_json =
        run_json("bpfix-bench/cases/stackoverflow-72606055/replay-verifier.log");
    let verifier_metadata_signal_json =
        run_json("bpfix-bench/cases/github-aya-rs-aya-521/replay-verifier.log");
    let protocol_signal_json = run_json(
        "bpfix-bench/cases/kernel-selftest-dynptr-fail-invalid-helper2-raw-tp-34ba04aa/replay-verifier.log",
    );
    let context_signal_json =
        run_json("bpfix-bench/cases/stackoverflow-56526650/replay-verifier.log");
    let schema: Value = serde_json::from_str(
        &std::fs::read_to_string(workspace_root().join("docs/evaluation/diagnostic.schema.json"))
            .expect("schema should be readable"),
    )
    .expect("schema should be JSON");
    let example: Value = serde_json::from_str(
        &std::fs::read_to_string(
            workspace_root().join("examples/editor/diagnostic.schema.example.json"),
        )
        .expect("editor example should be readable"),
    )
    .expect("editor example should be JSON");

    let output_keys = object_keys(&json);
    assert_eq!(object_keys(&schema["properties"]), output_keys);
    assert_eq!(string_array_set(&schema["required"]), output_keys);
    assert_eq!(object_keys(&example), output_keys);
    assert_eq!(
        schema["properties"]["diagnostic_version"]["const"],
        "bpfix.diagnostic/v3"
    );
    assert!(schema["properties"].get("missing_obligation").is_none());
    assert!(schema["properties"].get("candidate_repairs").is_none());
    assert!(schema["properties"].get("raw_log_excerpt").is_none());
    let failure_classes = string_array_set(&schema["properties"]["failure_class"]["enum"]);
    let next_actions = string_array_set(&schema["properties"]["next_action"]["enum"]);
    let evidence_kinds =
        string_array_set(&schema["$defs"]["evidence_item"]["properties"]["kind"]["enum"]);
    for diagnostic in [
        &json,
        &precision_json,
        &verifier_state_signal_json,
        &verifier_metadata_signal_json,
        &protocol_signal_json,
        &context_signal_json,
        &example,
    ] {
        assert!(failure_classes.contains(diagnostic["failure_class"].as_str().unwrap()));
        assert!(next_actions.contains(diagnostic["next_action"].as_str().unwrap()));
        for evidence in diagnostic["evidence"].as_array().unwrap() {
            assert!(evidence_kinds.contains(evidence["kind"].as_str().unwrap()));
        }
    }
    assert_eq!(json["next_action"], "provenance");
    assert_eq!(precision_json["next_action"], "bounds");
    assert_eq!(verifier_state_signal_json["next_action"], "environment");
    assert_eq!(verifier_metadata_signal_json["next_action"], "environment");
    assert_eq!(protocol_signal_json["next_action"], "protocol");
    assert_eq!(context_signal_json["next_action"], "context");
    assert!(verifier_state_signal_json["evidence"]
        .as_array()
        .unwrap()
        .iter()
        .any(|evidence| evidence["kind"] == "verifier_state_signal"));
    assert!(verifier_metadata_signal_json["evidence"]
        .as_array()
        .unwrap()
        .iter()
        .any(|evidence| {
            evidence["kind"] == "verifier_state_signal"
                && evidence["detail"]
                    .as_str()
                    .unwrap()
                    .contains("BTF func_info")
        }));

    let metadata_keys = object_keys(&json["metadata"]);
    assert_eq!(
        object_keys(&schema["$defs"]["metadata"]["properties"]),
        metadata_keys
    );
    assert_eq!(
        string_array_set(&schema["$defs"]["metadata"]["required"]),
        metadata_keys
    );
    assert_eq!(object_keys(&example["metadata"]), metadata_keys);

    let source_span_keys = object_keys(&json["source_span"]);
    assert_eq!(
        object_keys(&schema["$defs"]["source_span"]["properties"]),
        source_span_keys
    );
    assert_eq!(
        string_array_set(&schema["$defs"]["source_span"]["required"]),
        source_span_keys
    );
    assert_eq!(object_keys(&example["source_span"]), source_span_keys);
}

fn object_keys(value: &Value) -> BTreeSet<String> {
    value
        .as_object()
        .expect("value should be a JSON object")
        .keys()
        .cloned()
        .collect()
}

fn string_array_set(value: &Value) -> BTreeSet<String> {
    value
        .as_array()
        .expect("value should be a JSON array")
        .iter()
        .map(|item| {
            item.as_str()
                .expect("array item should be a string")
                .to_string()
        })
        .collect()
}

#[test]
fn replay_log_uses_bpfanalysis_verifier_trace_parser() {
    let json = run_json("bpfix-bench/cases/stackoverflow-60053570/replay-verifier.log");
    assert_eq!(json["error_id"], "BPFIX-E001");
    assert_eq!(json["source_span"]["path"], "prog.c");
    assert_eq!(json["source_span"]["instruction_pc"], 26);
    assert!(json["metadata"]["trace_state_count"].as_u64().unwrap() > 0);
}

#[test]
fn signed_packet_offset_case_runs_without_yaml_metadata() {
    let json = run_json("bpfix-bench/cases/stackoverflow-70750259/replay-verifier.log");
    assert_eq!(json["error_id"], "BPFIX-E005");
    assert_eq!(json["failure_class"], "source_bug");
    assert!(json["required_proof"]
        .as_str()
        .unwrap()
        .contains("cannot be negative"));
    assert!(json["metadata"]["case_id"].is_null());
    assert_eq!(json["source_span"]["path"], "prog.c");
    assert_eq!(json["source_span"]["instruction_pc"], 33);
}

#[test]
fn branch_merge_case_is_classified_from_proof_events_without_yaml() {
    let json = run_json("bpfix-bench/cases/stackoverflow-53136145/replay-verifier.log");
    assert_eq!(json["error_id"], "BPFIX-E006");
    assert_eq!(json["failure_class"], "lowering_artifact");
    assert!(json["metadata"]["case_id"].is_null());
    assert_eq!(json["metadata"]["input_kind"], "verifier-log-region");
    assert_eq!(json["source_span"]["path"], "prog.c");
    assert_eq!(json["source_span"]["instruction_pc"], 37);
    assert!(json["evidence"].as_array().unwrap().iter().any(|evidence| {
        evidence["kind"] == "lowering_artifact_signal"
            && evidence["detail"]
                .as_str()
                .unwrap()
                .contains("compiler-lowered control flow")
    }));
    assert!(json["related_spans"].as_array().unwrap().len() >= 2);
    let labels = json["related_spans"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|span| span["label"].as_str())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(labels.contains("nearby source context for pointer provenance"));
    assert!(labels.contains("verifier state changes from pkt to scalar"));
    assert!(!labels.contains("proof established by a verifier-visible bounds check"));
}

#[test]
fn lowering_artifact_shapes_are_classified_from_verifier_evidence() {
    let stack_alignment =
        run_json("bpfix-bench/cases/github-commit-cilium-4853fb153410/replay-verifier.log");
    assert_eq!(stack_alignment["error_id"], "BPFIX-E007");
    assert_eq!(stack_alignment["failure_class"], "lowering_artifact");
    assert!(stack_alignment["message"]
        .as_str()
        .unwrap()
        .contains("verifier-visible compiler lowering"));
    assert!(stack_alignment["evidence"]
        .as_array()
        .unwrap()
        .iter()
        .any(|evidence| {
            evidence["kind"] == "lowering_artifact_signal"
                && evidence["detail"]
                    .as_str()
                    .unwrap()
                    .contains("stack access requires stronger alignment")
        }));

    let unproven_alignment_artifact = run_json_stdin(
        "\
0: R1=ctx() R10=fp0
10: R1=ctx() R10=fp0
10: (79) r1 = *(u64 *)(r1 +4)
misaligned stack access off 0+-16+4 size 8
processed 11 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0
",
    );
    assert_eq!(unproven_alignment_artifact["error_id"], "BPFIX-E007");
    assert_eq!(unproven_alignment_artifact["failure_class"], "source_bug");
    assert!(!unproven_alignment_artifact["evidence"]
        .as_array()
        .unwrap()
        .iter()
        .any(|evidence| evidence["kind"] == "lowering_artifact_signal"));

    let stale_alignment_state = run_json_stdin(
        "\
9: (07) r1 += -16                     ; R1_w=fp-16
10: (79) r1 = *(u64 *)(r1 +4)
misaligned stack access off 0+-16+4 size 8
10: (79) r1 = *(u64 *)(r1 +4)
misaligned stack access off 0+-16+4 size 8
processed 12 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0
",
    );
    assert_eq!(stale_alignment_state["error_id"], "BPFIX-E007");
    assert_eq!(stale_alignment_state["failure_class"], "source_bug");
    assert!(!stale_alignment_state["evidence"]
        .as_array()
        .unwrap()
        .iter()
        .any(|evidence| evidence["kind"] == "lowering_artifact_signal"));

    let stale_alignment_opcode = run_json_stdin(
        "\
9: (07) r1 += -16                     ; R1_w=fp-16
10: (79) r1 = *(u64 *)(r1 +4)
misaligned stack access off 0+-16+4 size 8
processed 11 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0
misaligned stack access off 0+-16+4 size 8
",
    );
    assert_eq!(stale_alignment_opcode["error_id"], "BPFIX-E007");
    assert!(stale_alignment_opcode["source_span"]["instruction_pc"].is_null());
    assert_eq!(stale_alignment_opcode["failure_class"], "source_bug");
    assert!(!stale_alignment_opcode["evidence"]
        .as_array()
        .unwrap()
        .iter()
        .any(|evidence| evidence["kind"] == "lowering_artifact_signal"));

    let pointer_shift =
        run_json("bpfix-bench/cases/github-commit-cilium-847014aa62f9/replay-verifier.log");
    assert_eq!(pointer_shift["error_id"], "BPFIX-E006");
    assert_eq!(pointer_shift["failure_class"], "lowering_artifact");
    assert!(pointer_shift["evidence"]
        .as_array()
        .unwrap()
        .iter()
        .any(|evidence| {
            evidence["kind"] == "lowering_artifact_signal"
                && evidence["detail"]
                    .as_str()
                    .unwrap()
                    .contains("integer operation drops pointer provenance")
        }));

    let stale_pointer_shift_state = run_json_stdin(
        "\
4: (07) r3 += 14                      ; R3_w=pkt(off=14,r=0)
5: (67) r3 <<= 32
R3 pointer arithmetic with <<= operator prohibited
5: (67) r3 <<= 32
R3 pointer arithmetic with <<= operator prohibited
processed 6 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0
",
    );
    assert_eq!(stale_pointer_shift_state["error_id"], "BPFIX-E006");
    assert_eq!(stale_pointer_shift_state["failure_class"], "source_bug");
    assert!(!stale_pointer_shift_state["evidence"]
        .as_array()
        .unwrap()
        .iter()
        .any(|evidence| evidence["kind"] == "lowering_artifact_signal"));

    let modified_ctx =
        run_json("bpfix-bench/cases/github-commit-cilium-86c904761b39/replay-verifier.log");
    assert_eq!(modified_ctx["error_id"], "BPFIX-E006");
    assert_eq!(modified_ctx["failure_class"], "lowering_artifact");
    assert!(modified_ctx["evidence"]
        .as_array()
        .unwrap()
        .iter()
        .any(|evidence| {
            evidence["kind"] == "lowering_artifact_signal"
                && evidence["detail"]
                    .as_str()
                    .unwrap()
                    .contains("context access violates")
        }));

    let stale_modified_ctx_state = run_json_stdin(
        "\
3: R2_w=12 R3_w=ctx(off=12)
4: (61) r2 = *(u32 *)(r3 +4)
dereference of modified ctx ptr R3 off=12 disallowed
4: (61) r2 = *(u32 *)(r3 +4)
dereference of modified ctx ptr R3 off=12 disallowed
processed 5 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0
",
    );
    assert_eq!(stale_modified_ctx_state["error_id"], "BPFIX-E006");
    assert_eq!(stale_modified_ctx_state["failure_class"], "source_bug");
    assert!(!stale_modified_ctx_state["evidence"]
        .as_array()
        .unwrap()
        .iter()
        .any(|evidence| evidence["kind"] == "lowering_artifact_signal"));

    let pointer_merge =
        run_json("bpfix-bench/cases/github-commit-cilium-4dc7d8047caf/replay-verifier.log");
    assert_eq!(pointer_merge["error_id"], "BPFIX-E006");
    assert_eq!(pointer_merge["failure_class"], "lowering_artifact");
    assert!(pointer_merge["evidence"]
        .as_array()
        .unwrap()
        .iter()
        .any(|evidence| {
            evidence["kind"] == "lowering_artifact_signal"
                && evidence["detail"]
                    .as_str()
                    .unwrap()
                    .contains("distinct pointer proofs")
        }));

    let stale_pointer_merge_state = run_json_stdin(
        "\
; old verifier attempt @ prog.c:1
26: R0=sock(ref_obj_id=2)
27: (61) r7 = *(u32 *)(r0 +4)
same insn cannot be used with different pointers
processed 3 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0
; current verifier attempt @ prog.c:2
26: R0=sock_common(ref_obj_id=4)
27: (61) r7 = *(u32 *)(r0 +4)
same insn cannot be used with different pointers
processed 3 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0
",
    );
    assert_eq!(stale_pointer_merge_state["error_id"], "BPFIX-E006");
    assert_eq!(stale_pointer_merge_state["failure_class"], "source_bug");
    assert!(!stale_pointer_merge_state["evidence"]
        .as_array()
        .unwrap()
        .iter()
        .any(|evidence| evidence["kind"] == "lowering_artifact_signal"));

    let ctx_argument =
        run_json("bpfix-bench/cases/github-commit-cilium-caf84595d9cb/replay-verifier.log");
    assert_eq!(ctx_argument["error_id"], "BPFIX-E010");
    assert_eq!(ctx_argument["failure_class"], "lowering_artifact");
    assert!(ctx_argument["evidence"]
        .as_array()
        .unwrap()
        .iter()
        .any(|evidence| {
            evidence["kind"] == "lowering_artifact_signal"
                && evidence["detail"].as_str().unwrap().contains("liveness")
        }));

    let stale_ctx_argument_state = run_json_stdin(
        "\
; ret = mock_fib_lookup(ctx, &fib, sizeof(fib), 0); @ prog.c:44
0: R1=ctx() R10=fp0
24: R1=fp-64
26: (85) call pc+7
arg#0 expects pointer to ctx
Caller passes invalid args into func#1 ('mock_fib_lookup')
processed 27 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0
0: R1=ctx() R10=fp0
24: R1=fp-64
26: (85) call pc+7
arg#0 expects pointer to ctx
Caller passes invalid args into func#1 ('mock_fib_lookup')
processed 27 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0
",
    );
    assert_eq!(stale_ctx_argument_state["error_id"], "BPFIX-E010");
    assert_eq!(stale_ctx_argument_state["failure_class"], "source_bug");
    assert!(!stale_ctx_argument_state["evidence"]
        .as_array()
        .unwrap()
        .iter()
        .any(|evidence| evidence["kind"] == "lowering_artifact_signal"));

    let alu32_copy =
        run_json("bpfix-bench/cases/github-commit-cilium-4d36cac2ee63/replay-verifier.log");
    assert_eq!(alu32_copy["error_id"], "BPFIX-E006");
    assert_eq!(alu32_copy["failure_class"], "lowering_artifact");
    assert!(alu32_copy["evidence"]
        .as_array()
        .unwrap()
        .iter()
        .any(|evidence| {
            evidence["kind"] == "lowering_artifact_signal"
                && evidence["detail"]
                    .as_str()
                    .unwrap()
                    .contains("32-bit register copy")
        }));

    let shared_pointer_path =
        run_json("bpfix-bench/cases/github-commit-cilium-50c319d0cbfe/replay-verifier.log");
    assert_eq!(shared_pointer_path["error_id"], "BPFIX-E006");
    assert_eq!(shared_pointer_path["failure_class"], "lowering_artifact");
    assert!(shared_pointer_path["message"]
        .as_str()
        .unwrap()
        .contains("verifier-visible compiler lowering"));

    let shared_uninit =
        run_json("bpfix-bench/cases/github-commit-cilium-c3b65fce8b84/replay-verifier.log");
    assert_eq!(shared_uninit["error_id"], "BPFIX-E003");
    assert_eq!(shared_uninit["failure_class"], "lowering_artifact");
    assert!(shared_uninit["evidence"]
        .as_array()
        .unwrap()
        .iter()
        .any(|evidence| {
            evidence["kind"] == "lowering_artifact_signal"
                && evidence["detail"]
                    .as_str()
                    .unwrap()
                    .contains("shared instruction")
        }));

    let packet_range_loss =
        run_json("bpfix-bench/cases/github-iovisor-bcc-5062/replay-verifier.log");
    assert_eq!(packet_range_loss["error_id"], "BPFIX-E001");
    assert_eq!(packet_range_loss["failure_class"], "lowering_artifact");
    assert!(packet_range_loss["evidence"]
        .as_array()
        .unwrap()
        .iter()
        .any(|evidence| {
            evidence["kind"] == "lowering_artifact_signal"
                && evidence["detail"]
                    .as_str()
                    .unwrap()
                    .contains("packet access range earlier")
        }));
    let packet_range_labels = packet_range_loss["related_spans"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|span| span["label"].as_str())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(packet_range_labels.contains("packet range 60 bytes"));
    assert!(packet_range_labels.contains("dropped to 0 bytes"));

    let constant_scalar_load =
        run_json("bpfix-bench/cases/github-commit-bcc-42c00adb4181/replay-verifier.log");
    assert_eq!(constant_scalar_load["error_id"], "BPFIX-E006");
    assert_eq!(constant_scalar_load["failure_class"], "lowering_artifact");
    assert!(constant_scalar_load["evidence"]
        .as_array()
        .unwrap()
        .iter()
        .any(|evidence| {
            evidence["kind"] == "lowering_artifact_signal"
                && evidence["detail"]
                    .as_str()
                    .unwrap()
                    .contains("small scalar constant")
        }));

    let wide_map_value_access =
        run_json("bpfix-bench/cases/github-orangeopensource-p4rt-ovs-5/replay-verifier.log");
    assert_eq!(wide_map_value_access["error_id"], "BPFIX-E005");
    assert_eq!(wide_map_value_access["failure_class"], "lowering_artifact");
    assert!(wide_map_value_access["evidence"]
        .as_array()
        .unwrap()
        .iter()
        .any(|evidence| {
            evidence["kind"] == "lowering_artifact_signal"
                && evidence["detail"]
                    .as_str()
                    .unwrap()
                    .contains("map-value access wider")
        }));

    let checked_map_relation =
        run_json("bpfix-bench/cases/stackoverflow-74178703/replay-verifier.log");
    assert_eq!(checked_map_relation["error_id"], "BPFIX-E005");
    assert_eq!(checked_map_relation["failure_class"], "lowering_artifact");
    assert!(checked_map_relation["evidence"]
        .as_array()
        .unwrap()
        .iter()
        .any(|evidence| {
            evidence["kind"] == "lowering_artifact_signal"
                && evidence["detail"]
                    .as_str()
                    .unwrap()
                    .contains("source bounds the map-value expression")
        }));
}

#[test]
fn verifier_precision_limits_are_triage_not_source_bugs() {
    let packet_precision = run_json("bpfix-bench/cases/stackoverflow-70873332/replay-verifier.log");
    assert_eq!(packet_precision["error_id"], "BPFIX-E001");
    assert_eq!(packet_precision["failure_class"], "verifier_false_positive");
    assert_eq!(packet_precision["help_safety"], "triage_only");
    assert!(packet_precision["evidence"]
        .as_array()
        .unwrap()
        .iter()
        .any(|evidence| {
            evidence["kind"] == "verifier_precision_signal"
                && evidence["detail"]
                    .as_str()
                    .unwrap()
                    .contains("packet-offset precision boundary")
        }));

    let map_relation = run_json("bpfix-bench/cases/stackoverflow-77762365/replay-verifier.log");
    assert_eq!(map_relation["error_id"], "BPFIX-E005");
    assert_eq!(map_relation["failure_class"], "verifier_false_positive");
    assert_eq!(map_relation["help_safety"], "triage_only");
    assert!(map_relation["message"]
        .as_str()
        .unwrap()
        .contains("verifier precision limit"));

    let helper_clamp_relation =
        run_json("bpfix-bench/cases/stackoverflow-72560675/replay-verifier.log");
    assert_eq!(helper_clamp_relation["error_id"], "BPFIX-E005");
    assert_eq!(
        helper_clamp_relation["failure_class"],
        "verifier_false_positive"
    );
    assert_eq!(helper_clamp_relation["help_safety"], "triage_only");
    assert!(evidence_contains(
        &helper_clamp_relation,
        "verifier_precision_signal",
        "cross-variable range relation"
    ));

    let split_payload_relation =
        run_json("bpfix-bench/cases/stackoverflow-79095876/replay-verifier.log");
    assert_eq!(split_payload_relation["error_id"], "BPFIX-E005");
    assert_eq!(
        split_payload_relation["failure_class"],
        "verifier_false_positive"
    );
    assert_eq!(split_payload_relation["help_safety"], "triage_only");
    assert!(evidence_contains(
        &split_payload_relation,
        "verifier_precision_signal",
        "cross-variable range relation"
    ));

    let helper_min_name_without_relation_guard = run_json_stdin(
        "func#0 @0\n\
         0: R1=map_value(map=heap,ks=4,vs=70) R2=scalar(umax=16383) R10=fp0\n\
         ; if (bpf_probe_read_user(map_buf, min, src)) { @ prog.c:20\n\
         1: (85) call bpf_probe_read_user#112\n\
         invalid access to map value, value_size=70 off=0 size=16383\n\
         R1 min value is outside of the allowed memory range\n",
    );
    assert_eq!(
        helper_min_name_without_relation_guard["error_id"],
        "BPFIX-E005"
    );
    assert_eq!(
        helper_min_name_without_relation_guard["failure_class"],
        "source_bug"
    );
    assert!(!evidence_contains(
        &helper_min_name_without_relation_guard,
        "verifier_precision_signal",
        "cross-variable range relation"
    ));
    assert!(evidence_contains(
        &helper_min_name_without_relation_guard,
        "verifier_state_signal",
        "map-value pointer access crosses"
    ));

    let helper_relation_guard_too_small_for_value = run_json_stdin(
        "func#0 @0\n\
         0: R1=map_value(map=heap,ks=4,vs=70) R2=scalar(umax=16383) R3=scalar(umax=1000) R4=scalar(umax=1) R10=fp0\n\
         ; if (event->len + min <= 1000) @ prog.c:19\n\
         1: (25) if r3 > 0x3e8 goto pc+1 ; R3=scalar(umax=1000) R4=scalar(umax=1)\n\
         ; if (bpf_probe_read_user(map_buf, min, src)) { @ prog.c:20\n\
         2: (85) call bpf_probe_read_user#112\n\
         invalid access to map value, value_size=70 off=0 size=16383\n\
         R1 min value is outside of the allowed memory range\n",
    );
    assert_eq!(
        helper_relation_guard_too_small_for_value["error_id"],
        "BPFIX-E005"
    );
    assert_eq!(
        helper_relation_guard_too_small_for_value["failure_class"],
        "source_bug"
    );
    assert!(!evidence_contains(
        &helper_relation_guard_too_small_for_value,
        "verifier_precision_signal",
        "cross-variable range relation"
    ));
    assert!(evidence_contains(
        &helper_relation_guard_too_small_for_value,
        "verifier_state_signal",
        "map-value pointer access crosses"
    ));

    let packet_repeated_source =
        run_json("bpfix-bench/cases/stackoverflow-70729664/replay-verifier.log");
    assert_eq!(packet_repeated_source["error_id"], "BPFIX-E001");
    assert_eq!(
        packet_repeated_source["failure_class"],
        "verifier_false_positive"
    );
    assert_eq!(packet_repeated_source["help_safety"], "triage_only");
    assert!(packet_repeated_source["evidence"]
        .as_array()
        .unwrap()
        .iter()
        .any(|evidence| {
            evidence["kind"] == "verifier_precision_signal"
                && evidence["detail"]
                    .as_str()
                    .unwrap()
                    .contains("packet-offset precision boundary")
        }));

    let unrelated_guard = "\
; if (ctx->other + len + 64 > data_end) @ prog.c:10
10: R1=pkt(id=4,off=64,r=64,smin=umin=smin32=umin32=20,smax=umax=smax32=umax32=0x1003b,var_off=(0x0; 0x1ffff)) R2=pkt(id=3,off=26,r=0,smin=umin=smin32=umin32=20,smax=umax=smax32=umax32=0x1003b,var_off=(0x0; 0x1ffff)) R6=pkt_end()
10: (2d) if r1 > r6 goto pc+1
20: R2=pkt(id=3,off=26,r=0,smin=umin=smin32=umin32=20,smax=umax=smax32=umax32=0x1003b,var_off=(0x0; 0x1ffff)) R6=pkt_end()
; return *(__u8 *)(ctx->data + len); @ prog.c:20
20: (71) r8 = *(u8 *)(r2 +0)
invalid access to packet, off=26 size=1, R2(id=3,off=26,r=0)
processed 21 insns (limit 1000000) max_states_per_insn 0 total_states 1 peak_states 1 mark_read 0
";
    let unrelated = run_json_stdin(unrelated_guard);
    assert_eq!(unrelated["failure_class"], "source_bug");
    assert!(!unrelated["evidence"]
        .as_array()
        .unwrap()
        .iter()
        .any(|evidence| {
            evidence["kind"] == "lowering_artifact_signal"
                || evidence["kind"] == "verifier_precision_signal"
        }));

    let unrelated_guard_with_prior_history = "\
; char *p = data + len; @ prog.c:4
0: R2=pkt(off=26,r=100) R6=pkt_end()
; char *other_checked = other + len + 64; @ prog.c:10
2: R1=pkt(id=4,off=64,r=64,smin=umin=smin32=umin32=20,smax=umax=smax32=umax32=0x1003b,var_off=(0x0; 0x1ffff)) R6=pkt_end()
; if (other_checked > data_end) @ prog.c:11
2: (2d) if r1 > r6 goto pc+1
20: R2=pkt(id=3,off=26,r=0,smin=umin=smin32=umin32=20,smax=umax=smax32=umax32=0x1003b,var_off=(0x0; 0x1ffff)) R6=pkt_end()
; return *(__u8 *)(p); @ prog.c:20
20: (71) r8 = *(u8 *)(r2 +0)
invalid access to packet, off=26 size=1, R2(id=3,off=26,r=0)
processed 21 insns (limit 1000000) max_states_per_insn 0 total_states 1 peak_states 1 mark_read 0
";
    let unrelated_with_history = run_json_stdin(unrelated_guard_with_prior_history);
    assert_eq!(unrelated_with_history["failure_class"], "source_bug");
    assert!(!unrelated_with_history["evidence"]
        .as_array()
        .unwrap()
        .iter()
        .any(|evidence| {
            evidence["kind"] == "lowering_artifact_signal"
                || evidence["kind"] == "verifier_precision_signal"
        }));

    let packet_sizeof_guard =
        run_json("bpfix-bench/cases/stackoverflow-70760516/replay-verifier.log");
    assert_eq!(packet_sizeof_guard["error_id"], "BPFIX-E001");
    assert_eq!(
        packet_sizeof_guard["failure_class"],
        "verifier_false_positive"
    );
    assert_eq!(packet_sizeof_guard["help_safety"], "triage_only");
    assert!(packet_sizeof_guard["evidence"]
        .as_array()
        .unwrap()
        .iter()
        .any(|evidence| {
            evidence["kind"] == "verifier_precision_signal"
                && evidence["detail"]
                    .as_str()
                    .unwrap()
                    .contains("packet-offset precision boundary")
        }));
}

#[test]
fn verifier_precision_labels_without_runtime_proof_stay_source_bugs() {
    let off_by_one_guard = run_json("bpfix-bench/cases/stackoverflow-72575736/replay-verifier.log");
    assert_eq!(off_by_one_guard["error_id"], "BPFIX-E001");
    assert_eq!(off_by_one_guard["failure_class"], "source_bug");

    let loop_callback = run_json("bpfix-bench/cases/stackoverflow-77967675/replay-verifier.log");
    assert_eq!(loop_callback["error_id"], "BPFIX-E001");
    assert_eq!(loop_callback["failure_class"], "source_bug");
}

#[test]
fn map_lookup_unreadable_key_argument_points_to_helper_arg() {
    let unreadable_key =
        run_json("bpfix-bench/cases/github-commit-cilium-3740e9db8fef/replay-verifier.log");
    assert_eq!(unreadable_key["error_id"], "BPFIX-E003");
    assert_eq!(unreadable_key["failure_class"], "source_bug");
    assert!(unreadable_key["message"]
        .as_str()
        .unwrap()
        .contains("map lookup key pointer argument is unreadable"));
    assert!(unreadable_key["required_proof"]
        .as_str()
        .unwrap()
        .contains("initialized map key storage"));
    assert!(evidence_contains(
        &unreadable_key,
        "verifier_state_signal",
        "bpf_map_lookup_elem consumes R2"
    ));
    assert!(unreadable_key["help"]
        .as_array()
        .unwrap()
        .iter()
        .any(|help| help
            .as_str()
            .unwrap()
            .contains("not an uninitialized key pointer")));

    let address_of_key_argument = run_json_stdin(
        "0: R1=ctx() R10=fp0\n\
         ; __u64 *value = bpf_map_lookup_elem(&values, &key); @ prog.c:19\n\
         0: (18) r1 = 0xffff8994f9d68800 ; R1_w=map_ptr(map=values,ks=4,vs=8)\n\
         2: (85) call bpf_map_lookup_elem#1\n\
         R2 !read_ok\n",
    );
    assert_eq!(address_of_key_argument["error_id"], "BPFIX-E003");
    assert_eq!(address_of_key_argument["failure_class"], "source_bug");
    assert!(!evidence_contains(
        &address_of_key_argument,
        "verifier_state_signal",
        "bpf_map_lookup_elem consumes R2"
    ));

    let expression_key_argument = run_json_stdin(
        "0: R1=ctx() R10=fp0\n\
         ; __u64 *value = bpf_map_lookup_elem(&values, key + 0); @ prog.c:19\n\
         0: (18) r1 = 0xffff8994f9d68800 ; R1_w=map_ptr(map=values,ks=4,vs=8)\n\
         2: (85) call bpf_map_lookup_elem#1\n\
         R2 !read_ok\n",
    );
    assert_eq!(expression_key_argument["error_id"], "BPFIX-E003");
    assert_eq!(expression_key_argument["failure_class"], "source_bug");
    assert!(!evidence_contains(
        &expression_key_argument,
        "verifier_state_signal",
        "bpf_map_lookup_elem consumes R2"
    ));

    let cast_key_argument = run_json_stdin(
        "0: R1=ctx() R10=fp0\n\
         ; __u64 *value = bpf_map_lookup_elem(&values, (void *)key); @ prog.c:19\n\
         0: (18) r1 = 0xffff8994f9d68800 ; R1_w=map_ptr(map=values,ks=4,vs=8)\n\
         2: (85) call bpf_map_lookup_elem#1\n\
         R2 !read_ok\n",
    );
    assert_eq!(cast_key_argument["error_id"], "BPFIX-E003");
    assert_eq!(cast_key_argument["failure_class"], "source_bug");
    assert!(!evidence_contains(
        &cast_key_argument,
        "verifier_state_signal",
        "bpf_map_lookup_elem consumes R2"
    ));

    let non_map_helper = run_json_stdin(
        "0: R1=ctx() R10=fp0\n\
         ; bpf_probe_read_kernel(dst, len, key); @ prog.c:19\n\
         2: (85) call bpf_probe_read_kernel#113\n\
         R2 !read_ok\n",
    );
    assert_eq!(non_map_helper["error_id"], "BPFIX-E003");
    assert_eq!(non_map_helper["failure_class"], "source_bug");
    assert!(!evidence_contains(
        &non_map_helper,
        "verifier_state_signal",
        "bpf_map_lookup_elem consumes R2"
    ));
    assert!(!evidence_contains(
        &non_map_helper,
        "verifier_state_signal",
        "helper call consumes an argument register"
    ));
    assert!(!evidence_contains(
        &non_map_helper,
        "verifier_state_signal",
        "program ABI did not provide"
    ));

    let map_lookup_mentioned_but_not_terminal = run_json_stdin(
        "0: R1=ctx() R10=fp0\n\
         ; if (bpf_map_lookup_elem(&values, key)) bpf_probe_read_kernel(dst, len, key); @ prog.c:19\n\
         2: (85) call bpf_probe_read_kernel#113\n\
         R2 !read_ok\n",
    );
    assert_eq!(
        map_lookup_mentioned_but_not_terminal["error_id"],
        "BPFIX-E003"
    );
    assert_eq!(
        map_lookup_mentioned_but_not_terminal["failure_class"],
        "source_bug"
    );
    assert!(!evidence_contains(
        &map_lookup_mentioned_but_not_terminal,
        "verifier_state_signal",
        "bpf_map_lookup_elem consumes R2"
    ));

    let stale_map_lookup_before_terminal_helper = run_json_stdin(
        "0: R1=ctx() R10=fp0\n\
         2: (85) call bpf_map_lookup_elem#1\n\
         ; if (bpf_map_lookup_elem(&values, key)) bpf_probe_read_kernel(dst, len, key); @ prog.c:19\n\
         2: (85) call bpf_probe_read_kernel#113\n\
         R2 !read_ok\n",
    );
    assert_eq!(
        stale_map_lookup_before_terminal_helper["error_id"],
        "BPFIX-E003"
    );
    assert_eq!(
        stale_map_lookup_before_terminal_helper["failure_class"],
        "source_bug"
    );
    assert!(!evidence_contains(
        &stale_map_lookup_before_terminal_helper,
        "verifier_state_signal",
        "bpf_map_lookup_elem consumes R2"
    ));

    let state_line_after_terminal_map_lookup = run_json_stdin(
        "0: R1=ctx() R10=fp0\n\
         ; __u64 *value = bpf_map_lookup_elem(&values, key); @ prog.c:19\n\
         2: (85) call bpf_map_lookup_elem#1\n\
         2: R1=map_ptr(map=values,ks=4,vs=8) R2=scalar()\n\
         R2 !read_ok\n",
    );
    assert_eq!(
        state_line_after_terminal_map_lookup["error_id"],
        "BPFIX-E003"
    );
    assert_eq!(
        state_line_after_terminal_map_lookup["failure_class"],
        "source_bug"
    );
    assert!(evidence_contains(
        &state_line_after_terminal_map_lookup,
        "verifier_state_signal",
        "bpf_map_lookup_elem consumes R2"
    ));

    let ambiguous_same_line_lookup = run_json_stdin(
        "0: R1=ctx() R10=fp0\n\
         ; if (bpf_map_lookup_elem(&values, key)) value = bpf_map_lookup_elem(&values, &key); @ prog.c:19\n\
         2: (85) call bpf_map_lookup_elem#1\n\
         R2 !read_ok\n",
    );
    assert_eq!(ambiguous_same_line_lookup["error_id"], "BPFIX-E003");
    assert_eq!(ambiguous_same_line_lookup["failure_class"], "source_bug");
    assert!(!evidence_contains(
        &ambiguous_same_line_lookup,
        "verifier_state_signal",
        "bpf_map_lookup_elem consumes R2"
    ));
}

#[test]
fn stack_initialization_source_state_signals_cover_unreadable_exits_and_helper_reads() {
    let unreadable_return =
        run_json("bpfix-bench/cases/github-commit-bcc-80b1e778aa72/replay-verifier.log");
    assert_eq!(unreadable_return["error_id"], "BPFIX-E003");
    assert_eq!(unreadable_return["failure_class"], "source_bug");
    assert!(unreadable_return["message"]
        .as_str()
        .unwrap()
        .contains("return register is unreadable"));
    assert!(evidence_contains(
        &unreadable_return,
        "verifier_state_signal",
        "rejects BPF_EXIT because"
    ));

    let legacy_skb_load = run_json("bpfix-bench/cases/stackoverflow-67441023/replay-verifier.log");
    assert_eq!(legacy_skb_load["error_id"], "BPFIX-E003");
    assert_eq!(legacy_skb_load["failure_class"], "source_bug");
    assert!(legacy_skb_load["message"]
        .as_str()
        .unwrap()
        .contains("legacy skb load"));
    assert!(evidence_contains(
        &legacy_skb_load,
        "verifier_state_signal",
        "legacy skb load"
    ));

    let dynptr_slice_small_buffer =
        run_json("bpfix-bench/cases/kernel-selftest-dynptr-fail-test-dynptr-skb-small-buff-cgroup-skb-egress-4f498dbd/replay-verifier.log");
    assert_eq!(dynptr_slice_small_buffer["error_id"], "BPFIX-E003");
    assert_eq!(dynptr_slice_small_buffer["failure_class"], "source_bug");
    assert!(dynptr_slice_small_buffer["message"]
        .as_str()
        .unwrap()
        .contains("helper memory/length pair"));
    assert!(evidence_contains(
        &dynptr_slice_small_buffer,
        "verifier_state_signal",
        "stack pointer and length"
    ));

    let initialized_stack_buffer_large_enough = run_json_stdin(
        "0: R1=ctx() R10=fp0\n\
         1: (7b) *(u64 *)(r10 -24) = r2        ; R2_w=0 R10=fp0 fp-24_w=0\n\
         2: (bf) r3 = r10                      ; R3_w=fp0 R10=fp0\n\
         3: (07) r3 += -24                     ; R3_w=fp-24\n\
         4: (b7) r4 = 8                        ; R4_w=8\n\
         5: (85) call bpf_dynptr_slice#71567\n\
         invalid read from stack R3 off -24+8 size 8\n\
         arg#2 arg#3 memory, len pair leads to invalid memory access\n",
    );
    assert_eq!(
        initialized_stack_buffer_large_enough["error_id"],
        "BPFIX-E003"
    );
    assert!(!evidence_contains(
        &initialized_stack_buffer_large_enough,
        "verifier_state_signal",
        "stack pointer and length"
    ));
}

#[test]
fn underchecked_packet_guards_report_source_state_signal() {
    let off_by_one_guard = run_json("bpfix-bench/cases/stackoverflow-72575736/replay-verifier.log");
    assert_eq!(off_by_one_guard["error_id"], "BPFIX-E001");
    assert_eq!(off_by_one_guard["failure_class"], "source_bug");
    assert!(evidence_contains(
        &off_by_one_guard,
        "verifier_state_signal",
        "source has a packet bounds check"
    ));
    assert!(off_by_one_guard["help"]
        .as_array()
        .unwrap()
        .iter()
        .any(|help| help.as_str().unwrap().contains("include the access width")));

    let underchecked_copy =
        run_json("bpfix-bench/cases/stackoverflow-73088287/replay-verifier.log");
    assert_eq!(underchecked_copy["error_id"], "BPFIX-E001");
    assert_eq!(underchecked_copy["failure_class"], "source_bug");
    assert!(evidence_contains(
        &underchecked_copy,
        "verifier_state_signal",
        "shorter packet range"
    ));

    let underchecked_payload =
        run_json("bpfix-bench/cases/stackoverflow-78186253/replay-verifier.log");
    assert_eq!(underchecked_payload["error_id"], "BPFIX-E001");
    assert_eq!(underchecked_payload["failure_class"], "source_bug");
    assert!(evidence_contains(
        &underchecked_payload,
        "verifier_state_signal",
        "shorter packet range"
    ));

    let derived_header_pointer =
        run_json("bpfix-bench/cases/stackoverflow-76277872/replay-verifier.log");
    assert_eq!(derived_header_pointer["error_id"], "BPFIX-E001");
    assert_eq!(derived_header_pointer["failure_class"], "source_bug");
    assert!(evidence_contains(
        &derived_header_pointer,
        "verifier_state_signal",
        "packet register's proven range is shorter"
    ));

    let stale_branch_state_from_prior_fragment = run_json_stdin(
        "\
0: R1=pkt(off=14,r=14) R7=pkt_end()
0: (2d) if r1 > r7 goto pc+1
invalid access to packet, off=26 size=4, R1(id=0,off=26,r=14)
processed 1 insns (limit 1000000) max_states_per_insn 0 total_states 1 peak_states 1 mark_read 0
func#1 @0
0: (61) r2 = *(u32 *)(r1 +12)
invalid access to packet, off=26 size=4, R1(id=0,off=26,r=14)
",
    );
    assert_eq!(
        stale_branch_state_from_prior_fragment["error_id"],
        "BPFIX-E001"
    );
    assert_eq!(
        stale_branch_state_from_prior_fragment["failure_class"],
        "source_bug"
    );
    assert!(!evidence_contains(
        &stale_branch_state_from_prior_fragment,
        "verifier_state_signal",
        "packet register's proven range is shorter"
    ));

    let loop_callback = run_json("bpfix-bench/cases/stackoverflow-77967675/replay-verifier.log");
    assert_eq!(loop_callback["error_id"], "BPFIX-E001");
    assert_eq!(loop_callback["failure_class"], "source_bug");
    assert!(!evidence_contains(
        &loop_callback,
        "verifier_state_signal",
        "shorter packet range"
    ));

    let unrelated_guard = "\
; if (ctx->other + len + 1 > data_end) @ prog.c:10
10: R1=pkt(id=8,off=1,r=1,smin=umin=smin32=umin32=20,smax=umax=smax32=umax32=0x1003b,var_off=(0x0; 0x1ffff)) R2=pkt(id=3,off=26,r=0,smin=umin=smin32=umin32=20,smax=umax=smax32=umax32=0x1003b,var_off=(0x0; 0x1ffff)) R6=pkt_end()
10: (2d) if r1 > r6 goto pc+1
; return *(__u16 *)(ctx->data + len); @ prog.c:20
20: (69) r0 = *(u16 *)(r2 +0)
invalid access to packet, off=26 size=2, R2(id=3,off=26,r=0)
processed 21 insns (limit 1000000) max_states_per_insn 0 total_states 1 peak_states 1 mark_read 0
";
    let unrelated = run_json_stdin(unrelated_guard);
    assert_eq!(unrelated["error_id"], "BPFIX-E001");
    assert_eq!(unrelated["failure_class"], "source_bug");
    assert!(!evidence_contains(
        &unrelated,
        "verifier_state_signal",
        "shorter packet range"
    ));

    let unrelated_guard_with_nearby_packet_branch = "\
; if (ctx->other + len + 1 > data_end) @ prog.c:10
10: R1=pkt(id=8,off=1,r=1,smin=umin=smin32=umin32=20,smax=umax=smax32=umax32=0x1003b,var_off=(0x0; 0x1ffff)) R2=pkt(id=3,off=26,r=0,smin=umin=smin32=umin32=20,smax=umax=smax32=umax32=0x1003b,var_off=(0x0; 0x1ffff)) R6=pkt_end()
10: (2d) if r1 > r6 goto pc+1
12: R2=pkt(id=3,off=26,r=0,smin=umin=smin32=umin32=20,smax=umax=smax32=umax32=0x1003b,var_off=(0x0; 0x1ffff)) R7=scalar()
12: (1d) if r2 == r7 goto pc+1
; return *(__u16 *)(ctx->data + len); @ prog.c:20
20: (69) r0 = *(u16 *)(r2 +0)
invalid access to packet, off=26 size=2, R2(id=3,off=26,r=0)
processed 21 insns (limit 1000000) max_states_per_insn 0 total_states 1 peak_states 1 mark_read 0
";
    let unrelated_nearby = run_json_stdin(unrelated_guard_with_nearby_packet_branch);
    assert_eq!(unrelated_nearby["error_id"], "BPFIX-E001");
    assert_eq!(unrelated_nearby["failure_class"], "source_bug");
    assert!(!evidence_contains(
        &unrelated_nearby,
        "verifier_state_signal",
        "shorter packet range"
    ));
}

#[test]
fn map_pointer_scalar_zero_reports_missing_relocation() {
    let scalar_zero_map_arg =
        run_json("bpfix-bench/cases/stackoverflow-72606055/replay-verifier.log");
    assert_eq!(scalar_zero_map_arg["error_id"], "BPFIX-E021");
    assert_eq!(
        scalar_zero_map_arg["failure_class"],
        "environment_or_configuration"
    );
    assert_eq!(scalar_zero_map_arg["help_safety"], "triage_only");
    assert!(scalar_zero_map_arg["required_proof"]
        .as_str()
        .unwrap()
        .contains("apply the map relocation"));
    assert!(scalar_zero_map_arg["evidence"]
        .as_array()
        .unwrap()
        .iter()
        .any(|evidence| {
            evidence["kind"] == "verifier_state_signal"
                && evidence["detail"].as_str().unwrap().contains("scalar zero")
        }));
    assert!(scalar_zero_map_arg["help"]
        .as_array()
        .unwrap()
        .iter()
        .any(|help| help.as_str().unwrap().contains("applies map relocations")));

    let declared_map_symbol = run_json_stdin(
        "0: R1=ctx() R10=fp0\n\
         ; struct { __uint(type, BPF_MAP_TYPE_ARRAY); } my_map SEC(\".maps\"); @ prog.c:3\n\
         ; value = bpf_map_lookup_elem(&my_map, &key); @ prog.c:10\n\
         0: (b7) r1 = 0                  ; R1_w=0\n\
         1: (85) call bpf_map_lookup_elem#1\n\
         R1 type=scalar expected=map_ptr\n",
    );
    assert_eq!(declared_map_symbol["error_id"], "BPFIX-E021");
    assert_eq!(
        declared_map_symbol["failure_class"],
        "environment_or_configuration"
    );
    assert!(declared_map_symbol["evidence"]
        .as_array()
        .unwrap()
        .iter()
        .any(|evidence| evidence["kind"] == "verifier_state_signal"));

    let undeclared_map_symbol = run_json_stdin(
        "0: R1=ctx() R10=fp0\n\
         ; value = bpf_map_lookup_elem(&my_map, &key); @ prog.c:10\n\
         0: (b7) r1 = 0                  ; R1_w=0\n\
         1: (85) call bpf_map_lookup_elem#1\n\
         R1 type=scalar expected=map_ptr\n",
    );
    assert_source_bug_without_verifier_state_signal(&undeclared_map_symbol, "BPFIX-E008");

    let wrong_map_argument =
        run_json("bpfix-bench/cases/stackoverflow-70091221/replay-verifier.log");
    assert_eq!(wrong_map_argument["error_id"], "BPFIX-E008");
    assert_eq!(wrong_map_argument["failure_class"], "source_bug");
    assert!(evidence_contains(
        &wrong_map_argument,
        "verifier_state_signal",
        "helper or kfunc contract"
    ));

    let literal_null_map = run_json_stdin(
        "0: R1=ctx() R10=fp0\n\
         ; value = bpf_map_lookup_elem(0, &key); @ prog.c:10\n\
         0: (b7) r1 = 0                  ; R1_w=0\n\
         1: (85) call bpf_map_lookup_elem#1\n\
         R1 type=scalar expected=map_ptr\n",
    );
    assert_source_bug_without_verifier_state_signal(&literal_null_map, "BPFIX-E008");

    let suffixed_null_map = run_json_stdin(
        "0: R1=ctx() R10=fp0\n\
         ; value = bpf_map_lookup_elem(0ULL, &key); @ prog.c:10\n\
         0: (b7) r1 = 0                  ; R1_w=0\n\
         1: (85) call bpf_map_lookup_elem#1\n\
         R1 type=scalar expected=map_ptr\n",
    );
    assert_source_bug_without_verifier_state_signal(&suffixed_null_map, "BPFIX-E008");

    let cast_null_map = run_json_stdin(
        "0: R1=ctx() R10=fp0\n\
         ; value = bpf_map_lookup_elem((struct bpf_map *)0, &key); @ prog.c:10\n\
         0: (b7) r1 = 0                  ; R1_w=0\n\
         1: (85) call bpf_map_lookup_elem#1\n\
         R1 type=scalar expected=map_ptr\n",
    );
    assert_source_bug_without_verifier_state_signal(&cast_null_map, "BPFIX-E008");

    let zero_valued_variable_map = run_json_stdin(
        "0: R1=ctx() R10=fp0\n\
         ; void *m = 0; @ prog.c:9\n\
         ; value = bpf_map_lookup_elem(m, &key); @ prog.c:10\n\
         0: (b7) r1 = 0                  ; R1_w=0\n\
         1: (85) call bpf_map_lookup_elem#1\n\
         R1 type=scalar expected=map_ptr\n",
    );
    assert_source_bug_without_verifier_state_signal(&zero_valued_variable_map, "BPFIX-E008");

    let map_named_zero_variable = run_json_stdin(
        "0: R1=ctx() R10=fp0\n\
         ; void *map = 0; @ prog.c:9\n\
         ; value = bpf_map_lookup_elem(map, &key); @ prog.c:10\n\
         0: (b7) r1 = 0                  ; R1_w=0\n\
         1: (85) call bpf_map_lookup_elem#1\n\
         R1 type=scalar expected=map_ptr\n",
    );
    assert_source_bug_without_verifier_state_signal(&map_named_zero_variable, "BPFIX-E008");

    let map_ptr_named_zero_variable = run_json_stdin(
        "0: R1=ctx() R10=fp0\n\
         ; void *my_map_ptr = 0; @ prog.c:9\n\
         ; value = bpf_map_lookup_elem(my_map_ptr, &key); @ prog.c:10\n\
         0: (b7) r1 = 0                  ; R1_w=0\n\
         1: (85) call bpf_map_lookup_elem#1\n\
         R1 type=scalar expected=map_ptr\n",
    );
    assert_source_bug_without_verifier_state_signal(&map_ptr_named_zero_variable, "BPFIX-E008");

    let address_of_key_argument = run_json_stdin(
        "0: R1=ctx() R10=fp0\n\
         ; value = bpf_map_lookup_elem(&key, &key); @ prog.c:10\n\
         0: (b7) r1 = 0                  ; R1_w=0\n\
         1: (85) call bpf_map_lookup_elem#1\n\
         R1 type=scalar expected=map_ptr\n",
    );
    assert_source_bug_without_verifier_state_signal(&address_of_key_argument, "BPFIX-E008");

    let stale_map_lookup_before_terminal_non_map_helper = run_json_stdin(
        "0: R1=ctx() R10=fp0\n\
         ; struct { __uint(type, BPF_MAP_TYPE_ARRAY); } my_map SEC(\".maps\"); @ prog.c:3\n\
         1: (85) call bpf_map_lookup_elem#1\n\
         ; value = bpf_map_lookup_elem(&my_map, &key); @ prog.c:10\n\
         1: (85) call bpf_probe_read_kernel#113\n\
         R1 type=scalar expected=map_ptr\n",
    );
    assert_source_bug_without_verifier_state_signal(
        &stale_map_lookup_before_terminal_non_map_helper,
        "BPFIX-E008",
    );
}

#[test]
fn verifier_metadata_reports_e021_without_overmatching_helper_errors() {
    let missing_func_info = run_json("bpfix-bench/cases/github-aya-rs-aya-521/replay-verifier.log");
    assert_eq!(missing_func_info["error_id"], "BPFIX-E021");
    assert_eq!(
        missing_func_info["failure_class"],
        "environment_or_configuration"
    );
    assert_eq!(missing_func_info["help_safety"], "triage_only");
    assert!(missing_func_info["required_proof"]
        .as_str()
        .unwrap()
        .contains("BTF func_info"));
    assert!(evidence_contains(
        &missing_func_info,
        "verifier_state_signal",
        "missing BTF func_info"
    ));
    assert!(missing_func_info["help"]
        .as_array()
        .unwrap()
        .iter()
        .any(|help| help.as_str().unwrap().contains("BTF func_info")));

    let missing_reference_metadata =
        run_json("bpfix-bench/cases/github-cilium-cilium-35182/replay-verifier.log");
    assert_eq!(missing_reference_metadata["error_id"], "BPFIX-E021");
    assert_eq!(missing_reference_metadata["failure_class"], "source_bug");
    assert_eq!(missing_reference_metadata["help_safety"], "repair_hint");
    assert!(missing_reference_metadata["required_proof"]
        .as_str()
        .unwrap()
        .contains("reference type metadata"));
    assert!(evidence_contains(
        &missing_reference_metadata,
        "verifier_state_signal",
        "reference type is UNKNOWN"
    ));

    let erased_callee_signature =
        run_json("bpfix-bench/cases/github-commit-cilium-8eb389403823/replay-verifier.log");
    assert_eq!(erased_callee_signature["error_id"], "BPFIX-E021");
    assert_eq!(erased_callee_signature["failure_class"], "source_bug");
    assert!(erased_callee_signature["required_proof"]
        .as_str()
        .unwrap()
        .contains("reference type metadata"));
    assert!(evidence_contains(
        &erased_callee_signature,
        "verifier_state_signal",
        "reference type is UNKNOWN"
    ));

    let erased_second_argument = run_json_stdin(
        "func#0 @0\n\
         func#1 @3\n\
         0: R1=ctx() R2=ctx() R10=fp0\n\
         ; return mock_fib_lookup(ctx, (void *)ctx); @ prog.c:21\n\
         0: (85) call pc+1\n\
         arg#1 reference type('UNKNOWN ') size cannot be determined: -22\n\
         Caller passes invalid args into func#1 ('mock_fib_lookup')\n",
    );
    assert_eq!(erased_second_argument["error_id"], "BPFIX-E021");
    assert!(evidence_contains(
        &erased_second_argument,
        "verifier_state_signal",
        "reference type is UNKNOWN"
    ));

    let unrelated_first_arg_cast = run_json_stdin(
        "func#0 @0\n\
         func#1 @3\n\
         0: R1=ctx() R2=scalar() R10=fp0\n\
         ; return mock_fib_lookup((void *)ctx, len); @ prog.c:21\n\
         0: (85) call pc+1\n\
         arg#1 reference type('UNKNOWN ') size cannot be determined: -22\n\
         Caller passes invalid args into func#1 ('mock_fib_lookup')\n",
    );
    assert_eq!(unrelated_first_arg_cast["error_id"], "BPFIX-E010");
    assert!(!evidence_contains(
        &unrelated_first_arg_cast,
        "verifier_state_signal",
        "reference type is UNKNOWN"
    ));

    let helper_forbidden = run_json("bpfix-bench/cases/github-aya-rs-aya-1233/replay-verifier.log");
    assert_eq!(helper_forbidden["error_id"], "BPFIX-E009");
    assert!(!evidence_contains(
        &helper_forbidden,
        "verifier_state_signal",
        "metadata"
    ));

    let generic_missing_btf = run_json_stdin(
        "0: R1=ctx() R10=fp0\n\
         0: (85) call bpf_ktime_get_ns#5\n\
         missing btf\n",
    );
    assert_eq!(generic_missing_btf["error_id"], "BPFIX-E009");
    assert!(!evidence_contains(
        &generic_missing_btf,
        "verifier_state_signal",
        "func_info"
    ));
}

#[test]
fn fentry_context_argument_mismatch_overrides_terminal_environment_classifier() {
    let typed_context_mismatch =
        run_json("bpfix-bench/cases/stackoverflow-79878809/replay-verifier.log");
    assert_eq!(typed_context_mismatch["error_id"], "BPFIX-E011");
    assert_eq!(typed_context_mismatch["failure_class"], "source_bug");
    assert_eq!(typed_context_mismatch["help_safety"], "repair_hint");
    assert!(typed_context_mismatch["evidence"]
        .as_array()
        .unwrap()
        .iter()
        .any(|evidence| {
            evidence["kind"] == "verifier_state_signal"
                && evidence["detail"]
                    .as_str()
                    .unwrap()
                    .contains("BPF_PROG argument load")
        }));
    let help = typed_context_mismatch["help"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|item| item.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(help.contains("BTF type is verifier-supported"));
    assert!(help.contains("unsupported pointer type"));
    assert!(!help.contains("section name"));
    assert!(!help.contains("attach type"));

    let context_abi_mismatch =
        run_json("bpfix-bench/cases/stackoverflow-67402772/replay-verifier.log");
    assert_eq!(context_abi_mismatch["error_id"], "BPFIX-E011");
    assert_eq!(
        context_abi_mismatch["failure_class"],
        "environment_or_configuration"
    );
    assert!(context_abi_mismatch["required_proof"]
        .as_str()
        .unwrap()
        .contains("active BPF program type"));
    assert!(context_abi_mismatch["evidence"]
        .as_array()
        .unwrap()
        .iter()
        .any(|evidence| {
            evidence["kind"] == "verifier_state_signal"
                && evidence["detail"]
                    .as_str()
                    .unwrap()
                    .contains("ctx register")
        }));

    let lowered_context_access =
        run_json("bpfix-bench/cases/github-commit-cilium-4bb6b56b5c22/replay-verifier.log");
    assert_eq!(lowered_context_access["error_id"], "BPFIX-E011");
    assert_eq!(
        lowered_context_access["failure_class"],
        "environment_or_configuration"
    );
    assert!(lowered_context_access["evidence"]
        .as_array()
        .unwrap()
        .iter()
        .any(|evidence| {
            evidence["kind"] == "verifier_state_signal"
                && evidence["detail"]
                    .as_str()
                    .unwrap()
                    .contains("ctx register")
        }));
    let help = lowered_context_access["help"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|item| item.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(help.contains("unavailable context slot"));
    assert!(!help.contains("section name"));
}

#[test]
fn unreadable_program_argument_overrides_stack_readability_classifier() {
    let entry_arg = run_json("bpfix-bench/cases/stackoverflow-69506785/replay-verifier.log");
    assert_eq!(entry_arg["error_id"], "BPFIX-E011");
    assert_eq!(entry_arg["failure_class"], "source_bug");
    assert!(evidence_contains(
        &entry_arg,
        "verifier_state_signal",
        "program ABI did not provide"
    ));
    assert!(entry_arg["required_proof"]
        .as_str()
        .unwrap()
        .contains("program-type context ABI"));
    let help = entry_arg["help"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|item| item.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(help.contains("pt_regs"));
    assert!(!help.contains("Initialize the full stack object"));

    let helper_arg =
        run_json("bpfix-bench/cases/github-commit-cilium-6b3c9f16c99f/replay-verifier.log");
    assert_eq!(helper_arg["error_id"], "BPFIX-E010");
    assert!(evidence_contains(
        &helper_arg,
        "verifier_state_signal",
        "helper call consumes an argument register"
    ));
    assert!(helper_arg["required_proof"]
        .as_str()
        .unwrap()
        .contains("helper argument register"));
    let helper_help = helper_arg["help"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|item| item.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(helper_help.contains("helper argument register"));
    assert!(!helper_help.contains("pt_regs"));
}

#[test]
fn helper_stack_write_beyond_frame_overrides_stack_initialization_classifier() {
    let oversized_stack =
        run_json("bpfix-bench/cases/github-commit-cilium-31a01b994f8b/replay-verifier.log");
    assert_eq!(oversized_stack["error_id"], "BPFIX-E006");
    assert_eq!(oversized_stack["failure_class"], "source_bug");
    assert!(evidence_contains(
        &oversized_stack,
        "verifier_state_signal",
        "frame-pointer stack region"
    ));
    assert!(oversized_stack["required_proof"]
        .as_str()
        .unwrap()
        .contains("-512..0"));
    let help = oversized_stack["help"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|item| item.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(help.contains("per-CPU map"));
    assert!(!help.contains("Initialize the full stack object"));
}

#[test]
fn unavailable_context_field_requires_ctx_state_and_matching_access_shape() {
    let scalar_base = run_json_stdin(
        "func#0 @0\n\
         0: R2=scalar() R10=fp0\n\
         1: (61) r3 = *(u32 *)(r2 +96)\n\
         invalid bpf_context access off=96 size=4\n",
    );
    assert_eq!(scalar_base["error_id"], "BPFIX-E011");
    assert_eq!(scalar_base["failure_class"], "environment_or_configuration");
    assert!(!evidence_contains(
        &scalar_base,
        "verifier_state_signal",
        "ctx register"
    ));

    let mismatched_size = run_json_stdin(
        "func#0 @0\n\
         0: R1=ctx() R10=fp0\n\
         1: (61) r3 = *(u32 *)(r1 +96)\n\
         invalid bpf_context access off=96 size=8\n",
    );
    assert_eq!(mismatched_size["error_id"], "BPFIX-E011");
    assert_eq!(
        mismatched_size["failure_class"],
        "environment_or_configuration"
    );
    assert!(!evidence_contains(
        &mismatched_size,
        "verifier_state_signal",
        "ctx register"
    ));

    let mismatched_offset = run_json_stdin(
        "func#0 @0\n\
         0: R1=ctx() R10=fp0\n\
         1: (61) r3 = *(u32 *)(r1 +96)\n\
         invalid bpf_context access off=100 size=4\n",
    );
    assert_eq!(mismatched_offset["error_id"], "BPFIX-E011");
    assert_eq!(
        mismatched_offset["failure_class"],
        "environment_or_configuration"
    );
    assert!(!evidence_contains(
        &mismatched_offset,
        "verifier_state_signal",
        "ctx register"
    ));
}

#[test]
fn kernel_object_field_access_uses_state_and_core_mismatch() {
    let diagnostic =
        run_json("bpfix-bench/cases/github-commit-bcc-a75f0180b714/replay-verifier.log");
    assert_eq!(diagnostic["error_id"], "BPFIX-E011");
    assert_eq!(diagnostic["failure_class"], "source_bug");
    assert_eq!(diagnostic["help_safety"], "repair_hint");
    assert!(evidence_contains(
        &diagnostic,
        "verifier_state_signal",
        "CO-RE relocation metadata targets a different struct"
    ));
    assert!(diagnostic["required_proof"]
        .as_str()
        .unwrap()
        .contains("verifier-supported helper or CO-RE access path"));
    let help = diagnostic["help"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|item| item.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(help.contains("BPF_CORE_READ"));
}

#[test]
fn kernel_object_field_access_requires_matching_state_access_and_core_mismatch() {
    let scalar_base = run_json_stdin(
        "libbpf: prog 'x': relo #0: <byte_off> [1] struct inet_sock.inet_sport (0:5 @ offset 798)\n\
         func#0 @0\n\
         0: R1=scalar() R10=fp0\n\
         1: (69) r2 = *(u16 *)(r1 +798)\n\
         access beyond struct sock at off 798 size 2\n",
    );
    assert_source_bug_without_verifier_state_signal(&scalar_base, "BPFIX-E011");

    let mismatched_size = run_json_stdin(
        "libbpf: prog 'x': relo #0: <byte_off> [1] struct inet_sock.inet_sport (0:5 @ offset 798)\n\
         func#0 @0\n\
         0: R1=ptr_sock() R10=fp0\n\
         1: (69) r2 = *(u16 *)(r1 +798)\n\
         access beyond struct sock at off 798 size 4\n",
    );
    assert_source_bug_without_verifier_state_signal(&mismatched_size, "BPFIX-E011");

    let no_core_mismatch = run_json_stdin(
        "func#0 @0\n\
         0: R1=ptr_sock() R10=fp0\n\
         1: (69) r2 = *(u16 *)(r1 +798)\n\
         access beyond struct sock at off 798 size 2\n",
    );
    assert_source_bug_without_verifier_state_signal(&no_core_mismatch, "BPFIX-E011");

    let same_core_struct = run_json_stdin(
        "libbpf: prog 'x': relo #0: <byte_off> [1] struct sock.sk_hash (0:5 @ offset 798)\n\
         func#0 @0\n\
         0: R1=ptr_sock() R10=fp0\n\
         1: (69) r2 = *(u16 *)(r1 +798)\n\
         access beyond struct sock at off 798 size 2\n",
    );
    assert_source_bug_without_verifier_state_signal(&same_core_struct, "BPFIX-E011");

    let prior_program_relocation = run_json_stdin(
        "libbpf: prog 'other_prog': relo #0: <byte_off> [1] struct inet_sock.inet_sport (0:5 @ offset 798)\n\
         libbpf: prog 'other_prog': relo #0: patched insn #1 (LDX/ST/STX) off 798 -> 798\n\
         libbpf: prog 'failed_prog': -- BEGIN PROG LOAD LOG --\n\
         func#0 @0\n\
         0: R1=ptr_sock() R10=fp0\n\
         1: (69) r2 = *(u16 *)(r1 +798)\n\
         access beyond struct sock at off 798 size 2\n\
         -- END PROG LOAD LOG --\n",
    );
    assert_source_bug_without_verifier_state_signal(&prior_program_relocation, "BPFIX-E011");

    let wrong_patched_instruction = run_json_stdin(
        "libbpf: prog 'failed_prog': relo #0: <byte_off> [1] struct inet_sock.inet_sport (0:5 @ offset 798)\n\
         libbpf: prog 'failed_prog': relo #0: patched insn #2 (LDX/ST/STX) off 798 -> 798\n\
         libbpf: prog 'failed_prog': -- BEGIN PROG LOAD LOG --\n\
         func#0 @0\n\
         0: R1=ptr_sock() R10=fp0\n\
         1: (69) r2 = *(u16 *)(r1 +798)\n\
         access beyond struct sock at off 798 size 2\n\
         -- END PROG LOAD LOG --\n",
    );
    assert_source_bug_without_verifier_state_signal(&wrong_patched_instruction, "BPFIX-E011");

    let prior_same_program_attempt = run_json_stdin(
        "libbpf: prog 'failed_prog': relo #0: <byte_off> [1] struct inet_sock.inet_sport (0:5 @ offset 798)\n\
         libbpf: prog 'failed_prog': relo #0: patched insn #1 (LDX/ST/STX) off 798 -> 798\n\
         libbpf: prog 'failed_prog': -- BEGIN PROG LOAD LOG --\n\
         func#0 @0\n\
         0: R0=scalar() R10=fp0\n\
         1: (95) exit\n\
         -- END PROG LOAD LOG --\n\
         libbpf: prog 'failed_prog': -- BEGIN PROG LOAD LOG --\n\
         func#0 @0\n\
         0: R1=ptr_sock() R10=fp0\n\
         1: (69) r2 = *(u16 *)(r1 +798)\n\
         access beyond struct sock at off 798 size 2\n\
         -- END PROG LOAD LOG --\n",
    );
    assert_source_bug_without_verifier_state_signal(&prior_same_program_attempt, "BPFIX-E011");
}

#[test]
fn exception_throw_with_live_reference_overrides_jit_environment_classifier() {
    let live_reference_throw = run_json(
        "bpfix-bench/cases/kernel-selftest-exceptions-fail-reject-with-cb-reference-tc-c99ec1a7/replay-verifier.log",
    );
    assert_eq!(live_reference_throw["error_id"], "BPFIX-E004");
    assert_eq!(live_reference_throw["failure_class"], "source_bug");
    assert_eq!(live_reference_throw["help_safety"], "repair_hint");
    assert!(live_reference_throw["required_proof"]
        .as_str()
        .unwrap()
        .contains("release verifier-tracked references"));
    assert!(live_reference_throw["evidence"]
        .as_array()
        .unwrap()
        .iter()
        .any(|evidence| {
            evidence["kind"] == "verifier_state_signal"
                && evidence["detail"]
                    .as_str()
                    .unwrap()
                    .contains("references are live")
        }));
    let help = live_reference_throw["help"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|item| item.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(help.contains("Release verifier-tracked references"));
    assert!(!help.contains("JIT support"));
    let text = run_text(
        "bpfix-bench/cases/kernel-selftest-exceptions-fail-reject-with-cb-reference-tc-c99ec1a7/replay-verifier.log",
    );
    assert!(text.contains("error[BPFIX-E004]: exception callback can throw"));
    assert!(text.contains("bpf_throw can run while verifier-tracked references are live"));
    assert!(text.contains("note[verifier-state]: verifier state reaches bpf_throw"));
    assert!(!text.contains("kernel or JIT does not support this instruction or feature"));

    let raw_log_without_source_comments = "\
0: R1=scalar() R10=fp0 refs=2
1: frame1: R1=scalar() R10=fp0 refs=2 cb
1: (b7) r1 = 0                       ; frame1: R1_w=0 refs=2 cb
2: (85) call bpf_throw#73439
JIT does not support calling kfunc bpf_throw#73439
processed 3 insns (limit 1000000) max_states_per_insn 0 total_states 1 peak_states 1 mark_read 0
";
    let raw = run_json_stdin(raw_log_without_source_comments);
    assert_eq!(raw["error_id"], "BPFIX-E004");
    assert_eq!(raw["failure_class"], "source_bug");

    let async_callback_throw = run_json(
        "bpfix-bench/cases/kernel-selftest-exceptions-fail-reject-async-callback-throw-tc-a86cf7b1/replay-verifier.log",
    );
    assert_eq!(async_callback_throw["error_id"], "BPFIX-E016");
    assert_eq!(
        async_callback_throw["failure_class"],
        "environment_or_configuration"
    );
    assert!(!async_callback_throw["evidence"]
        .as_array()
        .unwrap()
        .iter()
        .any(|evidence| evidence["kind"] == "verifier_state_signal"));

    let rbtree_throw_with_lock_state = run_json(
        "bpfix-bench/cases/kernel-selftest-exceptions-fail-reject-with-rbtree-add-throw-tc-e943cfe2/replay-verifier.log",
    );
    assert_ne!(rbtree_throw_with_lock_state["error_id"], "BPFIX-E004");
    assert_eq!(rbtree_throw_with_lock_state["error_id"], "BPFIX-E015");
    assert!(evidence_contains(
        &rbtree_throw_with_lock_state,
        "verifier_state_signal",
        "enters a synchronous callback"
    ));
    let help = rbtree_throw_with_lock_state["help"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|item| item.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(help.contains("Move callback-invoking operations"));
    assert!(!help.contains("Keep acquire and release operations balanced"));

    let unlocked_before_callback = run_json_stdin(
        "0: R10=fp0\n\
         0: (85) call bpf_spin_lock#93\n\
         1: (85) call bpf_spin_unlock#94\n\
         2: (85) call bpf_rbtree_add_impl#73007\n\
         from 2 to 4: frame1: R10=fp0 cb\n\
         4: frame1: R10=fp0 cb\n\
         5: (85) call bpf_throw#73439\n\
         function calls are not allowed while holding a lock\n\
         processed 6 insns (limit 1000000) max_states_per_insn 0 total_states 1 peak_states 1 mark_read 0\n",
    );
    assert_eq!(unlocked_before_callback["error_id"], "BPFIX-E015");
    assert!(!evidence_contains(
        &unlocked_before_callback,
        "verifier_state_signal",
        "enters a synchronous callback"
    ));

    let callback_completed_before_terminal = run_json_stdin(
        "0: R10=fp0\n\
         0: (85) call bpf_spin_lock#93\n\
         1: (85) call bpf_loop#181\n\
         from 1 to 3: frame1: R10=fp0 cb\n\
         3: frame1: R10=fp0 cb\n\
         4: R10=fp0\n\
         5: (85) call bpf_throw#73439\n\
         function calls are not allowed while holding a lock\n\
         processed 6 insns (limit 1000000) max_states_per_insn 0 total_states 1 peak_states 1 mark_read 0\n",
    );
    assert_eq!(callback_completed_before_terminal["error_id"], "BPFIX-E015");
    assert!(!evidence_contains(
        &callback_completed_before_terminal,
        "verifier_state_signal",
        "enters a synchronous callback"
    ));

    let non_callback_lock_reject = run_json(
        "bpfix-bench/cases/kernel-selftest-irq-irq-wrong-kfunc-class-2-tc-03b53958/replay-verifier.log",
    );
    assert_eq!(non_callback_lock_reject["error_id"], "BPFIX-E013");
    assert!(!evidence_contains(
        &non_callback_lock_reject,
        "verifier_state_signal",
        "enters a synchronous callback"
    ));
}

#[test]
fn reference_live_at_exit_reports_state_signal() {
    let kptr_leak = run_json(
        "bpfix-bench/cases/kernel-selftest-cgrp-kfunc-failure-cgrp-kfunc-xchg-unreleased-tp-btf-cgroup-mkdir-241e8fc0/replay-verifier.log",
    );
    assert_eq!(kptr_leak["error_id"], "BPFIX-E004");
    assert_eq!(kptr_leak["failure_class"], "source_bug");
    assert!(evidence_contains(
        &kptr_leak,
        "verifier_state_signal",
        "BPF_EXIT with the terminal reference id"
    ));
    assert!(kptr_leak["required_proof"]
        .as_str()
        .unwrap()
        .contains("before each BPF_EXIT"));
    assert!(kptr_leak["help"]
        .as_array()
        .unwrap()
        .iter()
        .any(|help| help.as_str().unwrap().contains("cleanup blocks")));

    let crypto_leak = run_json(
        "bpfix-bench/cases/kernel-selftest-crypto-basic-crypto-acquire-syscall-b8afbe98/replay-verifier.log",
    );
    assert_eq!(crypto_leak["error_id"], "BPFIX-E004");
    assert!(evidence_contains(
        &crypto_leak,
        "verifier_state_signal",
        "refs set"
    ));

    let iterator_leak = run_json_stdin(
        "5: (85) call bpf_iter_num_new#71887 ; R0_w=scalar() fp-8_w=iter_num(ref_id=1,state=active,depth=0) refs=1\n\
         6: (b4) w0 = 0 ; R0_w=0 refs=1\n\
         7: (95) exit\n\
         Unreleased reference id=1 alloc_insn=5\n",
    );
    assert_eq!(iterator_leak["error_id"], "BPFIX-E004");
    assert!(evidence_contains(
        &iterator_leak,
        "verifier_state_signal",
        "BPF_EXIT with the terminal reference id"
    ));

    let stale_terminal_without_live_ref = run_json_stdin(
        "5: (85) call bpf_ringbuf_reserve#131 ; R0_w=ringbuf_mem_or_null(id=2,ref_obj_id=2) refs=2\n\
         6: R0=scalar()\n\
         7: (95) exit\n\
         Unreleased reference id=2 alloc_insn=5\n",
    );
    assert_source_bug_without_verifier_state_signal(&stale_terminal_without_live_ref, "BPFIX-E004");

    let non_exit_terminal_site = run_json_stdin(
        "5: (85) call bpf_ringbuf_reserve#131 ; R0_w=ringbuf_mem_or_null(id=2,ref_obj_id=2) refs=2\n\
         6: (b4) w0 = 0 ; R0_w=0 refs=2\n\
         Unreleased reference id=2 alloc_insn=5\n",
    );
    assert_source_bug_without_verifier_state_signal(&non_exit_terminal_site, "BPFIX-E004");

    let dynptr_release_twice =
        run_json("bpfix-bench/cases/kernel-selftest-dynptr-fail-release-twice-raw-tp-3722429d/replay-verifier.log");
    assert_eq!(dynptr_release_twice["error_id"], "BPFIX-E019");
    assert!(!evidence_contains(
        &dynptr_release_twice,
        "verifier_state_signal",
        "BPF_EXIT with the terminal reference id"
    ));

    let irq_lock_ref =
        run_json("bpfix-bench/cases/kernel-selftest-irq-irq-wrong-kfunc-class-2-tc-03b53958/replay-verifier.log");
    assert_eq!(irq_lock_ref["error_id"], "BPFIX-E013");
    assert!(!evidence_contains(
        &irq_lock_ref,
        "verifier_state_signal",
        "BPF_EXIT with the terminal reference id"
    ));

    let exception_throw = run_json(
        "bpfix-bench/cases/kernel-selftest-exceptions-fail-reject-with-cb-reference-tc-c99ec1a7/replay-verifier.log",
    );
    assert_eq!(exception_throw["error_id"], "BPFIX-E004");
    assert!(!evidence_contains(
        &exception_throw,
        "verifier_state_signal",
        "BPF_EXIT with the terminal reference id"
    ));

    let missing_reference_metadata =
        run_json("bpfix-bench/cases/github-aya-rs-aya-521/replay-verifier.log");
    assert_eq!(missing_reference_metadata["error_id"], "BPFIX-E021");
    assert!(!evidence_contains(
        &missing_reference_metadata,
        "verifier_state_signal",
        "BPF_EXIT with the terminal reference id"
    ));
}

#[test]
fn exception_callback_protocol_reports_direct_call_and_return_contract() {
    for path in [
        "bpfix-bench/cases/kernel-selftest-exceptions-fail-reject-exception-cb-call-global-func-tc-bd94f6f8/replay-verifier.log",
        "bpfix-bench/cases/kernel-selftest-exceptions-fail-reject-exception-cb-call-static-func-tc-f3ceb9b7/replay-verifier.log",
    ] {
        let json = run_json(path);
        assert_eq!(json["error_id"], "BPFIX-E013");
        assert_eq!(json["failure_class"], "source_bug");
        assert_eq!(json["source_span"]["instruction_pc"], 3);
        assert!(json["source_span"]["source_text"]
            .as_str()
            .unwrap()
            .contains("exception_cb1"));
        assert!(evidence_contains(
            &json,
            "verifier_state_signal",
            "exception callback"
        ));
        let help = json["help"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|item| item.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(help.contains("Keep exception callbacks out of ordinary subprogram call graphs"));
        assert!(!help.contains("Check the exact register passed"));
    }

    let bad_return = run_json(
        "bpfix-bench/cases/kernel-selftest-exceptions-fail-reject-set-exception-cb-bad-ret1-fentry-bpf-check-8124b586/replay-verifier.log",
    );
    assert_eq!(bad_return["error_id"], "BPFIX-E013");
    assert_eq!(bad_return["failure_class"], "source_bug");
    assert!(bad_return["required_proof"]
        .as_str()
        .unwrap()
        .contains("return-value contract"));
    assert!(evidence_contains(
        &bad_return,
        "verifier_state_signal",
        "exception callback"
    ));
    let bad_return_help = bad_return["help"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|item| item.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(bad_return_help.contains("returns satisfy"));
    assert!(!bad_return_help.contains("Clamp the index or length"));

    let ordinary_return_range =
        run_json("bpfix-bench/cases/stackoverflow-77191387/replay-verifier.log");
    assert_eq!(ordinary_return_range["error_id"], "BPFIX-E005");
    assert!(!evidence_contains(
        &ordinary_return_range,
        "verifier_state_signal",
        "exception callback"
    ));

    let malformed_direct_call = run_json_stdin(
        "0: R10=fp0\n\
         insn 3 cannot call exception cb directly\n\
         processed 1 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0\n",
    );
    assert_eq!(malformed_direct_call["error_id"], "BPFIX-E010");
    assert!(!evidence_contains(
        &malformed_direct_call,
        "verifier_state_signal",
        "exception callback"
    ));

    let assumed_valid_without_validation = run_json_stdin(
        "3: (85) call pc+1\n\
         Func#2 ('exception_cb1') is global and assumed valid.\n\
         insn 3 cannot call exception cb directly\n\
         processed 4 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0\n",
    );
    assert_eq!(assumed_valid_without_validation["error_id"], "BPFIX-E010");
    assert!(!evidence_contains(
        &assumed_valid_without_validation,
        "verifier_state_signal",
        "exception callback"
    ));

    let arbitrary_name_direct_call = run_json_stdin(
        "; return my_cb(x); @ prog.c:9\n\
         3: (85) call pc+1\n\
         Validating my_cb() func#1...\n\
         4: R0_w=scalar()\n\
         insn 3 cannot call exception cb directly\n\
         processed 5 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0\n",
    );
    assert_eq!(arbitrary_name_direct_call["error_id"], "BPFIX-E013");
    assert!(evidence_contains(
        &arbitrary_name_direct_call,
        "verifier_state_signal",
        "exception callback"
    ));

    let ordinary_return_after_prior_callback_validation = run_json_stdin(
        "Validating exception_cb_ok() func#1...\n\
         1: R0_w=0\n\
         1: (95) exit\n\
         Func#1 ('exception_cb_ok') is safe for any args that match its prototype\n\
         2: R1=scalar() R10=fp0\n\
         2: (bf) r0 = r1                       ; R0_w=scalar(id=1)\n\
         3: (95) exit\n\
         At program exit the register R0 has unknown scalar value should have been in [0, 0]\n\
         processed 4 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0\n",
    );
    assert_eq!(
        ordinary_return_after_prior_callback_validation["error_id"],
        "BPFIX-E005"
    );
    assert!(!evidence_contains(
        &ordinary_return_after_prior_callback_validation,
        "verifier_state_signal",
        "exception callback"
    ));

    let known_bad_subprogram_return = run_json_stdin(
        "Validating my_cb() func#1...\n\
         2: R10=fp0\n\
         2: (b7) r0 = 2                       ; R0_w=2\n\
         3: (95) exit\n\
         At program exit the register R0 has unknown scalar value should have been in [3, 4]\n\
         processed 4 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 1 mark_read 0\n",
    );
    assert_eq!(known_bad_subprogram_return["error_id"], "BPFIX-E013");
    assert!(evidence_contains(
        &known_bad_subprogram_return,
        "verifier_state_signal",
        "subprogram"
    ));

    let satisfied_exact_subprogram_return = run_json_stdin(
        "Validating my_cb() func#1...\n\
         2: R10=fp0\n\
         2: (b7) r0 = 3                       ; R0_w=3\n\
         3: (95) exit\n\
         At program exit the register R0 has unknown scalar value should have been in [3, 4]\n\
         processed 4 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 1 mark_read 0\n",
    );
    assert_eq!(satisfied_exact_subprogram_return["error_id"], "BPFIX-E005");
    assert!(!evidence_contains(
        &satisfied_exact_subprogram_return,
        "verifier_state_signal",
        "subprogram"
    ));

    let satisfied_wide_subprogram_return = run_json_stdin(
        "Validating my_cb() func#1...\n\
         2: R10=fp0\n\
         2: (bc) w0 = w1                       ; R0_w=scalar(smin32=3,smax32=4,umin32=3,umax32=4)\n\
         3: (95) exit\n\
         At program exit the register R0 has unknown scalar value should have been in [3, 4]\n\
         processed 4 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 1 mark_read 0\n",
    );
    assert_eq!(satisfied_wide_subprogram_return["error_id"], "BPFIX-E005");
    assert!(!evidence_contains(
        &satisfied_wide_subprogram_return,
        "verifier_state_signal",
        "subprogram"
    ));
}

#[test]
fn exception_throw_signal_uses_nearest_callback_state() {
    let log = "\
0: (85) call bpf_loop#181
0: frame1: R1=scalar() R10=fp0 refs=2 cb
0: R1=scalar() R10=fp0
; bpf_throw(0); @ prog.c:12
1: (85) call bpf_throw#73439
JIT does not support calling kfunc bpf_throw#73439
processed 2 insns (limit 1000000) max_states_per_insn 0 total_states 1 peak_states 1 mark_read 0
";

    let json = run_json_stdin(log);

    assert_eq!(json["error_id"], "BPFIX-E016");
    assert_eq!(json["failure_class"], "environment_or_configuration");
    assert!(!json["evidence"]
        .as_array()
        .unwrap()
        .iter()
        .any(|evidence| evidence["kind"] == "verifier_state_signal"));

    let zero_refs_log = "\
0: frame1: R1=scalar() R10=fp0 refs=0 cb
; bpf_throw(0); @ prog.c:12
1: (85) call bpf_throw#73439
JIT does not support calling kfunc bpf_throw#73439
processed 2 insns (limit 1000000) max_states_per_insn 0 total_states 1 peak_states 1 mark_read 0
";
    let zero_refs = run_json_stdin(zero_refs_log);
    assert_eq!(zero_refs["error_id"], "BPFIX-E016");
    assert_eq!(zero_refs["failure_class"], "environment_or_configuration");

    let async_refs_log = "\
0: frame1: R1=scalar() R10=fp0 refs=2 async_cb
; bpf_throw(0); @ prog.c:12
1: (85) call bpf_throw#73439
JIT does not support calling kfunc bpf_throw#73439
processed 2 insns (limit 1000000) max_states_per_insn 0 total_states 1 peak_states 1 mark_read 0
";
    let async_refs = run_json_stdin(async_refs_log);
    assert_eq!(async_refs["error_id"], "BPFIX-E016");
    assert_eq!(async_refs["failure_class"], "environment_or_configuration");

    let state_between_throw_and_reject_log = "\
1: (85) call bpf_throw#73439
1: frame1: R1=scalar() R10=fp0 refs=2 cb
JIT does not support calling kfunc bpf_throw#73439
processed 2 insns (limit 1000000) max_states_per_insn 0 total_states 1 peak_states 1 mark_read 0
";
    let state_between_throw_and_reject = run_json_stdin(state_between_throw_and_reject_log);
    assert_eq!(state_between_throw_and_reject["error_id"], "BPFIX-E004");
    assert_eq!(
        state_between_throw_and_reject["failure_class"],
        "source_bug"
    );
    assert!(state_between_throw_and_reject["evidence"]
        .as_array()
        .unwrap()
        .iter()
        .any(|evidence| evidence["kind"] == "verifier_state_signal"));

    let repeated_pc_retry_log = "\
0: frame1: R1=scalar() R10=fp0 refs=2 cb
1: (85) call bpf_throw#73439
JIT does not support calling kfunc bpf_throw#73439
0: frame1: R1=scalar() R10=fp0 refs=2 cb
1: (85) call bpf_timer_start#123
JIT does not support calling kfunc bpf_timer_start#123
processed 4 insns (limit 1000000) max_states_per_insn 0 total_states 2 peak_states 1 mark_read 0
";
    let repeated_pc_retry = run_json_stdin(repeated_pc_retry_log);
    assert_eq!(repeated_pc_retry["error_id"], "BPFIX-E016");
    assert_eq!(
        repeated_pc_retry["failure_class"],
        "environment_or_configuration"
    );
    assert!(!repeated_pc_retry["evidence"]
        .as_array()
        .unwrap()
        .iter()
        .any(|evidence| evidence["kind"] == "verifier_state_signal"));

    let state_after_terminal_log = "\
1: (85) call bpf_throw#73439
JIT does not support calling kfunc bpf_throw#73439
1: frame1: R1=scalar() R10=fp0 refs=2 cb
processed 2 insns (limit 1000000) max_states_per_insn 0 total_states 1 peak_states 1 mark_read 0
";
    let state_after_terminal = run_json_stdin(state_after_terminal_log);
    assert_eq!(state_after_terminal["error_id"], "BPFIX-E016");
    assert_eq!(
        state_after_terminal["failure_class"],
        "environment_or_configuration"
    );
    assert!(!state_after_terminal["evidence"]
        .as_array()
        .unwrap()
        .iter()
        .any(|evidence| evidence["kind"] == "verifier_state_signal"));
}

#[test]
fn packet_bounds_diagnostic_reports_prior_verifier_range_proof() {
    let json = run_json("bpfix-bench/cases/github-iovisor-bcc-5062/replay-verifier.log");

    assert_eq!(json["error_id"], "BPFIX-E001");
    assert_eq!(json["failure_class"], "lowering_artifact");

    let labels = json["related_spans"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|span| span["label"].as_str())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(labels.contains("verifier had proved packet range 60 bytes"));
    assert!(labels.contains("required 60 bytes"));
    assert!(json["help"].as_array().unwrap().iter().any(|item| item
        .as_str()
        .unwrap()
        .contains("packet pointer derivation that received the data_end proof")));
}

#[test]
fn packet_bounds_diagnostic_reports_insufficient_verifier_range() {
    let json = run_json("bpfix-bench/cases/stackoverflow-73088287/replay-verifier.log");

    assert_eq!(json["error_id"], "BPFIX-E001");
    assert_eq!(json["failure_class"], "source_bug");

    assert!(
        !json["evidence"].as_array().unwrap().iter().any(|evidence| {
            evidence["kind"] == "lowering_artifact_signal"
                || evidence["kind"] == "verifier_precision_signal"
        })
    );

    let related_spans = json["related_spans"].as_array().unwrap();
    assert!(related_spans.iter().any(|span| {
        span["path"] == "prog.c"
            && span["instruction_pc"] == 26
            && span["source_text"]
                .as_str()
                .unwrap()
                .contains("checked > data_end")
    }));
    assert!(!related_spans.iter().any(|span| {
        span["instruction_pc"] == json["source_span"]["instruction_pc"]
            && span["source_text"] == json["source_span"]["source_text"]
    }));

    let labels = related_spans
        .iter()
        .filter_map(|span| span["label"].as_str())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(labels.contains("verifier only proves packet range 43 bytes"));
    assert!(labels.contains("rejected access requires 59 bytes"));
    assert!(evidence_contains(
        &json,
        "verifier_state_signal",
        "shorter packet range"
    ));

    let help = json["help"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|item| item.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(help.contains("data_end check"));

    for path in [
        "bpfix-bench/cases/github-cilium-cilium-41522/replay-verifier.log",
        "bpfix-bench/cases/stackoverflow-60053570/replay-verifier.log",
    ] {
        let diagnostic = run_json(path);
        assert_eq!(diagnostic["error_id"], "BPFIX-E001");
        assert_eq!(diagnostic["failure_class"], "source_bug");
        assert!(evidence_contains(
            &diagnostic,
            "verifier_state_signal",
            "packet register's proven range"
        ));
        assert!(diagnostic["required_proof"]
            .as_str()
            .unwrap()
            .contains("off + size"));
    }

    let stale_register_state = "\
0: R2=pkt(r=30) R10=fp0
1: R2=scalar() R10=fp0
; byte = *ptr; @ prog.c:20
2: (71) r1 = *(u8 *)(r2 +19)
invalid access to packet, off=19 size=1, R2(id=0,off=19,r=0)
processed 3 insns (limit 1000000) max_states_per_insn 0 total_states 1 peak_states 1 mark_read 0
";
    let stale = run_json_stdin(stale_register_state);
    let stale_labels = stale["related_spans"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|span| span["label"].as_str())
        .collect::<Vec<_>>()
        .join("\n");
    assert_eq!(stale["failure_class"], "source_bug");
    assert!(!stale["evidence"]
        .as_array()
        .unwrap()
        .iter()
        .any(|evidence| {
            evidence["kind"] == "lowering_artifact_signal"
                || evidence["kind"] == "verifier_precision_signal"
        }));
    assert!(!stale_labels.contains("verifier had proved packet range"));
    assert!(!stale_labels.contains("verifier only proves packet range"));
    assert!(!evidence_contains(
        &stale,
        "verifier_state_signal",
        "packet register's proven range"
    ));

    let mismatched_memory_base = "\
0: R2=pkt(r=0) R3=pkt(r=0) R10=fp0
; byte = *ptr; @ prog.c:20
1: (71) r1 = *(u8 *)(r3 +19)
invalid access to packet, off=19 size=1, R2(id=0,off=19,r=0)
processed 2 insns (limit 1000000) max_states_per_insn 0 total_states 1 peak_states 1 mark_read 0
";
    let mismatched_base = run_json_stdin(mismatched_memory_base);
    assert_eq!(mismatched_base["failure_class"], "source_bug");
    assert!(!evidence_contains(
        &mismatched_base,
        "verifier_state_signal",
        "packet register's proven range"
    ));

    let mismatched_reported_range = "\
0: R2=pkt(r=10) R10=fp0
; byte = *ptr; @ prog.c:20
1: (71) r1 = *(u8 *)(r2 +19)
invalid access to packet, off=19 size=1, R2(id=0,off=19,r=0)
processed 2 insns (limit 1000000) max_states_per_insn 0 total_states 1 peak_states 1 mark_read 0
";
    let mismatched_range = run_json_stdin(mismatched_reported_range);
    assert_eq!(mismatched_range["failure_class"], "source_bug");
    assert!(!evidence_contains(
        &mismatched_range,
        "verifier_state_signal",
        "packet register's proven range"
    ));

    let mismatched_instruction_offset = "\
0: R2=pkt(r=0) R10=fp0
; byte = *ptr; @ prog.c:20
1: (71) r1 = *(u8 *)(r2 +0)
invalid access to packet, off=19 size=1, R2(id=0,off=19,r=0)
processed 2 insns (limit 1000000) max_states_per_insn 0 total_states 1 peak_states 1 mark_read 0
";
    let mismatched_offset = run_json_stdin(mismatched_instruction_offset);
    assert_eq!(mismatched_offset["failure_class"], "source_bug");
    assert!(!evidence_contains(
        &mismatched_offset,
        "verifier_state_signal",
        "packet register's proven range"
    ));

    let mismatched_instruction_width = "\
0: R2=pkt(r=0) R10=fp0
; half = *ptr; @ prog.c:20
1: (69) r1 = *(u16 *)(r2 +19)
invalid access to packet, off=19 size=1, R2(id=0,off=19,r=0)
processed 2 insns (limit 1000000) max_states_per_insn 0 total_states 1 peak_states 1 mark_read 0
";
    let mismatched_width = run_json_stdin(mismatched_instruction_width);
    assert_eq!(mismatched_width["failure_class"], "source_bug");
    assert!(!evidence_contains(
        &mismatched_width,
        "verifier_state_signal",
        "packet register's proven range"
    ));

    let mismatched_helper_offset = "\
0: R1=pkt(off=0,r=0) R10=fp0
; ret = bpf_csum_diff(ptr, 4, 0, 0, 0); @ prog.c:20
1: (85) call bpf_csum_diff#28
invalid access to packet, off=34 size=4, R1(id=0,off=34,r=0)
processed 2 insns (limit 1000000) max_states_per_insn 0 total_states 1 peak_states 1 mark_read 0
";
    let mismatched_helper = run_json_stdin(mismatched_helper_offset);
    assert_eq!(mismatched_helper["failure_class"], "source_bug");
    assert!(!evidence_contains(
        &mismatched_helper,
        "verifier_state_signal",
        "packet register's proven range"
    ));

    let call_text_inside_non_call_instruction = "\
0: R1=pkt(off=0,r=0) R10=fp0
; not_a_helper_call(); @ prog.c:20
1: (b7) r0 = 0 ; call bpf_csum_diff#28
invalid access to packet, off=0 size=4, R1(id=0,off=0,r=0)
processed 2 insns (limit 1000000) max_states_per_insn 0 total_states 1 peak_states 1 mark_read 0
";
    let non_call = run_json_stdin(call_text_inside_non_call_instruction);
    assert_eq!(non_call["failure_class"], "source_bug");
    assert!(!evidence_contains(
        &non_call,
        "verifier_state_signal",
        "packet register's proven range"
    ));

    let negative_terminal_offset_mismatch = "\
0: R2=pkt(r=0) R10=fp0
; half = *ptr; @ prog.c:20
1: (69) r1 = *(u16 *)(r2 +0)
invalid access to packet, off=-1 size=2, R2(id=0,off=-1,r=0)
processed 2 insns (limit 1000000) max_states_per_insn 0 total_states 1 peak_states 1 mark_read 0
";
    let negative_offset = run_json_stdin(negative_terminal_offset_mismatch);
    assert_eq!(negative_offset["failure_class"], "source_bug");
    assert!(!evidence_contains(
        &negative_offset,
        "verifier_state_signal",
        "packet register's proven range"
    ));

    let unrelated_helper_call = "\
0: R2=pkt(r=0) R10=fp0
; random = bpf_get_prandom_u32(); @ prog.c:20
1: (85) call bpf_get_prandom_u32#7
invalid access to packet, off=0 size=4, R2(id=0,off=0,r=0)
processed 2 insns (limit 1000000) max_states_per_insn 0 total_states 1 peak_states 1 mark_read 0
";
    let unrelated_helper = run_json_stdin(unrelated_helper_call);
    assert_eq!(unrelated_helper["failure_class"], "source_bug");
    assert!(!evidence_contains(
        &unrelated_helper,
        "verifier_state_signal",
        "packet register's proven range"
    ));

    let stale_packet_lineage = "\
0: R2=pkt(id=1,off=0,r=100) R10=fp0
1: R2=pkt(id=2,off=0,r=0) R10=fp0
; byte = *ptr; @ prog.c:20
2: (71) r1 = *(u8 *)(r2 +59)
invalid access to packet, off=59 size=1, R2(id=2,off=59,r=0)
processed 3 insns (limit 1000000) max_states_per_insn 0 total_states 1 peak_states 1 mark_read 0
";
    let stale_packet = run_json_stdin(stale_packet_lineage);
    assert_eq!(stale_packet["failure_class"], "source_bug");
    assert!(!stale_packet["evidence"]
        .as_array()
        .unwrap()
        .iter()
        .any(|evidence| {
            evidence["kind"] == "lowering_artifact_signal"
                || evidence["kind"] == "verifier_precision_signal"
        }));
    let stale_packet_labels = stale_packet["related_spans"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|span| span["label"].as_str())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(!stale_packet_labels.contains("verifier had proved packet range 100 bytes"));

    let stale_mixed_packet_lineage = "\
0: R2=pkt(off=0,r=100) R10=fp0
1: R2=pkt(id=2,off=0,r=0,smin=umin=smin32=umin32=0,smax=umax=smax32=umax32=0x1003b,var_off=(0x0; 0x1ffff)) R10=fp0
; byte = *ptr; @ prog.c:20
2: (71) r1 = *(u8 *)(r2 +59)
invalid access to packet, off=59 size=1, R2(id=2,off=59,r=0)
processed 3 insns (limit 1000000) max_states_per_insn 0 total_states 1 peak_states 1 mark_read 0
";
    let stale_mixed = run_json_stdin(stale_mixed_packet_lineage);
    assert_eq!(stale_mixed["failure_class"], "source_bug");
    assert!(!stale_mixed["evidence"]
        .as_array()
        .unwrap()
        .iter()
        .any(|evidence| {
            evidence["kind"] == "lowering_artifact_signal"
                || evidence["kind"] == "verifier_precision_signal"
        }));
    let stale_mixed_labels = stale_mixed["related_spans"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|span| span["label"].as_str())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(!stale_mixed_labels.contains("verifier had proved packet range 100 bytes"));

    let stale_mixed_same_offset_packet_lineage = "\
; char *p = data + 26; @ prog.c:10
0: R2=pkt(off=26,r=100) R10=fp0
1: R2=pkt(id=2,off=26,r=0,smin=umin=smin32=umin32=20,smax=umax=smax32=umax32=0x1003b,var_off=(0x0; 0x1ffff)) R10=fp0
; byte = *p; @ prog.c:20
2: (71) r1 = *(u8 *)(r2 +0)
invalid access to packet, off=26 size=1, R2(id=2,off=26,r=0)
processed 3 insns (limit 1000000) max_states_per_insn 0 total_states 1 peak_states 1 mark_read 0
";
    let stale_mixed_same_offset = run_json_stdin(stale_mixed_same_offset_packet_lineage);
    assert_eq!(stale_mixed_same_offset["failure_class"], "source_bug");
    assert!(!stale_mixed_same_offset["evidence"]
        .as_array()
        .unwrap()
        .iter()
        .any(|evidence| {
            evidence["kind"] == "lowering_artifact_signal"
                || evidence["kind"] == "verifier_precision_signal"
        }));
    let stale_mixed_same_offset_labels = stale_mixed_same_offset["related_spans"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|span| span["label"].as_str())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(!stale_mixed_same_offset_labels.contains("verifier had proved packet range 100 bytes"));

    let stale_mixed_variable_derivation = "\
; char *p = data + len; @ prog.c:10
0: R2=pkt(off=26,r=100) R10=fp0
1: R2=pkt(id=2,off=26,r=0,smin=umin=smin32=umin32=20,smax=umax=smax32=umax32=0x1003b,var_off=(0x0; 0x1ffff)) R10=fp0
; byte = *p; @ prog.c:20
2: (71) r1 = *(u8 *)(r2 +0)
invalid access to packet, off=26 size=1, R2(id=2,off=26,r=0)
processed 3 insns (limit 1000000) max_states_per_insn 0 total_states 1 peak_states 1 mark_read 0
";
    let stale_variable = run_json_stdin(stale_mixed_variable_derivation);
    assert_eq!(stale_variable["failure_class"], "source_bug");
    assert!(!stale_variable["evidence"]
        .as_array()
        .unwrap()
        .iter()
        .any(|evidence| {
            evidence["kind"] == "lowering_artifact_signal"
                || evidence["kind"] == "verifier_precision_signal"
        }));
    let stale_variable_labels = stale_variable["related_spans"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|span| span["label"].as_str())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(!stale_variable_labels.contains("verifier had proved packet range 100 bytes"));

    let one_byte_without_range = "\
0: R2=pkt(r=0) R10=fp0
; byte = *ptr; @ prog.c:10
1: (71) r1 = *(u8 *)(r2 +0)
invalid access to packet, off=0 size=1, R2(id=0,off=0,r=0)
processed 2 insns (limit 1000000) max_states_per_insn 0 total_states 1 peak_states 1 mark_read 0
";
    let one_byte = run_json_stdin(one_byte_without_range);
    let one_byte_labels = one_byte["related_spans"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|span| span["label"].as_str())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(!one_byte_labels.contains("verifier only proves packet range"));
}

#[test]
fn atomic_alignment_signal_requires_instruction_scoped_scalar_base() {
    let no_state = run_json_stdin(
        "\
15: (db) r0 = atomic64_cmpxchg((u64 *)(r1 +0), r0, r2)
misaligned access off (0x0; 0xffffffffffffffff)+0+0 size 8
",
    );
    assert_eq!(no_state["error_id"], "BPFIX-E007");
    assert_eq!(no_state["failure_class"], "source_bug");
    assert!(!evidence_contains(
        &no_state,
        "verifier_state_signal",
        "base register is scalar"
    ));

    let pointer_base = run_json_stdin(
        "\
14: R1=map_value(map=prog.bss,ks=4,vs=8) R0=0 R2=1
15: (db) r0 = atomic64_cmpxchg((u64 *)(r1 +0), r0, r2)
misaligned access off (0x0; 0xffffffffffffffff)+0+0 size 8
",
    );
    assert_eq!(pointer_base["error_id"], "BPFIX-E007");
    assert_eq!(pointer_base["failure_class"], "source_bug");
    assert!(!evidence_contains(
        &pointer_base,
        "verifier_state_signal",
        "base register is scalar"
    ));

    let comment_mentions_atomic = run_json_stdin(
        "\
14: R1=scalar() R10=fp0
15: (79) r0 = *(u64 *)(r1 +0) ; comment mentions atomic xchg
misaligned access off (0x0; 0xffffffffffffffff)+0+0 size 8
",
    );
    assert_eq!(comment_mentions_atomic["error_id"], "BPFIX-E007");
    assert_eq!(comment_mentions_atomic["failure_class"], "source_bug");
    assert!(!evidence_contains(
        &comment_mentions_atomic,
        "verifier_state_signal",
        "base register is scalar"
    ));
}

#[test]
fn loop_bound_diagnostic_uses_cur_old_state_snapshots() {
    let loop_bound = run_json("bpfix-bench/cases/stackoverflow-56872436/replay-verifier.log");
    assert_eq!(loop_bound["error_id"], "BPFIX-E018");
    assert_eq!(loop_bound["failure_class"], "source_bug");
    assert!(evidence_contains(
        &loop_bound,
        "verifier_state_signal",
        "current and previous loop-entry states"
    ));
    assert!(loop_bound["required_proof"]
        .as_str()
        .unwrap()
        .contains("back edge"));

    let no_snapshots = run_json_stdin(
        "\
10: (05) goto pc-1
infinite loop detected at insn 10
",
    );
    assert_eq!(no_snapshots["error_id"], "BPFIX-E018");
    assert_eq!(no_snapshots["failure_class"], "source_bug");
    assert!(!evidence_contains(
        &no_snapshots,
        "verifier_state_signal",
        "current and previous loop-entry states"
    ));

    let changing_loop_carried_state = run_json_stdin(
        "\
-- BEGIN PROG LOAD LOG --
func#0 @0
10: (05) goto pc-1
infinite loop detected at insn 10
cur state: R0=map_value(map=m,ks=4,vs=4) R1=1 R2=scalar(smin=0,smax=umax=10,var_off=(0x0; 0xf)) R10=fp0 fp-8=mmmm????
old state: R0=map_value(map=m,ks=4,vs=4) R1=2 R2=scalar(smin=0,smax=umax=10,var_off=(0x0; 0xf)) R10=fp0 fp-8=mmmm????
-- END PROG LOAD LOG --
",
    );
    assert_eq!(changing_loop_carried_state["error_id"], "BPFIX-E018");
    assert_eq!(changing_loop_carried_state["failure_class"], "source_bug");
    assert!(!evidence_contains(
        &changing_loop_carried_state,
        "verifier_state_signal",
        "current and previous loop-entry states"
    ));

    let stale_snapshots_after_boundary = run_json_stdin(
        "\
-- BEGIN PROG LOAD LOG --
func#0 @0
10: (05) goto pc-1
infinite loop detected at insn 10
processed 11 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0
cur state: R0=map_value(map=m,ks=4,vs=4) R1=1 R2=scalar(smin=0,smax=umax=10,var_off=(0x0; 0xf)) R10=fp0 fp-8=mmmm????
old state: R0=map_value(map=m,ks=4,vs=4) R1=1 R2=scalar(smin=0,smax=umax=10,var_off=(0x0; 0xf)) R10=fp0 fp-8=mmmm????
-- END PROG LOAD LOG --
",
    );
    assert_eq!(stale_snapshots_after_boundary["error_id"], "BPFIX-E018");
    assert_eq!(
        stale_snapshots_after_boundary["failure_class"],
        "source_bug"
    );
    assert!(!evidence_contains(
        &stale_snapshots_after_boundary,
        "verifier_state_signal",
        "current and previous loop-entry states"
    ));

    let different_reference_state = run_json_stdin(
        "\
-- BEGIN PROG LOAD LOG --
func#0 @0
10: (05) goto pc-1
infinite loop detected at insn 10
cur state: R0=map_value(map=m,ks=4,vs=4) R1=1 R2=scalar(smin=0,smax=umax=10,var_off=(0x0; 0xf)) R10=fp0 fp-8=mmmm???? refs=1
old state: R0=map_value(map=m,ks=4,vs=4) R1=1 R2=scalar(smin=0,smax=umax=10,var_off=(0x0; 0xf)) R10=fp0 fp-8=mmmm???? refs=2
-- END PROG LOAD LOG --
",
    );
    assert_eq!(different_reference_state["error_id"], "BPFIX-E018");
    assert_eq!(different_reference_state["failure_class"], "source_bug");
    assert!(!evidence_contains(
        &different_reference_state,
        "verifier_state_signal",
        "current and previous loop-entry states"
    ));

    let different_precise_state = run_json_stdin(
        "\
-- BEGIN PROG LOAD LOG --
func#0 @0
10: (05) goto pc-1
infinite loop detected at insn 10
cur state: R0=map_value(map=m,ks=4,vs=4) R1=1 R2=Pscalar(smin=0,smax=umax=10,var_off=(0x0; 0xf)) R10=fp0 fp-8=mmmm????
old state: R0=map_value(map=m,ks=4,vs=4) R1=1 R2=scalar(smin=0,smax=umax=10,var_off=(0x0; 0xf)) R10=fp0 fp-8=mmmm????
-- END PROG LOAD LOG --
",
    );
    assert_eq!(different_precise_state["error_id"], "BPFIX-E018");
    assert_eq!(different_precise_state["failure_class"], "source_bug");
    assert!(!evidence_contains(
        &different_precise_state,
        "verifier_state_signal",
        "current and previous loop-entry states"
    ));

    let different_source_frame_state = run_json_stdin(
        "\
-- BEGIN PROG LOAD LOG --
func#0 @0
10: (05) goto pc-1
infinite loop detected at insn 10
cur state: R0=map_value(map=m,ks=4,vs=4) R1=fp[1]-8 R2=scalar(smin=0,smax=umax=10,var_off=(0x0; 0xf)) R10=fp0 fp-8=mmmm????
old state: R0=map_value(map=m,ks=4,vs=4) R1=fp[0]-8 R2=scalar(smin=0,smax=umax=10,var_off=(0x0; 0xf)) R10=fp0 fp-8=mmmm????
-- END PROG LOAD LOG --
",
    );
    assert_eq!(different_source_frame_state["error_id"], "BPFIX-E018");
    assert_eq!(different_source_frame_state["failure_class"], "source_bug");
    assert!(!evidence_contains(
        &different_source_frame_state,
        "verifier_state_signal",
        "current and previous loop-entry states"
    ));
}

#[test]
fn ordinary_source_bugs_are_not_overclassified_as_runtime_artifacts() {
    let pointer_load_reuse =
        run_json("bpfix-bench/cases/stackoverflow-56965789/replay-verifier.log");
    assert_eq!(pointer_load_reuse["error_id"], "BPFIX-E011");
    assert_eq!(pointer_load_reuse["failure_class"], "source_bug");
    assert!(evidence_contains(
        &pointer_load_reuse,
        "verifier_state_signal",
        "consumed register is scalar"
    ));

    let generic_alignment =
        run_json("bpfix-bench/cases/stackoverflow-76441958/replay-verifier.log");
    assert_eq!(generic_alignment["error_id"], "BPFIX-E007");
    assert_eq!(generic_alignment["failure_class"], "source_bug");
    assert!(evidence_contains(
        &generic_alignment,
        "verifier_state_signal",
        "base register is scalar"
    ));

    let packet_bounds = run_json("bpfix-bench/cases/stackoverflow-60053570/replay-verifier.log");
    assert_eq!(packet_bounds["error_id"], "BPFIX-E001");
    assert_eq!(packet_bounds["failure_class"], "source_bug");

    let off_by_one_packet_loop =
        run_json("bpfix-bench/cases/stackoverflow-76637174/replay-verifier.log");
    assert_eq!(off_by_one_packet_loop["error_id"], "BPFIX-E001");
    assert_eq!(off_by_one_packet_loop["failure_class"], "source_bug");

    let underchecked_packet_copy =
        run_json("bpfix-bench/cases/stackoverflow-73088287/replay-verifier.log");
    assert_eq!(underchecked_packet_copy["error_id"], "BPFIX-E001");
    assert_eq!(underchecked_packet_copy["failure_class"], "source_bug");

    let underchecked_packet_offset =
        run_json("bpfix-bench/cases/stackoverflow-78186253/replay-verifier.log");
    assert_eq!(underchecked_packet_offset["error_id"], "BPFIX-E001");
    assert_eq!(underchecked_packet_offset["failure_class"], "source_bug");

    let underchecked_packet_write =
        run_json("bpfix-bench/cases/github-commit-cilium-ceaa4c42b010/replay-verifier.log");
    assert_eq!(underchecked_packet_write["error_id"], "BPFIX-E001");
    assert_eq!(underchecked_packet_write["failure_class"], "source_bug");

    let helper_bounds = run_json("bpfix-bench/cases/stackoverflow-77713434/replay-verifier.log");
    assert_eq!(helper_bounds["error_id"], "BPFIX-E005");
    assert_eq!(helper_bounds["failure_class"], "source_bug");
    assert!(evidence_contains(
        &helper_bounds,
        "verifier_state_signal",
        "map-value pointer access crosses"
    ));

    let csum_helper_bounds =
        run_json("bpfix-bench/cases/github-iovisor-bcc-2463/replay-verifier.log");
    assert_eq!(csum_helper_bounds["error_id"], "BPFIX-E005");
    assert_eq!(csum_helper_bounds["failure_class"], "source_bug");
    assert!(evidence_contains(
        &csum_helper_bounds,
        "verifier_state_signal",
        "unsafe range at the use"
    ));

    let csum_from_size_bounds = run_json_stdin(
        "0: R2=scalar(smin=-1,smax=umax=16,var_off=(0x0; 0x10)) R4=8 R10=fp0\n\
         ; bpf_csum_diff(from, from_size, to, to_size, seed); @ prog.c:9\n\
         1: (85) call bpf_csum_diff#28\n\
         R2 min value is negative, either use unsigned or 'var &= const'\n\
         processed 2 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0\n",
    );
    assert_eq!(csum_from_size_bounds["error_id"], "BPFIX-E005");
    assert_eq!(csum_from_size_bounds["failure_class"], "source_bug");
    assert!(evidence_contains(
        &csum_from_size_bounds,
        "verifier_state_signal",
        "unsafe range at the use"
    ));

    let fixed_offset_map_value_bounds =
        run_json("bpfix-bench/cases/stackoverflow-73282201/replay-verifier.log");
    assert_eq!(fixed_offset_map_value_bounds["error_id"], "BPFIX-E005");
    assert_eq!(fixed_offset_map_value_bounds["failure_class"], "source_bug");
    assert!(fixed_offset_map_value_bounds["message"]
        .as_str()
        .unwrap()
        .contains("map-value access exceeds"));
    assert!(fixed_offset_map_value_bounds["required_proof"]
        .as_str()
        .unwrap()
        .contains("declared map value size"));
    assert!(fixed_offset_map_value_bounds["help"]
        .as_array()
        .unwrap()
        .iter()
        .any(|help| help.as_str().unwrap().contains("map-value field offsets")));
    assert!(evidence_contains(
        &fixed_offset_map_value_bounds,
        "verifier_state_signal",
        "map-value pointer access crosses"
    ));

    let branch_refined_map_value_bounds =
        run_json("bpfix-bench/cases/stackoverflow-75515263/replay-verifier.log");
    assert_eq!(branch_refined_map_value_bounds["error_id"], "BPFIX-E005");
    assert_eq!(
        branch_refined_map_value_bounds["failure_class"],
        "source_bug"
    );
    assert!(evidence_contains(
        &branch_refined_map_value_bounds,
        "verifier_state_signal",
        "map-value pointer access crosses"
    ));

    for path in [
        "bpfix-bench/cases/kernel-selftest-dynptr-fail-data-slice-out-of-bounds-map-value-raw-tp-de37aa84/replay-verifier.log",
        "bpfix-bench/cases/kernel-selftest-dynptr-fail-data-slice-out-of-bounds-skb-tc-b903ac49/replay-verifier.log",
    ] {
        let memory_object_bounds = run_json(path);
        assert_eq!(memory_object_bounds["error_id"], "BPFIX-E005");
        assert_eq!(memory_object_bounds["failure_class"], "source_bug");
        assert!(memory_object_bounds["message"]
            .as_str()
            .unwrap()
            .contains("memory-object access exceeds"));
        assert!(memory_object_bounds["required_proof"]
            .as_str()
            .unwrap()
            .contains("verifier-reported object size"));
        assert!(evidence_contains(
            &memory_object_bounds,
            "verifier_state_signal",
            "fixed object size"
        ));
    }

    let mismatched_memory_object_state = run_json_stdin(
        "0: R0=mem(sz=8) R10=fp0\n\
         1: (71) r1 = *(u8 *)(r0 +5)\n\
         invalid access to memory, mem_size=4 off=5 size=1\n\
         R0 min value is outside of the allowed memory range\n",
    );
    assert_eq!(mismatched_memory_object_state["error_id"], "BPFIX-E005");
    assert!(!evidence_contains(
        &mismatched_memory_object_state,
        "verifier_state_signal",
        "fixed object size"
    ));

    let negative_memory_object_offset = run_json_stdin(
        "0: R0=mem(sz=4) R10=fp0\n\
         1: (71) r1 = *(u8 *)(r0 -1)\n\
         invalid access to memory, mem_size=4 off=-1 size=1\n\
         R0 min value is outside of the allowed memory range\n",
    );
    assert_eq!(negative_memory_object_offset["error_id"], "BPFIX-E005");
    assert!(evidence_contains(
        &negative_memory_object_offset,
        "verifier_state_signal",
        "fixed object size"
    ));

    let return_range = run_json("bpfix-bench/cases/stackoverflow-77191387/replay-verifier.log");
    assert_eq!(return_range["error_id"], "BPFIX-E005");
    assert_eq!(return_range["failure_class"], "source_bug");
    assert!(return_range["message"]
        .as_str()
        .unwrap()
        .contains("program return value"));
    assert!(return_range["required_proof"]
        .as_str()
        .unwrap()
        .contains("value in R0"));
    assert!(evidence_contains(
        &return_range,
        "verifier_state_signal",
        "BPF_EXIT with a return register"
    ));

    let branch_delta_map_value_bounds = run_json_stdin(
        "func#0 @0\n\
         0: R1=ctx() R10=fp0\n\
         4: (18) r1 = 0xffff89975b852400 ; R1_w=map_ptr(map=lookup,ks=4,vs=8)\n\
         6: (85) call bpf_map_lookup_elem#1 ; R0_w=map_value_or_null(id=1,map=lookup,ks=4,vs=8)\n\
         7: (15) if r0 == 0x0 goto pc+10 ; R0_w=map_value(map=lookup,ks=4,vs=8)\n\
         13: (69) r3 = *(u16 *)(r0 +8)\n\
         invalid access to map value, value_size=8 off=8 size=2\n\
         R0 min value is outside of the allowed memory range\n",
    );
    assert_eq!(branch_delta_map_value_bounds["error_id"], "BPFIX-E005");
    assert_eq!(branch_delta_map_value_bounds["failure_class"], "source_bug");
    assert!(evidence_contains(
        &branch_delta_map_value_bounds,
        "verifier_state_signal",
        "map-value pointer access crosses"
    ));

    let direct_width_too_wide_remains_lowering = run_json_stdin(
        "func#0 @0\n\
         0: R0=map_value(map=m,ks=4,vs=4) R10=fp0\n\
         1: (79) r1 = *(u64 *)(r0 +0)\n\
         invalid access to map value, value_size=4 off=0 size=8\n\
         R0 min value is outside of the allowed memory range\n",
    );
    assert_eq!(
        direct_width_too_wide_remains_lowering["error_id"],
        "BPFIX-E005"
    );
    assert_eq!(
        direct_width_too_wide_remains_lowering["failure_class"],
        "lowering_artifact"
    );
    assert!(evidence_contains(
        &direct_width_too_wide_remains_lowering,
        "lowering_artifact_signal",
        "wider than the verifier-proven map value size"
    ));

    let in_bounds_map_value_shape = run_json_stdin(
        "func#0 @0\n\
         0: R0=map_value(map=m,ks=4,vs=16) R10=fp0\n\
         1: (71) r1 = *(u8 *)(r0 +15)\n\
         invalid access to map value, value_size=16 off=15 size=1\n\
         R0 min value is outside of the allowed memory range\n",
    );
    assert_eq!(in_bounds_map_value_shape["error_id"], "BPFIX-E005");
    assert_eq!(in_bounds_map_value_shape["failure_class"], "source_bug");
    assert!(!evidence_contains(
        &in_bounds_map_value_shape,
        "verifier_state_signal",
        "map-value pointer access crosses"
    ));

    let mismatched_map_value_width = run_json_stdin(
        "func#0 @0\n\
         0: R0=map_value(map=m,ks=4,vs=16) R10=fp0\n\
         1: (71) r1 = *(u8 *)(r0 +16)\n\
         invalid access to map value, value_size=16 off=16 size=2\n\
         R0 min value is outside of the allowed memory range\n",
    );
    assert_eq!(mismatched_map_value_width["error_id"], "BPFIX-E005");
    assert_eq!(mismatched_map_value_width["failure_class"], "source_bug");
    assert!(!evidence_contains(
        &mismatched_map_value_width,
        "verifier_state_signal",
        "map-value pointer access crosses"
    ));

    let helper_bounds_mismatched_length_state = run_json_stdin(
        "func#0 @0\n\
         0: R1=map_value(map=m,ks=4,vs=70) R2=16 R10=fp0\n\
         1: (85) call bpf_probe_read_user#112\n\
         invalid access to map value, value_size=70 off=0 size=16383\n\
         R1 min value is outside of the allowed memory range\n",
    );
    assert_eq!(
        helper_bounds_mismatched_length_state["error_id"],
        "BPFIX-E005"
    );
    assert_eq!(
        helper_bounds_mismatched_length_state["failure_class"],
        "source_bug"
    );
    assert!(!evidence_contains(
        &helper_bounds_mismatched_length_state,
        "verifier_state_signal",
        "map-value pointer access crosses"
    ));

    let helper_bounds_terminal_reports_length_register = run_json_stdin(
        "func#0 @0\n\
         0: R1=map_value(map=m,ks=4,vs=70) R2=scalar(umax=16383) R10=fp0\n\
         1: (85) call bpf_probe_read_user#112\n\
         invalid access to map value, value_size=70 off=0 size=16383\n\
         R2 min value is outside of the allowed memory range\n",
    );
    assert_eq!(
        helper_bounds_terminal_reports_length_register["error_id"],
        "BPFIX-E005"
    );
    assert_eq!(
        helper_bounds_terminal_reports_length_register["failure_class"],
        "source_bug"
    );
    assert!(evidence_contains(
        &helper_bounds_terminal_reports_length_register,
        "verifier_state_signal",
        "map-value pointer access crosses"
    ));

    let unrelated_helper_map_value_bounds = run_json_stdin(
        "func#0 @0\n\
         0: R1=map_value(map=m,ks=4,vs=70) R2=scalar(umax=16383) R10=fp0\n\
         1: (85) call bpf_get_prandom_u32#7\n\
         invalid access to map value, value_size=70 off=0 size=16383\n\
         R1 min value is outside of the allowed memory range\n",
    );
    assert_eq!(unrelated_helper_map_value_bounds["error_id"], "BPFIX-E005");
    assert_eq!(
        unrelated_helper_map_value_bounds["failure_class"],
        "source_bug"
    );
    assert!(!evidence_contains(
        &unrelated_helper_map_value_bounds,
        "verifier_state_signal",
        "map-value pointer access crosses"
    ));

    let branch_delta_map_value_overridden_by_later_scalar = run_json_stdin(
        "func#0 @0\n\
         0: R0=map_value_or_null(id=1,map=lookup,ks=4,vs=8) R10=fp0\n\
         7: (15) if r0 == 0x0 goto pc+10 ; R0_w=map_value(map=lookup,ks=4,vs=8)\n\
         12: R0=scalar()\n\
         13: (69) r3 = *(u16 *)(r0 +8)\n\
         invalid access to map value, value_size=8 off=8 size=2\n\
         R0 min value is outside of the allowed memory range\n",
    );
    assert_eq!(
        branch_delta_map_value_overridden_by_later_scalar["error_id"],
        "BPFIX-E005"
    );
    assert_eq!(
        branch_delta_map_value_overridden_by_later_scalar["failure_class"],
        "source_bug"
    );
    assert!(!evidence_contains(
        &branch_delta_map_value_overridden_by_later_scalar,
        "verifier_state_signal",
        "map-value pointer access crosses"
    ));

    for path in [
        "bpfix-bench/cases/github-aya-rs-aya-1062/replay-verifier.log",
        "bpfix-bench/cases/github-aya-rs-aya-1207/replay-verifier.log",
        "bpfix-bench/cases/github-commit-bcc-0ae562c8862f/replay-verifier.log",
    ] {
        let scalar_range = run_json(path);
        assert_eq!(scalar_range["error_id"], "BPFIX-E005");
        assert_eq!(scalar_range["failure_class"], "source_bug");
        assert!(evidence_contains(
            &scalar_range,
            "verifier_state_signal",
            "unsafe range at the use"
        ));
    }

    let stack_variable_offset =
        run_json("bpfix-bench/cases/stackoverflow-78525670/replay-verifier.log");
    assert_eq!(stack_variable_offset["error_id"], "BPFIX-E005");
    assert_eq!(stack_variable_offset["failure_class"], "source_bug");
    assert!(stack_variable_offset["message"]
        .as_str()
        .unwrap()
        .contains("stack variable-offset access"));
    assert!(evidence_contains(
        &stack_variable_offset,
        "verifier_state_signal",
        "stack pointer's variable byte interval"
    ));

    let stack_interval_crosses_frame_top = run_json_stdin(
        "0: R1=fp(off=-4,smin=umin=0,smax=umax=8) R10=fp0\n\
         1: (71) r0 = *(u8 *)(r1 +0)\n\
         invalid unbounded variable-offset read from stack R1\n",
    );
    assert_eq!(stack_interval_crosses_frame_top["error_id"], "BPFIX-E005");
    assert!(evidence_contains(
        &stack_interval_crosses_frame_top,
        "verifier_state_signal",
        "stack pointer's variable byte interval"
    ));

    let stack_interval_safe = run_json_stdin(
        "0: R1=fp(off=-16,smin=umin=0,smax=umax=7) R10=fp0\n\
         1: (71) r0 = *(u8 *)(r1 +0)\n\
         invalid unbounded variable-offset read from stack R1\n",
    );
    assert_eq!(stack_interval_safe["error_id"], "BPFIX-E005");
    assert!(!evidence_contains(
        &stack_interval_safe,
        "verifier_state_signal",
        "stack pointer's variable byte interval"
    ));

    let exact_safe_helper_length = run_json_stdin(
        "0: R2=16 R10=fp0\n\
         ; bpf_probe_read_user(buf, len, ctx); @ prog.c:9\n\
         1: (85) call bpf_probe_read_user#112\n\
         R2 min value is negative, either use unsigned or 'var &= const'\n\
         processed 2 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0\n",
    );
    assert_eq!(exact_safe_helper_length["error_id"], "BPFIX-E005");
    assert_eq!(exact_safe_helper_length["failure_class"], "source_bug");
    assert!(!evidence_contains(
        &exact_safe_helper_length,
        "verifier_state_signal",
        "unsafe range at the use"
    ));

    let bounded_safe_helper_length = run_json_stdin(
        "0: R2=scalar(smin=0,smax=umax=16,var_off=(0x0; 0x10)) R10=fp0\n\
         ; bpf_probe_read_user(buf, len, ctx); @ prog.c:9\n\
         1: (85) call bpf_probe_read_user#112\n\
         R2 min value is negative, either use unsigned or 'var &= const'\n\
         processed 2 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0\n",
    );
    assert_eq!(bounded_safe_helper_length["error_id"], "BPFIX-E005");
    assert_eq!(bounded_safe_helper_length["failure_class"], "source_bug");
    assert!(!evidence_contains(
        &bounded_safe_helper_length,
        "verifier_state_signal",
        "unsafe range at the use"
    ));

    let comment_only_register = run_json_stdin(
        "0: R2=scalar(smin=-1,smax=umax=16,var_off=(0x0; 0x10)) R10=fp0\n\
         ; not the failing scalar use; @ prog.c:9\n\
         1: (b7) r0 = 0 ; len = r2\n\
         R2 min value is negative, either use unsigned or 'var &= const'\n\
         processed 2 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0\n",
    );
    assert_eq!(comment_only_register["error_id"], "BPFIX-E005");
    assert_eq!(comment_only_register["failure_class"], "source_bug");
    assert!(!evidence_contains(
        &comment_only_register,
        "verifier_state_signal",
        "unsafe range at the use"
    ));

    let destination_only_register = run_json_stdin(
        "0: R2=scalar(smin=-1,smax=umax=16,var_off=(0x0; 0x10)) R10=fp0\n\
         ; len = 0; @ prog.c:9\n\
         1: (b7) r2 = 0\n\
         R2 min value is negative, either use unsigned or 'var &= const'\n\
         processed 2 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0\n",
    );
    assert_eq!(destination_only_register["error_id"], "BPFIX-E005");
    assert_eq!(destination_only_register["failure_class"], "source_bug");
    assert!(!evidence_contains(
        &destination_only_register,
        "verifier_state_signal",
        "unsafe range at the use"
    ));

    let register_copy_rhs = run_json_stdin(
        "0: R2=scalar(smin=-1,smax=umax=16,var_off=(0x0; 0x10)) R10=fp0\n\
         ; len = other; @ prog.c:9\n\
         1: (bf) r1 = r2\n\
         R2 min value is negative, either use unsigned or 'var &= const'\n\
         processed 2 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0\n",
    );
    assert_eq!(register_copy_rhs["error_id"], "BPFIX-E005");
    assert_eq!(register_copy_rhs["failure_class"], "source_bug");
    assert!(!evidence_contains(
        &register_copy_rhs,
        "verifier_state_signal",
        "unsafe range at the use"
    ));

    let unrelated_helper_argument = run_json_stdin(
        "0: R5=scalar(smin=-1,smax=umax=16,var_off=(0x0; 0x10)) R10=fp0\n\
         ; bpf_get_prandom_u32(); @ prog.c:9\n\
         1: (85) call bpf_get_prandom_u32#7\n\
         R5 min value is negative, either use unsigned or 'var &= const'\n\
         processed 2 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0\n",
    );
    assert_eq!(unrelated_helper_argument["error_id"], "BPFIX-E005");
    assert_eq!(unrelated_helper_argument["failure_class"], "source_bug");
    assert!(!evidence_contains(
        &unrelated_helper_argument,
        "verifier_state_signal",
        "unsafe range at the use"
    ));

    let map_value_guard_too_large =
        run_json("bpfix-bench/cases/stackoverflow-78196801/replay-verifier.log");
    assert_eq!(map_value_guard_too_large["error_id"], "BPFIX-E005");
    assert_eq!(map_value_guard_too_large["failure_class"], "source_bug");
    assert!(map_value_guard_too_large["message"]
        .as_str()
        .unwrap()
        .contains("map-value index guard exceeds the map value size"));
    assert!(map_value_guard_too_large["required_proof"]
        .as_str()
        .unwrap()
        .contains("field offset and access width"));
    assert!(evidence_contains(
        &map_value_guard_too_large,
        "verifier_state_signal",
        "source bounds the map-value index"
    ));

    let map_value_guard_too_large_2 =
        run_json("bpfix-bench/cases/stackoverflow-78208591/replay-verifier.log");
    assert_eq!(map_value_guard_too_large_2["error_id"], "BPFIX-E005");
    assert_eq!(map_value_guard_too_large_2["failure_class"], "source_bug");
    assert!(evidence_contains(
        &map_value_guard_too_large_2,
        "verifier_state_signal",
        "source bounds the map-value index"
    ));

    let map_value_state_offset_guard = run_json_stdin(
        "0: R1=ctx() R10=fp0\n\
         ; if (idx <= 19) @ prog.c:12\n\
         10: (25) if r1 > 0x13 goto pc+3 ; R1=scalar(smin=0,smax=umax=19)\n\
         ; value->flags[idx] = 1; @ prog.c:13\n\
         11: (0f) r0 += r1\n\
         12: R0_w=map_value(map=output_map,ks=1,vs=20,off=8,smin=0,smax=umax=19,var_off=(0x0; 0x13)) R1=scalar(smin=0,smax=umax=19,var_off=(0x0; 0x13))\n\
         13: (73) *(u8 *)(r0 +0) = r1\n\
         invalid access to map value, value_size=20 off=27 size=1\n\
         R0 max value is outside of the allowed memory range\n",
    );
    assert!(evidence_contains(
        &map_value_state_offset_guard,
        "verifier_state_signal",
        "source bounds the map-value index"
    ));

    let source_text_guard_without_verifier_branch_proof = run_json_stdin(
        "0: R1=ctx() R10=fp0\n\
         ; if (idx < 64) @ prog.c:12\n\
         10: (25) if r2 > 0x3f goto pc+3 ; R2=scalar(smin=0,smax=umax=63) R1=scalar(smin=0,smax=umax=63)\n\
         ; value->flags[idx] = 1; @ prog.c:13\n\
         11: (0f) r0 += r1\n\
         12: R0_w=map_value(map=output_map,ks=1,vs=20,smin=0,smax=umax=63,var_off=(0x0; 0x3f)) R1=scalar(smin=0,smax=umax=63,var_off=(0x0; 0x3f))\n\
         13: (73) *(u8 *)(r0 +0) = r1\n\
         invalid access to map value, value_size=20 off=63 size=1\n\
         R0 max value is outside of the allowed memory range\n",
    );
    assert!(!evidence_contains(
        &source_text_guard_without_verifier_branch_proof,
        "verifier_state_signal",
        "source bounds the map-value index"
    ));

    let register_prefix_add = run_json_stdin(
        "0: R1=ctx() R10=fp0\n\
         ; if (idx < 64) @ prog.c:12\n\
         10: (25) if r1 > 0x3f goto pc+3 ; R1=scalar(smin=0,smax=umax=63)\n\
         ; value->flags[idx] = 1; @ prog.c:13\n\
         11: (0f) r0 += r10\n\
         12: R0_w=map_value(map=output_map,ks=1,vs=20,smin=0,smax=umax=63,var_off=(0x0; 0x3f)) R1=scalar(smin=0,smax=umax=63,var_off=(0x0; 0x3f))\n\
         13: (73) *(u8 *)(r0 +0) = r1\n\
         invalid access to map value, value_size=20 off=63 size=1\n\
         R0 max value is outside of the allowed memory range\n",
    );
    assert!(!evidence_contains(
        &register_prefix_add,
        "verifier_state_signal",
        "source bounds the map-value index"
    ));

    let future_pc_guard = run_json_stdin(
        "0: R1=ctx() R10=fp0\n\
         ; if (idx < 64) @ prog.c:12\n\
         20: (25) if r1 > 0x3f goto pc+3 ; R1=scalar(smin=0,smax=umax=63)\n\
         ; value->flags[idx] = 1; @ prog.c:13\n\
         11: (0f) r0 += r1\n\
         12: R0_w=map_value(map=output_map,ks=1,vs=20,smin=0,smax=umax=63,var_off=(0x0; 0x3f)) R1=scalar(smin=0,smax=umax=63,var_off=(0x0; 0x3f))\n\
         13: (73) *(u8 *)(r0 +0) = r1\n\
         invalid access to map value, value_size=20 off=63 size=1\n\
         R0 max value is outside of the allowed memory range\n",
    );
    assert!(!evidence_contains(
        &future_pc_guard,
        "verifier_state_signal",
        "source bounds the map-value index"
    ));

    let stale_retry_fragment = run_json_stdin(
        "0: R1=ctx() R10=fp0\n\
         ; if (idx < 64) @ prog.c:12\n\
         10: (25) if r2 > 0x3f goto pc+3 ; R2=scalar(smin=0,smax=umax=63)\n\
         11: (0f) r0 += r2\n\
         ; if (idx < 64) @ prog.c:12\n\
         10: (25) if r2 > 0x3f goto pc+3 ; R2=scalar(smin=0,smax=umax=63) R1=scalar(smin=0,smax=umax=63)\n\
         ; value->flags[idx] = 1; @ prog.c:13\n\
         11: (0f) r0 += r1\n\
         12: R0_w=map_value(map=output_map,ks=1,vs=20,smin=0,smax=umax=63,var_off=(0x0; 0x3f)) R1=scalar(smin=0,smax=umax=63,var_off=(0x0; 0x3f))\n\
         13: (73) *(u8 *)(r0 +0) = r1\n\
         invalid access to map value, value_size=20 off=63 size=1\n\
         R0 max value is outside of the allowed memory range\n",
    );
    assert!(!evidence_contains(
        &stale_retry_fragment,
        "verifier_state_signal",
        "source bounds the map-value index"
    ));

    let stale_terminal_offset_fragment = run_json_stdin(
        "0: R1=ctx() R10=fp0\n\
         13: (73) *(u8 *)(r0 +0) = r1\n\
         ; if (idx <= 19) @ prog.c:12\n\
         10: (25) if r1 > 0x13 goto pc+3 ; R1=scalar(smin=0,smax=umax=19)\n\
         ; value->flags[idx] = 1; @ prog.c:13\n\
         11: (0f) r0 += r1\n\
         12: R0_w=map_value(map=output_map,ks=1,vs=20,smin=0,smax=umax=19,var_off=(0x0; 0x13)) R1=scalar(smin=0,smax=umax=19,var_off=(0x0; 0x13))\n\
         13: (73) *(u8 *)(r0 +8) = r1\n\
         invalid access to map value, value_size=20 off=27 size=1\n\
         R0 max value is outside of the allowed memory range\n",
    );
    assert!(evidence_contains(
        &stale_terminal_offset_fragment,
        "verifier_state_signal",
        "source bounds the map-value index"
    ));

    let state_line_after_terminal_map_value_access = run_json_stdin(
        "0: R1=ctx() R10=fp0\n\
         ; if (idx <= 19) @ prog.c:12\n\
         10: (25) if r1 > 0x13 goto pc+3 ; R1=scalar(smin=0,smax=umax=19)\n\
         ; value->flags[idx] = 1; @ prog.c:13\n\
         11: (0f) r0 += r1\n\
         12: R0_w=map_value(map=output_map,ks=1,vs=20,smin=0,smax=umax=19,var_off=(0x0; 0x13)) R1=scalar(smin=0,smax=umax=19,var_off=(0x0; 0x13))\n\
         13: (73) *(u8 *)(r0 +8) = r1\n\
         13: R0_w=map_value(map=output_map,ks=1,vs=20,smin=0,smax=umax=19,var_off=(0x0; 0x13)) R1=1\n\
         invalid access to map value, value_size=20 off=27 size=1\n\
         R0 max value is outside of the allowed memory range\n",
    );
    assert!(evidence_contains(
        &state_line_after_terminal_map_value_access,
        "verifier_state_signal",
        "source bounds the map-value index"
    ));

    let unrelated_map_value_guard = run_json_stdin(
        "0: R1=ctx() R10=fp0\n\
         ; if (other < 64) @ prog.c:12\n\
         10: (25) if r1 > 0x3f goto pc+3 ; R1=scalar(smin=0,smax=umax=63)\n\
         ; value->flags[idx] = 1; @ prog.c:13\n\
         11: (0f) r0 += r1\n\
         12: R0_w=map_value(map=output_map,ks=1,vs=20,smin=0,smax=umax=63,var_off=(0x0; 0x3f)) R1=scalar(smin=0,smax=umax=63,var_off=(0x0; 0x3f))\n\
         13: (73) *(u8 *)(r0 +0) = r1\n\
         invalid access to map value, value_size=20 off=63 size=1\n\
         R0 max value is outside of the allowed memory range\n",
    );
    assert!(!evidence_contains(
        &unrelated_map_value_guard,
        "verifier_state_signal",
        "source bounds the map-value index"
    ));
}

#[test]
fn scalar_pointer_state_signal_handles_inv_and_pkt_end_variants() {
    let invalid_inv = run_json_stdin(
        "func#0 @0\n\
         0: R2=scalar() R10=fp0\n\
         1: (61) r0 = *(u32 *)(r2 +0)\n\
         R2 invalid mem access 'inv'\n",
    );
    assert_eq!(invalid_inv["error_id"], "BPFIX-E011");
    assert!(evidence_contains(
        &invalid_inv,
        "verifier_state_signal",
        "consumed register is scalar"
    ));

    let packet_end_spelling = run_json_stdin(
        "func#0 @0\n\
         0: R1=ctx() R10=fp0\n\
         0: (61) r0 = *(u32 *)(r1 +80) ; R0_w=pkt_end() R1=ctx()\n\
         1: (07) r0 += 1\n\
         R0 pointer arithmetic on PTR_TO_PACKET_END prohibited\n",
    );
    assert_eq!(packet_end_spelling["error_id"], "BPFIX-E011");
    assert!(evidence_contains(
        &packet_end_spelling,
        "verifier_state_signal",
        "pkt_end state"
    ));
}

#[test]
fn scalar_pointer_state_signal_requires_matching_current_instruction_state() {
    let mismatched_base_register = run_json_stdin(
        "func#0 @0\n\
         0: R1=scalar() R2=scalar() R10=fp0\n\
         1: (61) r0 = *(u32 *)(r2 +0)\n\
         R1 invalid mem access 'scalar'\n",
    );
    assert_eq!(mismatched_base_register["error_id"], "BPFIX-E006");
    assert!(!evidence_contains(
        &mismatched_base_register,
        "verifier_state_signal",
        "consumed register is scalar"
    ));

    let stale_state_after_terminal = run_json_stdin(
        "func#0 @0\n\
         1: (61) r0 = *(u32 *)(r1 +0)\n\
         R1 invalid mem access 'scalar'\n\
         2: R1=scalar() R10=fp0\n",
    );
    assert_eq!(stale_state_after_terminal["error_id"], "BPFIX-E006");
    assert!(!evidence_contains(
        &stale_state_after_terminal,
        "verifier_state_signal",
        "consumed register is scalar"
    ));
}

#[test]
fn scalar_zero_pointer_lifecycle_reports_null_action() {
    for path in [
        "bpfix-bench/cases/github-commit-cilium-848d41d1909b/replay-verifier.log",
        "bpfix-bench/cases/kernel-selftest-iters-iter-err-too-permissive1-raw-tp-25649784/replay-verifier.log",
        "bpfix-bench/cases/kernel-selftest-iters-looping-missing-null-check-fail-raw-tp-732d9857/replay-verifier.log",
    ] {
        let diagnostic = run_json(path);
        assert_eq!(diagnostic["error_id"], "BPFIX-E011");
        assert_eq!(diagnostic["failure_class"], "source_bug");
        assert_eq!(diagnostic["next_action"], "null");
        assert!(evidence_contains(
            &diagnostic,
            "verifier_state_signal",
            "exact scalar zero"
        ));
    assert!(diagnostic["required_proof"]
            .as_str()
            .unwrap()
            .contains("non-null"));
    }

    let helper_return_copy_through = run_json_stdin(
        "func#0 @0\n\
         0: R6=fp-8 R7=scalar() R10=fp0\n\
         1: (bf) r1 = r6\n\
         2: (b7) r2 = 0\n\
         3: (b7) r3 = 1000\n\
         4: (85) call bpf_iter_num_new#71887\n\
         5: (bf) r1 = r6\n\
         6: (85) call bpf_iter_num_next#71889 ; R0_w=0\n\
         7: (bf) r7 = r0\n\
         8: R7=0 R10=fp0\n\
         9: (61) r1 = *(u32 *)(r7 +0)\n\
         R7 invalid mem access 'scalar'\n",
    );
    assert_eq!(helper_return_copy_through["error_id"], "BPFIX-E011");
    assert_eq!(helper_return_copy_through["next_action"], "null");
    assert!(evidence_contains(
        &helper_return_copy_through,
        "verifier_state_signal",
        "exact scalar zero"
    ));

    let numeric_helper_return_copy_through = run_json_stdin(
        "func#0 @0\n\
         0: R6=fp-8 R7=scalar() R10=fp0\n\
         1: (bf) r1 = r6\n\
         2: (b7) r2 = 0\n\
         3: (b7) r3 = 1000\n\
         4: (85) call bpf_iter_num_new#71887\n\
         5: (bf) r1 = r6\n\
         6: (85) call 71889 ; R0_w=0\n\
         7: (bf) r7 = r0\n\
         8: R7=0 R10=fp0\n\
         9: (61) r1 = *(u32 *)(r7 +0)\n\
         R7 invalid mem access 'scalar'\n",
    );
    assert_eq!(numeric_helper_return_copy_through["error_id"], "BPFIX-E011");
    assert_eq!(numeric_helper_return_copy_through["next_action"], "null");
    assert!(evidence_contains(
        &numeric_helper_return_copy_through,
        "verifier_state_signal",
        "exact scalar zero"
    ));

    let no_pointer_lifecycle = run_json_stdin(
        "func#0 @0\n\
         0: R1=ctx() R10=fp0\n\
         1: (b7) r1 = 0\n\
         2: R1=0 R10=fp0\n\
         3: (61) r0 = *(u32 *)(r1 +0)\n\
         R1 invalid mem access 'scalar'\n",
    );
    assert_eq!(no_pointer_lifecycle["error_id"], "BPFIX-E011");
    assert_eq!(no_pointer_lifecycle["next_action"], "provenance");
    assert!(!evidence_contains(
        &no_pointer_lifecycle,
        "verifier_state_signal",
        "exact scalar zero"
    ));

    let explicit_zero_after_nullable_history = run_json_stdin(
        "func#0 @0\n\
         0: R1=map_value_or_null(id=1,map=test,ks=4,vs=8) R10=fp0\n\
         1: (b7) r1 = 0\n\
         2: R1=0 R10=fp0\n\
         3: (61) r0 = *(u32 *)(r1 +0)\n\
         R1 invalid mem access 'scalar'\n",
    );
    assert_eq!(
        explicit_zero_after_nullable_history["error_id"],
        "BPFIX-E011"
    );
    assert_eq!(
        explicit_zero_after_nullable_history["next_action"],
        "provenance"
    );
    assert!(!evidence_contains(
        &explicit_zero_after_nullable_history,
        "verifier_state_signal",
        "exact scalar zero"
    ));
}

#[test]
fn opaque_probe_read_pointer_values_report_protocol_action() {
    for path in [
        "bpfix-bench/cases/stackoverflow-77387582/replay-verifier.log",
        "bpfix-bench/cases/stackoverflow-79097886/replay-verifier.log",
    ] {
        let diagnostic = run_json(path);
        assert_eq!(diagnostic["error_id"], "BPFIX-E011");
        assert_eq!(diagnostic["failure_class"], "source_bug");
        assert_eq!(diagnostic["next_action"], "protocol");
        assert!(evidence_contains(
            &diagnostic,
            "verifier_state_signal",
            "helper-written stack storage"
        ));
        assert!(diagnostic["required_proof"]
            .as_str()
            .unwrap()
            .contains("verifier-approved helper"));
    }

    let helper_output_pointer = run_json_stdin(
        "func#0 @0\n\
         0: R1=fp-8 R2=8 R3=scalar() R10=fp0\n\
         1: (85) call bpf_probe_read_kernel#113\n\
         2: R7=scalar() R10=fp0 fp-8=mmmmmmmm\n\
         3: (79) r7 = *(u64 *)(r10 -8)\n\
         4: (71) r0 = *(u8 *)(r7 +0)\n\
         R7 invalid mem access 'scalar'\n",
    );
    assert_eq!(helper_output_pointer["error_id"], "BPFIX-E011");
    assert_eq!(helper_output_pointer["next_action"], "protocol");
    assert!(evidence_contains(
        &helper_output_pointer,
        "verifier_state_signal",
        "helper-written stack storage"
    ));

    let copied_helper_output_pointer = run_json_stdin(
        "func#0 @0\n\
         0: R1=fp-8 R2=8 R3=scalar() R6=scalar() R7=scalar() R10=fp0\n\
         1: (85) call bpf_probe_read_kernel#113\n\
         2: R6=scalar() R7=scalar() R10=fp0 fp-8=mmmmmmmm\n\
         3: (79) r6 = *(u64 *)(r10 -8)\n\
         4: (bf) r7 = r6\n\
         5: R7=scalar() R10=fp0\n\
         6: (71) r0 = *(u8 *)(r7 +0)\n\
         R7 invalid mem access 'scalar'\n",
    );
    assert_eq!(copied_helper_output_pointer["error_id"], "BPFIX-E011");
    assert_eq!(copied_helper_output_pointer["next_action"], "protocol");
    assert!(evidence_contains(
        &copied_helper_output_pointer,
        "verifier_state_signal",
        "helper-written stack storage"
    ));

    let numeric_helper_id = run_json_stdin(
        "func#0 @0\n\
         0: R1=fp-8 R2=8 R3=scalar() R10=fp0\n\
         1: (85) call 113\n\
         2: R7=scalar() R10=fp0 fp-8=mmmmmmmm\n\
         3: (79) r7 = *(u64 *)(r10 -8)\n\
         4: (71) r0 = *(u8 *)(r7 +0)\n\
         R7 invalid mem access 'scalar'\n",
    );
    assert_eq!(numeric_helper_id["error_id"], "BPFIX-E011");
    assert_eq!(numeric_helper_id["next_action"], "protocol");
    assert!(evidence_contains(
        &numeric_helper_id,
        "verifier_state_signal",
        "helper-written stack storage"
    ));
}

#[test]
fn opaque_probe_read_pointer_signal_requires_matching_helper_output_stack_slot() {
    let unrelated_helper_output = run_json_stdin(
        "func#0 @0\n\
         0: R1=fp-16 R2=8 R3=scalar() R10=fp0\n\
         1: (85) call bpf_probe_read_kernel#113\n\
         2: R7=scalar() R10=fp0 fp-16=mmmmmmmm\n\
         3: (79) r7 = *(u64 *)(r10 -8)\n\
         4: (71) r0 = *(u8 *)(r7 +0)\n\
         R7 invalid mem access 'scalar'\n",
    );
    assert_eq!(unrelated_helper_output["error_id"], "BPFIX-E011");
    assert_eq!(unrelated_helper_output["next_action"], "provenance");
    assert!(!evidence_contains(
        &unrelated_helper_output,
        "verifier_state_signal",
        "helper-written stack storage"
    ));
    assert!(evidence_contains(
        &unrelated_helper_output,
        "verifier_state_signal",
        "consumed register is scalar"
    ));

    let overwritten_helper_output = run_json_stdin(
        "func#0 @0\n\
         0: R1=fp-8 R2=8 R3=scalar() R10=fp0\n\
         1: (85) call bpf_probe_read_kernel#113\n\
         2: R0=scalar() R10=fp0 fp-8=mmmmmmmm\n\
         3: (7b) *(u64 *)(r10 -8) = r0\n\
         4: R7=scalar() R10=fp0 fp-8=mmmmmmmm\n\
         5: (79) r7 = *(u64 *)(r10 -8)\n\
         6: (71) r0 = *(u8 *)(r7 +0)\n\
         R7 invalid mem access 'scalar'\n",
    );
    assert_eq!(overwritten_helper_output["error_id"], "BPFIX-E011");
    assert_eq!(overwritten_helper_output["next_action"], "provenance");
    assert!(!evidence_contains(
        &overwritten_helper_output,
        "verifier_state_signal",
        "helper-written stack storage"
    ));

    let helper_clobbered_output = run_json_stdin(
        "func#0 @0\n\
         0: R1=fp-8 R2=8 R3=scalar() R10=fp0\n\
         1: (85) call bpf_probe_read_kernel#113\n\
         2: R1=fp-8 R2=8 R7=scalar() R10=fp0 fp-8=mmmmmmmm\n\
         3: (85) call bpf_get_current_comm#16\n\
         4: R7=scalar() R10=fp0 fp-8=mmmmmmmm\n\
         5: (79) r7 = *(u64 *)(r10 -8)\n\
         6: (71) r0 = *(u8 *)(r7 +0)\n\
         R7 invalid mem access 'scalar'\n",
    );
    assert_eq!(helper_clobbered_output["error_id"], "BPFIX-E011");
    assert_eq!(helper_clobbered_output["next_action"], "provenance");
    assert!(!evidence_contains(
        &helper_clobbered_output,
        "verifier_state_signal",
        "helper-written stack storage"
    ));

    let unknown_helper_clobbered_output = run_json_stdin(
        "func#0 @0\n\
         0: R1=fp-8 R2=8 R3=scalar() R10=fp0\n\
         1: (85) call bpf_probe_read_kernel#113\n\
         2: R1=scalar() R2=scalar() R3=fp-8 R7=scalar() R10=fp0 fp-8=mmmmmmmm\n\
         3: (85) call bpf_unknown_stack_writer#999\n\
         4: R7=scalar() R10=fp0 fp-8=mmmmmmmm\n\
         5: (79) r7 = *(u64 *)(r10 -8)\n\
         6: (71) r0 = *(u8 *)(r7 +0)\n\
         R7 invalid mem access 'scalar'\n",
    );
    assert_eq!(unknown_helper_clobbered_output["error_id"], "BPFIX-E011");
    assert_eq!(unknown_helper_clobbered_output["next_action"], "provenance");
    assert!(!evidence_contains(
        &unknown_helper_clobbered_output,
        "verifier_state_signal",
        "helper-written stack storage"
    ));

    let partial_later_probe_read = run_json_stdin(
        "func#0 @0\n\
         0: R1=fp-8 R2=8 R3=scalar() R10=fp0\n\
         1: (85) call bpf_probe_read_kernel#113\n\
         2: R1=fp-8 R2=4 R3=scalar() R7=scalar() R10=fp0 fp-8=mmmmmmmm\n\
         3: (85) call bpf_probe_read_kernel#113\n\
         4: R7=scalar() R10=fp0 fp-8=mmmmmmmm\n\
         5: (79) r7 = *(u64 *)(r10 -8)\n\
         6: (71) r0 = *(u8 *)(r7 +0)\n\
         R7 invalid mem access 'scalar'\n",
    );
    assert_eq!(partial_later_probe_read["error_id"], "BPFIX-E011");
    assert_eq!(partial_later_probe_read["next_action"], "provenance");
    assert!(!evidence_contains(
        &partial_later_probe_read,
        "verifier_state_signal",
        "helper-written stack storage"
    ));

    let random_scalar_pointer =
        run_json("bpfix-bench/cases/stackoverflow-78471487/replay-verifier.log");
    assert_eq!(random_scalar_pointer["error_id"], "BPFIX-E011");
    assert_eq!(random_scalar_pointer["next_action"], "provenance");
    assert!(!evidence_contains(
        &random_scalar_pointer,
        "verifier_state_signal",
        "helper-written stack storage"
    ));
}

#[test]
fn stale_data_pointer_after_invalidating_helper_reports_state_signal() {
    for path in [
        "bpfix-bench/cases/github-commit-cilium-2ff1a462cd33/replay-verifier.log",
        "bpfix-bench/cases/github-commit-cilium-3f356b0156d8/replay-verifier.log",
    ] {
        let diagnostic = run_json(path);
        assert_eq!(diagnostic["error_id"], "BPFIX-E011");
        assert_eq!(diagnostic["failure_class"], "source_bug");
        assert_eq!(diagnostic["next_action"], "provenance");
        assert!(evidence_contains(
            &diagnostic,
            "verifier_state_signal",
            "intervening packet-mutating helper invalidated"
        ));
        assert!(diagnostic["required_proof"]
            .as_str()
            .unwrap()
            .contains("preserve pointer provenance"));
    }

    for path in [
        "bpfix-bench/cases/kernel-selftest-dynptr-fail-skb-invalid-data-slice1-tc-0b35a757/replay-verifier.log",
        "bpfix-bench/cases/kernel-selftest-dynptr-fail-skb-invalid-data-slice3-tc-a15c4322/replay-verifier.log",
        "bpfix-bench/cases/kernel-selftest-dynptr-fail-dynptr-invalidate-slice-reinit-raw-tp-f5b71f50/replay-verifier.log",
        "bpfix-bench/cases/kernel-selftest-dynptr-fail-invalid-data-slices-raw-tp-6798c725/replay-verifier.log",
        "bpfix-bench/cases/kernel-selftest-dynptr-fail-xdp-invalid-data-slice1-xdp-c0fa30d5/replay-verifier.log",
    ] {
        let diagnostic = run_json(path);
        assert_eq!(diagnostic["error_id"], "BPFIX-E011");
        assert_eq!(diagnostic["failure_class"], "source_bug");
        assert_eq!(diagnostic["next_action"], "protocol");
        assert!(evidence_contains(
            &diagnostic,
            "verifier_state_signal",
            "dynptr data or slice helper result"
        ));
        assert!(diagnostic["required_proof"]
            .as_str()
            .unwrap()
            .contains("dynptr data/slice lifecycle"));
    }
}

#[test]
fn stale_data_pointer_signal_requires_invalidating_helper_after_pointer_state() {
    let non_invalidating_helper = run_json_stdin(
        "func#0 @0\n\
         0: R7=pkt(r=14) R10=fp0\n\
         1: (85) call bpf_get_prandom_u32#7\n\
         2: (71) r0 = *(u8 *)(r7 +0)\n\
         R7 invalid mem access 'scalar'\n",
    );
    assert_no_stale_pointer_invalidation_signal(&non_invalidating_helper);

    let pointer_reacquired_after_helper = run_json_stdin(
        "func#0 @0\n\
         0: (85) call bpf_xdp_adjust_head#44\n\
         1: R7=pkt(r=14) R10=fp0\n\
         2: (71) r0 = *(u8 *)(r7 +0)\n\
         R7 invalid mem access 'scalar'\n",
    );
    assert_no_stale_pointer_invalidation_signal(&pointer_reacquired_after_helper);

    let scalar_state_after_invalidating_helper = run_json_stdin(
        "func#0 @0\n\
         0: R7=pkt(r=14) R10=fp0\n\
         1: (85) call bpf_xdp_adjust_head#44\n\
         2: R7=scalar() R10=fp0\n\
         3: (71) r0 = *(u8 *)(r7 +0)\n\
         R7 invalid mem access 'scalar'\n",
    );
    assert_no_stale_pointer_invalidation_signal(&scalar_state_after_invalidating_helper);
    assert!(evidence_contains(
        &scalar_state_after_invalidating_helper,
        "verifier_state_signal",
        "consumed register is scalar"
    ));

    let local_dynptr_data_ignores_packet_helper = run_json_stdin(
        "func#0 @0\n\
         0: R3=fp-16 R4=fp-32 R10=fp0\n\
         1: (85) call bpf_dynptr_from_skb#71549\n\
         2: (85) call bpf_dynptr_from_mem#197\n\
         3: R1=fp-32 R10=fp0\n\
         4: (85) call bpf_dynptr_data#203\n\
         5: R7=mem(sz=1) R10=fp0\n\
         6: (85) call bpf_skb_pull_data#39\n\
         7: (71) r0 = *(u8 *)(r7 +0)\n\
         R7 invalid mem access 'scalar'\n",
    );
    assert_no_stale_pointer_invalidation_signal(&local_dynptr_data_ignores_packet_helper);

    let unrelated_dynptr_write = run_json_stdin(
        "func#0 @0\n\
         0: R4=fp-16 R10=fp0\n\
         1: (85) call bpf_dynptr_from_mem#197\n\
         2: R1=fp-16 R10=fp0\n\
         3: (85) call bpf_dynptr_data#203\n\
         4: R7=mem(sz=1) R10=fp0\n\
         5: R1=fp-32 R10=fp0\n\
         6: (85) call bpf_dynptr_write#202\n\
         7: (71) r0 = *(u8 *)(r7 +0)\n\
         R7 invalid mem access 'scalar'\n",
    );
    assert_no_stale_pointer_invalidation_signal(&unrelated_dynptr_write);

    let later_data_pointer_producer_for_different_register = run_json_stdin(
        "func#0 @0\n\
         0: R4=fp-16 R10=fp0\n\
         1: (85) call bpf_dynptr_from_mem#197\n\
         2: R1=fp-16 R10=fp0\n\
         3: (85) call bpf_dynptr_data#203\n\
         4: (bf) r7 = r0 ; R7_w=mem(sz=1)\n\
         5: R4=fp-32 R10=fp0\n\
         6: (85) call bpf_dynptr_from_mem#197\n\
         7: R1=fp-32 R10=fp0\n\
         8: (85) call bpf_dynptr_data#203\n\
         9: (bf) r8 = r0 ; R7=mem(sz=1) R8_w=mem(sz=1)\n\
         10: R1=fp-32 R10=fp0\n\
         11: (85) call bpf_dynptr_write#202\n\
         12: (71) r0 = *(u8 *)(r7 +0)\n\
         R7 invalid mem access 'scalar'\n",
    );
    assert_no_stale_pointer_invalidation_signal(
        &later_data_pointer_producer_for_different_register,
    );

    let r0_clobber_breaks_dynptr_lineage = run_json_stdin(
        "func#0 @0\n\
         0: R4=fp-16 R10=fp0\n\
         1: (85) call bpf_dynptr_from_mem#197\n\
         2: R1=fp-16 R10=fp0\n\
         3: (85) call bpf_dynptr_data#203\n\
         4: (85) call bpf_get_prandom_u32#7\n\
         5: (bf) r7 = r0 ; R7_w=mem(sz=1)\n\
         6: R1=fp-16 R10=fp0\n\
         7: (85) call bpf_dynptr_write#202\n\
         8: (71) r0 = *(u8 *)(r7 +0)\n\
         R7 invalid mem access 'scalar'\n",
    );
    assert_no_stale_pointer_invalidation_signal(&r0_clobber_breaks_dynptr_lineage);

    let callback_writes_unrelated_stack_slot = run_json_stdin(
        "func#0 @0\n\
         func#1 @10\n\
         0: R4=fp-16 R10=fp0\n\
         1: (85) call bpf_dynptr_from_mem#197\n\
         2: R1=fp-16 R10=fp0\n\
         3: (85) call bpf_dynptr_data#203\n\
         4: (bf) r7 = r0 ; R7_w=mem(sz=1)\n\
         5: R3=fp-16 R7=mem(sz=1) R10=fp0\n\
         6: (85) call bpf_loop#181\n\
         from 6 to 10: frame1: R1=scalar() R2=fp[0]-32 R10=fp0 cb\n\
         10: frame1: R1=scalar() R2=fp[0]-32 R10=fp0 cb\n\
         11: (63) *(u32 *)(r2 +0) = r1 ; frame1: R1_w=123 R2=fp[0]-32 cb\n\
         from 11 to 6: R7=scalar() R10=fp0\n\
         7: (71) r0 = *(u8 *)(r7 +0)\n\
         R7 invalid mem access 'scalar'\n",
    );
    assert_no_stale_pointer_invalidation_signal(&callback_writes_unrelated_stack_slot);

    let r0_clobbered_by_bpf_loop_return = run_json_stdin(
        "func#0 @0\n\
         func#1 @10\n\
         0: R4=fp-16 R10=fp0\n\
         1: (85) call bpf_dynptr_from_mem#197\n\
         2: R1=fp-16 R10=fp0\n\
         3: (85) call bpf_dynptr_data#203\n\
         4: R0=mem(sz=1) R3=fp-16 R10=fp0\n\
         5: (85) call bpf_loop#181\n\
         from 5 to 10: frame1: R1=scalar() R2=fp[0]-16 R10=fp0 cb\n\
         10: frame1: R1=scalar() R2=fp[0]-16 R10=fp0 cb\n\
         11: (63) *(u32 *)(r2 +0) = r1 ; frame1: R1_w=123 R2=fp[0]-16 cb\n\
         from 11 to 5: R0=scalar() R10=fp0\n\
         6: (71) r1 = *(u8 *)(r0 +0)\n\
         R0 invalid mem access 'scalar'\n",
    );
    assert_no_stale_pointer_invalidation_signal(&r0_clobbered_by_bpf_loop_return);

    let r0_call_clobber_without_return_state = run_json_stdin(
        "func#0 @0\n\
         func#1 @10\n\
         0: R4=fp-16 R10=fp0\n\
         1: (85) call bpf_dynptr_from_mem#197\n\
         2: R1=fp-16 R10=fp0\n\
         3: (85) call bpf_dynptr_data#203\n\
         4: R0=mem(sz=1) R3=fp-16 R10=fp0\n\
         5: (85) call bpf_loop#181\n\
         from 5 to 10: frame1: R1=scalar() R2=fp[0]-16 R10=fp0 cb\n\
         10: frame1: R1=scalar() R2=fp[0]-16 R10=fp0 cb\n\
         11: (63) *(u32 *)(r2 +0) = r1 ; frame1: R1_w=123 R2=fp[0]-16 cb\n\
         6: (71) r1 = *(u8 *)(r0 +0)\n\
         R0 invalid mem access 'scalar'\n",
    );
    assert_no_stale_pointer_invalidation_signal(&r0_call_clobber_without_return_state);

    let callback_local_register_assignment_preserves_caller_lineage = run_json_stdin(
        "func#0 @0\n\
         func#1 @10\n\
         0: R4=fp-16 R10=fp0\n\
         1: (85) call bpf_dynptr_from_mem#197\n\
         2: R1=fp-16 R10=fp0\n\
         3: (85) call bpf_dynptr_data#203\n\
         4: (bf) r7 = r0 ; R7_w=mem(sz=1)\n\
         5: R3=fp-16 R7=mem(sz=1) R10=fp0\n\
         6: (85) call bpf_loop#181\n\
         from 6 to 10: frame1: R1=scalar() R2=fp[0]-16 R10=fp0 cb\n\
         10: frame1: R1=scalar() R2=fp[0]-16 R10=fp0 cb\n\
         11: (bf) r7 = r2 ; frame1: R2=fp[0]-16 R7_w=fp[0]-16 cb\n\
         12: (63) *(u32 *)(r2 +0) = r1 ; frame1: R1_w=123 R2=fp[0]-16 cb\n\
         from 12 to 6: R7=scalar() R10=fp0\n\
         7: (71) r0 = *(u8 *)(r7 +0)\n\
         R7 invalid mem access 'scalar'\n",
    );
    assert_eq!(
        callback_local_register_assignment_preserves_caller_lineage["next_action"],
        "protocol"
    );
    assert!(evidence_contains(
        &callback_local_register_assignment_preserves_caller_lineage,
        "verifier_state_signal",
        "dynptr data or slice helper result"
    ));

    let callback_interior_data_pointer_overlaps_dynptr_slot = run_json_stdin(
        "func#0 @0\n\
         func#1 @10\n\
         0: R4=fp-24 R10=fp0\n\
         1: (85) call bpf_dynptr_from_mem#197\n\
         2: R1=fp-24 R10=fp0\n\
         3: (85) call bpf_dynptr_data#203\n\
         4: (bf) r7 = r0 ; R7_w=mem(sz=1)\n\
         5: R3=fp-16 R7=mem(sz=1) R10=fp0\n\
         6: (85) call bpf_loop#181\n\
         from 6 to 10: frame1: R1=scalar() R2=fp[0]-16 R10=fp0 cb\n\
         10: frame1: R1=scalar() R2=fp[0]-16 R10=fp0 cb\n\
         11: (63) *(u32 *)(r2 +0) = r1 ; frame1: R1_w=123 R2=fp[0]-16 cb\n\
         from 11 to 6: R7=scalar() R10=fp0\n\
         7: (71) r0 = *(u8 *)(r7 +0)\n\
         R7 invalid mem access 'scalar'\n",
    );
    assert_eq!(
        callback_interior_data_pointer_overlaps_dynptr_slot["next_action"],
        "protocol"
    );
    assert!(evidence_contains(
        &callback_interior_data_pointer_overlaps_dynptr_slot,
        "verifier_state_signal",
        "dynptr data or slice helper result"
    ));
}

#[test]
fn nullable_pointer_uses_report_state_discipline() {
    for path in [
        "bpfix-bench/cases/github-cilium-cilium-36936/replay-verifier.log",
        "bpfix-bench/cases/github-commit-cilium-5a76cf2c5e96/replay-verifier.log",
        "bpfix-bench/cases/kernel-selftest-dynptr-fail-data-slice-missing-null-check1-raw-tp-af2be9c9/replay-verifier.log",
    ] {
        let diagnostic = run_json(path);
        assert_eq!(diagnostic["error_id"], "BPFIX-E002");
        assert_eq!(diagnostic["failure_class"], "source_bug");
        assert!(evidence_contains(
            &diagnostic,
            "verifier_state_signal",
            "nullable helper result"
        ));
        assert!(diagnostic["required_proof"]
            .as_str()
            .unwrap()
            .contains("same verifier-visible branch"));
        assert!(diagnostic["help"]
            .as_array()
            .unwrap()
            .iter()
            .any(|help| help.as_str().unwrap().contains("non-null branch")));
    }

    let mismatched_memory_base = run_json_stdin(
        "0: R0=map_value_or_null(id=1,map=test,ks=4,vs=8) R2=map_value(map=test,ks=4,vs=8)\n\
         1: (79) r1 = *(u64 *)(r2 +0)\n\
         R0 invalid mem access 'map_value_or_null'\n",
    );
    assert_source_bug_without_verifier_state_signal(&mismatched_memory_base, "BPFIX-E002");

    let non_nullable_state = run_json_stdin(
        "0: R0=map_value(map=test,ks=4,vs=8)\n\
         1: (79) r0 = *(u64 *)(r0 +0)\n\
         R0 invalid mem access 'map_value_or_null'\n",
    );
    assert_source_bug_without_verifier_state_signal(&non_nullable_state, "BPFIX-E002");

    let register_prefix_is_not_arithmetic_target = run_json_stdin(
        "0: R1=map_value_or_null(id=1,map=test,ks=4,vs=8) R10=fp0\n\
         1: (07) r10 += -8\n\
         R1 pointer arithmetic on map_value_or_null prohibited, null-check it first\n",
    );
    assert_source_bug_without_verifier_state_signal(
        &register_prefix_is_not_arithmetic_target,
        "BPFIX-E002",
    );

    let trusted_arg_terminal_is_not_generic_nullable = run_json_stdin(
        "0: R1=map_value_or_null(id=1,map=test,ks=4,vs=8)\n\
         1: (85) call bpf_obj_new#200\n\
         R1 type=map_value_or_null expected=ptr_, trusted arg0\n",
    );
    assert_source_bug_without_verifier_state_signal(
        &trusted_arg_terminal_is_not_generic_nullable,
        "BPFIX-E002",
    );

    let helper_arg_terminal_must_be_call = run_json_stdin(
        "0: R1=ctx() R3=map_value_or_null(id=1,map=test,ks=4,vs=8) R10=fp0\n\
         1: (bf) r2 = r10\n\
         Possibly NULL pointer passed to helper arg3\n",
    );
    assert_source_bug_without_verifier_state_signal(
        &helper_arg_terminal_must_be_call,
        "BPFIX-E002",
    );

    let helper_arg_terminal_requires_instruction_site = run_json_stdin(
        "0: R1=ctx() R3=map_value_or_null(id=1,map=test,ks=4,vs=8) R10=fp0\n\
         Possibly NULL pointer passed to helper arg3\n",
    );
    assert_source_bug_without_verifier_state_signal(
        &helper_arg_terminal_requires_instruction_site,
        "BPFIX-E002",
    );

    let impossible_helper_arg_is_ignored = run_json_stdin(
        "0: R1=ctx() R6=map_value_or_null(id=1,map=test,ks=4,vs=8)\n\
         1: (85) call bpf_map_update_elem#2\n\
         Possibly NULL pointer passed to helper arg6\n",
    );
    assert_source_bug_without_verifier_state_signal(
        &impossible_helper_arg_is_ignored,
        "BPFIX-E002",
    );

    let impossible_helper_arg_cannot_fallback_to_terminal_register = run_json_stdin(
        "0: R1=ctx() R6=map_value_or_null(id=1,map=test,ks=4,vs=8)\n\
         1: (85) call bpf_map_update_elem#2\n\
         R6 Possibly NULL pointer passed to helper arg6\n",
    );
    assert_source_bug_without_verifier_state_signal(
        &impossible_helper_arg_cannot_fallback_to_terminal_register,
        "BPFIX-E002",
    );
}

#[test]
fn trusted_nullable_arguments_report_state_discipline() {
    let cpumask_trusted_arg =
        run_json("bpfix-bench/cases/kernel-selftest-cpumask-failure-test-global-mask-no-null-check-tp-btf-task-newtask-655f6c03/replay-verifier.log");
    assert_eq!(cpumask_trusted_arg["error_id"], "BPFIX-E015");
    assert_eq!(cpumask_trusted_arg["failure_class"], "source_bug");
    assert!(evidence_contains(
        &cpumask_trusted_arg,
        "verifier_state_signal",
        "nullable RCU/trusted pointer"
    ));
    assert!(cpumask_trusted_arg["required_proof"]
        .as_str()
        .unwrap()
        .contains("RCU/trusted pointer argument"));
    assert!(!cpumask_trusted_arg["help"]
        .as_array()
        .unwrap()
        .iter()
        .any(|help| help
            .as_str()
            .unwrap()
            .contains("nullable pointer returned by a helper")));

    let cgroup_trusted_arg =
        run_json("bpfix-bench/cases/kernel-selftest-cgrp-kfunc-failure-cgrp-kfunc-release-untrusted-tp-btf-cgroup-mkdir-9eb3123d/replay-verifier.log");
    assert_eq!(cgroup_trusted_arg["error_id"], "BPFIX-E015");
    assert!(evidence_contains(
        &cgroup_trusted_arg,
        "verifier_state_signal",
        "nullable RCU/trusted pointer"
    ));

    let nullable_kptr_exchange =
        run_json("bpfix-bench/cases/kernel-selftest-cpumask-failure-test-global-mask-rcu-no-null-check-tp-btf-task-newtask-c8a92e39/replay-verifier.log");
    assert_eq!(nullable_kptr_exchange["error_id"], "BPFIX-E015");
    assert!(evidence_contains(
        &nullable_kptr_exchange,
        "verifier_state_signal",
        "nullable RCU/trusted pointer"
    ));

    let generic_nullable_helper_arg = run_json_stdin(
        "0: R1=ctx() R10=fp0\n\
         1: R3=map_value_or_null(id=1,map=test,ks=4,vs=8)\n\
         2: (85) call bpf_map_update_elem#2\n\
         Possibly NULL pointer passed to helper arg3\n",
    );
    assert_eq!(generic_nullable_helper_arg["error_id"], "BPFIX-E002");
    assert_eq!(generic_nullable_helper_arg["failure_class"], "source_bug");
    assert!(evidence_contains(
        &generic_nullable_helper_arg,
        "verifier_state_signal",
        "nullable helper result"
    ));
    assert!(!evidence_contains(
        &generic_nullable_helper_arg,
        "verifier_state_signal",
        "nullable RCU/trusted pointer"
    ));

    let nullable_map_value_to_kptr_xchg = run_json_stdin(
        "0: R1=ctx() R10=fp0\n\
         1: R2=map_value_or_null(id=1,map=test,ks=4,vs=8)\n\
         2: (85) call bpf_kptr_xchg#194\n\
         Possibly NULL pointer passed to helper arg2\n",
    );
    assert_eq!(nullable_map_value_to_kptr_xchg["error_id"], "BPFIX-E002");
    assert!(evidence_contains(
        &nullable_map_value_to_kptr_xchg,
        "verifier_state_signal",
        "nullable helper result"
    ));
    assert!(!evidence_contains(
        &nullable_map_value_to_kptr_xchg,
        "verifier_state_signal",
        "nullable RCU/trusted pointer"
    ));

    let live_regs_only_kptr_call = run_json_stdin(
        "func#0 @0\n\
         Live regs before insn:\n\
          15: .12....... (85) call bpf_kptr_xchg#194\n\
         0: R1=ctx() R10=fp0\n\
         14: R2=rcu_ptr_or_null_bpf_cpumask(id=5)\n\
         Possibly NULL pointer passed to helper arg2\n",
    );
    assert_eq!(live_regs_only_kptr_call["error_id"], "BPFIX-E015");
    assert!(evidence_contains(
        &live_regs_only_kptr_call,
        "verifier_state_signal",
        "nullable RCU/trusted pointer"
    ));

    let unknown_terminal_kptr_call = run_stdin_output(
        "func#0 @0\n\
         0: R1=ctx() R10=fp0\n\
         14: R2=rcu_ptr_or_null_bpf_cpumask(id=5)\n\
         15: (85) call bpf_kptr_xchg#194\n\
         invalid verifier frobnication\n",
        &["-", "--format", "json", "--fail-on-unsupported"],
    );
    assert!(unknown_terminal_kptr_call.status.success());
    assert!(unknown_terminal_kptr_call.stderr.is_empty());
    let unknown_terminal_kptr_call: Value =
        serde_json::from_slice(&unknown_terminal_kptr_call.stdout).expect("bpfix should emit JSON");
    assert_eq!(unknown_terminal_kptr_call["error_id"], "BPFIX-E015");
    assert_eq!(unknown_terminal_kptr_call["diagnostic_kind"], "supported");
    assert!(evidence_contains(
        &unknown_terminal_kptr_call,
        "verifier_state_signal",
        "nullable RCU/trusted pointer"
    ));

    let generic_nullable_unknown_terminal_kptr_call = run_stdin_output(
        "func#0 @0\n\
         0: R1=ctx() R10=fp0\n\
         14: R2=map_value_or_null(id=1,map=test,ks=4,vs=8)\n\
         15: (85) call bpf_kptr_xchg#194\n\
         invalid verifier frobnication\n",
        &["-", "--format", "json", "--fail-on-unsupported"],
    );
    assert_eq!(
        generic_nullable_unknown_terminal_kptr_call.status.code(),
        Some(2)
    );
    assert!(generic_nullable_unknown_terminal_kptr_call
        .stderr
        .is_empty());
    let generic_nullable_unknown_terminal_kptr_call: Value =
        serde_json::from_slice(&generic_nullable_unknown_terminal_kptr_call.stdout)
            .expect("bpfix should emit JSON");
    assert_eq!(
        generic_nullable_unknown_terminal_kptr_call["diagnostic_kind"],
        "unsupported_verifier_message"
    );
    assert!(!evidence_contains(
        &generic_nullable_unknown_terminal_kptr_call,
        "verifier_state_signal",
        "nullable RCU/trusted pointer"
    ));

    let kptr_destination_error_with_nullable_r2 = run_json_stdin(
        "func#0 @0\n\
         0: R1=ctx() R10=fp0\n\
         14: R2=rcu_ptr_or_null_bpf_cpumask(id=5)\n\
         15: (85) call bpf_kptr_xchg#194\n\
         R1 has no valid kptr\n",
    );
    assert_eq!(
        kptr_destination_error_with_nullable_r2["error_id"],
        "BPFIX-E013"
    );
    assert!(!evidence_contains(
        &kptr_destination_error_with_nullable_r2,
        "verifier_state_signal",
        "nullable RCU/trusted pointer"
    ));
}

#[test]
fn kfunc_argument_type_contract_reports_object_mismatch() {
    let stack_cast_cgroup =
        run_json("bpfix-bench/cases/kernel-selftest-cgrp-kfunc-failure-cgrp-kfunc-acquire-fp-tp-btf-cgroup-mkdir-7d3a90fe/replay-verifier.log");
    assert_eq!(stack_cast_cgroup["error_id"], "BPFIX-E023");
    assert_eq!(stack_cast_cgroup["failure_class"], "source_bug");
    assert!(evidence_contains(
        &stack_cast_cgroup,
        "verifier_state_signal",
        "modern BPF object"
    ));
    assert!(stack_cast_cgroup["required_proof"]
        .as_str()
        .unwrap()
        .contains("verifier-approved object"));

    let walked_cgroup =
        run_json("bpfix-bench/cases/kernel-selftest-cgrp-kfunc-failure-cgrp-kfunc-acquire-trusted-walked-tp-btf-cgroup-mkdir-6deeac84/replay-verifier.log");
    assert_eq!(walked_cgroup["error_id"], "BPFIX-E023");
    assert!(evidence_contains(
        &walked_cgroup,
        "verifier_state_signal",
        "modern BPF object"
    ));

    let rcu_release_cgroup =
        run_json("bpfix-bench/cases/kernel-selftest-cgrp-kfunc-failure-cgrp-kfunc-rcu-get-release-tp-btf-cgroup-mkdir-29aa212b/replay-verifier.log");
    assert_eq!(rcu_release_cgroup["error_id"], "BPFIX-E023");
    assert!(evidence_contains(
        &rcu_release_cgroup,
        "verifier_state_signal",
        "modern BPF object"
    ));

    let plain_cpumask =
        run_json("bpfix-bench/cases/kernel-selftest-cpumask-failure-test-mutate-cpumask-tp-btf-task-newtask-d7b7c258/replay-verifier.log");
    assert_eq!(plain_cpumask["error_id"], "BPFIX-E023");
    assert!(evidence_contains(
        &plain_cpumask,
        "verifier_state_signal",
        "modern BPF object"
    ));
    assert!(plain_cpumask["help"]
        .as_array()
        .unwrap()
        .iter()
        .any(|help| help.as_str().unwrap().contains("modern BPF object helpers")));

    let cpumask_fp_contract =
        run_json("bpfix-bench/cases/kernel-selftest-cpumask-failure-test-populate-invalid-destination-tp-btf-task-newtask-2aa0585a/replay-verifier.log");
    assert_eq!(cpumask_fp_contract["error_id"], "BPFIX-E023");
    assert!(evidence_contains(
        &cpumask_fp_contract,
        "verifier_state_signal",
        "modern BPF object"
    ));

    let out_of_rcu_cpumask =
        run_json("bpfix-bench/cases/kernel-selftest-cpumask-failure-test-global-mask-out-of-rcu-tp-btf-task-newtask-55a16b69/replay-verifier.log");
    assert_eq!(out_of_rcu_cpumask["error_id"], "BPFIX-E023");
    assert!(evidence_contains(
        &out_of_rcu_cpumask,
        "verifier_state_signal",
        "modern BPF object"
    ));

    let invalid_kptr_storage =
        run_json("bpfix-bench/cases/kernel-selftest-cpumask-failure-test-invalid-nested-array-tp-btf-task-newtask-bd05d03f/replay-verifier.log");
    assert_eq!(invalid_kptr_storage["error_id"], "BPFIX-E023");
    assert!(evidence_contains(
        &invalid_kptr_storage,
        "verifier_state_signal",
        "modern BPF object"
    ));

    let invalid_cpumask_source =
        run_json("bpfix-bench/cases/kernel-selftest-cpumask-failure-test-populate-invalid-source-tp-btf-task-newtask-149c6ecc/replay-verifier.log");
    assert_eq!(invalid_cpumask_source["error_id"], "BPFIX-E023");
    assert!(evidence_contains(
        &invalid_cpumask_source,
        "verifier_state_signal",
        "modern BPF object"
    ));

    let skb_without_reference =
        run_json("bpfix-bench/cases/kernel-selftest-dynptr-fail-skb-invalid-ctx-fentry-fentry-skb-tx-error-17cea403/replay-verifier.log");
    assert_eq!(skb_without_reference["error_id"], "BPFIX-E023");
    assert!(evidence_contains(
        &skb_without_reference,
        "verifier_state_signal",
        "modern BPF object"
    ));

    let ordinary_fp_contract = run_json_stdin(
        "func#0 @0\n\
         0: R1=ctx() R10=fp0\n\
         1: R1=scalar()\n\
         2: (85) call bpf_map_lookup_elem#1\n\
         R1 type=scalar expected=fp\n",
    );
    assert_eq!(ordinary_fp_contract["error_id"], "BPFIX-E008");
    assert!(!evidence_contains(
        &ordinary_fp_contract,
        "verifier_state_signal",
        "modern BPF object"
    ));
}

#[test]
fn helper_type_contract_mismatch_uses_callsite_state() {
    let ringbuf_mem_mismatch =
        run_json("bpfix-bench/cases/kernel-selftest-dynptr-fail-ringbuf-invalid-api-raw-tp-87a443d6/replay-verifier.log");
    assert_eq!(ringbuf_mem_mismatch["error_id"], "BPFIX-E008");
    assert_eq!(ringbuf_mem_mismatch["failure_class"], "source_bug");
    assert!(evidence_contains(
        &ringbuf_mem_mismatch,
        "verifier_state_signal",
        "verifier state at the call site"
    ));
    assert!(ringbuf_mem_mismatch["required_proof"]
        .as_str()
        .unwrap()
        .contains("exact verifier-visible type"));

    let map_value_as_map_ptr =
        run_json("bpfix-bench/cases/stackoverflow-70091221/replay-verifier.log");
    assert_eq!(map_value_as_map_ptr["error_id"], "BPFIX-E008");
    assert!(evidence_contains(
        &map_value_as_map_ptr,
        "verifier_state_signal",
        "helper or kfunc contract"
    ));

    let stack_pointer_as_trusted_object =
        run_json("bpfix-bench/cases/stackoverflow-79348306/replay-verifier.log");
    assert_eq!(stack_pointer_as_trusted_object["error_id"], "BPFIX-E008");
    assert!(evidence_contains(
        &stack_pointer_as_trusted_object,
        "verifier_state_signal",
        "printed actual type"
    ));

    let stale_or_inconsistent_terminal = run_json_stdin(
        "func#0 @0\n\
         0: R1=fp0 R10=fp0\n\
         1: (85) call bpf_map_lookup_elem#1\n\
         R1 type=scalar expected=fp\n",
    );
    assert_source_bug_without_verifier_state_signal(&stale_or_inconsistent_terminal, "BPFIX-E008");

    let overwritten_after_matching_state = run_json_stdin(
        "func#0 @0\n\
         0: R1=scalar() R10=fp0\n\
         1: (bf) r1 = r10\n\
         2: (85) call bpf_map_lookup_elem#1\n\
         R1 type=scalar expected=fp\n",
    );
    assert_source_bug_without_verifier_state_signal(
        &overwritten_after_matching_state,
        "BPFIX-E008",
    );
}

#[test]
fn helper_argument_contracts_use_callsite_state() {
    let raw_map_pointer_access =
        run_json("bpfix-bench/cases/github-aya-rs-aya-1002/replay-verifier.log");
    assert_eq!(raw_map_pointer_access["error_id"], "BPFIX-E010");
    assert_eq!(raw_map_pointer_access["failure_class"], "source_bug");
    assert!(raw_map_pointer_access["message"]
        .as_str()
        .unwrap()
        .contains("map pointer is accessed"));
    assert!(evidence_contains(
        &raw_map_pointer_access,
        "verifier_state_signal",
        "base register is a map_ptr"
    ));

    let packet_payload = run_json("bpfix-bench/cases/github-aya-rs-aya-440/replay-verifier.log");
    assert_eq!(packet_payload["error_id"], "BPFIX-E010");
    assert_eq!(packet_payload["failure_class"], "source_bug");
    assert!(packet_payload["message"]
        .as_str()
        .unwrap()
        .contains("packet memory"));
    assert!(evidence_contains(
        &packet_payload,
        "verifier_state_signal",
        "passes a packet pointer and scalar length"
    ));

    let terminal_without_map_pointer_state = run_json_stdin(
        "func#0 @0\n\
         0: R1=scalar() R2=0 R10=fp0\n\
         1: (7b) *(u64 *)(r1 +0) = r2\n\
         only read from bpf_array is supported\n",
    );
    assert_source_bug_without_verifier_state_signal(
        &terminal_without_map_pointer_state,
        "BPFIX-E010",
    );

    let terminal_with_map_value_base = run_json_stdin(
        "func#0 @0\n\
         0: R1=map_value(map=events,ks=4,vs=8) R2=0 R10=fp0\n\
         1: (7b) *(u64 *)(r1 +0) = r2\n\
         only read from bpf_array is supported\n",
    );
    assert_source_bug_without_verifier_state_signal(&terminal_with_map_value_base, "BPFIX-E010");

    let terminal_without_packet_payload_state = run_json_stdin(
        "func#0 @0\n\
         0: R1=ctx() R2=map_ptr(map=events,ks=4,vs=4) R3=0 R4=fp-8 R5=8 R10=fp0\n\
         1: (85) call bpf_perf_event_output#25\n\
         helper access to the packet is not allowed\n",
    );
    assert_source_bug_without_verifier_state_signal(
        &terminal_without_packet_payload_state,
        "BPFIX-E010",
    );
}

#[test]
fn terminal_error_selection_ignores_state_lines_and_uses_final_reject() {
    let pointer_bitwise = run_json("bpfix-bench/cases/stackoverflow-68460177/replay-verifier.log");
    assert_eq!(pointer_bitwise["error_id"], "BPFIX-E006");
    assert_eq!(pointer_bitwise["failure_class"], "source_bug");
    assert!(pointer_bitwise["message"]
        .as_str()
        .unwrap()
        .contains("R4 bitwise operator |= on pointer prohibited"));
    assert!(evidence_contains(
        &pointer_bitwise,
        "verifier_state_signal",
        "prohibited pointer arithmetic"
    ));

    let return_range = run_json("bpfix-bench/cases/stackoverflow-77191387/replay-verifier.log");
    assert_eq!(return_range["error_id"], "BPFIX-E005");
    assert_eq!(return_range["failure_class"], "source_bug");
    assert!(return_range["message"]
        .as_str()
        .unwrap()
        .contains("At program exit the register R0"));
    assert!(!return_range["message"]
        .as_str()
        .unwrap()
        .contains("from 20 to 22"));

    let dynptr_release_twice =
        run_json("bpfix-bench/cases/kernel-selftest-dynptr-fail-release-twice-raw-tp-3722429d/replay-verifier.log");
    assert_eq!(dynptr_release_twice["error_id"], "BPFIX-E019");
    assert!(dynptr_release_twice["message"]
        .as_str()
        .unwrap()
        .contains("arg 1 is an unacquired reference"));
    assert!(dynptr_release_twice["required_proof"]
        .as_str()
        .unwrap()
        .contains("exactly once"));
    assert!(evidence_contains(
        &dynptr_release_twice,
        "verifier_state_signal",
        "without a live reference"
    ));
    assert!(!dynptr_release_twice["evidence"][0]["detail"]
        .as_str()
        .unwrap()
        .contains("call bpf_ringbuf_discard_dynptr"));
    assert!(dynptr_release_twice["source_span"]["source_text"]
        .as_str()
        .unwrap()
        .contains("bpf_ringbuf_discard_dynptr"));
}

#[test]
fn dynptr_protocol_diagnostic_uses_specific_required_proof() {
    let interior_dynptr_arg =
        run_json("bpfix-bench/cases/kernel-selftest-dynptr-fail-invalid-helper2-raw-tp-34ba04aa/replay-verifier.log");
    assert_eq!(interior_dynptr_arg["error_id"], "BPFIX-E019");
    assert!(interior_dynptr_arg["required_proof"]
        .as_str()
        .unwrap()
        .contains("exact verifier-tracked dynptr stack slot"));
    assert!(!interior_dynptr_arg["required_proof"]
        .as_str()
        .unwrap()
        .contains("null"));
    assert!(evidence_contains(
        &interior_dynptr_arg,
        "verifier_state_signal",
        "unstable dynptr slot"
    ));

    let one_byte_interior_dynptr_arg =
        run_json("bpfix-bench/cases/kernel-selftest-dynptr-fail-invalid-read2-raw-tp-2cc2b993/replay-verifier.log");
    assert_eq!(one_byte_interior_dynptr_arg["error_id"], "BPFIX-E019");
    assert!(evidence_contains(
        &one_byte_interior_dynptr_arg,
        "verifier_state_signal",
        "interior dynptr pointer"
    ));

    let shifted_initializer =
        run_json("bpfix-bench/cases/kernel-selftest-dynptr-fail-invalid-offset-raw-tp-549f8135/replay-verifier.log");
    assert_eq!(shifted_initializer["error_id"], "BPFIX-E019");
    assert!(shifted_initializer["required_proof"]
        .as_str()
        .unwrap()
        .contains("exact verifier-tracked dynptr stack slot"));
    assert!(!shifted_initializer["required_proof"]
        .as_str()
        .unwrap()
        .contains("stack byte"));
    assert!(evidence_contains(
        &shifted_initializer,
        "verifier_state_signal",
        "unstable dynptr slot"
    ));

    let variable_offset_initializer =
        run_json("bpfix-bench/cases/kernel-selftest-dynptr-fail-dynptr-var-off-overwrite-tc-ab0a2e71/replay-verifier.log");
    assert_eq!(variable_offset_initializer["error_id"], "BPFIX-E019");
    assert!(evidence_contains(
        &variable_offset_initializer,
        "verifier_state_signal",
        "unstable dynptr slot"
    ));

    let global_dynptr = run_json(
        "bpfix-bench/cases/kernel-selftest-dynptr-fail-global-raw-tp-e92dc79e/replay-verifier.log",
    );
    assert_eq!(global_dynptr["error_id"], "BPFIX-E019");
    assert!(evidence_contains(
        &global_dynptr,
        "verifier_state_signal",
        "unstable dynptr slot"
    ));

    let stack_backed_from_mem =
        run_json("bpfix-bench/cases/kernel-selftest-dynptr-fail-dynptr-from-mem-invalid-api-raw-tp-1040be69/replay-verifier.log");
    assert_eq!(stack_backed_from_mem["error_id"], "BPFIX-E019");
    assert!(evidence_contains(
        &stack_backed_from_mem,
        "verifier_state_signal",
        "unsupported stack-backed input memory"
    ));

    let dynptr_read_into_slot =
        run_json("bpfix-bench/cases/kernel-selftest-dynptr-fail-dynptr-read-into-slot-raw-tp-5420cc35/replay-verifier.log");
    assert_eq!(dynptr_read_into_slot["error_id"], "BPFIX-E019");
    assert!(evidence_contains(
        &dynptr_read_into_slot,
        "verifier_state_signal",
        "write target overlaps"
    ));
    assert!(dynptr_read_into_slot["required_proof"]
        .as_str()
        .unwrap()
        .contains("disjoint from live verifier-tracked dynptr stack slots"));

    let uninit_write_into_slot =
        run_json("bpfix-bench/cases/kernel-selftest-dynptr-fail-uninit-write-into-slot-raw-tp-a80cb838/replay-verifier.log");
    assert_eq!(uninit_write_into_slot["error_id"], "BPFIX-E019");
    assert!(evidence_contains(
        &uninit_write_into_slot,
        "verifier_state_signal",
        "write target overlaps"
    ));

    let dynptr_release_twice_callback =
        run_json("bpfix-bench/cases/kernel-selftest-dynptr-fail-release-twice-callback-raw-tp-bd7b2a60/replay-verifier.log");
    assert_eq!(dynptr_release_twice_callback["error_id"], "BPFIX-E019");
    assert!(evidence_contains(
        &dynptr_release_twice_callback,
        "verifier_state_signal",
        "without a live reference"
    ));

    let uninitialized_dynptr_clone =
        run_json("bpfix-bench/cases/kernel-selftest-dynptr-fail-clone-invalid1-raw-tp-b7206632/replay-verifier.log");
    assert_eq!(uninitialized_dynptr_clone["error_id"], "BPFIX-E012");
    assert!(uninitialized_dynptr_clone["required_proof"]
        .as_str()
        .unwrap()
        .contains("exact verifier-tracked initialized dynptr stack slot"));
    assert!(evidence_contains(
        &uninitialized_dynptr_clone,
        "verifier_state_signal",
        "not the current initialized dynptr object"
    ));
    assert!(!evidence_contains(
        &uninitialized_dynptr_clone,
        "verifier_state_signal",
        "unstable dynptr slot"
    ));

    let overwritten_dynptr_slot =
        run_json("bpfix-bench/cases/kernel-selftest-dynptr-fail-invalid-write1-raw-tp-ba5ba8ca/replay-verifier.log");
    assert_eq!(overwritten_dynptr_slot["error_id"], "BPFIX-E012");
    assert!(evidence_contains(
        &overwritten_dynptr_slot,
        "verifier_state_signal",
        "not the current initialized dynptr object"
    ));
    assert!(!evidence_contains(
        &overwritten_dynptr_slot,
        "verifier_state_signal",
        "unstable dynptr slot"
    ));

    let initializer_overwrites_referenced_dynptr =
        run_json("bpfix-bench/cases/kernel-selftest-dynptr-fail-dynptr-overwrite-ref-raw-tp-3fed55ba/replay-verifier.log");
    assert_eq!(
        initializer_overwrites_referenced_dynptr["error_id"],
        "BPFIX-E012"
    );
    assert!(initializer_overwrites_referenced_dynptr["required_proof"]
        .as_str()
        .unwrap()
        .contains("reference is still live"));
    assert!(evidence_contains(
        &initializer_overwrites_referenced_dynptr,
        "verifier_state_signal",
        "dynptr reference is still live"
    ));

    let plain_write_overwrites_referenced_dynptr =
        run_json("bpfix-bench/cases/kernel-selftest-dynptr-fail-dynptr-pruning-type-confusion-tc-28056c9b/replay-verifier.log");
    assert_eq!(
        plain_write_overwrites_referenced_dynptr["error_id"],
        "BPFIX-E012"
    );
    assert!(evidence_contains(
        &plain_write_overwrites_referenced_dynptr,
        "verifier_state_signal",
        "dynptr reference is still live"
    ));

    let partial_write_overwrites_referenced_dynptr = run_json_stdin(
        "func#0 @0\n\
         0: R10=fp0\n\
         1: (85) call bpf_ringbuf_reserve_dynptr#198 ; R0_w=scalar() fp-16_w=dynptr_ringbuf(id=1,ref_id=2,dynptr_id=1) refs=2\n\
         2: R1=0 R10=fp0\n\
         2: (7b) *(u64 *)(r10 -20) = r1\n\
         cannot overwrite referenced dynptr\n",
    );
    assert_eq!(
        partial_write_overwrites_referenced_dynptr["error_id"],
        "BPFIX-E012"
    );
    assert!(evidence_contains(
        &partial_write_overwrites_referenced_dynptr,
        "verifier_state_signal",
        "dynptr reference is still live"
    ));

    let mismatched_ref_does_not_overclaim_live_dynptr_slot = run_json_stdin(
        "func#0 @0\n\
         0: R10=fp0\n\
         1: R4=fp-16 R10=fp0 fp-16_w=dynptr_ringbuf(id=1,ref_id=2,dynptr_id=1) refs=3\n\
         2: (85) call bpf_dynptr_from_mem#197\n\
         cannot overwrite referenced dynptr\n",
    );
    assert_eq!(
        mismatched_ref_does_not_overclaim_live_dynptr_slot["error_id"],
        "BPFIX-E012"
    );
    assert!(!evidence_contains(
        &mismatched_ref_does_not_overclaim_live_dynptr_slot,
        "verifier_state_signal",
        "dynptr reference is still live"
    ));

    let unavailable_dynptr_kfunc =
        run_json("bpfix-bench/cases/kernel-selftest-dynptr-fail-skb-invalid-ctx-xdp-1a32a21f/replay-verifier.log");
    assert_eq!(
        unavailable_dynptr_kfunc["failure_class"],
        "environment_or_configuration"
    );
    assert_eq!(unavailable_dynptr_kfunc["error_id"], "BPFIX-E009");

    let variable_slice_length =
        run_json("bpfix-bench/cases/kernel-selftest-dynptr-fail-dynptr-slice-var-len2-tc-673ab9e7/replay-verifier.log");
    assert_eq!(variable_slice_length["error_id"], "BPFIX-E019");
    assert!(variable_slice_length["message"]
        .as_str()
        .unwrap()
        .contains("must be a known constant"));
    assert!(variable_slice_length["required_proof"]
        .as_str()
        .unwrap()
        .contains("verifier-known constant length"));
    assert!(evidence_contains(
        &variable_slice_length,
        "verifier_state_signal",
        "R4 is still a scalar range"
    ));

    let variable_slice_length_with_unknown_terminal = run_stdin_output(
        "\
func#0 @0
0: R1=ctx() R10=fp0
10: (61) r4 = *(u32 *)(r1 +0)         ; R1_w=map_value(map=prog.data,ks=4,vs=4) R4_w=scalar(smin=0,smax=umax=0xffffffff,var_off=(0x0; 0xffffffff))
12: (26) if w4 > 0xe goto pc+12       ; R4_w=scalar(smin=smin32=0,smax=umax=smax32=umax32=14,var_off=(0x0; 0xf))
18: (85) call bpf_dynptr_slice_rdwr#71568
invalid verifier frobnication
",
        &["-", "--format", "json", "--fail-on-unsupported"],
    );
    assert!(variable_slice_length_with_unknown_terminal.status.success());
    assert!(variable_slice_length_with_unknown_terminal
        .stderr
        .is_empty());
    let variable_slice_length_with_unknown_terminal: Value =
        serde_json::from_slice(&variable_slice_length_with_unknown_terminal.stdout)
            .expect("bpfix should emit JSON");
    assert_eq!(
        variable_slice_length_with_unknown_terminal["error_id"],
        "BPFIX-E019"
    );
    assert_eq!(
        variable_slice_length_with_unknown_terminal["diagnostic_kind"],
        "supported"
    );
    assert!(evidence_contains(
        &variable_slice_length_with_unknown_terminal,
        "verifier_state_signal",
        "R4 is still a scalar range"
    ));

    let readonly_variable_slice_length_with_unknown_terminal = run_stdin_output(
        "\
func#0 @0
0: R1=ctx() R10=fp0
7: (61) r4 = *(u32 *)(r1 +0)          ; R1_w=map_value(map=prog.data,ks=4,vs=4) R4_w=scalar(smin=0,smax=umax=0xffffffff,var_off=(0x0; 0xffffffff))
9: (26) if w4 > 0xe goto pc+12        ; R4_w=scalar(smin=smin32=0,smax=umax=smax32=umax32=14,var_off=(0x0; 0xf))
14: (85) call bpf_dynptr_slice#71567
invalid verifier frobnication
",
        &["-", "--format", "json", "--fail-on-unsupported"],
    );
    assert!(readonly_variable_slice_length_with_unknown_terminal
        .status
        .success());
    assert!(readonly_variable_slice_length_with_unknown_terminal
        .stderr
        .is_empty());
    let readonly_variable_slice_length_with_unknown_terminal: Value =
        serde_json::from_slice(&readonly_variable_slice_length_with_unknown_terminal.stdout)
            .expect("bpfix should emit JSON");
    assert_eq!(
        readonly_variable_slice_length_with_unknown_terminal["error_id"],
        "BPFIX-E019"
    );
    assert_eq!(
        readonly_variable_slice_length_with_unknown_terminal["diagnostic_kind"],
        "supported"
    );

    let constant_slice_length_with_unknown_terminal = run_stdin_output(
        "\
func#0 @0
0: R1=ctx() R10=fp0
13: (b7) r4 = 14                      ; R4_w=14
14: (85) call bpf_dynptr_slice_rdwr#71568
invalid verifier frobnication
",
        &["-", "--format", "json", "--fail-on-unsupported"],
    );
    assert_eq!(
        constant_slice_length_with_unknown_terminal.status.code(),
        Some(2)
    );
    assert!(constant_slice_length_with_unknown_terminal
        .stderr
        .is_empty());
    let constant_slice_length_with_unknown_terminal: Value =
        serde_json::from_slice(&constant_slice_length_with_unknown_terminal.stdout)
            .expect("bpfix should emit JSON");
    assert_eq!(
        constant_slice_length_with_unknown_terminal["diagnostic_kind"],
        "unsupported_verifier_message"
    );
    assert!(!constant_slice_length_with_unknown_terminal["evidence"]
        .as_array()
        .unwrap()
        .iter()
        .any(|evidence| evidence["kind"] == "verifier_state_signal"));

    let unrelated_error_after_dynptr_call = run_stdin_output(
        "\
func#0 @0
0: R1=ctx() R10=fp0
7: (61) r4 = *(u32 *)(r1 +0)          ; R1_w=map_value(map=prog.data,ks=4,vs=4) R4_w=scalar(smin=0,smax=umax=0xffffffff,var_off=(0x0; 0xffffffff))
14: (85) call bpf_dynptr_slice_rdwr#71568
R1 invalid mem access 'scalar'
invalid verifier frobnication
",
        &["-", "--format", "json", "--fail-on-unsupported"],
    );
    assert_eq!(unrelated_error_after_dynptr_call.status.code(), Some(2));
    assert!(unrelated_error_after_dynptr_call.stderr.is_empty());
    let unrelated_error_after_dynptr_call: Value =
        serde_json::from_slice(&unrelated_error_after_dynptr_call.stdout)
            .expect("bpfix should emit JSON");
    assert_eq!(
        unrelated_error_after_dynptr_call["diagnostic_kind"],
        "unsupported_verifier_message"
    );
    assert!(!evidence_contains(
        &unrelated_error_after_dynptr_call,
        "verifier_state_signal",
        "R4 is still a scalar range"
    ));

    let unrelated_unbounded_error_after_dynptr_call = run_stdin_output(
        "\
func#0 @0
0: R1=ctx() R10=fp0
7: (61) r4 = *(u32 *)(r1 +0)          ; R1_w=map_value(map=prog.data,ks=4,vs=4) R4_w=scalar(smin=0,smax=umax=0xffffffff,var_off=(0x0; 0xffffffff))
14: (85) call bpf_dynptr_slice_rdwr#71568
R4 unbounded memory access, use 'var &= const' or 'if (var < const)'
invalid verifier frobnication
",
        &["-", "--format", "json", "--fail-on-unsupported"],
    );
    assert_eq!(
        unrelated_unbounded_error_after_dynptr_call.status.code(),
        Some(2)
    );
    assert!(unrelated_unbounded_error_after_dynptr_call
        .stderr
        .is_empty());
    let unrelated_unbounded_error_after_dynptr_call: Value =
        serde_json::from_slice(&unrelated_unbounded_error_after_dynptr_call.stdout)
            .expect("bpfix should emit JSON");
    assert_eq!(
        unrelated_unbounded_error_after_dynptr_call["diagnostic_kind"],
        "unsupported_verifier_message"
    );
    assert!(!evidence_contains(
        &unrelated_unbounded_error_after_dynptr_call,
        "verifier_state_signal",
        "R4 is still a scalar range"
    ));

    let unrelated_terminal_after_dynptr_detail = run_stdin_output(
        "\
func#0 @0
0: R10=fp0
1: (bf) r1 = r10                      ; R1_w=fp0 R10=fp0 fp-16_w=dynptr_ringbuf(id=1,dynptr_id=1)
2: (07) r1 += -8                      ; R1_w=fp-8
3: (85) call bpf_dynptr_data#203
cannot pass in dynptr at an offset=-8
invalid verifier frobnication
",
        &["-", "--format", "json", "--fail-on-unsupported"],
    );
    assert_eq!(
        unrelated_terminal_after_dynptr_detail.status.code(),
        Some(2)
    );
    assert!(unrelated_terminal_after_dynptr_detail.stderr.is_empty());
    let unrelated_terminal_after_dynptr_detail: Value =
        serde_json::from_slice(&unrelated_terminal_after_dynptr_detail.stdout)
            .expect("bpfix should emit JSON");
    assert_eq!(
        unrelated_terminal_after_dynptr_detail["diagnostic_kind"],
        "unsupported_verifier_message"
    );
    assert!(!evidence_contains(
        &unrelated_terminal_after_dynptr_detail,
        "verifier_state_signal",
        "interior dynptr pointer"
    ));

    let stale_interior_dynptr_pointer = run_stdin_output(
        "\
func#0 @0
0: R10=fp0
1: (85) call bpf_ringbuf_reserve_dynptr#198 ; R0_w=scalar() fp-16_w=dynptr_ringbuf(id=1,dynptr_id=1)
2: (7b) *(u64 *)(r10 -16) = r1        ; R1_w=0 R10=fp0 fp-16_w=0
3: (bf) r1 = r10                      ; R1_w=fp0 R10=fp0
4: (07) r1 += -15                     ; R1_w=fp-15
5: (85) call bpf_dynptr_data#203
invalid verifier frobnication
",
        &["-", "--format", "json", "--fail-on-unsupported"],
    );
    assert_eq!(stale_interior_dynptr_pointer.status.code(), Some(2));
    assert!(stale_interior_dynptr_pointer.stderr.is_empty());
    let stale_interior_dynptr_pointer: Value =
        serde_json::from_slice(&stale_interior_dynptr_pointer.stdout)
            .expect("bpfix should emit JSON");
    assert_eq!(
        stale_interior_dynptr_pointer["diagnostic_kind"],
        "unsupported_verifier_message"
    );
    assert!(!evidence_contains(
        &stale_interior_dynptr_pointer,
        "verifier_state_signal",
        "interior dynptr pointer"
    ));

    let unknown_terminal_uninitialized_dynptr = run_stdin_output(
        "\
func#0 @0
0: R10=fp0
1: R1=fp-16 R10=fp0 fp-16_w=0
2: (85) call bpf_dynptr_clone#71541
invalid verifier frobnication
",
        &["-", "--format", "json", "--fail-on-unsupported"],
    );
    assert_eq!(unknown_terminal_uninitialized_dynptr.status.code(), Some(2));
    let unknown_terminal_uninitialized_dynptr: Value =
        serde_json::from_slice(&unknown_terminal_uninitialized_dynptr.stdout)
            .expect("bpfix should emit JSON");
    assert_eq!(
        unknown_terminal_uninitialized_dynptr["diagnostic_kind"],
        "unsupported_verifier_message"
    );
    assert!(!evidence_contains(
        &unknown_terminal_uninitialized_dynptr,
        "verifier_state_signal",
        "not the current initialized dynptr object"
    ));

    let unknown_terminal_referenced_dynptr_overwrite = run_stdin_output(
        "\
func#0 @0
0: R10=fp0
1: (85) call bpf_ringbuf_reserve_dynptr#198 ; R0_w=scalar() fp-16_w=dynptr_ringbuf(id=1,ref_id=2,dynptr_id=1) refs=2
2: R1=0 R10=fp0
2: (7b) *(u64 *)(r10 -16) = r1
invalid verifier frobnication
",
        &["-", "--format", "json", "--fail-on-unsupported"],
    );
    assert_eq!(
        unknown_terminal_referenced_dynptr_overwrite.status.code(),
        Some(2)
    );
    let unknown_terminal_referenced_dynptr_overwrite: Value =
        serde_json::from_slice(&unknown_terminal_referenced_dynptr_overwrite.stdout)
            .expect("bpfix should emit JSON");
    assert_eq!(
        unknown_terminal_referenced_dynptr_overwrite["diagnostic_kind"],
        "unsupported_verifier_message"
    );
    assert!(!evidence_contains(
        &unknown_terminal_referenced_dynptr_overwrite,
        "verifier_state_signal",
        "dynptr reference is still live"
    ));

    let unknown_terminal_readonly_packet_dynptr_write = run_stdin_output(
        "\
func#0 @0
0: R10=fp0
1: (85) call bpf_dynptr_from_skb#71549 ; R0_w=scalar() fp-32_w=dynptr_skb(id=1,dynptr_id=1)
2: R1=fp-32 R4=14 R10=fp0
3: (85) call bpf_dynptr_slice_rdwr#71568
invalid verifier frobnication
",
        &["-", "--format", "json", "--fail-on-unsupported"],
    );
    assert_eq!(
        unknown_terminal_readonly_packet_dynptr_write.status.code(),
        Some(2)
    );
    let unknown_terminal_readonly_packet_dynptr_write: Value =
        serde_json::from_slice(&unknown_terminal_readonly_packet_dynptr_write.stdout)
            .expect("bpfix should emit JSON");
    assert_eq!(
        unknown_terminal_readonly_packet_dynptr_write["diagnostic_kind"],
        "unsupported_verifier_message"
    );
    assert!(!evidence_contains(
        &unknown_terminal_readonly_packet_dynptr_write,
        "verifier_state_signal",
        "packet-backed storage"
    ));

    let memory_backed_dynptr_write_terminal_does_not_claim_packet_backing = run_json_stdin(
        "func#0 @0\n\
         0: R4=fp-16 R10=fp0\n\
         1: (85) call bpf_dynptr_from_mem#197 ; R0_w=scalar() fp-16_w=dynptr_local(id=1,dynptr_id=1)\n\
         2: R1=fp-16 R4=8 R10=fp0\n\
         3: (85) call bpf_dynptr_slice_rdwr#71568\n\
         the prog does not allow writes to packet data\n",
    );
    assert_eq!(
        memory_backed_dynptr_write_terminal_does_not_claim_packet_backing["error_id"],
        "BPFIX-E012"
    );
    assert!(!evidence_contains(
        &memory_backed_dynptr_write_terminal_does_not_claim_packet_backing,
        "verifier_state_signal",
        "packet-backed storage"
    ));

    let read_write_slice_in_read_only_context =
        run_json("bpfix-bench/cases/kernel-selftest-dynptr-fail-invalid-slice-rdwr-rdonly-cgroup-skb-ingress-61688196/replay-verifier.log");
    assert_eq!(
        read_write_slice_in_read_only_context["error_id"],
        "BPFIX-E012"
    );
    assert_eq!(
        read_write_slice_in_read_only_context["next_action"],
        "environment"
    );
    assert!(read_write_slice_in_read_only_context["message"]
        .as_str()
        .unwrap()
        .contains("does not allow writes to packet data"));
    assert!(read_write_slice_in_read_only_context["required_proof"]
        .as_str()
        .unwrap()
        .contains("read-only dynptr packet access"));
    assert!(evidence_contains(
        &read_write_slice_in_read_only_context,
        "verifier_state_signal",
        "packet-backed storage"
    ));

    let generic_unacquired_reference = run_json_stdin(
        "0: (85) call bpf_obj_drop#108\n\
         arg 1 is an unacquired reference\n",
    );
    assert_ne!(generic_unacquired_reference["error_id"], "BPFIX-E012");
    assert_ne!(generic_unacquired_reference["error_id"], "BPFIX-E019");

    let dynptr_release_without_dynptr_state = run_json_stdin(
        "func#0 @0\n\
         0: R1=scalar() R10=fp0\n\
         1: (85) call bpf_ringbuf_discard_dynptr#200\n\
         arg 1 is an unacquired reference\n",
    );
    assert_eq!(
        dynptr_release_without_dynptr_state["error_id"],
        "BPFIX-E012"
    );
    assert!(!evidence_contains(
        &dynptr_release_without_dynptr_state,
        "verifier_state_signal",
        "without a live reference"
    ));

    let dynptr_release_with_same_offset_in_different_frame = run_json_stdin(
        "func#0 @0\n\
         func#1 @10\n\
         0: (85) call bpf_ringbuf_reserve_dynptr#198 ; R0_w=scalar() fp-16_w=dynptr_ringbuf(id=1,ref_id=2,dynptr_id=1) refs=2\n\
         10: frame1: R1=fp-16 R10=fp0 cb\n\
         11: (85) call bpf_ringbuf_discard_dynptr#200\n\
         arg 1 is an unacquired reference\n",
    );
    assert_eq!(
        dynptr_release_with_same_offset_in_different_frame["error_id"],
        "BPFIX-E012"
    );
    assert!(!evidence_contains(
        &dynptr_release_with_same_offset_in_different_frame,
        "verifier_state_signal",
        "without a live reference"
    ));

    let dynptr_release_without_current_frame_arg = run_json_stdin(
        "func#0 @0\n\
         func#1 @10\n\
         0: R1=fp-16 fp-16_w=dynptr_ringbuf(id=1,ref_id=2,dynptr_id=1) refs=2\n\
         10: frame1: R2=0 R10=fp0 cb\n\
         11: (85) call bpf_ringbuf_discard_dynptr#200\n\
         arg 1 is an unacquired reference\n",
    );
    assert_eq!(
        dynptr_release_without_current_frame_arg["error_id"],
        "BPFIX-E012"
    );
    assert!(!evidence_contains(
        &dynptr_release_without_current_frame_arg,
        "verifier_state_signal",
        "without a live reference"
    ));

    let raw_dynptr_storage_read =
        run_json("bpfix-bench/cases/kernel-selftest-dynptr-fail-invalid-read1-raw-tp-f61c0428/replay-verifier.log");
    assert_eq!(raw_dynptr_storage_read["error_id"], "BPFIX-E012");
    assert!(evidence_contains(
        &raw_dynptr_storage_read,
        "verifier_state_signal",
        "stack slot contains dynptr state"
    ));
    assert!(raw_dynptr_storage_read["required_proof"]
        .as_str()
        .unwrap()
        .contains("use dynptr helpers"));
    assert!(!raw_dynptr_storage_read["help"]
        .as_array()
        .unwrap()
        .iter()
        .any(|help| help.as_str().unwrap().contains("Initialize the full stack")));

    let dynptr_storage_passed_to_map =
        run_json("bpfix-bench/cases/kernel-selftest-dynptr-fail-add-dynptr-to-map1-raw-tp-2b5ac898/replay-verifier.log");
    assert_eq!(dynptr_storage_passed_to_map["error_id"], "BPFIX-E012");
    assert!(evidence_contains(
        &dynptr_storage_passed_to_map,
        "verifier_state_signal",
        "stack slot contains dynptr state"
    ));
    let dynptr_interior_read =
        run_json("bpfix-bench/cases/kernel-selftest-dynptr-fail-invalid-read3-raw-tp-99c4b958/replay-verifier.log");
    assert_eq!(dynptr_interior_read["error_id"], "BPFIX-E012");
    assert!(evidence_contains(
        &dynptr_interior_read,
        "verifier_state_signal",
        "stack slot contains dynptr state"
    ));
    let struct_copy_with_embedded_dynptr =
        run_json("bpfix-bench/cases/kernel-selftest-dynptr-fail-add-dynptr-to-map2-raw-tp-7a037daf/replay-verifier.log");
    assert_eq!(struct_copy_with_embedded_dynptr["error_id"], "BPFIX-E012");
    assert!(evidence_contains(
        &struct_copy_with_embedded_dynptr,
        "verifier_state_signal",
        "stack slot contains dynptr state"
    ));
    let embedded_dynptr_with_plain_prefix = run_json_stdin(
        "0: R10=fp0\n\
         1: (85) call bpf_ringbuf_reserve_dynptr#198 ; R0_w=scalar() fp-24_w=0 fp-16_w=dynptr_ringbuf(id=1,dynptr_id=1)\n\
         2: (85) call bpf_map_update_elem#2\n\
         invalid read from stack R3 off -24+0 size 24\n",
    );
    assert_eq!(embedded_dynptr_with_plain_prefix["error_id"], "BPFIX-E012");
    assert!(evidence_contains(
        &embedded_dynptr_with_plain_prefix,
        "verifier_state_signal",
        "stack slot contains dynptr state"
    ));

    let dynptr_slice_small_buffer =
        run_json("bpfix-bench/cases/kernel-selftest-dynptr-fail-test-dynptr-skb-small-buff-cgroup-skb-egress-4f498dbd/replay-verifier.log");
    assert_eq!(dynptr_slice_small_buffer["error_id"], "BPFIX-E003");
    assert!(!evidence_contains(
        &dynptr_slice_small_buffer,
        "verifier_state_signal",
        "stack slot contains dynptr state"
    ));
    let stale_dynptr_stack_state = run_json_stdin(
        "0: R10=fp0\n\
         1: (85) call bpf_ringbuf_reserve_dynptr#198 ; R0_w=scalar() fp-16_w=dynptr_ringbuf(id=1,dynptr_id=1)\n\
         2: (7b) *(u64 *)(r10 -16) = r1 ; R1_w=0 R10=fp0 fp-16_w=0\n\
         3: (61) r2 = *(u32 *)(r10 -16)\n\
         invalid read from stack off -16+0 size 4\n",
    );
    assert_eq!(stale_dynptr_stack_state["error_id"], "BPFIX-E003");
    assert!(!evidence_contains(
        &stale_dynptr_stack_state,
        "verifier_state_signal",
        "stack slot contains dynptr state"
    ));

    let unknown_terminal_dynptr_storage_read = run_stdin_output(
        "func#0 @0\n\
         0: R1=ctx() R10=fp0\n\
         5: (85) call bpf_ringbuf_reserve_dynptr#198 ; R0_w=scalar() fp-16_w=dynptr_ringbuf(id=1,dynptr_id=1)\n\
         6: R6=fp-16\n\
         6: (79) r1 = *(u64 *)(r6 +0)\n\
         invalid verifier frobnication\n",
        &["-", "--format", "json", "--fail-on-unsupported"],
    );
    assert!(unknown_terminal_dynptr_storage_read.status.success());
    assert!(unknown_terminal_dynptr_storage_read.stderr.is_empty());
    let unknown_terminal_dynptr_storage_read: Value =
        serde_json::from_slice(&unknown_terminal_dynptr_storage_read.stdout)
            .expect("bpfix should emit JSON");
    assert_eq!(
        unknown_terminal_dynptr_storage_read["error_id"],
        "BPFIX-E012"
    );
    assert_eq!(
        unknown_terminal_dynptr_storage_read["diagnostic_kind"],
        "supported"
    );
    assert!(evidence_contains(
        &unknown_terminal_dynptr_storage_read,
        "verifier_state_signal",
        "stack slot contains dynptr state"
    ));

    let unknown_terminal_dynptr_storage_store = run_stdin_output(
        "func#0 @0\n\
         0: R1=ctx() R10=fp0\n\
         5: (85) call bpf_ringbuf_reserve_dynptr#198 ; R0_w=scalar() fp-16_w=dynptr_ringbuf(id=1,dynptr_id=1)\n\
         6: R6=fp-16 R1=0\n\
         6: (7b) *(u64 *)(r6 +0) = r1\n\
         invalid verifier frobnication\n",
        &["-", "--format", "json", "--fail-on-unsupported"],
    );
    assert_eq!(unknown_terminal_dynptr_storage_store.status.code(), Some(2));
    assert!(unknown_terminal_dynptr_storage_store.stderr.is_empty());
    let unknown_terminal_dynptr_storage_store: Value =
        serde_json::from_slice(&unknown_terminal_dynptr_storage_store.stdout)
            .expect("bpfix should emit JSON");
    assert_eq!(
        unknown_terminal_dynptr_storage_store["diagnostic_kind"],
        "unsupported_verifier_message"
    );
    assert!(!evidence_contains(
        &unknown_terminal_dynptr_storage_store,
        "verifier_state_signal",
        "stack slot contains dynptr state"
    ));

    let write_terminal_dynptr_storage_store = run_json_stdin(
        "func#0 @0\n\
         0: R1=ctx() R10=fp0\n\
         5: (85) call bpf_ringbuf_reserve_dynptr#198 ; R0_w=scalar() fp-16_w=dynptr_ringbuf(id=1,dynptr_id=1)\n\
         6: R6=fp-16 R1=0\n\
         6: (7b) *(u64 *)(r6 +0) = r1\n\
         invalid write to stack off -16+0 size 8\n",
    );
    assert_ne!(
        write_terminal_dynptr_storage_store["error_id"],
        "BPFIX-E012"
    );
    assert!(!evidence_contains(
        &write_terminal_dynptr_storage_store,
        "verifier_state_signal",
        "stack slot contains dynptr state"
    ));

    let text =
        run_text("bpfix-bench/cases/kernel-selftest-dynptr-fail-release-twice-raw-tp-3722429d/replay-verifier.log");
    assert!(text.contains("release or submit each verifier-tracked dynptr reference exactly once"));
    assert!(text.contains("arg 1 is an unacquired reference"));
}

#[test]
fn iterator_state_storage_reports_protocol_violation() {
    let iterator_storage_read =
        run_json("bpfix-bench/cases/kernel-selftest-iters-state-safety-read-from-iter-slot-fail-raw-tp-812dc246/replay-verifier.log");
    assert_eq!(iterator_storage_read["error_id"], "BPFIX-E014");
    assert_eq!(iterator_storage_read["failure_class"], "source_bug");
    assert!(evidence_contains(
        &iterator_storage_read,
        "verifier_state_signal",
        "stack slot contains iterator state"
    ));
    assert!(iterator_storage_read["required_proof"]
        .as_str()
        .unwrap()
        .contains("iterator stack slot as opaque"));
    assert!(!iterator_storage_read["help"]
        .as_array()
        .unwrap()
        .iter()
        .any(|help| help.as_str().unwrap().contains("Initialize the full stack")));

    let iterator_double_create =
        run_json("bpfix-bench/cases/kernel-selftest-iters-state-safety-double-create-fail-raw-tp-11a53add/replay-verifier.log");
    assert_eq!(iterator_double_create["error_id"], "BPFIX-E014");
    assert!(evidence_contains(
        &iterator_double_create,
        "verifier_state_signal",
        "iterator helper receives an argument"
    ));
    assert!(iterator_double_create["required_proof"]
        .as_str()
        .unwrap()
        .contains("bpf_iter_* helpers"));

    let iterator_global_argument =
        run_json("bpfix-bench/cases/kernel-selftest-iters-iter-new-bad-arg-raw-tp-e25f0e76/replay-verifier.log");
    assert_eq!(iterator_global_argument["error_id"], "BPFIX-E014");
    assert!(evidence_contains(
        &iterator_global_argument,
        "verifier_state_signal",
        "iterator helper receives an argument"
    ));

    let iterator_slot_overwritten_by_helper =
        run_json("bpfix-bench/cases/kernel-selftest-iters-state-safety-compromise-iter-w-helper-write-fail-raw-tp-50431478/replay-verifier.log");
    assert_eq!(
        iterator_slot_overwritten_by_helper["error_id"],
        "BPFIX-E014"
    );
    assert!(evidence_contains(
        &iterator_slot_overwritten_by_helper,
        "verifier_state_signal",
        "iterator helper receives an argument"
    ));

    let iterator_double_destroy =
        run_json("bpfix-bench/cases/kernel-selftest-iters-state-safety-double-destroy-fail-raw-tp-224283ff/replay-verifier.log");
    assert_eq!(iterator_double_destroy["error_id"], "BPFIX-E014");
    assert!(evidence_contains(
        &iterator_double_destroy,
        "verifier_state_signal",
        "iterator helper receives an argument"
    ));

    let live_iterator_next_unknown_terminal = run_stdin_output(
        "func#0 @0\n\
         0: R1=ctx() R10=fp0\n\
         5: (85) call bpf_iter_num_new#71887 ; R0_w=scalar() fp-8_w=iter_num(ref_id=1,state=active,depth=0) refs=1\n\
         6: R1=fp-8 refs=1\n\
         7: (85) call bpf_iter_num_next#71886\n\
         invalid verifier frobnication\n",
        &["-", "--format", "json", "--fail-on-unsupported"],
    );
    assert_eq!(live_iterator_next_unknown_terminal.status.code(), Some(2));
    assert!(live_iterator_next_unknown_terminal.stderr.is_empty());
    let live_iterator_next_unknown_terminal: Value =
        serde_json::from_slice(&live_iterator_next_unknown_terminal.stdout)
            .expect("bpfix should emit JSON");
    assert_eq!(
        live_iterator_next_unknown_terminal["diagnostic_kind"],
        "unsupported_verifier_message"
    );
    assert!(!evidence_contains(
        &live_iterator_next_unknown_terminal,
        "verifier_state_signal",
        "iterator helper receives an argument"
    ));

    let consumed_iterator_next = run_json_stdin(
        "func#0 @0\n\
         0: R1=ctx() R10=fp0\n\
         5: (85) call bpf_iter_num_new#71887 ; R0_w=scalar() fp-8_w=iter_num(ref_id=1,state=active,depth=0) refs=1\n\
         6: R1=fp-8 refs=1\n\
         7: (85) call bpf_iter_num_destroy#71885\n\
         8: R1=fp-8\n\
         9: (85) call bpf_iter_num_next#71886\n\
         expected an initialized iter_num as arg #0\n",
    );
    assert_eq!(consumed_iterator_next["error_id"], "BPFIX-E014");
    assert!(evidence_contains(
        &consumed_iterator_next,
        "verifier_state_signal",
        "iterator helper receives an argument"
    ));

    let cross_frame_consumed_iterator = run_json_stdin(
        "func#0 @0\n\
         func#1 @10\n\
         0: (85) call bpf_iter_num_new#71887 ; R0_w=scalar() fp-8_w=iter_num(ref_id=1,state=active,depth=0) refs=1\n\
         1: R1=fp-8 refs=1\n\
         2: (85) call bpf_iter_num_destroy#71885\n\
         10: frame1: R1=fp[0]-8 R10=fp0 cb\n\
         11: (85) call bpf_iter_num_destroy#71885\n\
         expected an initialized iter_num as arg #0\n",
    );
    assert_eq!(cross_frame_consumed_iterator["error_id"], "BPFIX-E014");
    assert!(evidence_contains(
        &cross_frame_consumed_iterator,
        "verifier_state_signal",
        "iterator helper receives an argument"
    ));

    let unknown_terminal_iterator_storage_read = run_stdin_output(
        "func#0 @0\n\
         0: R1=ctx() R10=fp0\n\
         5: (85) call bpf_iter_num_new#71887 ; R0_w=scalar() fp-24_w=iter_num(ref_id=1,state=active,depth=0) refs=1\n\
         6: R6=fp-24\n\
         6: (79) r7 = *(u64 *)(r6 +0)\n\
         invalid verifier frobnication\n",
        &["-", "--format", "json", "--fail-on-unsupported"],
    );
    assert!(unknown_terminal_iterator_storage_read.status.success());
    assert!(unknown_terminal_iterator_storage_read.stderr.is_empty());
    let unknown_terminal_iterator_storage_read: Value =
        serde_json::from_slice(&unknown_terminal_iterator_storage_read.stdout)
            .expect("bpfix should emit JSON");
    assert_eq!(
        unknown_terminal_iterator_storage_read["error_id"],
        "BPFIX-E014"
    );
    assert_eq!(
        unknown_terminal_iterator_storage_read["diagnostic_kind"],
        "supported"
    );
    assert!(evidence_contains(
        &unknown_terminal_iterator_storage_read,
        "verifier_state_signal",
        "stack slot contains iterator state"
    ));

    let unknown_terminal_iterator_double_create = run_stdin_output(
        "func#0 @0\n\
         0: R1=ctx() R10=fp0\n\
         5: (85) call bpf_iter_num_new#71887 ; R0_w=scalar() fp-8_w=iter_num(ref_id=1,state=active,depth=0) refs=1\n\
         6: R6=fp-8 refs=1\n\
         7: R1=fp-8 refs=1\n\
         7: (85) call bpf_iter_num_new#71887\n\
         invalid verifier frobnication\n",
        &["-", "--format", "json", "--fail-on-unsupported"],
    );
    assert!(unknown_terminal_iterator_double_create.status.success());
    assert!(unknown_terminal_iterator_double_create.stderr.is_empty());
    let unknown_terminal_iterator_double_create: Value =
        serde_json::from_slice(&unknown_terminal_iterator_double_create.stdout)
            .expect("bpfix should emit JSON");
    assert_eq!(
        unknown_terminal_iterator_double_create["error_id"],
        "BPFIX-E014"
    );
    assert_eq!(
        unknown_terminal_iterator_double_create["diagnostic_kind"],
        "supported"
    );
    assert!(evidence_contains(
        &unknown_terminal_iterator_double_create,
        "verifier_state_signal",
        "iterator helper receives an argument"
    ));

    let unknown_terminal_iterator_new_on_initialized_slot = run_stdin_output(
        "func#0 @0\n\
         0: R1=ctx() R10=fp0\n\
         5: R1=fp-8 fp-8_w=0\n\
         5: (85) call bpf_iter_num_new#71887\n\
         invalid verifier frobnication\n",
        &["-", "--format", "json", "--fail-on-unsupported"],
    );
    assert!(unknown_terminal_iterator_new_on_initialized_slot
        .status
        .success());
    assert!(unknown_terminal_iterator_new_on_initialized_slot
        .stderr
        .is_empty());
    let unknown_terminal_iterator_new_on_initialized_slot: Value =
        serde_json::from_slice(&unknown_terminal_iterator_new_on_initialized_slot.stdout)
            .expect("bpfix should emit JSON");
    assert_eq!(
        unknown_terminal_iterator_new_on_initialized_slot["error_id"],
        "BPFIX-E014"
    );
    assert!(evidence_contains(
        &unknown_terminal_iterator_new_on_initialized_slot,
        "verifier_state_signal",
        "iterator helper receives an argument"
    ));

    let ordinary_iterator_new_unknown_terminal = run_stdin_output(
        "func#0 @0\n\
         0: R1=ctx() R10=fp0\n\
         5: R1=fp-8\n\
         5: (85) call bpf_iter_num_new#71887\n\
         invalid verifier frobnication\n",
        &["-", "--format", "json", "--fail-on-unsupported"],
    );
    assert_eq!(
        ordinary_iterator_new_unknown_terminal.status.code(),
        Some(2)
    );
    assert!(ordinary_iterator_new_unknown_terminal.stderr.is_empty());
    let ordinary_iterator_new_unknown_terminal: Value =
        serde_json::from_slice(&ordinary_iterator_new_unknown_terminal.stdout)
            .expect("bpfix should emit JSON");
    assert_eq!(
        ordinary_iterator_new_unknown_terminal["diagnostic_kind"],
        "unsupported_verifier_message"
    );
    assert!(!evidence_contains(
        &ordinary_iterator_new_unknown_terminal,
        "verifier_state_signal",
        "iterator helper receives an argument"
    ));

    let consumed_iterator_destroy_unknown_terminal = run_stdin_output(
        "func#0 @0\n\
         0: R1=ctx() R10=fp0\n\
         5: (85) call bpf_iter_num_new#71887 ; R0_w=scalar() fp-8_w=iter_num(ref_id=1,state=active,depth=0) refs=1\n\
         6: R1=fp-8 refs=1\n\
         7: (85) call bpf_iter_num_destroy#71885\n\
         8: R1=fp-8\n\
         9: (85) call bpf_iter_num_destroy#71885\n\
         invalid verifier frobnication\n",
        &["-", "--format", "json", "--fail-on-unsupported"],
    );
    assert_eq!(
        consumed_iterator_destroy_unknown_terminal.status.code(),
        Some(2)
    );
    assert!(consumed_iterator_destroy_unknown_terminal.stderr.is_empty());
    let consumed_iterator_destroy_unknown_terminal: Value =
        serde_json::from_slice(&consumed_iterator_destroy_unknown_terminal.stdout)
            .expect("bpfix should emit JSON");
    assert_eq!(
        consumed_iterator_destroy_unknown_terminal["diagnostic_kind"],
        "unsupported_verifier_message"
    );
    assert!(!evidence_contains(
        &consumed_iterator_destroy_unknown_terminal,
        "verifier_state_signal",
        "iterator helper receives an argument"
    ));

    let stale_prior_fragment_iterator_state = run_stdin_output(
        "func#0 @0\n\
         0: R1=ctx() R10=fp0\n\
         5: (85) call bpf_iter_num_new#71887 ; R0_w=scalar() fp-8_w=iter_num(ref_id=1,state=active,depth=0) refs=1\n\
         processed 6 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0\n\
         func#1 @0\n\
         0: R1=ctx() R10=fp0\n\
         5: R1=fp-8\n\
         5: (85) call bpf_iter_num_new#71887\n\
         invalid verifier frobnication\n",
        &["-", "--format", "json", "--fail-on-unsupported"],
    );
    assert_eq!(stale_prior_fragment_iterator_state.status.code(), Some(2));
    assert!(stale_prior_fragment_iterator_state.stderr.is_empty());
    let stale_prior_fragment_iterator_state: Value =
        serde_json::from_slice(&stale_prior_fragment_iterator_state.stdout)
            .expect("bpfix should emit JSON");
    assert_eq!(
        stale_prior_fragment_iterator_state["diagnostic_kind"],
        "unsupported_verifier_message"
    );
    assert!(!evidence_contains(
        &stale_prior_fragment_iterator_state,
        "verifier_state_signal",
        "iterator helper receives an argument"
    ));

    let stale_prior_fragment_ordinary_slot = run_stdin_output(
        "func#0 @0\n\
         0: R1=ctx() R10=fp0\n\
         5: R1=fp-8 fp-8_w=0\n\
         processed 6 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0\n\
         func#1 @0\n\
         0: R1=ctx() R10=fp0\n\
         5: R1=fp-8\n\
         5: (85) call bpf_iter_num_destroy#71885\n\
         invalid verifier frobnication\n",
        &["-", "--format", "json", "--fail-on-unsupported"],
    );
    assert_eq!(stale_prior_fragment_ordinary_slot.status.code(), Some(2));
    assert!(stale_prior_fragment_ordinary_slot.stderr.is_empty());
    let stale_prior_fragment_ordinary_slot: Value =
        serde_json::from_slice(&stale_prior_fragment_ordinary_slot.stdout)
            .expect("bpfix should emit JSON");
    assert_eq!(
        stale_prior_fragment_ordinary_slot["diagnostic_kind"],
        "unsupported_verifier_message"
    );
    assert!(!evidence_contains(
        &stale_prior_fragment_ordinary_slot,
        "verifier_state_signal",
        "iterator helper receives an argument"
    ));

    let ordinary_stack_read_unknown_terminal = run_stdin_output(
        "func#0 @0\n\
         0: R1=ctx() R10=fp0\n\
         5: R6=fp-24 fp-24_w=0\n\
         6: (79) r7 = *(u64 *)(r6 +0)\n\
         invalid verifier frobnication\n",
        &["-", "--format", "json", "--fail-on-unsupported"],
    );
    assert_eq!(ordinary_stack_read_unknown_terminal.status.code(), Some(2));
    assert!(ordinary_stack_read_unknown_terminal.stderr.is_empty());
    let ordinary_stack_read_unknown_terminal: Value =
        serde_json::from_slice(&ordinary_stack_read_unknown_terminal.stdout)
            .expect("bpfix should emit JSON");
    assert_eq!(
        ordinary_stack_read_unknown_terminal["diagnostic_kind"],
        "unsupported_verifier_message"
    );
    assert!(!evidence_contains(
        &ordinary_stack_read_unknown_terminal,
        "verifier_state_signal",
        "stack slot contains iterator state"
    ));

    let iterator_storage_store_unknown_terminal = run_stdin_output(
        "func#0 @0\n\
         0: R1=ctx() R10=fp0\n\
         5: (85) call bpf_iter_num_new#71887 ; R0_w=scalar() fp-24_w=iter_num(ref_id=1,state=active,depth=0) refs=1\n\
         6: R6=fp-24 R1=0\n\
         6: (7b) *(u64 *)(r6 +0) = r1\n\
         invalid verifier frobnication\n",
        &["-", "--format", "json", "--fail-on-unsupported"],
    );
    assert_eq!(
        iterator_storage_store_unknown_terminal.status.code(),
        Some(2)
    );
    assert!(iterator_storage_store_unknown_terminal.stderr.is_empty());
    let iterator_storage_store_unknown_terminal: Value =
        serde_json::from_slice(&iterator_storage_store_unknown_terminal.stdout)
            .expect("bpfix should emit JSON");
    assert_eq!(
        iterator_storage_store_unknown_terminal["diagnostic_kind"],
        "unsupported_verifier_message"
    );
    assert!(!evidence_contains(
        &iterator_storage_store_unknown_terminal,
        "verifier_state_signal",
        "stack slot contains iterator state"
    ));

    let iterator_storage_store_write_terminal = run_json_stdin(
        "func#0 @0\n\
         0: R1=ctx() R10=fp0\n\
         5: (85) call bpf_iter_num_new#71887 ; R0_w=scalar() fp-24_w=iter_num(ref_id=1,state=active,depth=0) refs=1\n\
         6: R6=fp-24 R1=0\n\
         6: (7b) *(u64 *)(r6 +0) = r1\n\
         invalid write to stack off -24+0 size 8\n",
    );
    assert_ne!(
        iterator_storage_store_write_terminal["error_id"],
        "BPFIX-E014"
    );
    assert!(!evidence_contains(
        &iterator_storage_store_write_terminal,
        "verifier_state_signal",
        "stack slot contains iterator state"
    ));
}

#[test]
fn irq_flag_state_reports_protocol_violation() {
    for path in [
        "bpfix-bench/cases/kernel-selftest-irq-irq-save-invalid-tc-86a07a3f/replay-verifier.log",
        "bpfix-bench/cases/kernel-selftest-irq-irq-restore-invalid-tc-e1f743bf/replay-verifier.log",
        "bpfix-bench/cases/kernel-selftest-irq-irq-flag-overwrite-tc-4c974993/replay-verifier.log",
    ] {
        let diagnostic = run_json(path);
        assert_eq!(diagnostic["error_id"], "BPFIX-E020");
        assert_eq!(diagnostic["failure_class"], "source_bug");
        assert!(evidence_contains(
            &diagnostic,
            "verifier_state_signal",
            "IRQ helper receives a stack slot"
        ));
        assert!(diagnostic["required_proof"]
            .as_str()
            .unwrap()
            .contains("bpf_local_irq_save"));
        assert!(!diagnostic["help"]
            .as_array()
            .unwrap()
            .iter()
            .any(|help| help.as_str().unwrap().contains("Initialize the full stack")));
    }

    for path in [
        "bpfix-bench/cases/kernel-selftest-irq-irq-restore-ooo-tc-84ede29d/replay-verifier.log",
        "bpfix-bench/cases/kernel-selftest-irq-irq-restore-ooo-3-tc-e0b5e5ee/replay-verifier.log",
        "bpfix-bench/cases/kernel-selftest-irq-irq-restore-ooo-3-subprog-tc-b32ae1a0/replay-verifier.log",
        "bpfix-bench/cases/kernel-selftest-irq-irq-restore-4-subprog-tc-f3feb6a1/replay-verifier.log",
        "bpfix-bench/cases/kernel-selftest-irq-irq-ooo-refs-array-tc-193001a6/replay-verifier.log",
        "bpfix-bench/cases/kernel-selftest-irq-irq-ooo-lock-cond-inv-tc-950f35d5/replay-verifier.log",
    ] {
        let diagnostic = run_json(path);
        assert_eq!(diagnostic["error_id"], "BPFIX-E013");
        assert_eq!(diagnostic["failure_class"], "source_bug");
        assert!(evidence_contains(
            &diagnostic,
            "verifier_state_signal",
            "newer outstanding IRQ state"
        ));
        assert!(diagnostic["required_proof"]
            .as_str()
            .unwrap()
            .contains("strict LIFO order"));
        assert!(!diagnostic["help"]
            .as_array()
            .unwrap()
            .iter()
            .any(|help| help.as_str().unwrap().contains("Release acquired references")));
    }

    let wrong_restore_helper_class =
        run_json("bpfix-bench/cases/kernel-selftest-irq-irq-wrong-kfunc-class-2-tc-03b53958/replay-verifier.log");
    assert_eq!(wrong_restore_helper_class["error_id"], "BPFIX-E013");
    assert_eq!(wrong_restore_helper_class["failure_class"], "source_bug");
    assert!(evidence_contains(
        &wrong_restore_helper_class,
        "verifier_state_signal",
        "restore helper whose class"
    ));
    assert!(wrong_restore_helper_class["required_proof"]
        .as_str()
        .unwrap()
        .contains("helper class"));
    assert!(wrong_restore_helper_class["help"]
        .as_array()
        .unwrap()
        .iter()
        .any(|help| help
            .as_str()
            .unwrap()
            .contains("bpf_res_spin_unlock_irqrestore")));
    assert!(!wrong_restore_helper_class["help"]
        .as_array()
        .unwrap()
        .iter()
        .any(|help| help
            .as_str()
            .unwrap()
            .contains("release operations balanced")));

    for path in [
        "bpfix-bench/cases/kernel-selftest-irq-irq-restore-missing-3-subprog-tc-8592c5d7/replay-verifier.log",
        "bpfix-bench/cases/kernel-selftest-irq-irq-restore-missing-3-minus-2-subprog-tc-5c202e26/replay-verifier.log",
    ] {
        let diagnostic = run_json(path);
        assert_eq!(diagnostic["error_id"], "BPFIX-E013");
        assert_eq!(diagnostic["failure_class"], "source_bug");
        assert!(evidence_contains(
            &diagnostic,
            "verifier_state_signal",
            "BPF_EXIT with live IRQ save references"
        ));
        assert!(diagnostic["required_proof"]
            .as_str()
            .unwrap()
            .contains("before any BPF_EXIT"));
        assert!(!diagnostic["help"]
            .as_array()
            .unwrap()
            .iter()
            .any(|help| help.as_str().unwrap().contains("release operations balanced")));
    }

    let unknown_terminal_irq_double_save = run_stdin_output(
        "func#0 @0\n\
         0: R1=ctx() R10=fp0\n\
         3: (85) call bpf_local_irq_save#72094 ; fp-8_w=ffffffff refs=1\n\
         4: R1=fp-8 refs=1\n\
         4: (85) call bpf_local_irq_save#72094\n\
         invalid verifier frobnication\n",
        &["-", "--format", "json", "--fail-on-unsupported"],
    );
    assert!(unknown_terminal_irq_double_save.status.success());
    assert!(unknown_terminal_irq_double_save.stderr.is_empty());
    let unknown_terminal_irq_double_save: Value =
        serde_json::from_slice(&unknown_terminal_irq_double_save.stdout)
            .expect("bpfix should emit JSON");
    assert_eq!(unknown_terminal_irq_double_save["error_id"], "BPFIX-E020");
    assert_eq!(
        unknown_terminal_irq_double_save["diagnostic_kind"],
        "supported"
    );
    assert!(evidence_contains(
        &unknown_terminal_irq_double_save,
        "verifier_state_signal",
        "IRQ helper receives a stack slot"
    ));

    let unknown_terminal_irq_restore_wrong_slot = run_stdin_output(
        "func#0 @0\n\
         0: R1=ctx() R10=fp0\n\
         3: R1=fp-8 fp-8_w=0 refs=1\n\
         3: (85) call bpf_local_irq_restore#72093\n\
         invalid verifier frobnication\n",
        &["-", "--format", "json", "--fail-on-unsupported"],
    );
    assert!(unknown_terminal_irq_restore_wrong_slot.status.success());
    assert!(unknown_terminal_irq_restore_wrong_slot.stderr.is_empty());
    let unknown_terminal_irq_restore_wrong_slot: Value =
        serde_json::from_slice(&unknown_terminal_irq_restore_wrong_slot.stdout)
            .expect("bpfix should emit JSON");
    assert_eq!(
        unknown_terminal_irq_restore_wrong_slot["error_id"],
        "BPFIX-E020"
    );
    assert!(evidence_contains(
        &unknown_terminal_irq_restore_wrong_slot,
        "verifier_state_signal",
        "IRQ helper receives a stack slot"
    ));

    let unknown_terminal_irq_restore_scalar_hex_slot = run_stdin_output(
        "func#0 @0\n\
         0: R1=ctx() R10=fp0\n\
         3: R1=fp-8 fp-8_w=0xffffffff refs=1\n\
         3: (85) call bpf_local_irq_restore#72093\n\
         invalid verifier frobnication\n",
        &["-", "--format", "json", "--fail-on-unsupported"],
    );
    assert!(unknown_terminal_irq_restore_scalar_hex_slot
        .status
        .success());
    assert!(unknown_terminal_irq_restore_scalar_hex_slot
        .stderr
        .is_empty());
    let unknown_terminal_irq_restore_scalar_hex_slot: Value =
        serde_json::from_slice(&unknown_terminal_irq_restore_scalar_hex_slot.stdout)
            .expect("bpfix should emit JSON");
    assert_eq!(
        unknown_terminal_irq_restore_scalar_hex_slot["error_id"],
        "BPFIX-E020"
    );
    assert!(evidence_contains(
        &unknown_terminal_irq_restore_scalar_hex_slot,
        "verifier_state_signal",
        "IRQ helper receives a stack slot"
    ));

    let unknown_terminal_irq_restore_interior_pointer = run_stdin_output(
        "func#0 @0\n\
         0: R1=ctx() R10=fp0\n\
         3: R1=fp-4 fp-8_w=ffffffff refs=1\n\
         3: (85) call bpf_local_irq_restore#72093\n\
         invalid verifier frobnication\n",
        &["-", "--format", "json", "--fail-on-unsupported"],
    );
    assert!(unknown_terminal_irq_restore_interior_pointer
        .status
        .success());
    assert!(unknown_terminal_irq_restore_interior_pointer
        .stderr
        .is_empty());
    let unknown_terminal_irq_restore_interior_pointer: Value =
        serde_json::from_slice(&unknown_terminal_irq_restore_interior_pointer.stdout)
            .expect("bpfix should emit JSON");
    assert_eq!(
        unknown_terminal_irq_restore_interior_pointer["error_id"],
        "BPFIX-E020"
    );
    assert!(evidence_contains(
        &unknown_terminal_irq_restore_interior_pointer,
        "verifier_state_signal",
        "IRQ helper receives a stack slot"
    ));

    let unknown_terminal_irq_restore_live_slot = run_stdin_output(
        "func#0 @0\n\
         0: R1=ctx() R10=fp0\n\
         3: R1=fp-8 fp-8_w=ffffffff refs=1\n\
         3: (85) call bpf_local_irq_restore#72093\n\
         invalid verifier frobnication\n",
        &["-", "--format", "json", "--fail-on-unsupported"],
    );
    assert_eq!(
        unknown_terminal_irq_restore_live_slot.status.code(),
        Some(2)
    );
    assert!(unknown_terminal_irq_restore_live_slot.stderr.is_empty());
    let unknown_terminal_irq_restore_live_slot: Value =
        serde_json::from_slice(&unknown_terminal_irq_restore_live_slot.stdout)
            .expect("bpfix should emit JSON");
    assert_eq!(
        unknown_terminal_irq_restore_live_slot["diagnostic_kind"],
        "unsupported_verifier_message"
    );
    assert!(!evidence_contains(
        &unknown_terminal_irq_restore_live_slot,
        "verifier_state_signal",
        "IRQ helper receives a stack slot"
    ));

    let stale_prior_fragment_irq_slot = run_stdin_output(
        "func#0 @0\n\
         0: R1=ctx() R10=fp0\n\
         3: (85) call bpf_local_irq_save#72094 ; fp-8_w=ffffffff refs=1\n\
         processed 4 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0\n\
         func#1 @0\n\
         0: R1=ctx() R10=fp0\n\
         3: R1=fp-8\n\
         3: (85) call bpf_local_irq_save#72094\n\
         invalid verifier frobnication\n",
        &["-", "--format", "json", "--fail-on-unsupported"],
    );
    assert_eq!(stale_prior_fragment_irq_slot.status.code(), Some(2));
    assert!(stale_prior_fragment_irq_slot.stderr.is_empty());
    let stale_prior_fragment_irq_slot: Value =
        serde_json::from_slice(&stale_prior_fragment_irq_slot.stdout)
            .expect("bpfix should emit JSON");
    assert_eq!(
        stale_prior_fragment_irq_slot["diagnostic_kind"],
        "unsupported_verifier_message"
    );
    assert!(!evidence_contains(
        &stale_prior_fragment_irq_slot,
        "verifier_state_signal",
        "IRQ helper receives a stack slot"
    ));

    let out_of_order_without_live_ref_state = run_json_stdin(
        "func#0 @0\n\
         0: R1=fp-8 fp-8_w=ffffffff\n\
         1: (85) call bpf_local_irq_restore#72093\n\
         cannot restore irq state out of order, expected id=2 acquired at insn_idx=0\n",
    );
    assert_eq!(
        out_of_order_without_live_ref_state["error_id"],
        "BPFIX-E013"
    );
    assert!(!evidence_contains(
        &out_of_order_without_live_ref_state,
        "verifier_state_signal",
        "newer outstanding IRQ state"
    ));

    let out_of_order_without_live_flag_slot = run_json_stdin(
        "func#0 @0\n\
         0: (85) call bpf_local_irq_save#72094 ; refs=1,2\n\
         1: R1=fp-8 fp-8_w=0 refs=1,2\n\
         2: (85) call bpf_local_irq_restore#72093\n\
         cannot restore irq state out of order, expected id=2 acquired at insn_idx=0\n",
    );
    assert_eq!(
        out_of_order_without_live_flag_slot["error_id"],
        "BPFIX-E013"
    );
    assert!(!evidence_contains(
        &out_of_order_without_live_flag_slot,
        "verifier_state_signal",
        "newer outstanding IRQ state"
    ));

    let helper_class_without_live_refs = run_json_stdin(
        "func#0 @0\n\
         0: R1=fp-16\n\
         1: (85) call bpf_local_irq_restore#72093\n\
         function calls are not allowed while holding a lock\n",
    );
    assert_eq!(helper_class_without_live_refs["error_id"], "BPFIX-E015");
    assert!(!evidence_contains(
        &helper_class_without_live_refs,
        "verifier_state_signal",
        "restore helper whose class"
    ));

    let helper_class_latest_state_clears_refs = run_json_stdin(
        "func#0 @0\n\
         0: (85) call bpf_res_spin_lock_irqsave#73032 ; fp-16_w=ffffffff refs=1\n\
         1: R1=fp-16\n\
         2: (85) call bpf_local_irq_restore#72093\n\
         function calls are not allowed while holding a lock\n",
    );
    assert_eq!(
        helper_class_latest_state_clears_refs["error_id"],
        "BPFIX-E015"
    );
    assert!(!evidence_contains(
        &helper_class_latest_state_clears_refs,
        "verifier_state_signal",
        "restore helper whose class"
    ));

    let helper_class_cross_frame_origin = run_json_stdin(
        "func#0 @0\n\
         func#1 @10\n\
         10: frame1: R2=fp[0]-16 R10=fp0\n\
         10: (85) call bpf_res_spin_lock_irqsave#73032 ; frame1: refs=1\n\
         1: R10=fp0 fp-16_w=ffffffff refs=1\n\
         2: R1=fp-16 refs=1\n\
         3: (85) call bpf_local_irq_restore#72093\n\
         function calls are not allowed while holding a lock\n",
    );
    assert_eq!(helper_class_cross_frame_origin["error_id"], "BPFIX-E013");
    assert!(evidence_contains(
        &helper_class_cross_frame_origin,
        "verifier_state_signal",
        "restore helper whose class"
    ));

    let helper_class_matching_local_restore = run_json_stdin(
        "func#0 @0\n\
         0: (85) call bpf_local_irq_save#72094 ; fp-8_w=ffffffff refs=1\n\
         1: R1=fp-8 refs=1\n\
         2: (85) call bpf_local_irq_restore#72093\n\
         function calls are not allowed while holding a lock\n",
    );
    assert_eq!(
        helper_class_matching_local_restore["error_id"],
        "BPFIX-E015"
    );
    assert!(!evidence_contains(
        &helper_class_matching_local_restore,
        "verifier_state_signal",
        "restore helper whose class"
    ));

    let helper_class_prefers_nearest_origin = run_json_stdin(
        "func#0 @0\n\
         0: (85) call bpf_res_spin_lock_irqsave#73032 ; fp-8_w=ffffffff refs=1\n\
         1: (85) call bpf_local_irq_save#72094 ; fp-8_w=ffffffff refs=1\n\
         2: R1=fp-8 refs=1\n\
         3: (85) call bpf_local_irq_restore#72093\n\
         function calls are not allowed while holding a lock\n",
    );
    assert_eq!(
        helper_class_prefers_nearest_origin["error_id"],
        "BPFIX-E015"
    );
    assert!(!evidence_contains(
        &helper_class_prefers_nearest_origin,
        "verifier_state_signal",
        "restore helper whose class"
    ));

    let helper_class_newest_lock_but_other_slot = run_json_stdin(
        "func#0 @0\n\
         0: (85) call bpf_local_irq_save#72094 ; fp-8_w=ffffffff refs=1\n\
         1: (85) call bpf_res_spin_lock_irqsave#73032 ; fp-16_w=ffffffff refs=1,2\n\
         2: R1=fp-8 refs=1,2\n\
         3: (85) call bpf_local_irq_restore#72093\n\
         function calls are not allowed while holding a lock\n",
    );
    assert_eq!(
        helper_class_newest_lock_but_other_slot["error_id"],
        "BPFIX-E015"
    );
    assert!(!evidence_contains(
        &helper_class_newest_lock_but_other_slot,
        "verifier_state_signal",
        "restore helper whose class"
    ));

    let exit_with_irq_terminal_without_live_refs = run_json_stdin(
        "func#0 @0\n\
         0: (85) call bpf_local_irq_save#72094\n\
         1: (95) exit\n\
         BPF_EXIT instruction in main prog cannot be used inside bpf_local_irq_save-ed region\n",
    );
    assert_eq!(
        exit_with_irq_terminal_without_live_refs["error_id"],
        "BPFIX-E015"
    );
    assert!(!evidence_contains(
        &exit_with_irq_terminal_without_live_refs,
        "verifier_state_signal",
        "BPF_EXIT with live IRQ save references"
    ));

    let exit_with_live_refs_without_prior_irq_save = run_json_stdin(
        "func#0 @0\n\
         0: R1=ctx() R10=fp0 refs=1\n\
         1: (95) exit\n\
         BPF_EXIT instruction in main prog cannot be used inside bpf_local_irq_save-ed region\n",
    );
    assert_eq!(
        exit_with_live_refs_without_prior_irq_save["error_id"],
        "BPFIX-E015"
    );
    assert!(!evidence_contains(
        &exit_with_live_refs_without_prior_irq_save,
        "verifier_state_signal",
        "BPF_EXIT with live IRQ save references"
    ));

    let exit_after_latest_state_clears_refs = run_json_stdin(
        "func#0 @0\n\
         0: (85) call bpf_local_irq_save#72094 ; refs=1\n\
         1: R0=0\n\
         2: (95) exit\n\
         BPF_EXIT instruction in main prog cannot be used inside bpf_local_irq_save-ed region\n",
    );
    assert_eq!(
        exit_after_latest_state_clears_refs["error_id"],
        "BPFIX-E015"
    );
    assert!(!evidence_contains(
        &exit_after_latest_state_clears_refs,
        "verifier_state_signal",
        "BPF_EXIT with live IRQ save references"
    ));

    let stale_prior_fragment_irq_save = run_json_stdin(
        "func#0 @0\n\
         0: (85) call bpf_local_irq_save#72094 ; refs=1\n\
         processed 1 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0\n\
         func#1 @0\n\
         0: R0=0 refs=1\n\
         1: (95) exit\n\
         BPF_EXIT instruction in main prog cannot be used inside bpf_local_irq_save-ed region\n",
    );
    assert_eq!(stale_prior_fragment_irq_save["error_id"], "BPFIX-E015");
    assert!(!evidence_contains(
        &stale_prior_fragment_irq_save,
        "verifier_state_signal",
        "BPF_EXIT with live IRQ save references"
    ));

    let same_pc_empty_state_overrides_stale_refs = run_json_stdin(
        "func#0 @0\n\
         0: (85) call bpf_local_irq_save#72094 ; refs=1\n\
         0: R0=0\n\
         1: (95) exit\n\
         BPF_EXIT instruction in main prog cannot be used inside bpf_local_irq_save-ed region\n",
    );
    assert_eq!(
        same_pc_empty_state_overrides_stale_refs["error_id"],
        "BPFIX-E015"
    );
    assert!(!evidence_contains(
        &same_pc_empty_state_overrides_stale_refs,
        "verifier_state_signal",
        "BPF_EXIT with live IRQ save references"
    ));
}

#[test]
fn sleepable_calls_report_non_sleepable_context() {
    for path in [
        "bpfix-bench/cases/kernel-selftest-irq-irq-sleepable-global-subprog-indirect-syscall-c96d09ca/replay-verifier.log",
        "bpfix-bench/cases/kernel-selftest-irq-irq-sleepable-helper-global-subprog-syscall-7d470f89/replay-verifier.log",
    ] {
        let diagnostic = run_json(path);
        assert_eq!(diagnostic["error_id"], "BPFIX-E016");
        assert_eq!(diagnostic["failure_class"], "source_bug");
        assert!(diagnostic["message"]
            .as_str()
            .unwrap()
            .contains("global functions that may sleep are not allowed"));
        assert!(evidence_contains(
            &diagnostic,
            "verifier_state_signal",
            "sleepable helper or subprogram call"
        ));
        assert!(diagnostic["required_proof"]
            .as_str()
            .unwrap()
            .contains("non-sleepable IRQ"));
    }

    let no_prior_non_sleepable_state = run_stdin_output(
        "func#0 @0\n\
         0: R1=ctx() R10=fp0\n\
         5: (85) call pc+4\n\
         global functions that may sleep are not allowed in non-sleepable context,\n\
         i.e., in a RCU/IRQ/preempt-disabled section, or in\n\
         a non-sleepable BPF program context\n",
        &["-", "--format", "json", "--fail-on-unsupported"],
    );
    assert!(no_prior_non_sleepable_state.status.success());
    assert!(no_prior_non_sleepable_state.stderr.is_empty());
    let no_prior_non_sleepable_state: Value =
        serde_json::from_slice(&no_prior_non_sleepable_state.stdout)
            .expect("bpfix should emit JSON");
    assert_ne!(no_prior_non_sleepable_state["error_id"], "BPFIX-E016");
    assert!(!evidence_contains(
        &no_prior_non_sleepable_state,
        "verifier_state_signal",
        "sleepable helper or subprogram call"
    ));

    let adjacent_independent_error = run_json_stdin(
        "func#0 @0\n\
         0: R1=ctx() R10=fp0\n\
         1: (85) call bpf_local_irq_save#72094\n\
         2: (85) call pc+4\n\
         global functions that may sleep are not allowed in non-sleepable context,\n\
         BPF_EXIT instruction in main prog cannot be used inside bpf_local_irq_save-ed region\n",
    );
    assert_eq!(adjacent_independent_error["error_id"], "BPFIX-E015");
    assert!(adjacent_independent_error["message"]
        .as_str()
        .unwrap()
        .contains("BPF_EXIT instruction"));
    assert!(!evidence_contains(
        &adjacent_independent_error,
        "verifier_state_signal",
        "sleepable helper or subprogram call"
    ));
}

#[test]
fn text_output_is_rust_style_multispan() {
    let text = run_text("bpfix-bench/cases/stackoverflow-53136145/replay-verifier.log");
    assert!(text.contains(
        "error[BPFIX-E006]: verifier-visible compiler lowering hides the required proof"
    ));
    assert!(text.contains("= class: lowering_artifact"));
    assert!(text.contains("= next action: provenance"));
    assert!(text.contains("--> prog.c:270"));
    assert!(text.contains("263 | if (ipv4_hdr)"));
    assert!(text.contains("267 | if (udph + sizeof(struct udphdr) > data_end)"));
    assert!(text.contains("270 | dst_port = __constant_ntohs(((struct udphdr *)udph)->dest);"));
    assert!(text.contains("nearby source context for pointer provenance"));
    assert!(text.contains("verifier state changes from pkt to scalar"));
    assert!(text.contains(
        "   = note[lowering]: compiler-lowered control flow hides an established packet-pointer proof"
    ));
    assert!(!text.contains("proof can be lost when branch-specific pointers are merged"));
    assert!(!text.contains("proof established by a verifier-visible bounds check"));
    assert!(text.contains("help: Preserve pointer provenance across the failing path"));
}

#[test]
fn text_output_explains_verifier_precision_triage() {
    let text = run_text("bpfix-bench/cases/stackoverflow-77762365/replay-verifier.log");

    assert!(text.contains("error[BPFIX-E005]: verifier precision limit may hide"));
    assert!(text.contains("= class: verifier_false_positive"));
    assert!(text.contains("help: triage_only"));
    assert!(text
        .contains("   = note[verifier-precision]: source-level map-value bounds guard is present"));
    assert!(text
        .contains("help: Make the remaining map-value capacity explicit in one bounded variable"));
}

#[test]
fn format_both_emits_text_then_parseable_json() {
    let path =
        workspace_root().join("bpfix-bench/cases/stackoverflow-53136145/replay-verifier.log");
    let output = run_with_args(&[path.to_str().unwrap(), "--format", "both"]);
    let stdout = String::from_utf8(output.stdout).expect("bpfix should emit UTF-8");
    let json_start = stdout
        .rfind("\n{\n")
        .expect("JSON object should follow text output")
        + 1;
    let (text, json_text) = stdout.split_at(json_start);
    let json: Value = serde_json::from_str(json_text).expect("--format both JSON should parse");

    assert!(text.starts_with("error[BPFIX-E006]:"));
    assert!(text.contains("= class: lowering_artifact"));
    assert_eq!(json["error_id"], "BPFIX-E006");
    assert_eq!(json["failure_class"], "lowering_artifact");
}

#[test]
fn case_id_is_explicit_metadata_not_derived_from_log_filename() {
    let path =
        workspace_root().join("bpfix-bench/cases/stackoverflow-60053570/replay-verifier.log");
    let path = path.to_str().expect("fixture path should be UTF-8");

    let default_json = run_json_with_args(&[path, "--format", "json"]);
    assert!(default_json["metadata"]["case_id"].is_null());

    let explicit_json = run_json_with_args(&[
        path,
        "--case-id",
        "stackoverflow-60053570",
        "--format",
        "json",
    ]);
    assert_eq!(
        explicit_json["metadata"]["case_id"],
        "stackoverflow-60053570"
    );
}

#[test]
fn noisy_build_log_is_reduced_to_verifier_region() {
    let replay = std::fs::read_to_string(
        workspace_root().join("bpfix-bench/cases/stackoverflow-53136145/replay-verifier.log"),
    )
    .expect("fixture should be readable");
    let noisy = format!(
        "clang -O2 -target bpf ...\nwarning: unrelated build warning\n{replay}\nmake: *** [load] Error 1\n"
    );
    let path = std::env::temp_dir().join(format!(
        "bpfix-noisy-{}-{}.log",
        std::process::id(),
        "branch"
    ));
    std::fs::write(&path, noisy).expect("temp log should be writable");
    let json = run_json_path(path.clone());
    let _ = std::fs::remove_file(path);

    assert_eq!(json["error_id"], "BPFIX-E006");
    assert_eq!(json["metadata"]["input_kind"], "verifier-log-region");
    assert_eq!(json["source_span"]["instruction_pc"], 37);
}

#[test]
fn ci_wrapped_log_is_reduced_to_verifier_region() {
    let replay = std::fs::read_to_string(
        workspace_root().join("bpfix-bench/cases/stackoverflow-53136145/replay-verifier.log"),
    )
    .expect("fixture should be readable");
    let wrapped = replay
        .lines()
        .map(|line| format!("2026-06-13T21:04:05.123Z \u{1b}[31m{line}\u{1b}[0m\n"))
        .collect::<String>();
    let ci_log =
        format!("::group::load BPF object\nwarning: unrelated CI noise\n{wrapped}::endgroup::\n");

    let json = run_json_stdin(&ci_log);

    assert_eq!(json["error_id"], "BPFIX-E006");
    assert_eq!(json["failure_class"], "lowering_artifact");
    assert_eq!(json["metadata"]["input_kind"], "verifier-log-region");
    assert_eq!(json["source_span"]["path"], "prog.c");
    assert_eq!(json["source_span"]["instruction_pc"], 37);
}

#[test]
fn stdin_log_path_does_not_need_yaml() {
    let replay = std::fs::read_to_string(
        workspace_root().join("bpfix-bench/cases/stackoverflow-70750259/replay-verifier.log"),
    )
    .expect("fixture should be readable");
    let json = run_json_stdin(&replay);

    assert_eq!(json["error_id"], "BPFIX-E005");
    assert_eq!(json["failure_class"], "source_bug");
    assert_eq!(json["source_span"]["instruction_pc"], 33);
}

#[test]
fn omitted_log_reads_stdin_by_default() {
    let replay = std::fs::read_to_string(
        workspace_root().join("bpfix-bench/cases/stackoverflow-70750259/replay-verifier.log"),
    )
    .expect("fixture should be readable");
    let json = run_json_stdin_with_args(&replay, &["--format", "json"]);

    assert_eq!(json["error_id"], "BPFIX-E005");
    assert_eq!(json["failure_class"], "source_bug");
    assert_eq!(json["metadata"]["input_kind"], "verifier-log-region");
    assert_eq!(json["source_span"]["instruction_pc"], 33);
}

#[test]
fn yaml_labels_do_not_change_runtime_diagnostic() {
    let replay = std::fs::read_to_string(
        workspace_root().join("bpfix-bench/cases/stackoverflow-53136145/replay-verifier.log"),
    )
    .expect("fixture should be readable");
    let indented_log = replay
        .lines()
        .map(|line| format!("    {line}\n"))
        .collect::<String>();
    let yaml = format!(
        "case_id: yaml-oracle\nlabel:\n  error_id: BPFIX-E009\n  taxonomy_class: environment_or_configuration\n  root_cause_description: SHOULD_NOT_LEAK\n  fix_direction: WRONG_REPAIR\nverifier_log:\n  combined: |\n{indented_log}"
    );

    let json = run_json_stdin(&yaml);

    assert_eq!(json["error_id"], "BPFIX-E006");
    assert_eq!(json["failure_class"], "lowering_artifact");
    assert!(json["metadata"]["case_id"].is_null());
    assert!(
        !json["evidence"].as_array().unwrap().iter().any(|evidence| {
            evidence["kind"] == "case_root_cause" || evidence["detail"] == "SHOULD_NOT_LEAK"
        })
    );
    assert!(!json["help"]
        .as_array()
        .unwrap()
        .iter()
        .any(|item| item == "WRONG_REPAIR"));
}

#[test]
fn input_without_verifier_rejection_gets_actionable_input_error() {
    let json = run_json_stdin("clang -O2 -target bpf -c prog.bpf.c\nbuild succeeded\n");

    assert_eq!(json["error_id"], "BPFIX-E000");
    assert_eq!(json["failure_class"], "input_error");
    assert_eq!(json["diagnostic_kind"], "unsupported_input");
    assert_eq!(json["help_safety"], "triage_only");
    assert!(json["help"]
        .as_array()
        .unwrap()
        .iter()
        .any(|item| item.as_str().unwrap().contains("bpftool -d")));
}

#[test]
fn fail_on_unsupported_exits_after_rendering_diagnostic() {
    let output = run_stdin_output(
        "clang -O2 -target bpf -c prog.bpf.c\nbuild succeeded\n",
        &["-", "--format", "json", "--fail-on-unsupported"],
    );
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stderr.is_empty());
    let json: Value = serde_json::from_slice(&output.stdout).expect("bpfix should emit JSON");
    assert_eq!(json["error_id"], "BPFIX-E000");
    assert_eq!(json["diagnostic_kind"], "unsupported_input");

    let output = run_stdin_output(
        "0: (95) exit\ninvalid verifier frobnication\n",
        &["-", "--format", "json", "--fail-on-unsupported"],
    );
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stderr.is_empty());
    let json: Value = serde_json::from_slice(&output.stdout).expect("bpfix should emit JSON");
    assert_eq!(json["error_id"], "BPFIX-E099");
    assert_eq!(json["diagnostic_kind"], "unsupported_verifier_message");

    let output = run_stdin_output(
        "0: (95) exit\nR0 !read_ok\n",
        &["-", "--format", "json", "--fail-on-unsupported"],
    );
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let json: Value = serde_json::from_slice(&output.stdout).expect("bpfix should emit JSON");
    assert_eq!(json["error_id"], "BPFIX-E003");
    assert_eq!(json["diagnostic_kind"], "supported");
}

#[test]
fn verifier_state_signal_can_replace_unsupported_terminal_message() {
    let log = "\
func#0 @0
0: frame1: R1=scalar() R10=fp0 refs=1 cb
0: (85) call bpf_throw#999
invalid verifier frobnication
";
    let output = run_stdin_output(log, &["-", "--format", "json", "--fail-on-unsupported"]);
    assert!(
        output.status.success(),
        "bpfix failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    let json: Value = serde_json::from_slice(&output.stdout).expect("bpfix should emit JSON");
    assert_eq!(json["error_id"], "BPFIX-E004");
    assert_eq!(json["failure_class"], "source_bug");
    assert_eq!(json["diagnostic_kind"], "supported");
    assert!(evidence_contains(
        &json,
        "verifier_state_signal",
        "bpf_throw"
    ));
}

#[test]
fn verifier_trace_without_structured_signal_stays_unsupported() {
    let log = "\
func#0 @0
0: R1=scalar() R10=fp0
0: (95) exit
invalid verifier frobnication
";
    let output = run_stdin_output(log, &["-", "--format", "json", "--fail-on-unsupported"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stderr.is_empty());
    let json: Value = serde_json::from_slice(&output.stdout).expect("bpfix should emit JSON");
    assert_eq!(json["error_id"], "BPFIX-E099");
    assert_eq!(json["diagnostic_kind"], "unsupported_verifier_message");
    assert!(evidence_contains(
        &json,
        "verifier_trace",
        "parsed 1 per-instruction verifier state snapshots"
    ));
    assert!(
        !json["evidence"].as_array().unwrap().iter().any(|evidence| {
            evidence["kind"] == "verifier_state_signal"
                || evidence["kind"] == "lowering_artifact_signal"
                || evidence["kind"] == "verifier_precision_signal"
        })
    );
}

#[test]
fn parser_recovery_warnings_do_not_pollute_json_stderr() {
    let output = run_json_stdin_output(
        "0: R1=scalar(foo=bar) fp-8_w=0\n1: (95) exit\nR1 invalid mem access 'scalar'\n",
    );
    assert!(
        output.status.success(),
        "bpfix failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stderr.is_empty(),
        "bpfix should keep parser recovery warnings out of stderr by default: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json: Value = serde_json::from_slice(&output.stdout).expect("bpfix should emit JSON");
    assert_eq!(json["error_id"], "BPFIX-E006");
    assert_eq!(json["metadata"]["trace_state_count"], 1);
}

#[test]
fn required_proof_uses_classifier_obligation_for_type_contracts() {
    let json = run_json_stdin("0: (bf) r1 = r10\nR1 type=scalar expected=fp\n");

    assert_eq!(json["error_id"], "BPFIX-E008");
    assert_eq!(json["failure_class"], "source_bug");
    assert!(json["required_proof"]
        .as_str()
        .unwrap()
        .contains("verifier-visible type required"));
    assert!(json["message"]
        .as_str()
        .unwrap()
        .contains("R1 type=scalar expected=fp"));
    assert!(!json["required_proof"]
        .as_str()
        .unwrap()
        .contains("inspect the terminal verifier line"));
}

#[test]
#[cfg(feature = "object-analysis")]
fn object_argument_is_validated_and_reported() {
    let log_path =
        workspace_root().join("bpfix-bench/cases/stackoverflow-53136145/replay-verifier.log");
    let object_path = workspace_root().join("bpfix-bench/cases/stackoverflow-53136145/prog.o");
    let json = run_json_with_args(&[
        "--object",
        object_path.to_str().unwrap(),
        log_path.to_str().unwrap(),
        "--format",
        "json",
    ]);

    assert_eq!(
        json["metadata"]["object_path"],
        object_path.to_str().unwrap()
    );
    assert_eq!(
        json["metadata"]["object_programs"][0]["section_name"],
        "xdp"
    );
    assert_eq!(
        json["metadata"]["object_programs"][0]["instruction_count"],
        54
    );
    assert!(
        json["metadata"]["object_programs"][0]["block_count"]
            .as_u64()
            .unwrap()
            > 0
    );
    assert!(
        json["metadata"]["object_programs"][0]["verifier_state_site_count"]
            .as_u64()
            .unwrap()
            > 0
    );
    assert!(json["metadata"]["object_programs"][0]["verifier_state_attach_error"].is_null());
}

#[test]
#[cfg(feature = "object-analysis")]
fn object_argument_attaches_section_local_states_from_loaded_layout() {
    let log_path = workspace_root()
        .join("bpfix-bench/cases/github-commit-cilium-968227de9cc5/replay-verifier.log");
    let object_path =
        workspace_root().join("bpfix-bench/cases/github-commit-cilium-968227de9cc5/prog.o");
    let json = run_json_with_args(&[
        "--object",
        object_path.to_str().unwrap(),
        log_path.to_str().unwrap(),
        "--format",
        "json",
    ]);

    assert_eq!(
        json["metadata"]["object_path"],
        object_path.to_str().unwrap()
    );
    assert_eq!(json["error_id"], "BPFIX-E011");
    assert!(evidence_contains(
        &json,
        "verifier_state_signal",
        "consumed register is scalar"
    ));
    assert!(
        json["metadata"]["object_programs"][0]["block_count"]
            .as_u64()
            .unwrap()
            > 0
    );
    assert!(
        json["metadata"]["object_programs"][0]["verifier_state_site_count"]
            .as_u64()
            .unwrap()
            > 0
    );
    assert!(json["metadata"]["object_programs"][0]["verifier_state_attach_error"].is_null());
}

#[test]
#[cfg(feature = "object-analysis")]
fn object_section_identifies_packet_context_fields_in_tracepoint() {
    let case = "bpfix-bench/cases/stackoverflow-72717564";
    let log_path = workspace_root().join(case).join("replay-verifier.log");
    let object_path = workspace_root().join(case).join("prog.o");

    let log_only = run_json_path(log_path.clone());
    assert_eq!(log_only["error_id"], "BPFIX-E011");
    assert_eq!(log_only["next_action"], "provenance");

    let with_object = run_json_with_args(&[
        "--object",
        object_path.to_str().unwrap(),
        log_path.to_str().unwrap(),
        "--format",
        "json",
    ]);

    assert_eq!(with_object["error_id"], "BPFIX-E011");
    assert_eq!(with_object["failure_class"], "source_bug");
    assert_eq!(with_object["next_action"], "environment");
    assert_eq!(
        with_object["metadata"]["object_programs"][0]["section_name"],
        "tracepoint/skb/consume_skb"
    );
    assert!(evidence_contains(
        &with_object,
        "verifier_state_signal",
        "non-packet program"
    ));
    assert!(with_object["required_proof"]
        .as_str()
        .unwrap()
        .contains("packet data/data_end"));
}

#[test]
#[cfg(feature = "object-analysis")]
fn object_argument_uses_rejected_program_section_states() {
    let log_path =
        workspace_root().join("bpfix-bench/cases/stackoverflow-72560675/replay-verifier.log");
    let object_path = workspace_root().join("bpfix-bench/cases/stackoverflow-72560675/prog.o");
    let json = run_json_with_args(&[
        "--object",
        object_path.to_str().unwrap(),
        log_path.to_str().unwrap(),
        "--format",
        "json",
    ]);
    let programs = json["metadata"]["object_programs"].as_array().unwrap();
    let enter = programs
        .iter()
        .find(|program| program["section_name"] == "tracepoint/syscalls/sys_enter_read")
        .unwrap();
    let exit = programs
        .iter()
        .find(|program| program["section_name"] == "tracepoint/syscalls/sys_exit_read")
        .unwrap();

    assert_eq!(json["error_id"], "BPFIX-E005");
    assert_eq!(enter["verifier_state_site_count"], 0);
    assert!(enter["verifier_state_attach_error"].is_null());
    assert!(exit["verifier_state_site_count"].as_u64().unwrap() > 0);
    assert!(exit["verifier_state_attach_error"].is_null());
}

#[test]
#[cfg(feature = "object-analysis")]
fn object_argument_stitches_reachable_text_subprograms() {
    let log_path = workspace_root().join(
        "bpfix-bench/cases/kernel-selftest-exceptions-fail-reject-exception-cb-call-static-func-tc-f3ceb9b7/replay-verifier.log",
    );
    let object_path = workspace_root().join(
        "bpfix-bench/cases/kernel-selftest-exceptions-fail-reject-exception-cb-call-static-func-tc-f3ceb9b7/prog.o",
    );
    let json = run_json_with_args(&[
        "--object",
        object_path.to_str().unwrap(),
        log_path.to_str().unwrap(),
        "--format",
        "json",
    ]);

    assert_eq!(json["error_id"], "BPFIX-E013");
    assert!(json["metadata"]["object_analysis_error"].is_null());
    assert_eq!(
        json["metadata"]["object_programs"][0]["section_name"],
        "?tc"
    );
    assert_eq!(
        json["metadata"]["object_programs"][0]["instruction_count"],
        7
    );
    assert!(
        json["metadata"]["object_programs"][0]["verifier_state_site_count"]
            .as_u64()
            .unwrap()
            > 0
    );
    assert!(json["metadata"]["object_programs"][0]["verifier_state_attach_error"].is_null());
}

#[test]
#[cfg(feature = "object-analysis")]
fn object_parse_error_is_reported_without_blocking_log_diagnostic() {
    let log_path =
        workspace_root().join("bpfix-bench/cases/stackoverflow-70750259/replay-verifier.log");
    let object_path =
        std::env::temp_dir().join(format!("bpfix-invalid-object-{}.o", std::process::id()));
    std::fs::write(&object_path, b"not an elf").expect("temp object should be writable");
    let json = run_json_with_args(&[
        "--object",
        object_path.to_str().unwrap(),
        log_path.to_str().unwrap(),
        "--format",
        "json",
    ]);
    let _ = std::fs::remove_file(&object_path);

    assert_eq!(json["error_id"], "BPFIX-E005");
    assert_eq!(
        json["metadata"]["object_path"],
        object_path.to_str().unwrap()
    );
    assert!(json["metadata"]["object_programs"]
        .as_array()
        .unwrap()
        .is_empty());
    assert!(json["metadata"]["object_analysis_error"]
        .as_str()
        .unwrap()
        .contains("failed to parse ELF object"));
}

#[test]
#[cfg(not(feature = "object-analysis"))]
fn object_argument_reports_disabled_feature_without_blocking_log_diagnostic() {
    let log_path =
        workspace_root().join("bpfix-bench/cases/stackoverflow-70750259/replay-verifier.log");
    let object_path = workspace_root().join("bpfix-bench/cases/stackoverflow-70750259/prog.o");
    let json = run_json_with_args(&[
        "--object",
        object_path.to_str().unwrap(),
        log_path.to_str().unwrap(),
        "--format",
        "json",
    ]);

    assert_eq!(json["error_id"], "BPFIX-E005");
    assert_eq!(
        json["metadata"]["object_path"],
        object_path.to_str().unwrap()
    );
    assert!(json["metadata"]["object_programs"]
        .as_array()
        .unwrap()
        .is_empty());
    assert!(json["metadata"]["object_analysis_error"]
        .as_str()
        .unwrap()
        .contains("--features object-analysis"));
}
