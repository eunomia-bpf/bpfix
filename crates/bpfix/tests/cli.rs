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
        "bpfix.diagnostic/v2"
    );
    assert!(schema["properties"].get("missing_obligation").is_none());
    assert!(schema["properties"].get("candidate_repairs").is_none());
    assert!(schema["properties"].get("raw_log_excerpt").is_none());
    let failure_classes = string_array_set(&schema["properties"]["failure_class"]["enum"]);
    let evidence_kinds =
        string_array_set(&schema["$defs"]["evidence_item"]["properties"]["kind"]["enum"]);
    for diagnostic in [
        &json,
        &precision_json,
        &verifier_state_signal_json,
        &verifier_metadata_signal_json,
        &example,
    ] {
        assert!(failure_classes.contains(diagnostic["failure_class"].as_str().unwrap()));
        for evidence in diagnostic["evidence"].as_array().unwrap() {
            assert!(evidence_kinds.contains(evidence["kind"].as_str().unwrap()));
        }
    }
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
    assert_source_bug_without_verifier_state_signal(&wrong_map_argument, "BPFIX-E008");

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

    let help = json["help"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|item| item.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(help.contains("Check the exact pointer and byte length"));

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
fn ordinary_source_bugs_are_not_overclassified_as_runtime_artifacts() {
    let pointer_load_reuse =
        run_json("bpfix-bench/cases/stackoverflow-56965789/replay-verifier.log");
    assert_eq!(pointer_load_reuse["error_id"], "BPFIX-E006");
    assert_eq!(pointer_load_reuse["failure_class"], "source_bug");

    let generic_alignment =
        run_json("bpfix-bench/cases/stackoverflow-76441958/replay-verifier.log");
    assert_eq!(generic_alignment["error_id"], "BPFIX-E007");
    assert_eq!(generic_alignment["failure_class"], "source_bug");

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
fn terminal_error_selection_ignores_state_lines_and_uses_final_reject() {
    let pointer_bitwise = run_json("bpfix-bench/cases/stackoverflow-68460177/replay-verifier.log");
    assert_eq!(pointer_bitwise["error_id"], "BPFIX-E006");
    assert_eq!(pointer_bitwise["failure_class"], "source_bug");
    assert!(pointer_bitwise["message"]
        .as_str()
        .unwrap()
        .contains("R4 bitwise operator |= on pointer prohibited"));

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
    assert!(!evidence_contains(
        &uninitialized_dynptr_clone,
        "verifier_state_signal",
        "unstable dynptr slot"
    ));

    let overwritten_dynptr_slot =
        run_json("bpfix-bench/cases/kernel-selftest-dynptr-fail-invalid-write1-raw-tp-ba5ba8ca/replay-verifier.log");
    assert_eq!(overwritten_dynptr_slot["error_id"], "BPFIX-E012");
    assert!(!evidence_contains(
        &overwritten_dynptr_slot,
        "verifier_state_signal",
        "unstable dynptr slot"
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

    let read_write_slice_in_read_only_context =
        run_json("bpfix-bench/cases/kernel-selftest-dynptr-fail-invalid-slice-rdwr-rdonly-cgroup-skb-ingress-61688196/replay-verifier.log");
    assert_eq!(
        read_write_slice_in_read_only_context["error_id"],
        "BPFIX-E012"
    );
    assert!(read_write_slice_in_read_only_context["message"]
        .as_str()
        .unwrap()
        .contains("does not allow writes to packet data"));
    assert!(read_write_slice_in_read_only_context["required_proof"]
        .as_str()
        .unwrap()
        .contains("read-only dynptr slice helper"));

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
    assert_eq!(json["error_id"], "BPFIX-E006");
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
