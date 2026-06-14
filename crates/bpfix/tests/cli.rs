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
    for diagnostic in [&json, &precision_json, &example] {
        assert!(failure_classes.contains(diagnostic["failure_class"].as_str().unwrap()));
        for evidence in diagnostic["evidence"].as_array().unwrap() {
            assert!(evidence_kinds.contains(evidence["kind"].as_str().unwrap()));
        }
    }

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

    let pointer_merge =
        run_json("bpfix-bench/cases/github-commit-cilium-4dc7d8047caf/replay-verifier.log");
    assert_eq!(pointer_merge["error_id"], "BPFIX-E006");
    assert_eq!(pointer_merge["failure_class"], "lowering_artifact");

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
    assert!(packet_range_labels.contains("packet range 74 bytes"));
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
        .any(|evidence| evidence["kind"] == "verifier_precision_signal"));

    let map_relation = run_json("bpfix-bench/cases/stackoverflow-77762365/replay-verifier.log");
    assert_eq!(map_relation["error_id"], "BPFIX-E005");
    assert_eq!(map_relation["failure_class"], "verifier_false_positive");
    assert_eq!(map_relation["help_safety"], "triage_only");
    assert!(map_relation["message"]
        .as_str()
        .unwrap()
        .contains("verifier precision limit"));
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
    assert!(labels.contains("verifier had proved packet range 74 bytes"));
    assert!(labels.contains("required 60 bytes"));
    assert!(json["help"].as_array().unwrap().iter().any(|item| item
        .as_str()
        .unwrap()
        .contains("packet pointer derivation that received the data_end proof")));
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

    let helper_bounds = run_json("bpfix-bench/cases/stackoverflow-77713434/replay-verifier.log");
    assert_eq!(helper_bounds["error_id"], "BPFIX-E005");
    assert_eq!(helper_bounds["failure_class"], "source_bug");
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
fn object_argument_keeps_diagnostic_when_log_pcs_use_loaded_layout() {
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
    assert!(
        json["metadata"]["object_programs"][0]["block_count"]
            .as_u64()
            .unwrap()
            > 0
    );
    assert!(
        json["metadata"]["object_programs"][0]["verifier_state_attach_error"]
            .as_str()
            .unwrap()
            .contains("could not be attached")
    );
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
