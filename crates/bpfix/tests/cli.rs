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
    let output = Command::new(env!("CARGO_BIN_EXE_bpfix"))
        .args(args)
        .output()
        .expect("bpfix should execute");
    assert!(
        output.status.success(),
        "bpfix failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("bpfix should emit JSON")
}

fn run_json_stdin(input: &str) -> Value {
    let mut child = Command::new(env!("CARGO_BIN_EXE_bpfix"))
        .arg("-")
        .arg("--format")
        .arg("json")
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
fn raw_yaml_packet_bounds_case_is_classified() {
    let json = run_json("bpfix-bench/raw/so/stackoverflow-60053570.yaml");
    assert_eq!(json["error_id"], "BPFIX-E001");
    assert_eq!(json["failure_class"], "source_bug");
    assert_eq!(json["metadata"]["case_id"], "stackoverflow-60053570");
    assert_eq!(json["source_span"]["instruction_pc"], 49);
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
    assert_eq!(json["failure_class"], "lowering_artifact");
    assert!(json["required_proof"]
        .as_str()
        .unwrap()
        .contains("cannot be negative"));
    assert_eq!(json["metadata"]["case_id"], "replay-verifier");
    assert_eq!(json["source_span"]["path"], "prog.c");
    assert_eq!(json["source_span"]["instruction_pc"], 33);
}

#[test]
fn branch_merge_case_is_classified_from_proof_events_without_yaml() {
    let json = run_json("bpfix-bench/cases/stackoverflow-53136145/replay-verifier.log");
    assert_eq!(json["error_id"], "BPFIX-E006");
    assert_eq!(json["failure_class"], "lowering_artifact");
    assert_eq!(json["metadata"]["case_id"], "replay-verifier");
    assert_eq!(json["metadata"]["input_kind"], "verifier-log-region");
    assert_eq!(json["source_span"]["path"], "prog.c");
    assert_eq!(json["source_span"]["instruction_pc"], 37);
    assert!(json["related_spans"].as_array().unwrap().len() >= 2);
}

#[test]
fn text_output_is_rust_style_multispan() {
    let text = run_text("bpfix-bench/cases/stackoverflow-53136145/replay-verifier.log");
    assert!(text.contains("error[BPFIX-E006]: pointer type proof is missing"));
    assert!(text.contains("= class: lowering_artifact"));
    assert!(text.contains("--> prog.c:270"));
    assert!(text.contains("263 | if (ipv4_hdr)"));
    assert!(text.contains("267 | if (udph + sizeof(struct udphdr) > data_end)"));
    assert!(text.contains("270 | dst_port = __constant_ntohs(((struct udphdr *)udph)->dest);"));
    assert!(text.contains("proof can be lost when branch-specific pointers are merged"));
    assert!(text.contains("proof established by a verifier-visible bounds check"));
    assert!(text.contains("help: Keep branch-specific pointer derivations"));
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
fn stdin_log_path_does_not_need_yaml() {
    let replay = std::fs::read_to_string(
        workspace_root().join("bpfix-bench/cases/stackoverflow-70750259/replay-verifier.log"),
    )
    .expect("fixture should be readable");
    let json = run_json_stdin(&replay);

    assert_eq!(json["error_id"], "BPFIX-E005");
    assert_eq!(json["failure_class"], "lowering_artifact");
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
    assert_eq!(json["metadata"]["case_id"], "yaml-oracle");
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
