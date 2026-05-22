use std::path::PathBuf;
use std::process::Command;

use serde_json::Value;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn run_json(path: &str) -> Value {
    let output = Command::new(env!("CARGO_BIN_EXE_bpfix"))
        .arg(workspace_root().join(path))
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
fn signed_packet_offset_case_uses_benchmark_label() {
    let json = run_json("bpfix-bench/cases/stackoverflow-70750259/replay-verifier.log");
    assert_eq!(json["error_id"], "BPFIX-E005");
    assert_eq!(json["failure_class"], "source_bug");
    assert_eq!(json["metadata"]["case_id"], "stackoverflow-70750259");
    assert_eq!(json["source_span"]["path"], "prog.c");
    assert_eq!(json["source_span"]["instruction_pc"], 33);
}

#[test]
fn branch_merge_case_is_classified_from_case_metadata() {
    let json = run_json("bpfix-bench/cases/stackoverflow-53136145/replay-verifier.log");
    assert_eq!(json["error_id"], "BPFIX-E006");
    assert_eq!(json["failure_class"], "lowering_artifact");
    assert_eq!(json["metadata"]["case_id"], "stackoverflow-53136145");
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
    assert!(text.contains("help: Keep the IPv4 and IPv6 UDP-pointer derivations"));
}
