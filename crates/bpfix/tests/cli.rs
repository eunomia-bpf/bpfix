use std::path::PathBuf;
use std::process::{Command, Stdio};

const SCALAR_REJECT_LOG: &str = r#"
func#0 @0
0: R1=ctx() R10=fp0
; value = *(u16 *)(ptr + 2); @ buggy.bpf.c:17
37: (69) r2 = *(u16 *)(r5 +2)
R5 invalid mem access 'scalar'
"#;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn run_stdin(input: &str, args: &[&str]) -> std::process::Output {
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

fn stdout(output: &std::process::Output) -> String {
    String::from_utf8(output.stdout.clone()).expect("bpfix stdout should be UTF-8")
}

fn stderr(output: &std::process::Output) -> String {
    String::from_utf8(output.stderr.clone()).expect("bpfix stderr should be UTF-8")
}

#[test]
fn stdin_renders_plain_text_diagnostic() {
    let output = run_stdin(SCALAR_REJECT_LOG, &["-"]);
    assert!(output.status.success(), "{}", stderr(&output));

    let text = stdout(&output);
    assert!(text.contains("error[BPFIX-"));
    assert!(text.contains("= class:"));
    assert!(text.contains("= diagnostic: supported"));
    assert!(text.contains("--> buggy.bpf.c:17"));
    assert!(text.contains("required proof:"));
    assert!(text.contains("help:"));
    assert!(!text.trim_start().starts_with('{'));
}

#[test]
fn path_input_renders_plain_text_diagnostic() {
    let path = workspace_root().join("bpfix-bench/cases/stackoverflow-53136145/replay-verifier.log");
    let output = Command::new(env!("CARGO_BIN_EXE_bpfix"))
        .arg(path)
        .output()
        .expect("bpfix should execute");
    assert!(output.status.success(), "{}", stderr(&output));

    let text = stdout(&output);
    assert!(text.contains("error[BPFIX-"));
    assert!(text.contains("R5 invalid mem access 'scalar'"));
    assert!(text.contains("= next action:"));
}

#[test]
fn format_flag_is_not_a_public_interface() {
    let output = run_stdin(SCALAR_REJECT_LOG, &["-", "--format", "json"]);
    assert!(!output.status.success());

    let err = stderr(&output);
    assert!(err.contains("unexpected argument") || err.contains("unknown argument"));
}

#[test]
fn fail_on_unsupported_exits_after_rendering_plain_text() {
    let output = run_stdin("build succeeded without a verifier log\n", &["-", "--fail-on-unsupported"]);
    assert_eq!(output.status.code(), Some(2));

    let text = stdout(&output);
    assert!(text.contains("error[BPFIX-E000]"));
    assert!(text.contains("= diagnostic: unsupported_input"));
    assert!(text.contains("no verifier rejection was found"));
}

#[test]
fn help_describes_plain_text_oriented_inputs() {
    let output = Command::new(env!("CARGO_BIN_EXE_bpfix"))
        .arg("--help")
        .output()
        .expect("bpfix --help should execute");
    assert!(output.status.success());

    let help = stdout(&output);
    assert!(help.contains("Verifier, build, bpftool, libbpf, Aya, or BCC log"));
    assert!(help.contains("Experimental compiled BPF object metadata"));
    assert!(!help.contains("--format"));
}
