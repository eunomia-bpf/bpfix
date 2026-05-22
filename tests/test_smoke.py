from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[1]


def test_expected_files_exist() -> None:
    expected = [
        ROOT / "pyproject.toml",
        ROOT / "bpfix-bench" / "manifest.yaml",
        ROOT / "bpfix-bench" / "raw" / "index.yaml",
        ROOT / "bpfix-bench" / "taxonomy.yaml",
        ROOT / "bpfix" / "schema" / "diagnostic.json",
        ROOT / "tools" / "validate_benchmark.py",
        ROOT / "tools" / "evaluate_benchmark.py",
        ROOT / "tools" / "sync_external_raw_bench.py",
        ROOT / "README.md",
        ROOT / "requirements.txt",
        ROOT / ".gitignore",
    ]
    missing = [path for path in expected if not path.exists()]
    assert not missing, f"missing expected files: {missing}"


def test_benchmark_manifest_has_expected_fields() -> None:
    payload = yaml.safe_load((ROOT / "bpfix-bench" / "manifest.yaml").read_text(encoding="utf-8"))
    assert payload["schema_version"] == "bpfix.benchmark/v1"
    assert payload["benchmark_id"] == "bpfix-bench-v1"
    assert isinstance(payload["cases"], list)
    assert len(payload["cases"]) >= 100

    first = payload["cases"][0]
    assert {"case_id", "path", "source_kind", "capture_id"}.issubset(first)


def test_replayable_case_manifest_has_expected_fields() -> None:
    payload = yaml.safe_load(
        (ROOT / "bpfix-bench" / "cases" / "stackoverflow-60053570" / "case.yaml").read_text(
            encoding="utf-8"
        )
    )
    assert payload["schema_version"] == "bpfix.case/v1"
    assert payload["capture"]["load_status"] == "verifier_reject"
    assert payload["capture"]["verifier_pass"] is False
    assert payload["reproducer"]["build_command"]
    assert payload["reproducer"]["load_command"]


def test_taxonomy_defines_all_five_classes() -> None:
    payload = yaml.safe_load((ROOT / "bpfix-bench" / "taxonomy.yaml").read_text(encoding="utf-8"))
    classes = payload["classes"]
    assert len(classes) == 5
    assert {entry["id"] for entry in classes} == {
        "source_bug",
        "lowering_artifact",
        "verifier_limit",
        "environment_or_configuration",
        "verifier_false_positive",
    }


def test_diagnostic_schema_accepts_minimal_example() -> None:
    schema = json.loads((ROOT / "bpfix" / "schema" / "diagnostic.json").read_text(encoding="utf-8"))
    example = {
        "diagnostic_version": "0.1.0",
        "error_id": "packet.bounds.missing_guard",
        "failure_class": "source_bug",
        "message": "packet access requires a dominating bounds check",
        "source_span": {
            "path": "bpfix-bench/cases/so-12345/prog.bpf.c",
            "line_start": 12,
            "line_end": 14
        },
        "missing_obligation": "prove packet cursor stays within data_end before load"
    }
    Draft202012Validator(schema).validate(example)


def test_cli_help_commands_work() -> None:
    scripts = [
        ROOT / "tools" / "validate_benchmark.py",
        ROOT / "tools" / "evaluate_benchmark.py",
        ROOT / "tools" / "sync_external_raw_bench.py",
    ]
    for script in scripts:
        result = subprocess.run(
            [sys.executable, str(script), "--help"],
            check=False,
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, result.stderr
        assert "usage" in result.stdout.lower()

    bpfix_result = subprocess.run(
        [sys.executable, "-m", "bpfix", "--help"],
        check=False,
        capture_output=True,
        text=True,
        cwd=ROOT,
    )
    assert bpfix_result.returncode == 0, bpfix_result.stderr
    assert "usage" in bpfix_result.stdout.lower()
