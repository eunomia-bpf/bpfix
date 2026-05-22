from __future__ import annotations

import json
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]

from bpfix.api import build_diagnostic, load_schema


def _load_verifier_log(relative_path: str) -> str:
    from bench_fixtures import load_verifier_log

    return load_verifier_log(relative_path)


def test_build_diagnostic_emits_schema_valid_payload() -> None:
    schema = load_schema()
    diagnostic = build_diagnostic(
        _load_verifier_log("bpfix-bench/raw/so/stackoverflow-70750259.yaml"),
        case_id="so-70750259",
        kernel_release="6.8.0-test",
        source_path="demo/prog.bpf.c",
    )

    Draft202012Validator(schema).validate(diagnostic)
    assert diagnostic["case_id"] == "so-70750259"
    assert diagnostic["kernel_release"] == "6.8.0-test"
    assert diagnostic["failure_class"] == "lowering_artifact"
    assert diagnostic["error_id"] == "BPFIX-E005"


def test_load_schema_matches_packaged_schema_file() -> None:
    expected = json.loads(
        (ROOT / "bpfix" / "schema" / "diagnostic.json").read_text(encoding="utf-8")
    )
    assert load_schema() == expected
