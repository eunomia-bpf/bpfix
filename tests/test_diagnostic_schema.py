from __future__ import annotations

import json
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]

from bpfix.extractor.pipeline import generate_diagnostic


def _load_verifier_log(relative_path: str) -> str:
    from bench_fixtures import load_verifier_log

    return load_verifier_log(relative_path)


def test_generate_diagnostic_json_matches_declared_schema() -> None:
    schema = json.loads((ROOT / "bpfix" / "schema" / "diagnostic.json").read_text(encoding="utf-8"))
    output = generate_diagnostic(
        _load_verifier_log("bpfix-bench/raw/so/stackoverflow-70750259.yaml")
    )

    Draft202012Validator(schema).validate(output.json_data)
