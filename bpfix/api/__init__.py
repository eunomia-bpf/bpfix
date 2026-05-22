"""Public helpers for producing schema-valid diagnostics from raw verifier logs."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from bpfix.extractor.pipeline import generate_diagnostic


SCHEMA_PATH = Path(__file__).resolve().parents[1] / "schema" / "diagnostic.json"


def load_schema(schema_path: Path | None = None) -> dict[str, Any]:
    """Load the diagnostic JSON schema for validation or downstream tooling."""

    path = schema_path or SCHEMA_PATH
    return json.loads(path.read_text(encoding="utf-8"))


def build_diagnostic(
    raw_log: str,
    *,
    case_id: str | None = None,
    source_path: str | None = None,
    kernel_release: str | None = None,
    catalog_path: str | Path | None = None,
    bpftool_xlated: str | None = None,
) -> dict[str, Any]:
    """Create a schema-valid structured diagnostic record from a raw verifier log."""

    output = generate_diagnostic(
        raw_log,
        catalog_path=str(catalog_path) if catalog_path is not None else None,
        bpftool_xlated=bpftool_xlated,
    )
    diagnostic: dict[str, Any] = dict(output.json_data)

    if case_id is not None:
        diagnostic["case_id"] = case_id
    if kernel_release is not None:
        diagnostic["kernel_release"] = kernel_release

    if source_path:
        source_span = dict(diagnostic.get("source_span") or {})
        current_path = str(source_span.get("path") or "")
        if current_path in {"", "<unknown>", "<source>", "<bytecode>"}:
            source_span["path"] = source_path
            diagnostic["source_span"] = source_span

        metadata = dict(diagnostic.get("metadata") or {})
        proof_spans = metadata.get("proof_spans")
        if isinstance(proof_spans, list):
            metadata["proof_spans"] = [
                {
                    **span,
                    "path": span.get("path") or source_path,
                }
                if isinstance(span, dict)
                else span
                for span in proof_spans
            ]
            diagnostic["metadata"] = metadata

    return diagnostic


__all__ = ["build_diagnostic", "load_schema", "SCHEMA_PATH"]
