#!/usr/bin/env python3
"""Unit tests for benchmark metadata validation."""

from __future__ import annotations

import copy
import sys
import tempfile
import unittest
from pathlib import Path

TOOLS_DIR = Path(__file__).resolve().parent
BENCH_ROOT = TOOLS_DIR.parent
sys.path.insert(0, str(TOOLS_DIR))

import validate_benchmark  # noqa: E402
import replay_case  # noqa: E402


def base_case_data() -> dict:
    return {
        "schema_version": "bpfix.case/v1",
        "case_id": "case-1",
        "source": {"kind": "stackoverflow"},
        "reproducer": {
            "reconstruction": "original",
        },
        "capture": {
            "capture_id": "cap-1",
            "terminal_error": "R1 invalid mem access 'scalar'",
            "rejected_insn_idx": 1,
        },
        "label": {
            "capture_id": "cap-1",
            "taxonomy_class": "source_bug",
        },
        "reporting": {
            "family_id": "family-1",
            "representative": True,
        },
    }


def base_manifest() -> dict:
    return {
        "environment_id": "env-1",
        "case_defaults": {
            "reproducer": {
                "build_command": "make",
                "load_command": "make replay-verify",
                "source_file": "prog.c",
                "object_path": "prog.o",
            },
            "capture": {
                "verifier_log": "replay-verifier.log",
                "capture_metadata": "capture.yaml",
                "log_quality": "trace_rich",
            },
        },
    }


def base_manifest_entry() -> dict:
    return {
        "case_id": "case-1",
        "source_kind": "stackoverflow",
        "family_id": "family-1",
        "representative": True,
        "capture_id": "cap-1",
    }


class ValidateCaseMetadataTest(unittest.TestCase):
    def validate_metadata(
        self,
        case_data: dict,
        manifest_entry: dict | None = None,
        manifest: dict | None = None,
    ) -> list[str]:
        manifest_data = manifest or base_manifest()
        with tempfile.TemporaryDirectory() as tmpdir:
            case_dir = Path(tmpdir)
            (case_dir / "capture.yaml").write_text(
                "\n".join(
                    [
                        "capture_id: cap-1",
                        "environment_id: env-1",
                        "build_command: make",
                        "load_command: make replay-verify",
                        "language: C",
                        "expected_load_status: verifier_reject",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            report = {"errors": [], "warnings": []}
            validate_benchmark.validate_case_metadata(
                case_dir,
                manifest_data,
                manifest_entry or base_manifest_entry(),
                validate_benchmark.with_case_defaults(case_data, manifest_data),
                report,
            )
            return report["errors"]

    def test_minimal_case_metadata_accepts_capture_yaml_provenance(self) -> None:
        self.assertEqual(self.validate_metadata(base_case_data()), [])

    def test_manifest_case_defaults_schema_is_validated(self) -> None:
        manifest = base_manifest()
        manifest["case_defaults"]["capture"]["unexpected"] = "value"
        manifest["case_defaults"]["reproducer"]["source_file"] = ""
        manifest["case_defaults"]["unknown"] = {}

        errors = validate_benchmark.validate_manifest_metadata(manifest)

        self.assertIn("invalid manifest.case_defaults.capture.unexpected", errors)
        self.assertIn("manifest.case_defaults.reproducer.source_file must be a non-empty string", errors)
        self.assertIn("invalid manifest.case_defaults section: 'unknown'", errors)

    def test_missing_verifier_log_default_is_rejected(self) -> None:
        manifest = base_manifest()
        del manifest["case_defaults"]["capture"]["verifier_log"]

        errors = self.validate_metadata(base_case_data(), manifest=manifest)

        self.assertIn("missing capture.verifier_log", errors)

    def test_case_metadata_default_override_is_respected(self) -> None:
        case_data = base_case_data()
        case_data["reproducer"]["load_command"] = "make custom-load"

        with tempfile.TemporaryDirectory() as tmpdir:
            case_dir = Path(tmpdir)
            (case_dir / "capture.yaml").write_text(
                "\n".join(
                    [
                        "capture_id: cap-1",
                        "environment_id: env-1",
                        "build_command: make",
                        "load_command: make custom-load",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            report = {"errors": [], "warnings": []}
            validate_benchmark.validate_case_metadata(
                case_dir,
                base_manifest(),
                base_manifest_entry(),
                validate_benchmark.with_case_defaults(case_data, base_manifest()),
                report,
            )

        self.assertEqual(report["errors"], [])

    def test_removed_case_yaml_fields_are_rejected(self) -> None:
        case_data = copy.deepcopy(base_case_data())
        for section, fields in validate_benchmark.REMOVED_CASE_FIELDS.items():
            case_data[section].update({field: "redundant" for field in fields})
        case_data["label"]["legacy_rejected_insn_idx"] = 99

        errors = self.validate_metadata(case_data)

        for section, fields in validate_benchmark.REMOVED_CASE_FIELDS.items():
            for field in fields:
                self.assertTrue(
                    any(f"{section}.{field} is redundant in case.yaml" in error for error in errors),
                    f"missing rejection for {section}.{field}: {errors}",
                )
        self.assertTrue(
            any("label.legacy_rejected_insn_idx is legacy numbering metadata" in error for error in errors),
            f"missing rejection for label.legacy_rejected_insn_idx: {errors}",
        )

    def test_legacy_source_kind_alias_is_rejected(self) -> None:
        case_data = base_case_data()
        case_data["source"]["kind"] = "commit_derived"
        manifest_entry = base_manifest_entry()
        manifest_entry["source_kind"] = "commit_derived"

        errors = self.validate_metadata(case_data, manifest_entry)

        self.assertIn("invalid source.kind: 'commit_derived'", errors)
        self.assertIn("invalid manifest.source_kind: 'commit_derived'", errors)

    def test_legacy_insn_numbering_raw_provenance_is_consistent(self) -> None:
        provenance = validate_benchmark.load_yaml_mapping(BENCH_ROOT / "raw" / "legacy-insn-numbering.yaml")
        manifest = validate_benchmark.load_yaml_mapping(BENCH_ROOT / "manifest.yaml")
        manifest_by_case = {entry["case_id"]: entry for entry in manifest["cases"]}
        seen_case_ids = set()

        for entry in provenance["entries"]:
            case_id = entry["case_id"]
            self.assertNotIn(case_id, seen_case_ids)
            seen_case_ids.add(case_id)
            self.assertIn(case_id, manifest_by_case)
            self.assertEqual(entry["source_kind"], manifest_by_case[case_id]["source_kind"])

            raw_record = BENCH_ROOT.parent / entry["raw_record"]
            self.assertTrue(raw_record.exists(), entry["raw_record"])

            case_yaml = BENCH_ROOT / manifest_by_case[case_id]["path"] / "case.yaml"
            case_data = validate_benchmark.load_yaml_mapping(case_yaml)
            self.assertNotIn("legacy_rejected_insn_idx", case_data.get("label", {}))

        self.assertEqual(len(seen_case_ids), 52)


class ReplayCommandResultTest(unittest.TestCase):
    def test_command_result_normalizes_timeout_bytes(self) -> None:
        result = replay_case.CommandResult(
            command="make replay-verify",
            returncode=None,
            stdout=b"partial stdout",
            stderr=b"partial stderr",
            timed_out=True,
        )

        self.assertEqual(result.stdout, "partial stdout")
        self.assertEqual(result.stderr, "partial stderr")
        self.assertEqual(result.combined_output, "partial stdout\npartial stderr")


if __name__ == "__main__":
    unittest.main()
