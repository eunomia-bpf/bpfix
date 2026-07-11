#!/usr/bin/env python3
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


TOOLS_DIR = Path(__file__).resolve().parent
ROOT = TOOLS_DIR.parents[1]
sys.path.insert(0, str(TOOLS_DIR))

import run_suite  # noqa: E402
from extract_verifier_failure import compact_verifier_log, latest_load_region  # noqa: E402


class VerifierLogSliceTests(unittest.TestCase):
    def test_latest_load_region_uses_last_attempt(self) -> None:
        text = """first preamble
-- BEGIN PROG LOAD LOG --
first rejection
-- END PROG LOAD LOG --
retry preamble
-- BEGIN PROG LOAD LOG --
second rejection
verification time 1 usec
-- END PROG LOAD LOG --
trailer
"""
        region = latest_load_region(text)
        self.assertNotIn("first rejection", region)
        self.assertNotIn("retry preamble", region)
        self.assertIn("second rejection", region)
        self.assertTrue(region.endswith("-- END PROG LOAD LOG --\n"))

    def test_missing_end_marker_keeps_region_to_eof(self) -> None:
        text = "preamble\n-- BEGIN PROG LOAD LOG --\nterminal rejection\n"
        self.assertEqual(
            latest_load_region(text),
            "-- BEGIN PROG LOAD LOG --\nterminal rejection\n",
        )

    def test_compaction_keeps_head_and_terminal_tail(self) -> None:
        middle = "".join(f"pc {index}: state\n" for index in range(1000))
        text = (
            "-- BEGIN PROG LOAD LOG --\n"
            "func#0 @0\n"
            + middle
            + "R1 invalid mem access 'scalar'\n"
            "verification time 1 usec\n"
            "-- END PROG LOAD LOG --\n"
        )
        compact = compact_verifier_log(text, max_chars=2_000)
        self.assertLessEqual(len(compact), 2_000)
        self.assertIn("func#0 @0", compact)
        self.assertIn("<omitted", compact)
        self.assertIn("R1 invalid mem access 'scalar'", compact)
        self.assertIn("-- END PROG LOAD LOG --", compact)

    def test_compaction_rejects_unusable_limit(self) -> None:
        with self.assertRaisesRegex(ValueError, "at least 2000"):
            compact_verifier_log("short", max_chars=1_999)


class BPFixHelperScriptTests(unittest.TestCase):
    def run_helper(
        self, exit_code: int
    ) -> tuple[subprocess.CompletedProcess[str], Path]:
        temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(temp_dir.cleanup)
        root = Path(temp_dir.name)
        fake_bpfix = root / "bpfix"
        fake_bpfix.write_text(
            "#!/bin/sh\n"
            "case \" $* \" in *\" --fail-on-unsupported \"*) ;; *) exit 64 ;; esac\n"
            "printf 'error[BPFIX-E001]: test diagnostic\\n'\n"
            "exit \"${FAKE_EXIT:-0}\"\n",
            encoding="utf-8",
        )
        fake_bpfix.chmod(0o755)
        log = root / "verifier.log"
        log.write_text("verifier rejection\n", encoding="utf-8")
        out = root / "out"
        env = os.environ.copy()
        env["FAKE_EXIT"] = str(exit_code)
        completed = subprocess.run(
            [
                str(
                    ROOT
                    / "skills"
                    / "ebpf-verifier-repair"
                    / "scripts"
                    / "run-bpfix-diagnostic.sh"
                ),
                "--bpfix",
                str(fake_bpfix),
                "--out",
                str(out),
                str(log),
            ],
            text=True,
            capture_output=True,
            check=False,
            env=env,
            cwd=ROOT,
        )
        return completed, out

    def test_helper_writes_plain_text_diagnostic(self) -> None:
        completed, out = self.run_helper(0)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(
            (out / "diagnostic.txt").read_text(encoding="utf-8"),
            "error[BPFIX-E001]: test diagnostic\n",
        )
        self.assertFalse((out / "diagnostic.json").exists())

    def test_helper_preserves_unsupported_artifact_and_exit_code(self) -> None:
        completed, out = self.run_helper(2)
        self.assertEqual(completed.returncode, 2)
        self.assertTrue((out / "diagnostic.txt").exists())
        self.assertIn("unsupported input/message", completed.stderr)


class SkillPromptTests(unittest.TestCase):
    def test_skill_guidance_includes_each_repair_phase(self) -> None:
        guidance = run_suite.skills_prompt_guidance(ROOT)
        for phrase in [
            "Extract The Failure Slice",
            "Contract Checklist",
            "Retry Matrix",
            "signed indexes",
            "verifier-tracked objects",
            "distinct branch-local side effects",
        ]:
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, guidance)

    def test_skill_metadata_tracks_every_injected_file(self) -> None:
        metadata = run_suite.skill_file_metadata(ROOT)
        self.assertEqual(len(metadata), len(run_suite.SKILL_FILES))
        self.assertTrue(all(row["exists"] for row in metadata))
        self.assertTrue(all(row["sha256"] for row in metadata))

    def test_main75_skill_logs_are_bounded_and_raw_only(self) -> None:
        split = ROOT / "bpfix-bench" / "splits" / "main.txt"
        for case_id in run_suite.read_split_file(split):
            case_dir = ROOT / "bpfix-bench" / "cases" / case_id
            label, diagnostic, guidance = run_suite.diagnostic_input(case_dir, "skills")
            with self.subTest(case=case_id):
                self.assertEqual(label, "raw verifier failure slice")
                self.assertLessEqual(len(diagnostic), 48_000)
                self.assertIn("verification time", diagnostic)
                self.assertIn("-- END PROG LOAD LOG --", diagnostic)
                self.assertIn("Do not use or infer from a BPFix", guidance)
                self.assertNotIn("error[BPFIX-", diagnostic)
                self.assertNotIn("= next action:", diagnostic)


if __name__ == "__main__":
    unittest.main()
