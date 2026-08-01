#!/usr/bin/env python3
from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock


TOOLS_DIR = Path(__file__).resolve().parent
ROOT = TOOLS_DIR.parents[1]
sys.path.insert(0, str(TOOLS_DIR))

import run_suite  # noqa: E402
from extract_verifier_failure import compact_verifier_log, latest_load_region  # noqa: E402


class FakeHTTPResponse:
    def __init__(self, payload: dict[str, object]) -> None:
        self.payload = payload

    def __enter__(self) -> FakeHTTPResponse:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def read(self) -> bytes:
        return json.dumps(self.payload).encode("utf-8")


class CostAccountingTests(unittest.TestCase):
    def test_normalizes_openai_and_responses_usage_fields(self) -> None:
        self.assertEqual(
            run_suite.normalize_token_usage(
                {
                    "prompt_tokens": 100,
                    "completion_tokens": 20,
                    "total_tokens": 120,
                    "completion_tokens_details": {"reasoning_tokens": 7},
                    "prompt_tokens_details": {"cached_tokens": 11},
                }
            ),
            {
                "prompt_tokens": 100,
                "completion_tokens": 20,
                "total_tokens": 120,
                "reasoning_tokens": 7,
                "cached_prompt_tokens": 11,
            },
        )
        self.assertEqual(
            run_suite.normalize_token_usage(
                {
                    "input_tokens": 80,
                    "output_tokens": 10,
                    "total_tokens": 90,
                    "output_tokens_details": {"reasoning_tokens": 3},
                }
            ),
            {
                "prompt_tokens": 80,
                "completion_tokens": 10,
                "total_tokens": 90,
                "reasoning_tokens": 3,
                "cached_prompt_tokens": None,
            },
        )

    @mock.patch.object(run_suite.urllib.request, "urlopen")
    def test_model_call_preserves_usage_and_provider_timings(self, urlopen: mock.Mock) -> None:
        urlopen.return_value = FakeHTTPResponse(
            {
                "choices": [
                    {
                        "finish_reason": "stop",
                        "message": {"content": "```c\nint x;\n```", "reasoning_content": "why"},
                    }
                ],
                "usage": {
                    "prompt_tokens": 16,
                    "completion_tokens": 8,
                    "total_tokens": 24,
                },
                "timings": {"prompt_ms": 2.5, "predicted_ms": 4.0},
            }
        )
        result = run_suite.call_openai_compatible(
            base_url="http://model.invalid/v1",
            api_key="none",
            model="test",
            prompt="repair this",
            timeout=1,
            max_tokens=32,
            temperature=0,
        )
        self.assertEqual(result["content"], "```c\nint x;\n```")
        self.assertEqual(result["reasoning_chars"], 3)
        self.assertEqual(result["token_usage"]["total_tokens"], 24)
        self.assertEqual(result["api_timings"]["prompt_ms"], 2.5)

    def test_aggregate_requires_complete_usage_coverage(self) -> None:
        attempts = [
            {
                "model_wall_time_seconds": 1.0,
                "oracle_wall_time_seconds": 2.0,
                "attempt_wall_time_seconds": 3.0,
                "token_usage": {
                    "prompt_tokens": 10,
                    "completion_tokens": 5,
                    "total_tokens": 15,
                    "reasoning_tokens": 0,
                    "cached_prompt_tokens": 2,
                },
            },
            {
                "model_wall_time_seconds": 4.0,
                "oracle_wall_time_seconds": None,
                "attempt_wall_time_seconds": 4.5,
                "token_usage": {
                    "prompt_tokens": 20,
                    "completion_tokens": 6,
                    "total_tokens": 26,
                    "reasoning_tokens": None,
                    "cached_prompt_tokens": None,
                },
            },
        ]
        cost = run_suite.aggregate_attempt_cost(attempts)
        self.assertEqual(cost["model_calls"], 2)
        self.assertEqual(cost["prompt_tokens"], 30)
        self.assertEqual(cost["total_tokens"], 41)
        self.assertIsNone(cost["reasoning_tokens"])
        self.assertEqual(cost["token_usage_coverage"]["reasoning_tokens"], 1)
        self.assertEqual(cost["model_wall_time_seconds"], 5.0)
        self.assertEqual(cost["oracle_wall_time_seconds"], 2.0)

    def test_policy_checkpoints_derive_from_one_retry_trajectory(self) -> None:
        def attempt(status: str, tokens: int) -> dict[str, object]:
            return {
                "status": status,
                "model_wall_time_seconds": 1.0,
                "oracle_wall_time_seconds": 1.0,
                "attempt_wall_time_seconds": 2.0,
                "token_usage": {
                    "prompt_tokens": tokens - 1,
                    "completion_tokens": 1,
                    "total_tokens": tokens,
                    "reasoning_tokens": 0,
                    "cached_prompt_tokens": 0,
                },
            }

        checkpoints = run_suite.repair_policy_checkpoints(
            [
                {"attempts": [attempt("pass", 10)]},
                {"attempts": [attempt("fail", 20), attempt("pass", 30)]},
                {"attempts": [attempt("fail", 40), attempt("fail", 50)]},
            ]
        )
        self.assertEqual([(row["max_attempts"], row["passed"]) for row in checkpoints], [(1, 1), (2, 2)])
        self.assertEqual(checkpoints[0]["cost"]["total_tokens"], 70)
        self.assertEqual(checkpoints[1]["cost"]["total_tokens"], 150)

        no_retry_needed = run_suite.repair_policy_checkpoints(
            [{"attempts": [attempt("pass", 10)]}],
            max_attempts=2,
        )
        self.assertEqual([(row["max_attempts"], row["passed"]) for row in no_retry_needed], [(1, 1), (2, 1)])
        self.assertEqual(no_retry_needed[0]["cost"], no_retry_needed[1]["cost"])

    @mock.patch.object(run_suite, "server_model_metadata", return_value={"reachable": False, "models": None})
    @mock.patch.object(run_suite, "call_openai_compatible", side_effect=TimeoutError("timed out"))
    def test_model_call_failure_is_recorded_as_attempt(
        self,
        _call: mock.Mock,
        _server: mock.Mock,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            results_dir = Path(temp_dir)
            with redirect_stdout(io.StringIO()):
                returncode = run_suite.main(
                    [
                        "--case",
                        "alu32_pointer_cookie_001",
                        "--results-dir",
                        str(results_dir),
                        "--base-url",
                        "http://model.invalid/v1",
                    ]
                )
            self.assertEqual(returncode, 1)
            summary_path = next(results_dir.rglob("summary.json"))
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
            attempts = summary["results"][0]["attempts"]
            self.assertEqual(len(attempts), 1)
            self.assertEqual(attempts[0]["failure_stage"], "model_call")
            self.assertIsNone(attempts[0]["token_usage"])
            self.assertEqual(summary["cost"]["model_calls"], 1)
            self.assertEqual(summary["cost"]["token_usage_coverage"]["total_tokens"], 0)


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
