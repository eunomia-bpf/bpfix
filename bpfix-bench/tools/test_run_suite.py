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
import audit_results  # noqa: E402
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

    @mock.patch.object(run_suite.urllib.request, "urlopen")
    def test_malformed_model_response_preserves_billable_usage(self, urlopen: mock.Mock) -> None:
        usage = {"prompt_tokens": 16, "completion_tokens": 1, "total_tokens": 17}
        for payload, expected_error in [
            (
                {"choices": [{"message": {"content": None}}], "usage": usage},
                "content is not a string",
            ),
            ({"choices": [], "usage": usage}, "choices[0] is missing or invalid"),
        ]:
            with self.subTest(error=expected_error):
                urlopen.return_value = FakeHTTPResponse(payload)
                result = run_suite.call_openai_compatible(
                    base_url="http://model.invalid/v1",
                    api_key="none",
                    model="test",
                    prompt="repair this",
                    timeout=1,
                    max_tokens=32,
                    temperature=0,
                )
                self.assertIsNone(result["content"])
                self.assertIn(expected_error, result["error"])
                self.assertEqual(result["token_usage"]["total_tokens"], 17)

    def test_aggregate_requires_complete_usage_coverage(self) -> None:
        empty_cost = run_suite.aggregate_attempt_cost([])
        self.assertEqual(empty_cost["model_calls"], 0)
        self.assertTrue(all(empty_cost[field] == 0 for field in run_suite.TOKEN_USAGE_FIELDS))

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

    def test_cost_audit_recomputes_totals_and_checkpoints(self) -> None:
        attempt = {
            "attempt": 1,
            "status": "pass",
            "failure_stage": "pass",
            "model_wall_time_seconds": 1.0,
            "oracle_wall_time_seconds": 2.0,
            "attempt_wall_time_seconds": 3.0,
            "token_usage": {
                "prompt_tokens": 10,
                "completion_tokens": 5,
                "total_tokens": 15,
                "reasoning_tokens": 0,
                "cached_prompt_tokens": 0,
            },
            "api_usage": {
                "prompt_tokens": 10,
                "completion_tokens": 5,
                "total_tokens": 15,
                "completion_tokens_details": {"reasoning_tokens": 0},
                "prompt_tokens_details": {"cached_tokens": 0},
            },
        }
        result = {
            "case": "case-1",
            "status": "pass",
            "failure_stage": "pass",
            "attempts": [attempt],
            "cost": run_suite.aggregate_attempt_cost([attempt]),
        }
        summary = {
            "run_metadata": {"repair_policy": {"max_attempts": 1}},
            "results": [result],
            "cost": run_suite.aggregate_attempt_cost([attempt]),
            "policy_checkpoints": run_suite.repair_policy_checkpoints([result], max_attempts=1),
        }
        self.assertEqual(
            audit_results.audit_cost_metrics(
                path=Path("summary.json"),
                summary=summary,
                results=summary["results"],
                require_cost_metrics=True,
            ),
            [],
        )

        corrupted = json.loads(json.dumps(summary))
        corrupted["cost"]["total_tokens"] += 1
        corrupted["policy_checkpoints"][0]["passed"] = 0
        errors = audit_results.audit_cost_metrics(
            path=Path("summary.json"),
            summary=corrupted,
            results=corrupted["results"],
            require_cost_metrics=True,
        )
        self.assertTrue(any("cost does not match" in error for error in errors))
        self.assertTrue(any("policy_checkpoints do not match" in error for error in errors))

        def refresh_costs(payload: dict) -> None:
            payload_results = payload["results"]
            payload_attempts = payload_results[0]["attempts"]
            payload_results[0]["cost"] = run_suite.aggregate_attempt_cost(payload_attempts)
            payload["cost"] = run_suite.aggregate_attempt_cost(payload_attempts)
            limit = payload["run_metadata"]["repair_policy"]["max_attempts"]
            payload["policy_checkpoints"] = run_suite.repair_policy_checkpoints(
                payload_results,
                max_attempts=limit,
            )

        truncated = json.loads(json.dumps(summary))
        truncated["run_metadata"]["repair_policy"]["max_attempts"] = 2
        truncated["results"][0]["attempts"][0]["status"] = "fail"
        truncated["results"][0]["attempts"][0]["failure_stage"] = "verifier_load"
        truncated["results"][0]["status"] = "fail"
        truncated["results"][0]["failure_stage"] = "verifier_load"
        refresh_costs(truncated)
        errors = audit_results.audit_cost_metrics(
            path=Path("summary.json"),
            summary=truncated,
            results=truncated["results"],
            require_cost_metrics=True,
        )
        self.assertTrue(any("stops before exhausting" in error for error in errors))

        too_many = json.loads(json.dumps(summary))
        first_attempt = too_many["results"][0]["attempts"][0]
        first_attempt["status"] = "fail"
        first_attempt["failure_stage"] = "verifier_load"
        second_attempt = json.loads(json.dumps(attempt))
        second_attempt["attempt"] = 2
        too_many["results"][0]["attempts"].append(second_attempt)
        refresh_costs(too_many)
        errors = audit_results.audit_cost_metrics(
            path=Path("summary.json"),
            summary=too_many,
            results=too_many["results"],
            require_cost_metrics=True,
        )
        self.assertTrue(any("exceeds repair_policy.max_attempts" in error for error in errors))

        missing_provenance = json.loads(json.dumps(summary))
        missing_provenance["results"][0]["attempts"][0]["api_usage"] = None
        errors = audit_results.audit_cost_metrics(
            path=Path("summary.json"),
            summary=missing_provenance,
            results=missing_provenance["results"],
            require_cost_metrics=True,
        )
        self.assertTrue(any("token_usage does not match" in error for error in errors))

    def test_cost_audit_allows_legacy_only_when_not_required(self) -> None:
        legacy = {"results": []}
        self.assertEqual(
            audit_results.audit_cost_metrics(
                path=Path("legacy.json"),
                summary=legacy,
                results=[],
                require_cost_metrics=False,
            ),
            [],
        )
        errors = audit_results.audit_cost_metrics(
            path=Path("legacy.json"),
            summary=legacy,
            results=[],
            require_cost_metrics=True,
        )
        self.assertTrue(any("cost and policy_checkpoints are required" in error for error in errors))

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

    @mock.patch.object(run_suite, "server_model_metadata", return_value={"reachable": False, "models": None})
    @mock.patch.object(run_suite, "run_oracle")
    @mock.patch.object(run_suite, "call_openai_compatible")
    def test_transport_failure_consumes_attempt_then_retries(
        self,
        model_call: mock.Mock,
        run_oracle: mock.Mock,
        _server: mock.Mock,
    ) -> None:
        valid_response = {
            "content": "```c\nint x;\n```",
            "error": None,
            "finish_reason": "stop",
            "reasoning_chars": None,
            "token_usage": {
                "prompt_tokens": 10,
                "completion_tokens": 5,
                "total_tokens": 15,
                "reasoning_tokens": None,
                "cached_prompt_tokens": None,
            },
            "api_usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
            "api_timings": None,
        }
        malformed_response = {
            **valid_response,
            "content": None,
            "error": "choices[0].message.content is not a string",
        }
        scenarios = [
            ("timeout-pass", TimeoutError("timed out"), 0, "pass"),
            ("timeout-fail", TimeoutError("timed out"), 1, "fail"),
            ("malformed-fail", malformed_response, 1, "fail"),
        ]
        for name, first_result, oracle_returncode, final_status in scenarios:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temp_dir:
                model_call.reset_mock(side_effect=True)
                model_call.side_effect = [first_result, valid_response]
                run_oracle.return_value = subprocess.CompletedProcess(
                    args=["oracle"],
                    returncode=oracle_returncode,
                    stdout=(
                        "{}"
                        if oracle_returncode == 0
                        else '{"load":{"returncode":1},"map_setup":[]}'
                    ),
                    stderr="",
                )
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
                            "--repair-attempts",
                            "2",
                        ]
                    )
                self.assertEqual(returncode, 0 if final_status == "pass" else 1)
                summary_path = next(results_dir.rglob("summary.json"))
                summary = json.loads(summary_path.read_text(encoding="utf-8"))
                attempts = summary["results"][0]["attempts"]
                self.assertEqual(
                    [attempt["status"] for attempt in attempts],
                    ["model_error", final_status],
                )
                self.assertEqual(summary["results"][0]["status"], final_status)
                self.assertEqual(summary["results"][0]["attempt"], 2)
                self.assertEqual(model_call.call_count, 2)
                self.assertEqual(summary["policy_checkpoints"][0]["passed"], 0)
                self.assertEqual(
                    summary["policy_checkpoints"][1]["passed"],
                    1 if final_status == "pass" else 0,
                )
                self.assertEqual(
                    audit_results.audit_cost_metrics(
                        path=summary_path,
                        summary=summary,
                        results=summary["results"],
                        require_cost_metrics=True,
                    ),
                    [],
                )


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
