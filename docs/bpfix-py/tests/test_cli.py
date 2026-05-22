from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]


def test_python_m_bpfix_emits_json_for_case_manifest() -> None:
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "bpfix",
            str(ROOT / "bpfix-bench" / "raw" / "so" / "stackoverflow-60053570.yaml"),
            "--format",
            "json",
        ],
        check=False,
        capture_output=True,
        text=True,
        cwd=ROOT,
    )

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["error_id"] == "BPFIX-E001"
    assert payload["failure_class"] == "source_bug"
