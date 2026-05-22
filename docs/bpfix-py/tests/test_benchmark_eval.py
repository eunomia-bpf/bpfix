from __future__ import annotations

import pytest

from tools.evaluate_benchmark import parse_methods
from tools.sync_external_raw_bench import infer_github_source_kind


def test_parse_methods_accepts_known_subset() -> None:
    assert parse_methods("bpfix, baseline") == ["bpfix", "baseline"]


def test_parse_methods_rejects_unknown_method() -> None:
    with pytest.raises(ValueError, match="unknown methods"):
        parse_methods("bpfix,not_a_method")


def test_commit_raw_ids_use_canonical_prefix() -> None:
    assert infer_github_source_kind("github-commit-cilium-0bf33f653d79", {}) == "github_commit"
    assert infer_github_source_kind("github-cilium-cilium-12345", {}) == "github_issue"
