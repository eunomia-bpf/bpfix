"""Public Python package surface for BPFix."""

from __future__ import annotations

from .api import SCHEMA_PATH, build_diagnostic, load_schema
from .cli import build_parser, main
from .extractor import generate_diagnostic


__version__ = "0.1.0"

__all__ = [
    "SCHEMA_PATH",
    "build_diagnostic",
    "build_parser",
    "generate_diagnostic",
    "load_schema",
    "main",
]
