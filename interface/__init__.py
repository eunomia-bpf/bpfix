"""Compatibility imports for the pre-package-refactor `interface` namespace.

New code should import from `bpfix`.
"""

from __future__ import annotations

import sys

import bpfix
from bpfix import SCHEMA_PATH, build_diagnostic, generate_diagnostic, load_schema
from bpfix import api, baseline, catalogs, extractor, schema

sys.modules.setdefault(__name__ + ".api", api)
sys.modules.setdefault(__name__ + ".baseline", baseline)
sys.modules.setdefault(__name__ + ".catalogs", catalogs)
sys.modules.setdefault(__name__ + ".extractor", extractor)
sys.modules.setdefault(__name__ + ".schema", schema)

__all__ = [
    "SCHEMA_PATH",
    "build_diagnostic",
    "generate_diagnostic",
    "load_schema",
]
