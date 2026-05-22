#!/usr/bin/env python3
"""Syntax check all Python source files."""
import sys
import ast
from pathlib import Path

ROOT = Path("/home/yunwei37/workspace/ebpf-verifier-agent")
errors = []

for py_file in sorted(ROOT.rglob("*.py")):
    # Skip cache files and venvs
    if any(part.startswith(".") or part == "__pycache__" or part == "venv"
           for part in py_file.parts):
        continue
    try:
        source = py_file.read_text(encoding="utf-8")
        ast.parse(source, filename=str(py_file))
    except SyntaxError as e:
        errors.append((str(py_file.relative_to(ROOT)), str(e)))
        print(f"SYNTAX ERROR: {py_file.relative_to(ROOT)}: {e}")
    except Exception as e:
        errors.append((str(py_file.relative_to(ROOT)), str(e)))
        print(f"ERROR: {py_file.relative_to(ROOT)}: {e}")

if not errors:
    print("All files have valid syntax!")
else:
    print(f"\n{len(errors)} files with errors.")
sys.exit(len(errors))
