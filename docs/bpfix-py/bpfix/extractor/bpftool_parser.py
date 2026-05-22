"""Parse `bpftool prog dump xlated linum` output into instruction-indexed mappings."""

from __future__ import annotations

import re
from dataclasses import dataclass


INSTRUCTION_RE = re.compile(
    r"^\s*(?P<idx>\d+):\s*\((?P<opcode>[0-9a-fA-F]{2})\)\s*(?P<body>.*)$"
)
SOURCE_ANNOTATION_RE = re.compile(
    r"^(?P<source_text>.*?)(?:\s*@\s*(?P<file>.+?):(?P<line>\d+)(?::(?P<column>\d+))?)?\s*$"
)


@dataclass(slots=True)
class BpftoolSourceAnnotation:
    source_text: str | None = None
    source_file: str | None = None
    source_line: int | None = None
    source_column: int | None = None


@dataclass(slots=True)
class BpftoolInstructionMapping:
    insn_idx: int
    bytecode: str
    source_text: str | None = None
    source_file: str | None = None
    source_line: int | None = None
    source_column: int | None = None


def parse_bpftool_xlated_linum(output: str) -> dict[int, BpftoolInstructionMapping]:
    """Return an instruction-indexed view of `bpftool prog dump xlated linum` output."""

    mappings: dict[int, BpftoolInstructionMapping] = {}
    active_source: BpftoolSourceAnnotation | None = None

    for raw_line in output.splitlines():
        stripped = raw_line.strip()
        if not stripped:
            continue

        if stripped.startswith(";"):
            active_source = _parse_source_annotation(stripped[1:].strip())
            continue

        instruction_match = INSTRUCTION_RE.match(raw_line)
        if instruction_match is None:
            continue

        insn_idx = int(instruction_match.group("idx"))
        mapping = BpftoolInstructionMapping(
            insn_idx=insn_idx,
            bytecode=instruction_match.group("body").strip(),
        )
        if active_source is not None:
            mapping.source_text = active_source.source_text
            mapping.source_file = active_source.source_file
            mapping.source_line = active_source.source_line
            mapping.source_column = active_source.source_column
        mappings[insn_idx] = mapping

    return mappings


def _parse_source_annotation(text: str) -> BpftoolSourceAnnotation:
    match = SOURCE_ANNOTATION_RE.match(text.strip())
    if match is None:
        return BpftoolSourceAnnotation(source_text=text.strip() or None)

    source_text = (match.group("source_text") or "").strip() or None
    source_line = match.group("line")
    source_column = match.group("column")
    return BpftoolSourceAnnotation(
        source_text=source_text,
        source_file=match.group("file"),
        source_line=int(source_line) if source_line is not None else None,
        source_column=int(source_column) if source_column is not None else None,
    )
