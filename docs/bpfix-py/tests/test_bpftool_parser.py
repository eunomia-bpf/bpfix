from __future__ import annotations

from bpfix.extractor.bpftool_parser import parse_bpftool_xlated_linum


def test_parse_bpftool_xlated_linum_extracts_instruction_mapping() -> None:
    mappings = parse_bpftool_xlated_linum(
        """
        int __sys_bpf(int cmd, ...) {
           0: (bf) r6 = r1
           ; int __sys_bpf(int cmd, union bpf_attr __user *uattr, unsigned int size) @ bpf/syscall.c:5765:12
           1: (79) r7 = *(u64 *)(r6 +0)
           2: (79) r8 = *(u64 *)(r6 +8)
           ; if (cmd == BPF_MAP_CREATE) @ bpf/syscall.c:5768:6
           3: (15) if r7 == 0x0 goto pc+2
        }
        """
    )

    assert sorted(mappings) == [0, 1, 2, 3]
    assert mappings[0].bytecode == 'r6 = r1'
    assert mappings[0].source_file is None
    assert mappings[1].bytecode == 'r7 = *(u64 *)(r6 +0)'
    assert mappings[1].source_text == (
        'int __sys_bpf(int cmd, union bpf_attr __user *uattr, unsigned int size)'
    )
    assert mappings[1].source_file == 'bpf/syscall.c'
    assert mappings[1].source_line == 5765
    assert mappings[1].source_column == 12
    assert mappings[2].source_line == 5765
    assert mappings[3].source_text == 'if (cmd == BPF_MAP_CREATE)'
    assert mappings[3].source_file == 'bpf/syscall.c'
    assert mappings[3].source_line == 5768
    assert mappings[3].source_column == 6
