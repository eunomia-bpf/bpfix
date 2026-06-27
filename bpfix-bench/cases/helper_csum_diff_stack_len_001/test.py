#!/usr/bin/env python3
from __future__ import annotations

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))

from bpf_case import lookup_pinned_map_value, run_case


def ipv4_udp_packet(src: int, dst: int, payload_len: int = 8) -> bytes:
    eth = bytes.fromhex("00112233445566778899aabb0800")
    total_len = 20 + payload_len
    ip = struct.pack("!BBHHHBBHII", 0x45, 0, total_len, 0, 0, 64, 17, 0, src, dst)
    udp = struct.pack("!HHHH", 12345, 53, payload_len, 0)
    return eth + ip + udp + (b"\x42" * max(payload_len - 8, 0))


def frame(eth_type: int) -> bytes:
    return bytes.fromhex("00112233445566778899aabb") + eth_type.to_bytes(2, "big") + (b"\x00" * 64)


def pseudo_sum(src: int, dst: int, payload_len: int) -> int:
    total = 0
    for word in (src >> 16, src & 0xFFFF, dst >> 16, dst & 0xFFFF, 17, payload_len):
        total += word
        total = (total & 0xFFFF) + (total >> 16)
    total &= 0xFFFF
    return ((total & 0xFF) << 8) | (total >> 8)


def sum_map_equals(expected: int):
    def check(map_dir: Path) -> bool:
        value, _ = lookup_pinned_map_value(map_dir, "sums", struct.pack("<I", 0))
        return value is not None and len(value) >= 4 and struct.unpack("<I", value[:4])[0] == expected

    return check


def truncated_packet() -> bytes:
    return bytes.fromhex("00112233445566778899aabb")


if __name__ == "__main__":
    raise SystemExit(
        run_case(
            argv=sys.argv[1:],
            expected_reject_substrings=[
                "invalid read from stack",
            ],
            functional_tests=[
                (
                    "udp_pseudo_header_sum_v4a",
                    lambda: ipv4_udp_packet(0x0A010203, 0x0A090807),
                    1,
                    [],
                    [
                        (
                            "pseudo checksum includes protocol and length",
                            sum_map_equals(pseudo_sum(0x0A010203, 0x0A090807, 8)),
                        )
                    ],
                ),
                (
                    "udp_pseudo_header_sum_v4b",
                    lambda: ipv4_udp_packet(0xC0000201, 0xC6336402, 12),
                    1,
                    [],
                    [
                        (
                            "pseudo checksum changes with endpoint and length",
                            sum_map_equals(pseudo_sum(0xC0000201, 0xC6336402, 12)),
                        )
                    ],
                ),
                ("arp_passes", lambda: frame(0x0806), 2),
                ("truncated_passes", truncated_packet, 2),
            ],
            required_success_substrings=[
                "call bpf_csum_diff#28",
            ],
        )
    )
