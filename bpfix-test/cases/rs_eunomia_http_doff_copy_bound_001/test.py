#!/usr/bin/env python3
from __future__ import annotations

import re
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))

from bpf_case import lookup_pinned_map_value
from bpf_case import run_case

XDP_DROP = 1
XDP_PASS = 2
STATS_SIZE = 40


def u32(value: int) -> bytes:
    return value.to_bytes(4, "little")


def stats_value(captured: int, passed: int, hdr_len: int, dport: int, first: int, last: int) -> bytes:
    out = bytearray(STATS_SIZE)
    out[0:8] = captured.to_bytes(8, "little")
    out[8:16] = passed.to_bytes(8, "little")
    out[16:20] = hdr_len.to_bytes(4, "little")
    out[20:22] = dport.to_bytes(2, "little")
    out[22] = first & 0xFF
    out[23] = last & 0xFF
    return bytes(out)


def reset_stats() -> list[tuple[str, bytes, bytes]]:
    return [("stats", u32(0), bytes(STATS_SIZE))]


def stats_matches(expected: bytes):
    def check(map_dir: Path) -> bool:
        value, _ = lookup_pinned_map_value(map_dir, "stats", u32(0))
        return value == expected

    return check


def tcp_packet(
    *,
    dport: int = 443,
    ihl_words: int = 5,
    doff_words: int = 5,
    tcp_options: bytes = b"",
    payload: bytes = b"PAYLOADPAD12",
    truncate_tcp_to: int | None = None,
) -> bytes:
    eth = bytes.fromhex("00112233445566778899aabb") + (0x0800).to_bytes(2, "big")
    ip_options = bytes(range(1, 1 + (ihl_words - 5) * 4))
    sport = 1234
    flags = 0x18
    tcp = (
        sport.to_bytes(2, "big")
        + dport.to_bytes(2, "big")
        + b"\x01\x02\x03\x04"
        + b"\x05\x06\x07\x08"
        + bytes([(doff_words << 4) & 0xF0, flags])
        + b"\x10\x00"
        + b"\x00\x00"
        + b"\x00\x00"
        + tcp_options
    )
    if truncate_tcp_to is not None:
        tcp = tcp[:truncate_tcp_to]
        payload = b""
    total_len = ihl_words * 4 + len(tcp) + len(payload)
    ip = struct.pack(
        "!BBHHHBBHII",
        (4 << 4) | ihl_words,
        0,
        total_len,
        0,
        0,
        64,
        6,
        0,
        0x0A000001,
        0x0A000002,
    )
    return eth + ip + ip_options + tcp + payload


def udp_packet() -> bytes:
    eth = bytes.fromhex("00112233445566778899aabb") + (0x0800).to_bytes(2, "big")
    udp = (10000).to_bytes(2, "big") + (53).to_bytes(2, "big") + b"\0\0\0\0"
    ip = struct.pack("!BBHHHBBHII", 0x45, 0, 28, 0, 0, 64, 17, 0, 0x0A000001, 0x0A000002)
    return eth + ip + udp


def arp_packet() -> bytes:
    return bytes.fromhex("00112233445566778899aabb") + (0x0806).to_bytes(2, "big") + (b"\0" * 42)


def tcp_header_copy_contract(load_output: str) -> bool:
    reserve = load_output.find("call bpf_ringbuf_reserve#131")
    submit = load_output.find("call bpf_ringbuf_submit#132")
    if reserve == -1 or submit == -1 or reserve > submit:
        return False
    region = load_output[reserve:submit]
    packet_loads = re.findall(r"= \*\(u8 \*\)\(r\d+ \+\d+\)", region)
    ringbuf_writes = re.findall(r"\*\(u8 \*\)\(r\d+ \+\d+\) = r\d+", region)
    return len(packet_loads) >= 20 and len(ringbuf_writes) >= 20


def verifier_visible_window_bound(load_output: str) -> bool:
    return (
        "call bpf_ringbuf_reserve#131" in load_output
        and "call bpf_ringbuf_submit#132" in load_output
        and "invalid access to packet" not in load_output
    )


if __name__ == "__main__":
    options = bytes(range(0xA0, 0xAC))
    raise SystemExit(
        run_case(
            argv=sys.argv[1:],
            expected_reject_substrings=[
                "invalid access to packet",
            ],
            functional_tests=[
                (
                    "tcp_without_options_captured",
                    lambda: tcp_packet(dport=443, doff_words=5),
                    XDP_DROP,
                    reset_stats(),
                    [("stats records fixed TCP header", stats_matches(stats_value(1, 0, 20, 443, 0x04, 0x00)))],
                ),
                (
                    "tcp_with_options_captured",
                    lambda: tcp_packet(dport=8443, doff_words=8, tcp_options=options),
                    XDP_DROP,
                    reset_stats(),
                    [
                        (
                            "stats records variable TCP header",
                            stats_matches(stats_value(1, 0, 32, 8443, 0x04, 0xAB)),
                        )
                    ],
                ),
                (
                    "ip_options_tcp_captured",
                    lambda: tcp_packet(dport=9443, ihl_words=6, doff_words=8, tcp_options=options),
                    XDP_DROP,
                    reset_stats(),
                    [
                        (
                            "stats records TCP after IP options",
                            stats_matches(stats_value(1, 0, 32, 9443, 0x04, 0xAB)),
                        )
                    ],
                ),
                (
                    "truncated_tcp_options_pass",
                    lambda: tcp_packet(dport=8443, doff_words=8, tcp_options=options, truncate_tcp_to=24),
                    XDP_PASS,
                    reset_stats(),
                    [("truncated TCP options do not capture", stats_matches(stats_value(0, 1, 0, 0, 0, 0)))],
                ),
                (
                    "udp_pass",
                    udp_packet,
                    XDP_PASS,
                    reset_stats(),
                    [("UDP does not capture", stats_matches(stats_value(0, 1, 0, 0, 0, 0)))],
                ),
                (
                    "arp_pass",
                    arp_packet,
                    XDP_PASS,
                    reset_stats(),
                    [("ARP does not capture", stats_matches(stats_value(0, 1, 0, 0, 0, 0)))],
                ),
            ],
            required_success_substrings=[
                "call bpf_ringbuf_reserve#131",
                "call bpf_ringbuf_submit#132",
                "map=stats,ks=4,vs=40",
            ],
            required_success_predicates=[
                ("TCP header bytes are copied into the ringbuf record", tcp_header_copy_contract),
                ("verifier-visible TCP capture window bound is present", verifier_visible_window_bound),
            ],
        )
    )
