#!/usr/bin/env python3
"""Minimal BCC failure-capture pattern for BPFix.

Replace PROGRAM_TEXT with your BPF C source. This snippet focuses on preserving
the load failure text; it is not a complete BCC application.
"""

import subprocess
import sys
import traceback

PROGRAM_TEXT = r"""
int kprobe__do_sys_openat2(void *ctx) {
    return 0;
}
"""


def main() -> int:
    try:
        from bcc import BPF

        BPF(text=PROGRAM_TEXT)
        return 0
    except Exception:
        log = traceback.format_exc()
        with open("verifier.log", "w", encoding="utf-8") as fp:
            fp.write(log)
        print(log, file=sys.stderr)
        subprocess.run(["bpfix", "verifier.log"], check=False)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
