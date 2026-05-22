#!/usr/bin/env python3
"""Run all tests and capture output."""
import subprocess
import sys
import os

os.chdir("/home/yunwei37/workspace/ebpf-verifier-agent")

result = subprocess.run(
    [sys.executable, "-m", "pytest", "tests/", "-x", "-q", "--tb=short"],
    capture_output=True,
    text=True,
    timeout=300
)

with open("/tmp/test_output.txt", "w") as f:
    f.write("=== STDOUT ===\n")
    f.write(result.stdout)
    f.write("\n=== STDERR ===\n")
    f.write(result.stderr)
    f.write(f"\n=== Return code: {result.returncode} ===\n")

print("Done. Output written to /tmp/test_output.txt")
print("Return code:", result.returncode)
print("Last 100 lines of stdout:")
lines = result.stdout.splitlines()
print("\n".join(lines[-100:]))
