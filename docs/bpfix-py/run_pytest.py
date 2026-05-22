#!/usr/bin/env python3
"""Run pytest and capture results."""
import sys
import os
import subprocess

os.chdir("/home/yunwei37/workspace/ebpf-verifier-agent")
sys.path.insert(0, "/home/yunwei37/workspace/ebpf-verifier-agent")

result = subprocess.run(
    [sys.executable, "-m", "pytest", "tests/", "-x", "-q", "--tb=short", "--no-header"],
    cwd="/home/yunwei37/workspace/ebpf-verifier-agent",
    capture_output=True,
    text=True,
    timeout=600,
)

output = result.stdout + "\n" + result.stderr
print(output[-15000:])  # Last 15k chars
sys.exit(result.returncode)
