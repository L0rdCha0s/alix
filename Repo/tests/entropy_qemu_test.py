#!/usr/bin/env python3
"""Exercise real guest RDRAND entropy and explicit unsupported-CPU behavior."""
from pathlib import Path
import subprocess
import sys

sys.dont_write_bytecode = True
from cpp_runtime_qemu_test import run_native_elf

ROOT = Path(__file__).resolve().parents[1]

if __name__ == "__main__":
    try:
        run_native_elf("entropy_test.elf", ("ENTROPY_TEST: PASS",),
            ROOT / "build/test-out/entropy-qemu.log", "Native RDRAND entropy", 60,
            tcg_cpu="qemu64,+rdrand")
        run_native_elf("entropy_test.elf", ("ENTROPY_TEST: unsupported PASS",),
            ROOT / "build/test-out/entropy-unsupported-qemu.log", "Unsupported entropy source", 60,
            arguments=("unsupported",), tcg_cpu="qemu64,-rdrand")
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"Entropy QEMU test failed: {error}", file=sys.stderr)
        sys.exit(1)
