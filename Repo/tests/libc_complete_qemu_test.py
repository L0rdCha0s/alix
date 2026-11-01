#!/usr/bin/env python3
"""Run the C11 runtime acceptance fixture in an isolated eight-CPU Alix guest."""
from pathlib import Path
import sys

sys.dont_write_bytecode = True
from cpp_runtime_qemu_test import run_native_elf

ROOT = Path(__file__).resolve().parents[1]

if __name__ == "__main__":
    run_native_elf("libc_complete_test.elf", ("LIBC_COMPLETE_TEST: PASS",),
                   ROOT / "build/test-out/libc-complete-qemu.log",
                   "Native C11 libc, math, complex and threads", timeout_seconds=120)
