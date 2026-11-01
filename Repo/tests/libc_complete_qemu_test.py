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
    run_native_elf("libc_complete_test.elf", ("LIBC_QUICK_EXIT: PASS",),
                   ROOT / "build/test-out/libc-quick-exit-qemu.log",
                   "Native C11 quick-exit lifecycle", timeout_seconds=60,
                   arguments=("quick",), forbidden_markers=("FORBIDDEN_QUICK_FLUSH", "normal handler"))

    run_native_elf("libc_complete_owned_test.elf", ("LIBC_COMPLETE_TEST: PASS",),
                   ROOT / "build/test-out/libc-complete-owned-qemu.log",
                   "Complete C11 runtime with owned descriptors", timeout_seconds=120)
