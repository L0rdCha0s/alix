#!/usr/bin/env python3
"""Exercise real Alix compiler stack protection and fail-closed initialization."""
from pathlib import Path
import subprocess
import sys

sys.dont_write_bytecode = True
from cpp_runtime_qemu_test import run_native_elf

ROOT = Path(__file__).resolve().parents[1]


def main():
    run_native_elf("stack_protector_test.elf",
        ("STACK_PROTECTOR_TEST: PASS preinit=1 constructor=1 protected=42",),
        ROOT / "build/test-out/stack-protector-qemu.log",
        "Compiler stack protection before preinit and constructors", 60,
        tcg_cpu="qemu64,+rdrand")
    run_native_elf("stack_protector_test.elf",
        ("ALIX_STACK_PROTECTOR: stack corruption",),
        ROOT / "build/test-out/stack-protector-corrupt-qemu.log",
        "Compiler epilogue detects changed stack guard", 60,
        arguments=("corrupt",), tcg_cpu="qemu64,+rdrand",
        forbidden_markers=("STACK_PROTECTOR_TEST: PASS",))
    run_native_elf("stack_protector_test.elf",
        ("ALIX_STACK_PROTECTOR: entropy unavailable",),
        ROOT / "build/test-out/stack-protector-no-entropy-qemu.log",
        "Protected process terminates without entropy", 60,
        tcg_cpu="qemu64,-rdrand,-rdseed",
        forbidden_markers=("STACK_PROTECTOR_TEST: PASS",
                           "ALIX_STACK_PROTECTOR: stack corruption"))
    run_native_elf("stack_protector_unprotected_test.elf",
        ("STACK_PROTECTOR_UNPROTECTED: PASS",),
        ROOT / "build/test-out/stack-protector-unprotected-qemu.log",
        "Unprotected process runs without entropy", 60,
        tcg_cpu="qemu64,-rdrand,-rdseed",
        forbidden_markers=("ALIX_STACK_PROTECTOR:",))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"Stack protector QEMU test failed: {error}", file=sys.stderr)
        sys.exit(1)
