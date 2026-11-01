#!/usr/bin/env python3
"""Run the real upstream C++ runtime acceptance ELF in Alix."""
from pathlib import Path
import subprocess
import sys

sys.dont_write_bytecode = True
from cpp_runtime_qemu_test import run_native_elf

ROOT = Path(__file__).resolve().parents[1]

if __name__ == "__main__":
    try:
        sys.exit(run_native_elf("libcxx_runtime_test.elf",
            ("CPP_STDLIB_TEST: files PASS threads=8 binary=1 append=1 seek64=1 missing=1",
             "CPP_STDLIB_TEST: main PASS", "CPP_STDLIB_TEST: exit PASS"),
            ROOT / "build/test-out/libcxx-runtime-qemu.log", "Upstream libc++ and libc++abi", 60))
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"C++ standard-library QEMU test failed: {error}", file=sys.stderr)
        sys.exit(1)
