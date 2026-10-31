#!/usr/bin/env python3
"""Execute the upstream Rust standard library against native Alix services."""
from pathlib import Path
import subprocess
import sys

sys.dont_write_bytecode = True
from cpp_runtime_qemu_test import run_native_elf

ROOT = Path(__file__).resolve().parents[1]

if __name__ == "__main__":
    try:
        sys.exit(run_native_elf("rust_std_test.elf", ("RUST_STD_TEST: PASS",),
            ROOT / "build/test-out/rust-std-qemu.log", "Upstream Rust std", 60,
            tcg_cpu="qemu64,+rdrand"))
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"Rust standard-library QEMU test failed: {error}", file=sys.stderr)
        sys.exit(1)
