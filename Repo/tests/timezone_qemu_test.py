#!/usr/bin/env python3
"""Exercise POSIX rules and actual TZif file loading/formatting in Alix."""
from pathlib import Path
import subprocess
import sys

sys.dont_write_bytecode = True
from cpp_runtime_qemu_test import run_native_elf

ROOT = Path(__file__).resolve().parents[1]

if __name__ == "__main__":
    try:
        sys.exit(run_native_elf("timezone_test.elf",
            ("TIMEZONE_TEST: PASS workers=8 cpu_mask=0xFF tzif_samples=63 posix=1 fold=1 gap=1 format=1",),
            ROOT / "build/test-out/timezone-qemu.log",
            "Native timezone rules, TZif data and calendar formatting", 90))
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"Timezone QEMU test failed: {error}", file=sys.stderr)
        sys.exit(1)
