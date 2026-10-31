#!/usr/bin/env python3
"""Verify anonymous discard, demand-zero faults and preserved permissions."""
import argparse
from pathlib import Path
import subprocess
import sys

sys.dont_write_bytecode = True
from cpp_runtime_qemu_test import run_native_elf

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--test", choices=("advice", "write", "none", "exec", "all"), default="all")
    choice = parser.parse_args().test
    if choice in ("advice", "all"):
        run_native_elf("thread_vm_advice_test.elf", ("VM_ADVICE_TEST: PASS",),
                       ROOT / "build/test-out/vm-advice-qemu.log", "Anonymous demand-zero discard", 60)
    for mode, error in (("write", 6), ("none", 4), ("exec", 20)):
        if choice in (mode, "all"):
            run_native_elf("thread_vm_advice_test.elf", (f"VM_ADVICE_FAULT: armed fault-{mode}",),
                           ROOT / f"build/test-out/vm-advice-fault-{mode}-qemu.log",
                           f"Discarded page {mode} protection", 60, (f"fault-{mode}",), error)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"VM advice QEMU test failed: {error}", file=sys.stderr)
        sys.exit(1)
