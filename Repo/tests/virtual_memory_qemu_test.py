#!/usr/bin/env python3
"""Verify native VM behavior, safe copies and hardware permission faults."""
import argparse
from pathlib import Path
import subprocess
import sys

sys.dont_write_bytecode = True
from cpp_runtime_qemu_test import run_native_elf

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--test", choices=("vm", "copy", "write", "none", "exec", "all"), default="all")
    choice = parser.parse_args().test
    if choice in ("vm", "all"):
        run_native_elf("virtual_memory_test.elf", ("VM_PLATFORM_TEST: PASS", "noreserve=8GiB"),
                       ROOT / "build/test-out/virtual-memory-qemu.log", "Anonymous VM and native JIT", 60)
    if choice in ("copy", "all"):
        run_native_elf("user_copy_test.elf", ("USER_COPY_TEST: PASS",),
                       ROOT / "build/test-out/user-copy-qemu.log", "Protected user-copy races", 60)
    for mode, error in (("write", 7), ("none", 4), ("exec", 21)):
        if choice in (mode, "all"):
            run_native_elf("virtual_memory_test.elf", (f"VM_FAULT_TEST: armed {mode}",),
                           ROOT / f"build/test-out/vm-fault-{mode}-qemu.log",
                           f"Hardware {mode} protection", 60, (f"fault-{mode}",), error)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"VM QEMU test failed: {error}", file=sys.stderr)
        sys.exit(1)
