#!/usr/bin/env python3
"""Check native non-TTY classification through the upstream descriptor runtime."""
from pathlib import Path
import subprocess
import sys

sys.dont_write_bytecode = True
from cpp_runtime_qemu_test import run_native_elf

ROOT = Path(__file__).resolve().parents[1]


def main():
    subprocess.run(["make", "all", "build/user/terminal_test.elf"], cwd=ROOT, check=True)
    run_native_elf("terminal_test.elf",
                   ("TERMINAL_TEST: PASS private_fds=1 non_tty=1 closed=1 unchanged=1 speeds=1",),
                   ROOT / "build/test-out/terminal-qemu.log", "Native terminal classification",
                   timeout_seconds=90, forbidden_markers=("TERMINAL_TEST: FAIL",))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"Terminal acceptance failed: {error}", file=sys.stderr)
        sys.exit(1)
