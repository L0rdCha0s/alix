#!/usr/bin/env python3
"""Native bounded pipes, event readiness, atomic SMP writes and SIGPIPE."""
from pathlib import Path
import subprocess
import sys

sys.dont_write_bytecode = True
from cpp_runtime_qemu_test import run_native_elf

ROOT = Path(__file__).resolve().parents[1]


def main():
    subprocess.run(["make", "all", "build/user/pipe_test.elf"], cwd=ROOT, check=True)
    run_native_elf("pipe_test.elf",
                   ("PIPE_TEST: PASS workers=8 records=512 atomic4096=1 wrap=1 idle_reads=3 EOF=1 SIGPIPE=1 pair_rollback=1",),
                   ROOT / "build/test-out/pipe-qemu.log", "Native owned pipes", timeout_seconds=120,
                   forbidden_markers=("PIPE_TEST: FAIL",))
    run_native_elf("pipe_test.elf", ("PIPE_TEST: default armed",),
                   ROOT / "build/test-out/pipe-default-qemu.log", "Native default SIGPIPE", timeout_seconds=90,
                   arguments=("default",), forbidden_markers=("PIPE_TEST: FAIL",),
                   expected_signal_termination=("PIPE_TEST: default armed", "raise", 13, 141, 0, None))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"Pipe acceptance failed: {error}", file=sys.stderr)
        sys.exit(1)
