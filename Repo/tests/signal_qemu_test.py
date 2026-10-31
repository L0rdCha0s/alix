#!/usr/bin/env python3
"""Run synchronous C signal dispatch and termination modes in real Alix."""
from pathlib import Path
import subprocess
import sys

sys.dont_write_bytecode = True
from cpp_runtime_qemu_test import run_native_elf

ROOT = Path(__file__).resolve().parents[1]


def main():
    cases = (
        ((), "SIGNAL_TEST: PASS handlers=2048 nested=2 persistent=1", "dispatch"),
        (("default-fpe",), "SIGNAL_TEST: default-fpe armed", "default-fpe"),
        (("abort-handler",), "SIGNAL_TEST: abort-handler PASS", "abort-handler"),
        (("abort-ignored",), "SIGNAL_TEST: abort-ignored armed", "abort-ignored"),
    )
    for arguments, marker, name in cases:
        run_native_elf("signal_test.elf", (marker,),
            ROOT / f"build/test-out/signal-{name}-qemu.log",
            f"Native C signal {name}", 60, arguments=arguments,
            forbidden_markers=("SIGNAL_TEST: PASS handlers=",) if arguments else ())
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"Signal QEMU test failed: {error}", file=sys.stderr)
        sys.exit(1)
