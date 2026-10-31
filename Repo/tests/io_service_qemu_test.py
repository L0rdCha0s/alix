#!/usr/bin/env python3
"""Run the optional executor boot test, prove user TLS, then restore normal kernel."""
import inspect
import os
from pathlib import Path
import subprocess
import sys

sys.dont_write_bytecode = True
from cpp_runtime_qemu_test import run_native_elf

ROOT = Path(__file__).resolve().parents[1]


def main():
    if "boot_markers" not in inspect.signature(run_native_elf).parameters:
        raise RuntimeError("native harness needs boot_markers support before this test can run")
    previous = os.environ.get("IO_SERVICE_SELFTEST")
    try:
        # The run-via-agent launch performs another make; preserve this option
        # there as well, even if a dependency changes between build and launch.
        os.environ["IO_SERVICE_SELFTEST"] = "1"
        subprocess.run(["make", "-W", "src/kernel/kernel.c", "all", "IO_SERVICE_SELFTEST=1",
                        "build/user/thread_tls_test.elf"], cwd=ROOT, check=True)
        run_native_elf("thread_tls_test.elf", ("THREAD_TLS_TEST: PASS",),
                       ROOT / "build/test-out/io-service-boot-qemu.log",
                       "Protected I/O boot lifecycle and post-boot TLS", timeout_seconds=90,
                       boot_markers=("IO_SERVICE_TEST: PASS workers=2 cleanup=independent killed_callers=3 "
                                     "late_outputs=2 retained_join=1 waiter_shutdown=1",),
                       forbidden_markers=("IO_SERVICE_TEST: FAIL",))
    finally:
        if previous is None:
            os.environ.pop("IO_SERVICE_SELFTEST", None)
        else:
            os.environ["IO_SERVICE_SELFTEST"] = previous
        # Removing an object from a make dependency list alone does not force
        # relinking. Rebuild kernel.c explicitly in both feature directions.
        subprocess.run(["make", "-W", "src/kernel/kernel.c", "all", "IO_SERVICE_SELFTEST=0"],
                       cwd=ROOT, check=True)
        symbols = subprocess.check_output(["x86_64-elf-nm", "--defined-only", "build/alix.elf"],
                                          cwd=ROOT, text=True)
        if any(line.split()[-1:] == ["io_service_boot_test"] for line in symbols.splitlines()):
            raise RuntimeError("default kernel restoration still contains the optional boot test")
    print("Protected I/O boot acceptance: PASS; ordinary kernel restored")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"I/O executor QEMU test failed: {error}", file=sys.stderr)
        sys.exit(1)
