#!/usr/bin/env python3
"""Verify native user-to-user argv launch and real child waiting on eight CPUs."""
from pathlib import Path
import subprocess
import sys
sys.dont_write_bytecode = True
from cpp_runtime_qemu_test import run_native_elf
ROOT = Path(__file__).resolve().parents[1]

def main():
    subprocess.run(["make", "all", "build/user/process_spawn_test.elf"], cwd=ROOT, check=True)
    run_native_elf("process_spawn_test.elf",
                   ("PROCESS_SPAWN_TEST: PASS private_inherit=1 argv=1 cwd=1 EOF_before_wait=1 status=1 WNOHANG=1 copy_rollback=1 waiters=8 orphan=1 killed_waiter=1",),
                   ROOT / "build/test-out/process-spawn-qemu.log", "Native child launch and wait", timeout_seconds=150,
                   forbidden_markers=("PROCESS_SPAWN_TEST: FAIL",), download_timeout_seconds=20)
    return 0

if __name__ == "__main__":
    try: sys.exit(main())
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"Native process acceptance failed: {error}", file=sys.stderr); sys.exit(1)
