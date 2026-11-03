#!/usr/bin/env python3
"""Execute environment, descriptor actions, PATH and signal attributes natively."""
from pathlib import Path
import subprocess
import sys
sys.dont_write_bytecode = True
from cpp_runtime_qemu_test import run_native_elf
ROOT = Path(__file__).resolve().parents[1]

def main():
    subprocess.run(["make", "-W", "include/process_internal.h", "-W", "include/syscall_defs.h",
                    "all", "build/user/posix_spawn_test.elf", "build/user/process_spawn_test.elf"], cwd=ROOT, check=True)
    run_native_elf("posix_spawn_test.elf",
                   ("POSIX_SPAWN_DEFAULT: PASS child_snapshot=1 source_before_filter=1 parent_untouched=1",
                    "POSIX_SPAWN_TEST: PASS environment_before_main=1 actions=1 cloexec_order=1 self_dup=1 PATH=1 signals=1 errors=1"),
                   ROOT / "build/test-out/posix-spawn-qemu.log", "Native POSIX spawn and startup environment", timeout_seconds=150,
                   forbidden_markers=("POSIX_SPAWN_TEST: FAIL",), download_timeout_seconds=20)
    run_native_elf("process_spawn_test.elf",
                   ("PROCESS_SPAWN_TEST: PASS private_inherit=1 argv=1 cwd=1 EOF_before_wait=1 status=1 WNOHANG=1 copy_rollback=1 waiters=8 orphan=1 killed_waiter=1",),
                   ROOT / "build/test-out/process-spawn-qemu.log", "Native process lifecycle regression", timeout_seconds=150,
                   forbidden_markers=("PROCESS_SPAWN_TEST: FAIL",), download_timeout_seconds=20)
    return 0

if __name__ == "__main__":
    try: sys.exit(main())
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"POSIX spawn acceptance failed: {error}", file=sys.stderr); sys.exit(1)
