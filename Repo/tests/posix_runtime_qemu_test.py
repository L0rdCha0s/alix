#!/usr/bin/env python3
"""Verify native semaphores, environment storage and immediate process exit."""
from cpp_runtime_qemu_test import ROOT, run_native_elf

if __name__ == "__main__":
    run_native_elf("posix_runtime_test.elf",
        ("POSIX_RUNTIME_TEST: SEM PASS cpus=8 tokens=20000 payloads=1000 signal=1",
         "POSIX_RUNTIME_TEST: PASS semaphores=1 putenv=1 spawn_snapshot=1 _exit=1"),
        ROOT / "build/test-out/posix-runtime-native-qemu.log", "native POSIX runtime", 65,
        expected_wait_status=0, fail_on_missing_markers_at_exit=True)
