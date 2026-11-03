#!/usr/bin/env python3
"""Verify shared POSIX sleep and caught-signal interruption on eight CPUs."""
from cpp_runtime_qemu_test import ROOT, run_native_elf

if __name__ == "__main__":
    run_native_elf("sleep_test.elf",
        ("SLEEP_TEST: PASS cpus=8 normal=8 interrupted=16 restart=1 uint_max=1 zero=1 errno=1",),
        ROOT / "build/test-out/sleep-native-qemu.log", "native POSIX sleep", 90,
        expected_wait_status=0, fail_on_missing_markers_at_exit=True)
