#!/usr/bin/env python3
"""Run native waitid status, non-consuming claims and concurrent reaping."""
from cpp_runtime_qemu_test import ROOT, run_native_elf

if __name__ == "__main__":
    run_native_elf("waitid_test.elf",
        ("WAITID_TEST: PASS cpus=8 peeks=64 mixed_reap=1 nohang=1 copy_rollback=1 signal=1 killed_waiter=1",),
        ROOT / "build/test-out/waitid-native-qemu.log", "native waitid and WNOWAIT", 150,
        expected_wait_status=0, fail_on_missing_markers_at_exit=True)
