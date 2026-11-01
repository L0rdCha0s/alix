#!/usr/bin/env python3
"""Native multi-CPU/process advisory locking and cancelled-waiter ownership."""
from cpp_runtime_qemu_test import ROOT, run_native_elf

if __name__ == "__main__":
    run_native_elf("flock_test.elf",
        ("FLOCK_NATIVE_TEST: PASS cpus=8 sections=256 shared=1 exclusive=1 aliases=1 close=1 rename=1 inherited=1 reuse=1 eintr=1 killed=1 progress=1 advisory=1",),
        ROOT / "build/test-out/flock-native-qemu.log", "Native file locks", 90,
        expected_wait_status=0, fail_on_missing_markers_at_exit=True)
