#!/usr/bin/env python3
"""Execute native FD quotas, failed-mutation preservation and spawn inheritance."""
from cpp_runtime_qemu_test import ROOT, run_native_elf
if __name__ == "__main__":
    run_native_elf("fd_limits_test.elf",
        ("FD_LIMITS_CHILD_TEST: PASS inherited=1 high_slots=1 allocation=1 isolated_hard=1",
         "FD_LIMITS_TEST: PASS cpus=8 operations=512 enforced=1 pipes=1 sockets=1 truncate_preserved=1 high_slots=1 spawn=1 checked_copy=1"),
        ROOT / "build/test-out/fd-limits-qemu.log", "Native descriptor limits", 100,
        expected_wait_status=0, fail_on_missing_markers_at_exit=True)
    run_native_elf("fd_limits_legacy_test.elf",
        ("FD_LIMITS_LEGACY_TEST: PASS unsupported=1 private_preserved=1 as_query=1",),
        ROOT / "build/test-out/fd-limits-legacy-qemu.log", "Legacy FD-limit namespace", 35,
        expected_wait_status=0, fail_on_missing_markers_at_exit=True)
