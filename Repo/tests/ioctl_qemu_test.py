#!/usr/bin/env python3
"""Exercise owned ioctl operations and legacy namespace rejection in Alix."""
from cpp_runtime_qemu_test import ROOT, run_native_elf

if __name__ == "__main__":
    run_native_elf("ioctl_test.elf",
        ("IOCTL_TEST: PASS cpus=8 snapshots=768 pipes=1 files=1 nonblock=1 cloexec=1 exact_copy=1 errors=1 eof=1",),
        ROOT / "build/test-out/ioctl-native-qemu.log", "Native descriptor controls", 90,
        expected_wait_status=0, fail_on_missing_markers_at_exit=True)
    run_native_elf("ioctl_legacy_test.elf",
        ("IOCTL_LEGACY_TEST: PASS unsupported=1 namespace_preserved=1",),
        ROOT / "build/test-out/ioctl-legacy-qemu.log", "Legacy ioctl rejection", 30,
        expected_wait_status=0, fail_on_missing_markers_at_exit=True)
