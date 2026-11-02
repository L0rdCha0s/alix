#!/usr/bin/env python3
"""Exercise actual NSPR resource objects on native and unavailable entropy CPUs."""
from cpp_runtime_qemu_test import ROOT, run_native_elf

if __name__ == "__main__":
    run_native_elf("nspr_resources_test.elf",
        ("NSPR_RESOURCES_TEST: PASS cpus=8 samples=512 memory=1 native_entropy=1 short_results=1 fd_pressure=1 checked_copy=1",),
        ROOT / "build/test-out/nspr-resources-qemu.log", "NSPR native resource APIs", 60,
        tcg_cpu="qemu64,+rdrand", expected_wait_status=0, fail_on_missing_markers_at_exit=True)
    run_native_elf("nspr_resources_test.elf",
        ("NSPR_RESOURCES_TEST: unsupported PASS error=1 output_unchanged=1 memory=1 cpus=8",),
        ROOT / "build/test-out/nspr-resources-unsupported-qemu.log", "NSPR unavailable entropy", 40,
        arguments=("unsupported",), tcg_cpu="qemu64,-rdrand", expected_wait_status=0,
        fail_on_missing_markers_at_exit=True)
