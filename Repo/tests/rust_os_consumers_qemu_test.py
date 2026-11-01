#!/usr/bin/env python3
"""Run real Gecko OS consumers against native Alix services."""
from cpp_runtime_qemu_test import ROOT, run_native_elf

if __name__ == "__main__":
    run_native_elf("rust_os_consumers_test.elf",
        ("RUST_OS_CONSUMERS_TEST: PASS cpus=8 actual_glean=1 records=256 errno_tls=8 c_abi=1 strerror=1 wide_paths=1 signal_probe=1",),
        ROOT / "build/test-out/rust-os-consumers-qemu.log", "Gecko Rust OS consumers", 60,
        expected_wait_status=0, fail_on_missing_markers_at_exit=True)
