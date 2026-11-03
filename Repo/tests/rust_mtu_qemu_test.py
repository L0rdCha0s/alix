#!/usr/bin/env python3
"""Run Gecko's actual MTU crate against native Alix routing."""
from cpp_runtime_qemu_test import ROOT, run_native_elf

if __name__ == "__main__":
    run_native_elf("rust_mtu_test.elf", (
        "RUST_MTU_TEST: PASS cpus=8 snapshots=512 native_route=1 local=1 default=1 c_abi=1 copy_checks=1 capability_errors=1",
    ), ROOT / "build/test-out/rust-mtu-qemu.log", "Native Gecko MTU route discovery", 100,
        expected_wait_status=0, fail_on_missing_markers_at_exit=True)
