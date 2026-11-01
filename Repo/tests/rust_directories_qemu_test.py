#!/usr/bin/env python3
"""Run Gecko's real directory-discovery crates in Alix."""
from cpp_runtime_qemu_test import ROOT, run_native_elf

if __name__ == "__main__":
    run_native_elf("rust_directories_test.elf",
        ("RUST_DIRECTORIES_TEST: PASS cpus=8 actual_dirs=1 xdg=1 defaults=1 overrides=1 user_dirs=1 bytes=1 account=1 profile_io=1",),
        ROOT / "build/test-out/rust-directories-qemu.log", "Gecko native directories", 60,
        tcg_cpu="qemu64,+rdrand", expected_wait_status=0, fail_on_missing_markers_at_exit=True)
