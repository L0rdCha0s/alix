#!/usr/bin/env python3
"""Run the actual Gecko URL crate against native Alix path and file APIs."""
from cpp_runtime_qemu_test import ROOT, run_native_elf

if __name__ == "__main__":
    run_native_elf("rust_file_urls_test.elf",
        ("RUST_FILE_URLS_TEST: PASS cpus=8 actual_url=1 percent=1 unicode=1 raw_bytes=1 local=1 remote_reject=1 nul_reject=1 file_readback=1",),
        ROOT / "build/test-out/rust-file-urls-qemu.log", "Gecko URL file paths", 45,
        expected_wait_status=0, fail_on_missing_markers_at_exit=True)
