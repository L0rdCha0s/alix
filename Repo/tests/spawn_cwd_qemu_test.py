#!/usr/bin/env python3
"""Verify ordered native child cwd actions without process-global mutation."""
from cpp_runtime_qemu_test import ROOT, run_native_elf
if __name__ == "__main__":
    run_native_elf("spawn_cwd_test.elf",
        ("SPAWN_CWD_TEST: PASS cpus=8 children=24 ordered=1 parent_unchanged=1 owned_paths=1 relative_exec=1 PATH=1 before_main=1 failures=1",),
        ROOT / "build/test-out/spawn-cwd-qemu.log", "Native spawn working-directory actions", 150,
        download_timeout_seconds=20, expected_wait_status=0, fail_on_missing_markers_at_exit=True)
