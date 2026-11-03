#!/usr/bin/env python3
import sys
sys.dont_write_bytecode = True
from cpp_runtime_qemu_test import ROOT, run_native_elf

if __name__ == "__main__":
    run_native_elf("base_symlink_test.elf",
        ("BASE_SYMLINK_TEST: PASS cpus=8 exclusive=1 follow=1 nofollow=1 dangling=1 cycle=1 access=1 copy_rollback=1",),
        ROOT / "build/test-out/base-symlink-qemu.log", "native symlink, no-follow and access APIs", 160,
        expected_wait_status=0, fail_on_missing_markers_at_exit=True)
