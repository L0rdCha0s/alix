#!/usr/bin/env python3
"""Verify native file resize and checked VFS path operations on eight CPUs."""
from cpp_runtime_qemu_test import ROOT, run_native_elf

if __name__ == "__main__":
    run_native_elf("filesystem_primitives_test.elf",
        ("FS_PRIMITIVES_TEST: PASS cpus=8 resize=1 zero_fill=1 shared_offset=1 shared_node=1 realpath=1 rmdir=1 copy_checks=1",),
        ROOT / "build/test-out/filesystem-primitives-qemu.log", "native filesystem primitives", 75,
        expected_wait_status=0, fail_on_missing_markers_at_exit=True)
