#!/usr/bin/env python3
"""Verify atomic umask, spawn inheritance and exclusive temporary files natively."""
from cpp_runtime_qemu_test import ROOT, run_native_elf

if __name__ == "__main__":
    run_native_elf("creation_modes_test.elf",
        ("CREATION_MODES_TEST: PASS cpus=8 temporary_files=128 atomic_umask=1 spawn=1 file_modes=1 directory_modes=1 shm=1 legacy_abi=1 path_chmod=1 fd_admission=1",),
        ROOT / "build/test-out/creation-modes-qemu.log", "native creation modes and temporary files", 150,
        expected_wait_status=0, fail_on_missing_markers_at_exit=True)
