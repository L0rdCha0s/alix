#!/usr/bin/env python3
"""Exercise the pinned musl random family with native mutexes on eight CPUs."""
from cpp_runtime_qemu_test import ROOT, run_native_elf

if __name__ == "__main__":
    run_native_elf("random_test.elf",
        ("RANDOM_TEST: PASS cpus=8 calls=1024 states=6 range=31 reseed=1 rand_independent=1",),
        ROOT / "build/test-out/random-native-qemu.log", "native POSIX random family", 120,
        expected_wait_status=0, fail_on_missing_markers_at_exit=True)
