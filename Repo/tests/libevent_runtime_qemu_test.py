#!/usr/bin/env python3
"""Run Gecko's configured libevent poll/select backends inside native Alix."""
from cpp_runtime_qemu_test import ROOT, run_native_elf

if __name__ == "__main__":
    run_native_elf("libevent_runtime_test.elf",
        ("LIBEVENT_TEST: PASS cpus=8 poll=8 select=8 timers=1 pipe_wake=1 entropy=1 interface_names=1",),
        ROOT / "build/test-out/libevent-native-qemu.log", "Gecko native libevent", 150,
        expected_wait_status=0, fail_on_missing_markers_at_exit=True)
