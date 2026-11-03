#!/usr/bin/env python3
"""Execute actual RLBox memory/minWASI, CPU clocks and WABT traps in Alix."""
from cpp_runtime_qemu_test import ROOT, run_native_elf

if __name__ == "__main__":
    run_native_elf("rlbox_runtime_test.elf", (
        "RLBOX_RUNTIME_TEST: PASS cpus=8 clocks=4 thread_cpu=1 process_cpu=1 sleep_excluded=1 alignment_8g=1 reserved_guard=1 minwasi=1 traps=8 cleanup=1",
    ), ROOT / "build/test-out/rlbox-runtime-qemu.log", "Native RLBox memory/minWASI and CPU clocks", 160,
        expected_wait_status=0, fail_on_missing_markers_at_exit=True)
    run_native_elf("rlbox_runtime_test.elf", ("VM_FAULT_TEST: armed write",),
        ROOT / "build/test-out/rlbox-guard-qemu.log", "Native RLBox hardware guard", 80,
        arguments=("guard",), expected_fault=6)
