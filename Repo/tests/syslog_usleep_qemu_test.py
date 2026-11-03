#!/usr/bin/env python3
import sys
sys.dont_write_bytecode = True
from cpp_runtime_qemu_test import ROOT, run_native_elf

if __name__ == "__main__":
    run_native_elf("syslog_usleep_test.elf",
        ("SYSLOG_USLEEP_TEST: PASS cpus=8 records=128 journal=1 mask=1 errno=1 fd_independent=1 timers=8 interrupts=8 max_delay=1",),
        ROOT / "build/test-out/syslog-usleep-qemu.log", "native syslog and interruptible usleep", 150,
        expected_wait_status=0, fail_on_missing_markers_at_exit=True)
