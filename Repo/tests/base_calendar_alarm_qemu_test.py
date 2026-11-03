#!/usr/bin/env python3
import sys
sys.dont_write_bytecode = True
from cpp_runtime_qemu_test import ROOT, run_native_elf

if __name__ == "__main__":
    run_native_elf("base_calendar_alarm_test.elf",
        ("BASE_CALENDAR_ALARM_TEST: PASS cpus=8 roundtrips=49152 directory_entries=32 alarm=1 blocked=1 replacement=1024 exit_cleanup=1 stat64=1",),
        ROOT / "build/test-out/base-calendar-alarm-qemu.log", "native calendar, alarm and directory APIs", 180,
        expected_wait_status=0, fail_on_missing_markers_at_exit=True)
