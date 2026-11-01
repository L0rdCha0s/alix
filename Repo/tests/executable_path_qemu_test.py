#!/usr/bin/env python3
"""Verify native executable discovery independently of argv and cwd."""
from cpp_runtime_qemu_test import ROOT, run_native_elf

if __name__ == '__main__':
    run_native_elf('executable_path_test.elf',
        ('EXECUTABLE_PATH_TEST: CHILD PASS constructor=1 argv_independent=1 cwd_independent=1 long_name=1',
         'EXECUTABLE_PATH_TEST: PASS kernel_loader=1 spawn=1 search=1 constructor=1 rename_snapshot=1 reply_checks=1'),
        ROOT / 'build/test-out/executable-path-native-qemu.log', 'native executable path discovery', 50,
        expected_wait_status=0, fail_on_missing_markers_at_exit=True)
