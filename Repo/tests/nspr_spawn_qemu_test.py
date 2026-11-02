#!/usr/bin/env python3
"""Execute the actual NSPR native spawn helper against Alix's process services."""
from cpp_runtime_qemu_test import ROOT,run_native_elf
if __name__=='__main__':
    run_native_elf('nspr_spawn_test.elf',
        ('NSPR_SPAWN_TEST: PASS cpus=8 children=25 stdio=1 crossed=1 cloexec=1 environment=1 cwd=1 before_main=1 failure_restore=1 no_fd_leak=1',),
        ROOT/'build/test-out/nspr-spawn-qemu.log','Native NSPR spawn helper',160,
        download_timeout_seconds=20,expected_wait_status=0,fail_on_missing_markers_at_exit=True)
