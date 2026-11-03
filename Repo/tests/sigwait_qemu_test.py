#!/usr/bin/env python3
"""Verify native synchronous signals, competing waiters and handler integration."""
from cpp_runtime_qemu_test import ROOT,run_native_elf
if __name__=='__main__':
    run_native_elf('sigwait_test.elf',
        ('SIGWAIT_TEST: PASS cpus=8 directed=512 process_waiters=8 no_handlers=1 coalescing=1 checked_copy=1 retry=1 nested_handler=1 killed_waiter=1',),
        ROOT/'build/test-out/sigwait-qemu.log','Native synchronous signal waiting',130,
        expected_wait_status=0,fail_on_missing_markers_at_exit=True)
