#!/usr/bin/env python3
"""Native gather writes, shared offsets and atomic pipe records on eight CPUs."""
from cpp_runtime_qemu_test import ROOT,run_native_elf
if __name__=='__main__':
    run_native_elf('writev_test.elf',
        ('WRITEV_TEST: PASS cpus=8 pipe_records=512 append_records=512 checked_copy=1 overflow=1 short_prefix=1 nonblock=1 sigpipe=1',),
        ROOT/'build/test-out/writev-qemu.log','Native gathered writes',120,
        expected_wait_status=0,fail_on_missing_markers_at_exit=True)
