#!/usr/bin/env python3
"""Real POSIX record locking, separate processes and killed-owner cleanup in Alix."""
from cpp_runtime_qemu_test import ROOT,run_native_elf
import json

if __name__=='__main__':
    run_native_elf('record_lock_test.elf',(
        'RECORD_LOCK_TEST: PASS cpus=8 operations=512 children=3 getlk=1 shared=1 split=1 offsets=1 close_any=1 dup2=1 killed_holder=1 killed_waiter=1 fresh_progress=1 copy_checks=1 utimes=1',
    ),ROOT/'build/test-out/record-lock-qemu.log','Native POSIX record locks',180,
        expected_wait_status=0,fail_on_missing_markers_at_exit=True)
    output=ROOT/'build/test-out'
    (output/'record-lock.acceptance.json').write_text(json.dumps({
        'scope':'Native POSIX record-lock primitives and utimes; complete browser separate',
        'cpus':8,'lock_rounds':512,'spawned_children':3,'killed_holder':True,'killed_waiter':True,
        'close_any_fd':True,'dup2_release':True,'getlk_readonly_fd':True,
        'boot':json.loads((output/'record-lock-qemu.boot-image.json').read_text()),
    },indent=2)+'\n')
