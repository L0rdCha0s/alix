#!/usr/bin/env python3
import sys
sys.dont_write_bytecode = True
from cpp_runtime_qemu_test import ROOT, run_native_elf
if __name__ == "__main__":
    run_native_elf("named_fifo_test.elf",
        ("NAMED_FIFO_TEST: PASS cpus=8 records=256 rendezvous=8 unlink=1 nonblock=1 signal=1 killed_opener=1 reservation=1",),
        ROOT / "build/test-out/named-fifo-qemu.log", "native named FIFO namespace and rendezvous", 180,
        expected_wait_status=0, fail_on_missing_markers_at_exit=True)
