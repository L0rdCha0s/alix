#!/usr/bin/env python3
"""Execute actual NSPR metadata converters and open typedef in native Alix."""
from cpp_runtime_qemu_test import ROOT, run_native_elf

if __name__ == "__main__":
    run_native_elf("nspr_file_abi_test.elf",
        ("NSPR_FILE_ABI_TEST: PASS open64=1 high_flags=1 stat=1 seconds=1 size64=1 overflow=1 nonblock=1 sync=1 fd_limits=1 mmap=1 msync=1",),
        ROOT / "build/test-out/nspr-file-abi-qemu.log", "NSPR native file ABI", 40,
        expected_wait_status=0, fail_on_missing_markers_at_exit=True)
