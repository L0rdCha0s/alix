#!/usr/bin/env python3
"""Run Gecko's actual vendored Rust libc FFI in native Alix."""
from cpp_runtime_qemu_test import ROOT, run_native_elf

if __name__ == '__main__':
    run_native_elf('rust_libc_ffi_test.elf',
        ('RUST_LIBC_FFI_TEST: PASS lp64=1 wchar16=1 heap=1 env=1 files=1 offset64=1 pipes=1 sockets=1 netdb=1 fsync=1 memory_pages=1 select=1 resize=1 realpath=1 rmdir=1',),
        ROOT / 'build/test-out/rust-libc-ffi-native-qemu.log', 'Gecko vendored Rust libc FFI', 50,
        expected_wait_status=0, fail_on_missing_markers_at_exit=True)
