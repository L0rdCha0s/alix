#!/usr/bin/env python3
"""Execute standard C/C++ interfaces linked to the owned descriptor runtime."""
from pathlib import Path
import subprocess
import sys
sys.dont_write_bytecode=True
from cpp_runtime_qemu_test import run_native_elf
ROOT=Path(__file__).resolve().parents[1]

def main():
    # Rebuild streams after the archive's smoke build; the same exact owned
    # object list feeds C, libc++/abi and the upstream compiler driver.
    subprocess.run(['make','all','build/user/owned_fd_libc_test.elf','zen-cxx-stream-test','zen-cxx-wide-test'],cwd=ROOT,check=True)
    cases=[
        ('owned_fd_libc_test.elf',('OWNED_FD_LIBC_TEST: PASS open=1 shared_offsets=1 fcntl=1 dup3=1 errno=1 stdio=1 redirect=1',),
         'owned-fd-libc-qemu.log','Standard C owned descriptor API','OWNED_LIBC_STDOUT_ONCE'),
        ('libcxx_runtime_test.elf',('CPP_STDLIB_TEST: main PASS','CPP_STDLIB_TEST: exit PASS'),
         'owned-libcxx-runtime-qemu.log','Upstream libc++/abi with owned descriptors',None),
        ('cxx_stream_test.elf',('CXX_STREAM_TEST: PASS workers=8 roundtrips=256 extended80=1',),
         'owned-cxx-stream-qemu.log','Owned narrow C++ streams','CXX_STREAM_TEST: cout PASS'),
        ('cxx_wide_test.elf',('CXX_WIDE_TEST: PASS wchar_bits=16 masks=133120 extended80=1',),
         'owned-cxx-wide-qemu.log','Owned wide C++ streams','CXX_WIDE_TEST: wcout PASS'),
    ]
    for binary,markers,name,label,once in cases:
        log=ROOT/'build/test-out'/name
        run_native_elf(binary,markers,log,label,timeout_seconds=90,
                       forbidden_markers=('OWNED_FD_LIBC_TEST: FAIL','CPP_STDLIB_TEST: main FAIL',
                                          'CPP_STDLIB_TEST: exit FAIL','CXX_STREAM_TEST: FAIL','CXX_WIDE_TEST: FAIL'))
        if once and log.read_text(errors='replace').count(once)!=1:
            raise RuntimeError(f'{label} did not emit standard output exactly once')
    print('Owned C/C++ runtime native acceptance PASS: standard descriptors, errno, ABI lifecycle, narrow/wide streams')
    return 0

if __name__=='__main__':
    try:sys.exit(main())
    except (OSError,RuntimeError,subprocess.SubprocessError) as error:
        print(f'Owned runtime acceptance failed: {error}',file=sys.stderr);sys.exit(1)
