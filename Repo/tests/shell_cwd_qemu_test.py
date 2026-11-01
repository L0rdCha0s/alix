#!/usr/bin/env python3
"""Run the optional two-session cwd fixture and restore the ordinary kernel."""
import os,subprocess,sys
from pathlib import Path
sys.dont_write_bytecode=True
from cpp_runtime_qemu_test import run_native_elf
ROOT=Path(__file__).resolve().parents[1]
def main():
    previous=os.environ.get('SHELL_CWD_SELFTEST')
    try:
        os.environ['SHELL_CWD_SELFTEST']='1'
        subprocess.run(['make','-W','src/kernel/kernel.c','all','SHELL_CWD_SELFTEST=1','build/user/thread_tls_test.elf'],cwd=ROOT,check=True)
        run_native_elf('thread_tls_test.elf',('THREAD_TLS_TEST: PASS',),ROOT/'build/test-out/shell-cwd-qemu.log',
                       'Independent shell-session cwd and post-boot TLS',timeout_seconds=90,
                       boot_markers=('SHELL_CWD_TEST: PASS sessions=2 independent_relative=1 owner_changes=1 close=1',),
                       forbidden_markers=('SHELL_CWD_TEST: FAIL',))
    finally:
        if previous is None:os.environ.pop('SHELL_CWD_SELFTEST',None)
        else:os.environ['SHELL_CWD_SELFTEST']=previous
        subprocess.run(['make','-W','src/kernel/kernel.c','all','SHELL_CWD_SELFTEST=0'],cwd=ROOT,check=True)
        symbols=subprocess.check_output(['x86_64-elf-nm','--defined-only','build/alix.elf'],cwd=ROOT,text=True)
        if any(line.split()[-1:]==['shell_cwd_boot_test'] for line in symbols.splitlines()):
            raise RuntimeError('normal kernel still contains shell cwd boot fixture')
    print('Two-session native cwd acceptance PASS; ordinary kernel restored')
    return 0
if __name__=='__main__':
    try:sys.exit(main())
    except (OSError,RuntimeError,subprocess.SubprocessError) as error:
        print(f'Shell cwd native acceptance failed: {error}',file=sys.stderr);sys.exit(1)
