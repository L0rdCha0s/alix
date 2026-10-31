#!/usr/bin/env python3
"""Run protected VFS boot cancellation plus user readlink; restore normal image."""
import os
from pathlib import Path
import subprocess
import sys

sys.dont_write_bytecode=True
from cpp_runtime_qemu_test import run_native_elf

ROOT=Path(__file__).resolve().parents[1]

def main():
    previous=os.environ.get("IO_VFS_SELFTEST")
    force=["-W","src/kernel/kernel.c","-W","src/kernel/vfs.c","-W","src/kernel/io/vfs_service.c"]
    try:
        os.environ["IO_VFS_SELFTEST"]="1"
        subprocess.run(["make",*force,"all","IO_VFS_SELFTEST=1","build/user/readlink_test.elf"],cwd=ROOT,check=True)
        run_native_elf("readlink_test.elf",("READLINK_TEST: PASS",),
                       ROOT/"build/test-out/vfs-owned-bridge-qemu.log",
                       "Real protected VFS cancellation and READLINK66",timeout_seconds=90,
                       boot_markers=("VFS_IO_TEST: PASS real_symlinks=1 cwd=1 target_limit=4095 killed_blocked_caller=1 fresh_call=1",),
                       forbidden_markers=("VFS_IO_TEST: FAIL","READLINK_TEST: FAIL"))
    finally:
        if previous is None: os.environ.pop("IO_VFS_SELFTEST",None)
        else: os.environ["IO_VFS_SELFTEST"]=previous
        # Both conditional VFS probes and the weak boot object must disappear;
        # removal of a make dependency/flag alone does not force recompilation.
        subprocess.run(["make",*force,"all","IO_VFS_SELFTEST=0"],cwd=ROOT,check=True)
        symbols=subprocess.check_output(["x86_64-elf-nm","--defined-only","build/alix.elf"],cwd=ROOT,text=True)
        forbidden={"vfs_io_boot_test","vfs_selftest_lock_tree","vfs_selftest_unlock_tree","io_vfs_selftest_active_handlers"}
        if any(line.split() and line.split()[-1] in forbidden for line in symbols.splitlines()):
            raise RuntimeError("ordinary kernel still contains an optional VFS test hook")
    print("Protected VFS/readlink native acceptance PASS; ordinary kernel restored")
    return 0

if __name__=="__main__":
    try: sys.exit(main())
    except (OSError,RuntimeError,subprocess.SubprocessError) as error:
        print(f"VFS native acceptance failed: {error}",file=sys.stderr);sys.exit(1)
