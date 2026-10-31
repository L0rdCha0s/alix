#!/usr/bin/env python3
"""Run the high-address fixture only after the reviewed layout reaches the kernel ELF."""
from pathlib import Path
import subprocess
import sys

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
sys.dont_write_bytecode=True

def main():
    symbols=subprocess.check_output(["x86_64-elf-nm","--defined-only",str(ROOT/"build/alix.elf")],text=True)
    values={line.split()[2]:int(line.split()[0],16) for line in symbols.splitlines() if len(line.split())==3}
    if values.get("__alix_user_pointer_limit")!=0x3FFFFFFFFFFF or values.get("__alix_user_stack_size")!=8<<20:
        raise RuntimeError("reviewed 64TiB layout is not present in the built kernel; refusing to boot an incompatible fixture")
    sys.path.insert(0,str(ROOT/"tests"))
    from cpp_runtime_qemu_test import run_native_elf
    run_native_elf(str(ROOT/"ports/zen/upstream/layout-validation/user_layout_test.elf"),
                   ("USER_LAYOUT_TEST: PASS payload=32MiB sparse=12GiB pages=8 workers=8 cpu_mask=0xFF pml4=63,64 tls_high=1 jit=42",),
                   ROOT/"build/test-out/user-layout-qemu.log","Large image and high PML4 native memory layout",180,
                   download_timeout_seconds=90)

if __name__=="__main__":main()
