#!/usr/bin/env python3
"""Execute genuine signal-aware jumps only on a kernel with syscall 67 support."""
from pathlib import Path
import argparse,subprocess,sys
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2]
parser=argparse.ArgumentParser();parser.add_argument('--timeout',type=int,default=120);args=parser.parse_args()
symbols=subprocess.check_output(['x86_64-elf-nm','--defined-only',str(ROOT/'build/alix.elf')],text=True)
if ' process_signal_jump\n' not in symbols:raise RuntimeError('Built kernel lacks reviewed signal checkpoint support')
sys.dont_write_bytecode=True;sys.path.insert(0,str(ROOT/'tests'))
from cpp_runtime_qemu_test import run_native_elf
run_native_elf(str(HERE/'out/signal_jump_test.elf'),
    ('SIGNAL_JUMP_TEST: PASS workers=8 cpu_mask=0xFF hardware=64 repeats=512 value0=1 negative=1 mask0=1 mask1=1 pending=1 nested=1 ancestor=1 fp=1 stale=1 owner=1',),
    ROOT/'build/test-out/signal-jump-qemu.log','Native signal-aware nonlocal jump',args.timeout)
