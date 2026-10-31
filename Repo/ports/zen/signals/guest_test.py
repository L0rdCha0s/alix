#!/usr/bin/env python3
"""Bounded isolated guest checks; refuses kernels without native signal support."""
from pathlib import Path
import argparse,subprocess,sys
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2]
parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--mode',choices=['normal','default','badframe','all'],default='normal');parser.add_argument('--timeout',type=int,default=120);args=parser.parse_args()
symbols=subprocess.check_output(['x86_64-elf-nm','--defined-only',str(ROOT/'build/alix.elf')],text=True)
if ' process_signal_return\n' not in symbols or ' g_user_signal_restorer\n' not in symbols:
    raise RuntimeError('Built kernel lacks the reviewed signal implementation; refusing incompatible guest execution')
sys.dont_write_bytecode=True;sys.path.insert(0,str(ROOT/'tests'))
from cpp_runtime_qemu_test import run_native_elf
modes=['normal','default','badframe'] if args.mode=='all' else [args.mode]
for mode in modes:
    markers={'normal':('SIGNAL_KERNEL_TEST: PASS workers=8 cpu_mask=0xFF signals=96 gpr=15 xmm=16 x87=1 alt=1 nested=1 forged=1 redzone=1 async=1 masks=1 sleep=1 stack=1 edited_rsp=1',),
             'default':('SIGNAL_KERNEL_TEST: DEFAULT_ARMED',),'badframe':('SIGNAL_KERNEL_TEST: BADFRAME_ARMED',)}[mode]
    kwargs={}
    if mode == 'default':
        kwargs['expected_signal_termination'] = ('SIGNAL_KERNEL_TEST: DEFAULT_ARMED', 'raise', 15, 143, 0, None)
    elif mode == 'badframe':
        kwargs['expected_exception'] = ('invalid_opcode', 'signal_badframe_probe')
        kwargs['expected_signal_termination'] = ('SIGNAL_KERNEL_TEST: BADFRAME_ARMED', 'fault', 4, 132, 6, 'signal_badframe_probe')
    run_native_elf(str(HERE/'out/signal_kernel_test.elf'),markers,ROOT/f'build/test-out/signal-kernel-{mode}-qemu.log',
                   'Native signal '+mode,args.timeout,arguments=() if mode=='normal' else (mode,),**kwargs)
