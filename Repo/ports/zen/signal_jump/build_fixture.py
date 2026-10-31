#!/usr/bin/env python3
from pathlib import Path
import argparse,json,subprocess
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2];OUT=HERE/'out';OUT.mkdir(exist_ok=True)
parser=argparse.ArgumentParser();parser.add_argument('--active',action='store_true');args=parser.parse_args()
if not args.active:subprocess.run(['python3',str(HERE/'compile_pending.py')],check=True)
headers=ROOT/'include' if args.active else OUT/'include';user=ROOT/'user/lib' if args.active else OUT/'user/lib'
flags=['-std=c11','-O2','-g','-ffreestanding','-fno-builtin','-fno-stack-protector','-fno-pic','-m64','-mno-red-zone','-mcmodel=large','-ftls-model=local-exec','-fshort-wchar','-frounding-math','-Wall','-Wextra','-Werror','-I'+str(headers),'-I'+str(user)]
objects=[]
for name in ['signal_jump_test.c','signal_jump_probe.S']:
 path=OUT/(Path(name).stem+'.o');subprocess.run(['x86_64-elf-gcc',*flags,'-c',str(HERE/name),'-o',str(path)],check=True);objects.append(str(path))
runtime=json.loads((ROOT/'ports/zen/upstream/alix-toolchain/runtime-objects.json').read_text())
if not args.active:runtime=[str(OUT/('user_'+Path(path).name)) if Path(path).name in {'syscall.o','setjmp.o'} else path for path in runtime]
binary=OUT/'signal_jump_test.elf';subprocess.run(['x86_64-elf-ld','-nostdlib','-z','noexecstack','-T',str(ROOT/'user/lib/link.ld'),'-o',str(binary),*runtime,*objects],check=True)
assert not subprocess.check_output(['x86_64-elf-nm','--undefined-only',str(binary)],text=True).strip()
print('Native signal-jump fixture linked; guest execution pending: '+str(binary))
