#!/usr/bin/env python3
"""Link a native signal fixture; a reviewed signal-enabled kernel is required."""
from pathlib import Path
import argparse,json,subprocess
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2];OUT=HERE/'out'
parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--active',action='store_true');args=parser.parse_args()
if not args.active:subprocess.run(['python3',str(HERE/'compile_pending.py')],check=True)
OUT.mkdir(exist_ok=True)
headers=ROOT/'include' if args.active else OUT/'include'
user=ROOT/'user/lib' if args.active else OUT/'user/lib'
flags=['-std=c11','-O2','-g','-ffreestanding','-fno-builtin','-fno-stack-protector','-fno-pic','-m64','-mno-red-zone','-mcmodel=large','-ftls-model=local-exec','-fshort-wchar','-Wall','-Wextra','-Werror','-I'+str(headers),'-I'+str(user)]
objects=[]
for name in ['signal_kernel_test.c','signal_context_probe.S']:
    path=OUT/(Path(name).stem+'.o');subprocess.run(['x86_64-elf-gcc',*flags,'-c',str(HERE/name),'-o',str(path)],check=True);objects.append(str(path))
runtime=json.loads((ROOT/'ports/zen/upstream/alix-toolchain/runtime-objects.json').read_text())
if not args.active:runtime=[str(OUT/Path(path).name) if Path(path).name in {'signal.o','syscall.o','libc.o','pthread.o'} else path for path in runtime]
binary=OUT/'signal_kernel_test.elf'
subprocess.run(['x86_64-elf-ld','-nostdlib','-z','noexecstack','-T',str(ROOT/'user/lib/link.ld'),'-o',str(binary),*runtime,*objects],check=True)
assert not subprocess.check_output(['x86_64-elf-nm','--undefined-only',str(binary)],text=True).strip()
print('Native signal fixture linked: '+str(binary))
print('Guest proof pending; only run on a reviewed/applied signal-enabled kernel.')
