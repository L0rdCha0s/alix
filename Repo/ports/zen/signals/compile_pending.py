#!/usr/bin/env python3
"""Compile staged production integration without changing active sources."""
from pathlib import Path
import subprocess
import shutil
ROOT=Path(__file__).resolve().parents[3]
HERE=Path(__file__).resolve().parent
STAGE=HERE/'pending'
OUT=HERE/'out';OUT.mkdir(exist_ok=True)
shutil.copytree(ROOT/'include',OUT/'include',dirs_exist_ok=True)
shutil.copytree(STAGE/'include',OUT/'include',dirs_exist_ok=True)
(OUT/'user/lib').mkdir(parents=True,exist_ok=True)
for base in [ROOT/'user/lib', STAGE/'user/lib']:
    for header in base.glob('*.h'): shutil.copy2(header,OUT/'user/lib'/header.name)
common=['x86_64-elf-gcc','-std=c11','-O2','-ffreestanding','-fno-stack-protector','-fno-builtin','-fno-pic','-m64','-mno-red-zone','-Wall','-Wextra','-Werror','-g','-fshort-wchar','-I'+str(OUT/'include'),'-I'+str(ROOT/'src/atk')]
for source in sorted(STAGE.rglob('*.c')):
    is_user='user' in source.relative_to(STAGE).parts
    flags=['-msse2','-mfpmath=sse','-mstackrealign','-mcmodel=large','-DNORMALUNIX','-DATK_NO_DESKTOP_APPS','-I'+str(OUT/'user/lib'),'-I'+str(ROOT/'user')] if is_user else ['-mgeneral-regs-only','-mfpmath=387','-mno-sse','-DKERNEL_BUILD']
    subprocess.run(common+flags+['-c',str(source),'-o',str(OUT/(source.stem+'.o'))],check=True,cwd=ROOT)
    print(source.relative_to(STAGE))
print('Pending native signal production objects: PASS')
