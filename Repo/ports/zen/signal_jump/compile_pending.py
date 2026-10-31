#!/usr/bin/env python3
from pathlib import Path
import shutil,subprocess
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2];STAGE=HERE/'pending';OUT=HERE/'out';OUT.mkdir(exist_ok=True)
shutil.copytree(ROOT/'include',OUT/'include',dirs_exist_ok=True);shutil.copytree(STAGE/'include',OUT/'include',dirs_exist_ok=True)
(OUT/'user/lib').mkdir(parents=True,exist_ok=True)
for base in [ROOT/'user/lib',STAGE/'user/lib']:
 for path in base.glob('*.h'):shutil.copy2(path,OUT/'user/lib'/path.name)
common=['-std=c11','-O2','-g','-ffreestanding','-fno-builtin','-fno-stack-protector','-fno-pic','-m64','-mno-red-zone','-fshort-wchar','-Wall','-Wextra','-Werror','-I'+str(OUT/'include'),'-I'+str(ROOT/'src/atk')]
for source in sorted(STAGE.rglob('*.c')):
 user='user' in source.relative_to(STAGE).parts
 flags=['-msse2','-mfpmath=sse','-mstackrealign','-mcmodel=large','-ftls-model=local-exec','-I'+str(OUT/'user/lib'),'-I'+str(ROOT/'user')] if user else ['-DKERNEL_BUILD','-mgeneral-regs-only','-mfpmath=387','-mno-sse']
 name=('user_' if user else 'kernel_')+source.stem+'.o'
 subprocess.run(['x86_64-elf-gcc',*common,*flags,'-c',str(source),'-o',str(OUT/name)],check=True)
 print(source.relative_to(STAGE))
print('Signal checkpoint native production compilation: PASS')
