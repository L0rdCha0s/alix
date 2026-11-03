#!/usr/bin/env python3
"""Build a real NSPR library consumer with no NSPR API replacements."""
from pathlib import Path
import subprocess
ROOT=Path(__file__).resolve().parents[2]
compiler=ROOT/'ports/zen/toolchain/alix-clang'
library=ROOT/'ports/zen/upstream/obj-gecko-alix/dist/bin/libnspr4.so'
assert library.is_file(),library
main=ROOT/'build/user/nspr_runtime_test.elf'
subprocess.run([str(compiler),'-O2','-fstack-protector-strong','-Wl,-u,__stack_chk_guard','-DALIX','-DXP_UNIX',
    '-I'+str(ROOT/'ports/zen/upstream/obj-gecko-alix/dist/include/nspr'),
    '-I'+str(ROOT/'ports/zen/upstream/firefox-159.0/nsprpub/pr/include'),
    str(ROOT/'tests/nspr_runtime_test.c'),'-o',str(main)],check=True)
def symbols(path):
    result={}
    for line in subprocess.check_output(['x86_64-elf-readelf','--dyn-syms','--wide',str(path)],text=True).splitlines():
        f=line.split()
        if len(f)>=8 and f[0].endswith(':') and f[0][:-1].isdigit():result[f[7]]=f
    return result
exports=symbols(main);imports=symbols(library)
missing=[name for name,f in imports.items() if f[6]=='UND' and f[4]!='WEAK' and
         (name not in exports or exports[name][6]=='UND' or exports[name][5] not in ('DEFAULT','PROTECTED'))]
assert not missing,'NSPR native runtime imports unavailable: '+', '.join(sorted(missing))
print('Complete NSPR library native import contract: PASS')
