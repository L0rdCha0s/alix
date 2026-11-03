#!/usr/bin/env python3
"""Build a protected DSO using the executable's real runtime and SSP exports."""
from pathlib import Path
import subprocess
ROOT=Path(__file__).resolve().parents[2]
compiler=ROOT/'ports/zen/toolchain/alix-clang'
output=ROOT/'build/ports/zen/ssp-loader';output.mkdir(parents=True,exist_ok=True)
plugin=output/'libalix-ssp-plugin.so'
subprocess.run([str(compiler),'-shared','-fPIC','-O2','-fstack-protector-strong',
    '-I'+str(ROOT/'ports/zen/upstream/obj-gecko-alix/dist/system_wrappers'),
    '-include',str(ROOT/'ports/zen/upstream/firefox-159.0/config/gcc_hidden.h'),
    str(ROOT/'tests/ssp_loader_plugin.c'),'-o',str(plugin)],check=True)
main=ROOT/'build/user/ssp_loader_test.elf'
subprocess.run([str(compiler),'-O2','-fstack-protector-strong','-Wl,-u,__stack_chk_guard',
    str(ROOT/'tests/ssp_loader_test.c'),'-o',str(main)],check=True)
def symbols(path):
    result={}
    for line in subprocess.check_output(['x86_64-elf-readelf','--dyn-syms','--wide',str(path)],text=True).splitlines():
        fields=line.split()
        if len(fields)>=8 and fields[0].endswith(':') and fields[0][:-1].isdigit():result[fields[7]]=fields
    return result
imports=symbols(plugin);exports=symbols(main)
for name in ('__stack_chk_guard','__stack_chk_fail','alix_environment_copy','alix_environment_free'):
    assert imports[name][5:7]==['DEFAULT','UND'],(name,imports.get(name))
    assert exports[name][5]=='DEFAULT' and exports[name][6]!='UND',(name,exports.get(name))
print('Protected DSO imports and actual executable exports: PASS')
