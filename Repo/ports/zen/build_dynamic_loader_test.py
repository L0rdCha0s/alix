#!/usr/bin/env python3
"""Compile real native shared libraries and an exported ET_EXEC loader consumer."""
from pathlib import Path
import subprocess
ROOT=Path(__file__).resolve().parents[2]
def main():
    out=ROOT/'build/ports/zen/dynamic-loader';out.mkdir(parents=True,exist_ok=True)
    compiler=ROOT/'ports/zen/toolchain/alix-clang'
    dep=out/'libalix-loader-dep.so';plugin=out/'libalix-loader-plugin.so'
    subprocess.run([str(compiler),'-shared','-fPIC','-O2',str(ROOT/'tests/loader_dependency.c'),'-Wl,--hash-style=gnu','-Wl,-z,pack-relative-relocs','-Wl,-soname,'+dep.name,'-o',str(dep)],check=True)
    subprocess.run([str(compiler),'-shared','-fPIC','-O2',str(ROOT/'tests/loader_plugin.c'),'-L'+str(out),'-lalix-loader-dep','-Wl,-rpath,$ORIGIN','-Wl,-soname,'+plugin.name,'-o',str(plugin)],check=True)
    missing=out/'unresolved.c';missing.write_text('extern int loader_symbol_does_not_exist(void);int loader_bad(void){return loader_symbol_does_not_exist();}\n')
    subprocess.run([str(compiler),'-shared','-fPIC',str(missing),'-o',str(out/'libalix-loader-unresolved.so')],check=True)
    (out/'loader-bad.elf').write_bytes(b'not an ELF shared object\n')
    subprocess.run([str(compiler)+'++','-shared','-fPIC','-O2',str(ROOT/'tests/loader_destructor.cpp'),'-o',str(out/'libalix-loader-destructor.so')],check=True)
    for name in ('provider','consumer'):
        subprocess.run([str(compiler),'-shared','-fPIC','-O2',str(ROOT/f'tests/loader_{name}.c'),'-o',str(out/f'libalix-loader-{name}.so')],check=True)
    subprocess.run([str(compiler),'-O2','-g',str(ROOT/'tests/dynamic_loader_test.c'),'-Wl,--gc-sections','-o',str(ROOT/'build/user/dynamic_loader_test.elf')],check=True)
    print('Native shared objects and exported executable built:',out)
if __name__=='__main__':main()
