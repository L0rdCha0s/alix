#!/usr/bin/env python3
"""Compile actual Gecko-vendored dynamic-loading crates and a native consumer."""
import os
from pathlib import Path
import subprocess
import tomllib
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
VENDOR=HERE.parent/'upstream/firefox-159.0/third_party/rust'
OUT=ROOT/'build/ports/zen/rust-dynamic-loading';OUT.mkdir(parents=True,exist_ok=True)
RUST=HERE/'rustc.py'

def compile_crate(directory,name,externs=(),features=()):
    manifest=tomllib.loads((directory/'Cargo.toml').read_text());package=manifest['package']
    env=os.environ.copy();env.update({'CARGO_PKG_NAME':package['name'],'CARGO_PKG_VERSION':package['version'],'CARGO_MANIFEST_DIR':str(directory)})
    output=OUT/f'lib{name}.rlib'
    argv=[str(RUST),'--crate-name',name,'--crate-type','rlib','--edition',package.get('edition','2015'),
          '--target','x86_64-unknown-alix','-C','panic=abort','-C','opt-level=2','-C','debuginfo=0',
          '-L','dependency='+str(OUT)]
    for dep,path in externs:argv+=['--extern',f'{dep}={path}']
    for feature in features:argv+=['--cfg',f'feature="{feature}"']
    subprocess.run([*argv,str(directory/'src/lib.rs'),'-o',str(output)],env=env,cwd=ROOT,check=True)
    return output

cfg=compile_crate(VENDOR/'cfg-if','cfg_if')
loading=compile_crate(VENDOR/'libloading','libloading',[('cfg_if',cfg)])
ash=compile_crate(VENDOR/'ash','ash',[('libloading',loading)],['loaded','std','debug'])
archive=OUT/'libtest.a'
subprocess.run([str(RUST),'--crate-name','alix_rust_dynamic_loading','--crate-type','staticlib','--edition','2021',
    '--target','x86_64-unknown-alix','-C','panic=abort','-C','opt-level=2','-L','dependency='+str(OUT),
    '--extern','libloading='+str(loading),'--extern','ash='+str(ash),
    str(ROOT/'tests/rust_dynamic_loading.rs'),'-o',str(archive)],cwd=ROOT,check=True)
compiler=ROOT/'ports/zen/toolchain/alix-clang'
subprocess.run([str(compiler),'-shared','-O2','-fPIC',str(ROOT/'tests/rust_loader_plugin.c'),
    '-Wl,--defsym,rust_loader_null=0','-o',str(OUT/'libalix-rust-loader.so')],check=True)
subprocess.run([str(compiler),str(ROOT/'tests/rust_dynamic_loading_test.c'),str(archive),
    '-o',str(ROOT/'build/user/rust_dynamic_loading_test.elf')],check=True)
print('Actual libloading and ash Alix consumer built')
