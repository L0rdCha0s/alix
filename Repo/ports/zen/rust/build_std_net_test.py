#!/usr/bin/env python3
"""Link the real native standard-library network backend with Alix's runtime."""
from pathlib import Path
import subprocess
ROOT=Path(__file__).resolve().parents[3]
HERE=ROOT/'ports/zen/rust'
compiler=ROOT/'ports/zen/toolchain/alix-clang'
out=ROOT/'build/ports/zen/rust-std-net';out.mkdir(parents=True,exist_ok=True)
abi=out/'abi.o'
subprocess.run([str(compiler),'-c',str(ROOT/'tests/rust_std_net_abi.c'),'-o',str(abi)],check=True)
output=ROOT/'build/user/rust_std_net_test.elf'
subprocess.run([str(HERE/'rustc.py'),'--edition=2021','--target=x86_64-unknown-alix','-Cpanic=abort','-Copt-level=2',
    '-Clinker-flavor=gcc','-Clinker='+str(compiler),'-Clink-arg='+str(abi),
    str(ROOT/'tests/rust_std_net.rs'),'-o',str(output)],check=True)
print('Native Rust standard-library TCP consumer built:',output)
