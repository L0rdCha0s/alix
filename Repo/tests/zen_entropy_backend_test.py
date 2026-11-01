#!/usr/bin/env python3
"""Compile the actual upstream Alix entropy branch with bounded/failure probes."""
from pathlib import Path
import os
import re
import shlex
import subprocess
import tempfile
import sys
sys.dont_write_bytecode=True
from audio_stream_contract_test import ROOT,function_definition

def main():
    source=(ROOT/"ports/zen/upstream/firefox-159.0/mfbt/RandomNum.cpp").read_text()
    body=function_definition(source,"MFBT_API bool GenerateRandomBytesFromOS(")
    body=re.sub(r"\bgetentropy\b","model_getentropy",body)
    code=r'''
#include <cassert>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#define MFBT_API
#define MOZ_ASSERT(value) assert(value)
static unsigned calls,fail_at;
static int model_getentropy(void *buffer,size_t bytes){
    assert(bytes&&bytes<=256);if(++calls==fail_at)return-1;memset(buffer,(int)calls,bytes);return 0;
}
'''+body+r'''
int main(){
    auto *buffer=static_cast<unsigned char*>(malloc(1040));assert(buffer);
    memset(buffer,0xa5,1040);assert(GenerateRandomBytesFromOS(buffer,513)&&calls==3);
    for(unsigned i=0;i<513;++i)assert(buffer[i]==i/256+1);
    for(unsigned i=513;i<1040;++i)assert(buffer[i]==0xa5);
    for(unsigned failure=1;failure<=3;++failure){
        calls=0;fail_at=failure;memset(buffer,0xa5,1040);assert(!GenerateRandomBytesFromOS(buffer,513)&&calls==failure);
        for(unsigned i=(failure-1)*256;i<1040;++i)assert(buffer[i]==0xa5);
    }
    fail_at=calls=0;memset(buffer,0xa5,1040);assert(GenerateRandomBytesFromOS(buffer,1001)&&calls==4);
    for(unsigned i=1001;i<1040;++i)assert(buffer[i]==0xa5);free(buffer);return 0;
}
'''
    compiler=shlex.split(os.environ.get("HOST_CXX","clang++"))
    with tempfile.TemporaryDirectory(prefix="alix-mfbt-entropy-") as directory:
        binary=Path(directory)/"entropy"
        subprocess.run([*compiler,"-std=c++20","-Wall","-Wextra","-Werror","-D__ALIX__",
                        "-x","c++","-","-o",str(binary)],input=code,text=True,check=True)
        subprocess.run([str(binary)],check=True)
    print("Native mfbt entropy branch PASS: bounded chunks, exact fill, guarded output and real failure propagation")
    return 0

if __name__=="__main__":raise SystemExit(main())
