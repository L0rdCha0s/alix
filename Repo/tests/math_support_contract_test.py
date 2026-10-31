#!/usr/bin/env python3
"""Exercise the production LLVM math adapters against the host C library."""
from pathlib import Path
import os
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PROGRAM = r'''
#include <math.h>
#include <fenv.h>
#include <errno.h>
#include <stdint.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#pragma STDC FENV_ACCESS ON
float alix_test_sqrtf(float), alix_test_fabsf(float), alix_test_scalbnf(float,int);
long double alix_test_fabsl(long double);
#define CHECK(c) do{if(!(c)){fprintf(stderr,"math support line %d bits=%08x n=%d mode=%d: %s\n",__LINE__,bits,n,mode,#c);abort();}}while(0)
static uint64_t state=0xcd3214ac12ef3456ULL;
static uint32_t next(void){state^=state<<13;state^=state>>7;state^=state<<17;return (uint32_t)state;}
int main(void) {
    const int modes[]={FE_TONEAREST,FE_DOWNWARD,FE_UPWARD,FE_TOWARDZERO};
    uint32_t bits=0;int n=0,mode=0;unsigned cases=0;
    for(mode=0;mode<4;++mode){CHECK(fesetround(modes[mode])==0);
        for(unsigned i=0;i<25000;++i){
            bits=next();n=(int)(next()%701)-350;float x;memcpy(&x,&bits,4);
            if(!isfinite(x))continue;
            feclearexcept(FE_ALL_EXCEPT);float expected=scalbnf(x,n);
            int expected_flags=fetestexcept(FE_ALL_EXCEPT);
            feclearexcept(FE_ALL_EXCEPT);errno=123;float actual=alix_test_scalbnf(x,n);
            CHECK(memcmp(&expected,&actual,4)==0);
            CHECK(fetestexcept(FE_ALL_EXCEPT)==expected_flags);
            CHECK(errno==123 || errno==ERANGE);
            float positive=fabsf(x), expected_root=sqrtf(positive);
            feclearexcept(FE_ALL_EXCEPT);float root=alix_test_sqrtf(positive);
            CHECK(memcmp(&root,&expected_root,4)==0);
            feclearexcept(FE_ALL_EXCEPT);errno=123;
            float absolute=alix_test_fabsf(x);long double extended=alix_test_fabsl((long double)x);
            CHECK(memcmp(&absolute,&positive,4)==0 && extended==(long double)positive);
            CHECK(fetestexcept(FE_ALL_EXCEPT)==0 && errno==123);++cases;
        }
        for(n=0;n<2;++n){
            feclearexcept(FE_ALL_EXCEPT);errno=0;
            float result=alix_test_scalbnf(n?-1.0f:1.0f,INT_MAX);(void)result;
            CHECK(errno==ERANGE && fetestexcept(FE_ALL_EXCEPT)==(FE_OVERFLOW|FE_INEXACT));
            feclearexcept(FE_ALL_EXCEPT);errno=0;
            result=alix_test_scalbnf(n?-1.0f:1.0f,INT_MIN);
            if(errno!=ERANGE || fetestexcept(FE_ALL_EXCEPT)!=(FE_UNDERFLOW|FE_INEXACT))
                fprintf(stderr,"extreme underflow errno=%d flags=%x result=%a\n",errno,fetestexcept(FE_ALL_EXCEPT),result);
            CHECK(errno==ERANGE && fetestexcept(FE_ALL_EXCEPT)==(FE_UNDERFLOW|FE_INEXACT));
        }
    }
    CHECK(fesetround(FE_TONEAREST)==0);feclearexcept(FE_ALL_EXCEPT);errno=0;
    CHECK(isnan(alix_test_sqrtf(-1)) && errno==EDOM && fetestexcept(FE_ALL_EXCEPT)==FE_INVALID);
    feclearexcept(FE_ALL_EXCEPT);errno=123;
    CHECK(signbit(alix_test_sqrtf(-0.0f)) && !signbit(alix_test_fabsf(-0.0f)));
    CHECK(fetestexcept(FE_ALL_EXCEPT)==0 && errno==123);
    bits=0x7f800001;float snan;memcpy(&snan,&bits,4);feclearexcept(FE_ALL_EXCEPT);
    CHECK(isnan(alix_test_scalbnf(snan,0)) && fetestexcept(FE_ALL_EXCEPT)==FE_INVALID);
    feclearexcept(FE_ALL_EXCEPT);feraiseexcept(FE_DIVBYZERO);errno=123;
    CHECK(alix_test_scalbnf(1.5f,3)==12 && errno==123 && fetestexcept(FE_ALL_EXCEPT)==FE_DIVBYZERO);
    printf("LLVM native math adapters: PASS cases=%u rounding=4 range_errno=1 flags=1\n",cases);
}
'''

def main():
    compiler = "/opt/homebrew/opt/llvm/bin/clang++"
    flags = ["--no-default-config", "-O2", "-g", "-frounding-math", "-fno-builtin"]
    if os.uname().sysname == "Darwin":
        flags += ["-isysroot", subprocess.check_output(["xcrun", "--show-sdk-path"], text=True).strip()]
    if os.environ.get("SANITIZE"): flags += ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"]
    with tempfile.TemporaryDirectory(prefix="alix-math-support-") as directory:
        path = Path(directory); (path/"test.c").write_text(PROGRAM)
        subprocess.run([compiler, "-std=c++20", *flags,
                        "-I"+str(ROOT/"ports/zen/upstream/llvm-project-22.1.8/libc"),
                        "-DLIBC_NAMESPACE=alix_llvm_libc", *["-D"+name+"=alix_test_"+name for name in
                        ("sqrtf","fabsf","fabsl","scalbnf")], "-c", str(ROOT/"user/lib/llvm_math.cpp"),
                        "-o", str(path/"math.o")], check=True)
        subprocess.run([compiler.replace("clang++","clang"),"-std=c11",*flags,
                        str(path/"test.c"),str(path/"math.o"),"-o",str(path/"test")],check=True)
        subprocess.run([str(path/"test")],check=True)

if __name__=="__main__":main()
