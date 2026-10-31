#!/usr/bin/env python3
"""Compare the production LLVM adapter with host libm, including FP flags."""
from pathlib import Path
import os
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
LLVM = ROOT / "ports/zen/upstream/llvm-project-22.1.8/libc"

PROGRAM = r'''
#include <math.h>
#include <fenv.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#pragma STDC FENV_ACCESS ON
float alix_test_nearbyintf(float);
double alix_test_nearbyint(double);
long double alix_test_nearbyintl(long double);
int alix_test_getround(void) { return fegetround(); }
#define CHECK(x) do {if(!(x)){fprintf(stderr,"nearbyint failure line %d: %s\n",__LINE__,#x);abort();}}while(0)
static uint64_t random_state = 0xc51293a2db492ab1ULL;
static uint64_t random_bits(void) {
    random_state ^= random_state << 13; random_state ^= random_state >> 7;
    random_state ^= random_state << 17; return random_state;
}
int main(void) {
    const int modes[] = {FE_TONEAREST,FE_DOWNWARD,FE_UPWARD,FE_TOWARDZERO};
    unsigned cases=0;
    for(unsigned m=0;m<4;++m) {
        CHECK(fesetround(modes[m])==0);
        for(unsigned i=0;i<25000;++i) {
            uint64_t bits=random_bits();double x;memcpy(&x,&bits,8);
            uint32_t small=(uint32_t)random_bits();float f;memcpy(&f,&small,4);
            /* NaNs are separately checked below, including signaling forms. */
            if(!isfinite(x)||!isfinite(f))continue;
            double expected=nearbyint(x);float expectedf=nearbyintf(f);
            feclearexcept(FE_ALL_EXCEPT);feraiseexcept(FE_DIVBYZERO);
            double actual=alix_test_nearbyint(x);float actualf=alix_test_nearbyintf(f);
            CHECK(fetestexcept(FE_ALL_EXCEPT)==FE_DIVBYZERO);
            CHECK(memcmp(&actual,&expected,8)==0 && memcmp(&actualf,&expectedf,4)==0);
            long double l=(long double)x, expectedl=nearbyintl(l);
            feclearexcept(FE_ALL_EXCEPT);
            long double actuall=alix_test_nearbyintl(l);
            CHECK(fetestexcept(FE_ALL_EXCEPT)==0);
            CHECK(actuall==expectedl && !!signbit(actuall)==!!signbit(expectedl));
            ++cases;
        }
        const double edges[]={0.,-0.,.5,-.5,1.5,-1.5,2.5,-2.5,3.5,-3.5,
                              0x1p-1074,-0x1p-1074,0x1.fffffffffffffp51,
                              -0x1.fffffffffffffp51,INFINITY,-INFINITY};
        for(unsigned i=0;i<sizeof(edges)/sizeof(edges[0]);++i) {
            double e=nearbyint(edges[i]);feclearexcept(FE_ALL_EXCEPT);
            double a=alix_test_nearbyint(edges[i]);
            CHECK(fetestexcept(FE_ALL_EXCEPT)==0 && memcmp(&a,&e,8)==0);
        }
    }
    CHECK(fesetround(FE_TONEAREST)==0);
    uint64_t snanbits=0x7ff0000000000001ULL;double snan;memcpy(&snan,&snanbits,8);
    feclearexcept(FE_ALL_EXCEPT);double quiet=alix_test_nearbyint(snan);
    CHECK(isnan(quiet) && fetestexcept(FE_ALL_EXCEPT)==FE_INVALID);
    uint64_t quietbits;memcpy(&quietbits,&quiet,8);CHECK(quietbits&0x8000000000000ULL);
    feclearexcept(FE_ALL_EXCEPT);CHECK(isnan(alix_test_nearbyint(quiet)));
    CHECK(fetestexcept(FE_ALL_EXCEPT)==0);
    uint32_t sf=0x7f800001;float signaling;memcpy(&signaling,&sf,4);
    feclearexcept(FE_ALL_EXCEPT);float qf=alix_test_nearbyintf(signaling);
    CHECK(isnan(qf) && fetestexcept(FE_ALL_EXCEPT)==FE_INVALID);
    feclearexcept(FE_ALL_EXCEPT);feraiseexcept(FE_INEXACT|FE_DIVBYZERO);
    CHECK(alix_test_nearbyint(1.25)==1);
    CHECK(fetestexcept(FE_ALL_EXCEPT)==(FE_INEXACT|FE_DIVBYZERO));
    printf("nearbyint production adapter: PASS cases=%u rounding=4 flags=preserved signaling_nan=1\n",cases);
}
'''

def main():
    compiler = os.environ.get("CXX", "/opt/homebrew/opt/llvm/bin/clang++")
    with tempfile.TemporaryDirectory(prefix="alix-nearbyint-") as directory:
        path = Path(directory)
        harness = path / "test.c"
        harness.write_text(PROGRAM)
        common = ["--no-default-config", "-O2", "-g", "-frounding-math", "-fno-builtin"]
        if os.uname().sysname == "Darwin":
            sdk = subprocess.check_output(["xcrun", "--show-sdk-path"], text=True).strip()
            common += ["-isysroot", sdk]
        if os.environ.get("SANITIZE"):
            common += ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"]
        subprocess.run([compiler, "-std=c++20", *common, "-I"+str(LLVM),
                        "-DLIBC_NAMESPACE=alix_llvm_libc", "-Dfegetround=alix_test_getround",
                        "-Dnearbyint=alix_test_nearbyint", "-Dnearbyintf=alix_test_nearbyintf",
                        "-Dnearbyintl=alix_test_nearbyintl", "-c", str(ROOT/"user/lib/llvm_nearbyint.cpp"),
                        "-o", str(path/"adapter.o")], check=True)
        subprocess.run([compiler.replace("clang++", "clang"), "-std=c11", *common,
                        str(harness), str(path/"adapter.o"), "-o", str(path/"test")], check=True)
        subprocess.run([str(path/"test")], check=True)

if __name__ == "__main__": main()
