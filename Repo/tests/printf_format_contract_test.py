#!/usr/bin/env python3
"""Compare production Alix formatting with host libc and exercise failures."""
import os
import argparse
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
from audio_stream_contract_test import ROOT, function_definition


def renamed(text):
    for name in ("printf", "vprintf", "perror", "fprintf", "vfprintf", "sprintf", "vsprintf", "snprintf", "vsnprintf", "asprintf", "vasprintf",
                 "FILE", "fpos_t", "stdout", "stderr", "frexpl", "strnlen", "wctob"):
        text = re.sub(r"\b" + name + r"\b", "native_" + name, text)
    for name in ("calloc", "realloc", "free"):
        text = re.sub(r"\b" + name + r"\b", "checked_" + name, text)
    return re.sub(r"\berrno\b", "test_errno", text)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("modes", nargs="*", choices=("huge", "alloc", "compare"))
    args = parser.parse_args()
    libc = (ROOT / "user/lib/libc.c").read_text()
    start = libc.index("static size_t file_write_bytes_unlocked(FILE *stream,")
    end = libc.index("#endif /* TTF_HOST_BUILD */", start)
    header = (ROOT / "include/stdio.h").read_text()
    file_type = header[header.index("typedef struct FILE"):header.index("extern FILE *stdout;")]
    prototypes = "\n".join(line for line in header.splitlines()
                           if re.match(r"int (?:v?s(?:n)?printf|v?fprintf|printf|v?asprintf)\(", line))
    floats = "\n".join(line for line in (ROOT / "user/lib/printf_float.c").read_text().splitlines()
                       if not line.startswith("#include"))
    float_header = "\n".join(line for line in (ROOT / "user/lib/printf_float.h").read_text().splitlines()
                             if not line.startswith("#include"))
    math = (ROOT / "user/lib/math.c").read_text()
    code = r'''
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <limits.h>
#include <inttypes.h>
#include <float.h>
#include <math.h>
#include <fenv.h>
#include <errno.h>
#include <time.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <unistd.h>
#include <wchar.h>
#pragma STDC FENV_ACCESS ON
#define CHECK(c) do { if (!(c)) { fprintf(stderr,"printf contract line %d: %s\n",__LINE__,#c); abort(); } } while(0)
static int test_errno;
static void *owned[128];
static unsigned live, allocation_calls;
static int fail_at=-1;
static size_t maximum_request;
static bool fail_allocation(size_t bytes) {
    if (bytes>maximum_request) maximum_request=bytes;
    unsigned call=allocation_calls++;
    return (fail_at>=0 && call==(unsigned)fail_at) || bytes>1024*1024;
}
static void *checked_calloc(size_t n,size_t size) {
    if (size && n>SIZE_MAX/size) return NULL;
    if (fail_allocation(n*size)) return NULL;
    void *value=calloc(n,size); CHECK(value && live<128); owned[live++]=value; return value;
}
static void *checked_realloc(void *old,size_t size) {
    if (fail_allocation(size)) return NULL;
    unsigned index=0;
    if (old) { while(index<live && owned[index]!=old) ++index; CHECK(index<live); }
    void *value=realloc(old,size); CHECK(value);
    if (old) owned[index]=value;
    else { CHECK(live<128); owned[live++]=value; }
    return value;
}
static void checked_free(void *value) {
    if (!value) return;
    unsigned index=0; while(index<live && owned[index]!=value) ++index; CHECK(index<live);
    owned[index]=owned[--live]; free(value);
}
typedef struct { unsigned state; } alix_mutex_t;
static unsigned stream_locks, stream_unlocks;
static void alix_mutex_lock(alix_mutex_t *mutex) { CHECK(!mutex->state); mutex->state=1; ++stream_locks; }
static void alix_mutex_unlock(alix_mutex_t *mutex) { CHECK(mutex->state==1); mutex->state=0; ++stream_unlocks; }
'''
    code += renamed(file_type) + "\n" + renamed(prototypes) + "\n" + float_header + "\n"
    code += r'''
static native_FILE captured_stdout;
static native_FILE *native_stdout=&captured_stdout;
static native_FILE captured_stderr;
static native_FILE *native_stderr=&captured_stderr;
static unsigned char captured[256];
static size_t captured_size, capture_limit=sizeof(captured), stream_calls;
static size_t file_write_bytes_unlocked(native_FILE *stream,const void *data,size_t count) {
    CHECK(stream && stream->mutex.state==1); ++stream_calls;
    size_t available=capture_limit-captured_size;
    size_t copy=count<available ? count : available;
    memcpy(captured+captured_size,data,copy); captured_size+=copy;
    if (copy<count) { stream->error=1; test_errno=EIO; }
    return copy;
}
'''
    code += renamed(function_definition(math, "long double frexpl(")) + "\n"
    code += renamed(function_definition(libc, "size_t strnlen(")) + "\n"
    wchar = (ROOT / "user/lib/wchar.c").read_text()
    code += renamed(function_definition(wchar, "int wctob(")) + "\n"
    code += renamed(function_definition(libc, "bool __alix_stdio_orient_unlocked(")) + "\n"
    code += renamed(floats) + "\n" + renamed(libc[start:end]) + r'''

static unsigned comparisons;
static void compare(const char *format,...) {
    static const size_t capacities[]={0,1,2,7,31,8192};
    char *actual=malloc(8192+16), *expected=malloc(8192+16); CHECK(actual && expected);
    for (unsigned index=0;index<sizeof(capacities)/sizeof(capacities[0]);++index) {
        size_t capacity=capacities[index]; memset(actual,0xa5,8208); memset(expected,0xa5,8208);
        va_list args,copy; va_start(args,format); va_copy(copy,args);
        int wanted=vsnprintf(expected,capacity,format,args); va_end(args);
        test_errno=0; int got=native_vsnprintf(actual,capacity,format,copy); va_end(copy);
        if (got!=wanted || (capacity && memcmp(actual,expected,capacity))) {
            fprintf(stderr,"format mismatch mode=%d fmt=%s cap=%zu got=%d want=%d\nactual=[%s]\nexpected=[%s]\n",
                    fegetround(),format,capacity,got,wanted,capacity?actual:"<none>",capacity?expected:"<none>"); abort();
        }
        for (size_t byte=capacity;byte<8208;++byte) CHECK((unsigned char)actual[byte]==0xa5);
        CHECK(!live); ++comparisons;
    }
    free(expected); free(actual);
}

static void integer_and_counts(void) {
    compare("%d %i %+d % d %08d %-08d %.0d",INT_MIN,INT_MAX,42,42,-42,42,0);
    compare("%#o %#.0o %#08o %#.5o %#x %#.0x %#012X",0u,0u,9u,9u,0x12u,0u,0x12u);
    compare("%hhd %hhu %hd %hu",(int)(signed char)-128,(unsigned int)(unsigned char)255,(int)(short)-32768,(unsigned int)(unsigned short)65535);
    compare("%ld %lu %lld %llu",LONG_MIN,ULONG_MAX,LLONG_MIN,ULLONG_MAX);
    compare("%jd %ju %zd %zu %td %tu",INTMAX_MIN,UINTMAX_MAX,(ssize_t)-123,SIZE_MAX,(ptrdiff_t)-456,(uintptr_t)UINTPTR_MAX);
    compare("%*.*d %*s %.*s %c %%",-13,7,-42,8,"abc",3,"abcdef",'x');
    compare("%.*g",INT_MIN,1.2345);
    compare("[%8.3ls]/[%lc]",L"abcdef",(wint_t)'Q');
    static const char *flags[]={"","#","0","-","+"," ","#0","-0","+#0"};
    char format[64];
    for(unsigned flag=0;flag<sizeof(flags)/sizeof(flags[0]);++flag)
        for(int precision=0;precision<8;++precision)
            for(unsigned value=0;value<40;value+=3) {
                snprintf(format,sizeof(format),"%%%s17.%do",flags[flag],precision); compare(format,value);
                snprintf(format,sizeof(format),"%%%s17.%dx",flags[flag],precision); compare(format,value);
            }
    char buffer[32]; signed char hh=-1; short h=-1; int n=-1; long l=-1; long long ll=-1; ssize_t z=-1; ptrdiff_t t=-1; intmax_t j=-1;
    int count=native_snprintf(buffer,2,"abc%hhn%hn%n%ln%lln%zn%tn%jn",&hh,&h,&n,&l,&ll,&z,&t,&j);
    CHECK(count==3 && !strcmp(buffer,"a") && hh==3 && h==3 && n==3 && l==3 && ll==3 && z==3 && t==3 && j==3);
    CHECK(native_sprintf(buffer,"%#x/%d",18u,-7)==7 && !strcmp(buffer,"0x12/-7"));
}

static void nan_contract(const char *format,double value,const char *flags,char conversion,int width) {
    /* Darwin libc omits a requested '+' on NaN; musl preserves it. C permits
     * implementation-defined NaN spelling, so verify musl's explicit contract
     * while keeping all finite/Inf comparisons against host libc strict. */
    char expected[64],payload[8],actual[64];
    size_t length=0;
    if (signbit(value)) payload[length++]='-';
    else if (strchr(flags,'+')) payload[length++]='+';
    else if (strchr(flags,' ')) payload[length++]=' ';
    memcpy(payload+length,conversion>='a' && conversion<='z' ? "nan" : "NAN",3); length+=3;
    size_t total=(size_t)width>length ? (size_t)width : length;
    memset(expected,' ',total); memcpy(expected+(strchr(flags,'-') ? 0 : total-length),payload,length); expected[total]=0;
    static const size_t caps[]={0,1,7,64};
    for(unsigned i=0;i<sizeof(caps)/sizeof(caps[0]);++i) {
        memset(actual,0xa5,sizeof(actual));
        CHECK(native_snprintf(actual,caps[i],format,value)==(int)total);
        if (caps[i]) { size_t copied=total<caps[i]-1 ? total : caps[i]-1; CHECK(!memcmp(actual,expected,copied) && actual[copied]==0); }
        CHECK(!live); ++comparisons;
    }
}

static void float_comparisons(void) {
    static const double values[]={0.0,-0.0,1.0,-1.0,1.25,-1.25,1.5,-1.5,1.9999999999999998,
        9.999999999999998,0.0001,0.00001,1e20,1e-20,DBL_MAX,DBL_MIN,DBL_TRUE_MIN,
        0x1.fffffffffffffp-1022,INFINITY,-INFINITY,NAN,-NAN};
    static const char *flags[]={"","#","+"," ","0","-","-0","+#0"};
    static const int precisions[]={0,1,2,6,17,40};
    char format[64];
    CHECK(fesetround(FE_TONEAREST)==0);
    {
        for(unsigned value=0;value<sizeof(values)/sizeof(values[0]);++value) {
            for(const char *conversion="fFeEgG";*conversion;++conversion) {
                snprintf(format,sizeof(format),"%%%c",*conversion);
                if (isnan(values[value])) nan_contract(format,values[value],"",*conversion,0);
                else compare(format,values[value]);
                for(unsigned flag=0;flag<sizeof(flags)/sizeof(flags[0]);++flag)
                    for(unsigned precision=0;precision<sizeof(precisions)/sizeof(precisions[0]);++precision) {
                        snprintf(format,sizeof(format),"%%%s23.%d%c",flags[flag],precisions[precision],*conversion);
                        if (isnan(values[value])) nan_contract(format,values[value],flags[flag],*conversion,23);
                        else compare(format,values[value]);
                    }
            }
        }
        compare("%+.25Lf/%#.17Le/%.21Lg",1.25L,-0.0001L,LDBL_MAX);
        compare("%.1074f",DBL_TRUE_MIN);
        compare("%.800e",1e-300);
    }
    CHECK(fesetround(FE_TONEAREST)==0);
    uint64_t random=UINT64_C(0x7934a25f11223344);
    for(unsigned sample=0;sample<1024;++sample) {
        random=random*UINT64_C(6364136223846793005)+1;
        union { uint64_t bits; double value; } number={.bits=random};
        if (!isfinite(number.value)) continue;
        compare("%.17g",number.value); compare("%.6e",number.value);
        compare("%#.9f",number.value); compare("%+.3g",number.value);
    }
}

static void hexadecimal_and_frexpl(void) {
    static const long double values[]={0.0L,-0.0L,1.0L,-1.25L,1.5L,1.125L,LDBL_MIN,LDBL_MAX,
                                       (long double)DBL_TRUE_MIN,0x1.fffffffffffffp-1022L};
    char actual[512],expected[512],format[64];
    for(unsigned value=0;value<sizeof(values)/sizeof(values[0]);++value) {
        int a_exp=0,h_exp=0; long double a=native_frexpl(values[value],&a_exp),h=frexpl(values[value],&h_exp);
        CHECK(a==h && signbit(a)==signbit(h) && a_exp==h_exp);
        for(unsigned precision=0;precision<2;++precision) {
            const char *fmt=precision ? "%.40La" : "%La";
            int n=native_snprintf(actual,sizeof(actual),fmt,values[value]);
            CHECK(n>0 && (size_t)n<sizeof(actual) && n==(int)strlen(actual));
            snprintf(expected,sizeof(expected),fmt,values[value]);
            char *end=NULL; long double restored=strtold(actual,&end);
            CHECK(end && !*end && restored==values[value] && signbit(restored)==signbit(values[value]));
            restored=strtold(expected,&end); CHECK(end && !*end && restored==values[value]);
        }
    }
    static const char *flags[]={"","#","+"," ","0","-","-0","+#0"};
    for(const char *conversion="aA";*conversion;++conversion)
        for(unsigned flag=0;flag<sizeof(flags)/sizeof(flags[0]);++flag)
            for(int precision=1;precision<8;++precision) {
                snprintf(format,sizeof(format),"%%%s20.%d%c",flags[flag],precision,*conversion);
                compare(format,1.25); compare(format,-1.125); compare(format,4.5);
                compare(format,INFINITY); compare(format,-INFINITY);
                nan_contract(format,NAN,flags[flag],*conversion,20);
                nan_contract(format,-NAN,flags[flag],*conversion,20);
            }
}

static void expected_format(const char *expected,const char *format,...) {
    static const size_t caps[]={0,1,7,64}; char actual[64]; size_t length=strlen(expected);
    for(unsigned i=0;i<sizeof(caps)/sizeof(caps[0]);++i) {
        memset(actual,0xa5,sizeof(actual));
        va_list args; va_start(args,format); int count=native_vsnprintf(actual,caps[i],format,args); va_end(args);
        size_t copied=caps[i] ? (length<caps[i]-1 ? length : caps[i]-1) : 0;
        if (count!=(int)length || (caps[i] && (memcmp(actual,expected,copied) || actual[copied]))) {
            fprintf(stderr,"rounding mismatch mode=%d format=%s actual=[%s] wanted=[%s] count=%d\n",
                    fegetround(),format,caps[i]?actual:"<none>",expected,count); abort();
        }
        CHECK(!live); ++comparisons;
    }
}

static void directed_rounding(void) {
    /* Darwin's printf ignores directed rounding on this host. These operands
     * and halfway points are exactly binary-representable, so expected decimal
     * and hexadecimal strings are independent of a host formatting oracle. */
    static const int modes[]={FE_TONEAREST,FE_DOWNWARD,FE_UPWARD,FE_TOWARDZERO};
    static const char *quarter[]={"0","0","1","0"};
    static const char *negative_quarter[]={"-0","-1","-0","-0"};
    static const char *half[]={"2","1","2","1"};
    static const char *negative_half[]={"-2","-2","-1","-1"};
    static const char *decimal[]={"1.2","1.2","1.3","1.2"};
    static const char *negative_decimal[]={"-1.2","-1.3","-1.2","-1.2"};
    static const char *scientific[]={"1.2e+00","1.2e+00","1.3e+00","1.2e+00"};
    static const char *negative_scientific[]={"-1.2e+00","-1.3e+00","-1.2e+00","-1.2e+00"};
    static const char *hexadecimal[]={"0x1.0p+0","0x1.0p+0","0x1.1p+0","0x1.0p+0"};
    static const char *negative_hexadecimal[]={"-0x1.0p+0","-0x1.1p+0","-0x1.0p+0","-0x1.0p+0"};
    for(unsigned i=0;i<sizeof(modes)/sizeof(modes[0]);++i) {
        CHECK(fesetround(modes[i])==0);
        expected_format(quarter[i],"%.0f",0.25); expected_format(negative_quarter[i],"%.0f",-0.25);
        expected_format(half[i],"%.0f",1.5); expected_format(negative_half[i],"%.0f",-1.5);
        expected_format(decimal[i],"%.1f",1.25); expected_format(negative_decimal[i],"%.1f",-1.25);
        expected_format(decimal[i],"%.2g",1.25); expected_format(negative_decimal[i],"%.2g",-1.25);
        expected_format(scientific[i],"%.1e",1.25); expected_format(negative_scientific[i],"%.1e",-1.25);
        expected_format(hexadecimal[i],"%.1a",1.03125); expected_format(negative_hexadecimal[i],"%.1a",-1.03125);
        expected_format(decimal[i],"%.1Lf",1.25L); expected_format(negative_decimal[i],"%.1Lf",-1.25L);
    }
    CHECK(fesetround(FE_TONEAREST)==0);
}

static void guarded_strings(void) {
    long page=sysconf(_SC_PAGESIZE); CHECK(page>0);
    char *mapping=mmap(NULL,(size_t)page*2,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
    CHECK(mapping!=MAP_FAILED && mprotect(mapping+page,(size_t)page,PROT_NONE)==0);
    char *text=mapping+page-8; memcpy(text,"ABCDEFGH",8);
    compare("%.*s",8,text);
    char output[16]; CHECK(native_snprintf(output,sizeof(output),"%.0s",mapping+page)==0 && !output[0]);
    CHECK(native_snprintf(NULL,0,"%.*s",8,text)==8);
    wchar_t *wide=(wchar_t *)(mapping+page-2*sizeof(wchar_t)); wide[0]='A'; wide[1]='B';
    compare("%.*ls",2,wide);
    CHECK(native_snprintf(output,sizeof(output),"%.0ls",(wchar_t *)(mapping+page))==0 && !output[0]);
    CHECK(munmap(mapping,(size_t)page*2)==0);
}

static void huge_counts(void) {
    struct timespec before,after; CHECK(!clock_gettime(CLOCK_MONOTONIC,&before));
    char small[8];
    CHECK(native_snprintf(NULL,0,"%*d",INT_MAX,7)==INT_MAX);
    CHECK(native_snprintf(small,sizeof(small),"%0*d",INT_MAX,7)==INT_MAX && !strcmp(small,"0000000"));
    CHECK(native_snprintf(NULL,0,"%.*d",INT_MAX,1)==INT_MAX);
    test_errno=0; CHECK(native_snprintf(small,sizeof(small),"x%*d",INT_MAX,1)==-1 && test_errno==EOVERFLOW);
    test_errno=0; CHECK(native_snprintf(NULL,0,"%.*d",INT_MAX,-1)==-1 && test_errno==EOVERFLOW);
    test_errno=0; CHECK(native_snprintf(NULL,0,"%*s",INT_MIN,"x")==-1 && test_errno==EOVERFLOW);
    test_errno=0; CHECK(native_snprintf(NULL,0,"%2147483648s","x")==-1 && test_errno==EOVERFLOW);
    test_errno=0; CHECK(native_snprintf(NULL,0,"%.2147483648g",1.0)==-1 && test_errno==EOVERFLOW);
    for (const char *conversion="fea";*conversion;++conversion) {
        char format[8]; snprintf(format,sizeof(format),"%%.*%c",*conversion);
        test_errno=0; CHECK(native_snprintf(NULL,0,format,INT_MAX,1.0)==-1 && test_errno==EOVERFLOW);
    }
    /* Huge general precision can still have a short result after trailing-zero removal. */
    CHECK(native_snprintf(NULL,0,"%.*g",INT_MAX,1.0)==1);
    CHECK(native_snprintf(small,sizeof(small),"%.*g",INT_MAX,0.0001)>0);
    test_errno=0; CHECK(native_snprintf(NULL,0,"%#.*g",INT_MAX,0.0001)==-1 && test_errno==EOVERFLOW);
    CHECK(!clock_gettime(CLOCK_MONOTONIC,&after));
    double elapsed=(after.tv_sec-before.tv_sec)+(after.tv_nsec-before.tv_nsec)*1e-9;
    CHECK(elapsed<2.0);
}

static void allocation_and_stream_errors(void) {
    char *output=(char *)1; char buffer[32];
    allocation_calls=0; fail_at=0; test_errno=0;
    CHECK(native_asprintf(&output,"abc")==-1 && !output && test_errno==ENOMEM && !live);
    allocation_calls=0; fail_at=1; int n=-1; test_errno=0;
    CHECK(native_asprintf(&output,"abc%n%f",&n,1.25)==-1 && !output && n==3 && test_errno==ENOMEM && !live);
    allocation_calls=0; fail_at=1; test_errno=0;
    CHECK(native_asprintf(&output,"%1000s","x")==-1 && !output && test_errno==ENOMEM && !live);
    allocation_calls=0; fail_at=0; test_errno=0;
    CHECK(native_snprintf(buffer,sizeof(buffer),"%f",1.25)==-1 && test_errno==ENOMEM && !buffer[0] && !live);
    fail_at=-1;
    CHECK(native_asprintf(&output,"")==0 && output && !output[0]); checked_free(output);
    union { int count; char bytes[sizeof(int)]; } alias={.bytes={'A','B',0,0}};
    CHECK(native_asprintf(&output,"%s%n/%s",alias.bytes,&alias.count,alias.bytes)==4);
    CHECK(output[0]=='A' && output[1]=='B' && output[2]=='/' && output[3]==2 && !output[4] && alias.count==2);
    checked_free(output);
    maximum_request=0; test_errno=0;
    CHECK(native_asprintf(&output,"%*s",INT_MAX,"x")==-1 && !output && test_errno==ENOMEM && !live);
    CHECK(maximum_request>1024*1024);
    test_errno=0; CHECK(native_snprintf(NULL,1,"x")==-1 && test_errno==EINVAL);
    test_errno=0; CHECK(native_snprintf(buffer,sizeof(buffer),NULL)==-1 && test_errno==EINVAL);
    test_errno=0; CHECK(native_snprintf(buffer,sizeof(buffer),"dangling%")==-1 && test_errno==EINVAL);
    test_errno=0; CHECK(native_snprintf(buffer,sizeof(buffer),"%ls",L"\u03a9")==-1 && test_errno==EILSEQ);
    test_errno=0; CHECK(native_snprintf(buffer,sizeof(buffer),"%lc",(wint_t)0x10041)==-1 && test_errno==EILSEQ);
    captured_size=stream_calls=stream_locks=stream_unlocks=0; capture_limit=sizeof(captured); captured_stdout.error=0;
    CHECK(native_printf("%s:%04d/%.2f","record",7,1.25)==16);
    CHECK(captured_size==16 && !memcmp(captured,"record:0007/1.25",16));
    CHECK(stream_locks==1 && stream_unlocks==1 && !captured_stdout.mutex.state && !captured_stdout.error);
    captured_size=stream_calls=0; capture_limit=3; test_errno=0;
    CHECK(native_fprintf(&captured_stdout,"abcdef")==-1 && captured_size==3 && captured_stdout.error && test_errno==EIO);
    captured_size=stream_calls=0; capture_limit=64; captured_stdout.error=0;
    CHECK(native_fprintf(&captured_stdout,"%*d",INT_MAX,7)==-1 && stream_calls<=2 && captured_size==64);
    captured_size=stream_calls=0; capture_limit=3; captured_stdout.error=0; test_errno=0;
    CHECK(native_fprintf(&captured_stdout,"%+20.3f",1.25)==-1 && captured_size==3 && captured_stdout.error && test_errno==EIO && !live);
    captured_stdout.orientation=1; test_errno=0;
    CHECK(native_fprintf(&captured_stdout,"")==-1 && test_errno==EINVAL && captured_stdout.error);
    captured_stdout.orientation=0;
    CHECK(native_fprintf(&captured_stdout,"")==0 && captured_stdout.orientation==-1);
    CHECK(stream_locks==stream_unlocks && !live);
}

int main(int argc,char **argv) {
    if (argc>1 && !strcmp(argv[1],"huge")) { huge_counts(); puts("huge width/precision fast-count contracts passed"); return 0; }
    if (argc>1 && !strcmp(argv[1],"alloc")) { allocation_and_stream_errors(); puts("allocation and stream contracts passed"); return 0; }
    integer_and_counts(); hexadecimal_and_frexpl(); guarded_strings(); float_comparisons(); directed_rounding();
    printf("production formatter comparison contracts passed: %u comparisons, LDBL_MANT_DIG=%d\n",comparisons,LDBL_MANT_DIG);
    return 0;
}
'''
    compiler = shlex.split(os.environ.get("HOST_CC", "cc"))
    with tempfile.TemporaryDirectory(prefix="alix-printf-contract-") as directory:
        source = Path(directory) / "test.c"
        binary = Path(directory) / "test"
        source.write_text(code)
        subprocess.run([*compiler, "-std=c11", "-Wall", "-Wextra", "-Werror", "-frounding-math",
                        str(source), "-o", str(binary)], check=True)
        modes = args.modes or ["huge", "alloc", "compare"]
        for mode in modes:
            subprocess.run([str(binary), mode], check=True, timeout=60)


if __name__ == "__main__":
    main()
