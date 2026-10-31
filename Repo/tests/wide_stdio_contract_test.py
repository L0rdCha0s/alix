#!/usr/bin/env python3
"""Exercise production wide streams/formatting with true 16-bit wchar units."""
import os
import re
import shlex
import sys

sys.dont_write_bytecode = True
from audio_stream_contract_test import ROOT, compile_and_run, function_definition
from stdio_stream_contract_test import build_program, rename as rename_stdio


def rename(text):
    text = "\n".join(line for line in text.splitlines() if not line.startswith("#include"))
    text = rename_stdio(text)
    for name in ("printf", "vprintf", "perror", "vfprintf", "fprintf", "snprintf", "vsnprintf", "sprintf", "vsprintf", "asprintf", "vasprintf",
                 "frexpl", "strnlen", "wchar_t", "wint_t", "btowc", "wctob", "fwide", "fgetwc", "getwc", "getwchar",
                 "fputwc", "putwc", "putwchar", "ungetwc", "fgetws", "fputws", "swprintf", "vswprintf", "fwprintf",
                 "vfwprintf", "wprintf", "vwprintf"):
        text = re.sub(r"\b" + name + r"\b", "native_" + name, text)
    text = re.sub(r"\bWEOF\b", "NATIVE_WEOF", text)
    text = re.sub(r"\bmodel_malloc\b", "wide_malloc", text)
    text = re.sub(r"\bmodel_free\b", "wide_free", text)
    text = re.sub(r"\bcalloc\b", "wide_calloc", text)
    return re.sub(r"\brealloc\b", "wide_realloc", text)


def main():
    code = "#include <wchar.h>\n#include <math.h>\n#include <float.h>\n#include <fenv.h>\n#include <stdarg.h>\n#include <sys/mman.h>\n#include <unistd.h>\n"
    code += build_program().replace("int main(void) {", "static int __attribute__((unused)) narrow_stream_main(void) {", 1)
    code += r'''
typedef uint16_t native_wchar_t;
typedef uint32_t native_wint_t;
#define NATIVE_WEOF ((native_wint_t)-1)
static pthread_mutex_t allocation_lock=PTHREAD_MUTEX_INITIALIZER;
static void *wide_allocations[128]; static unsigned wide_live;
static size_t wide_max_request;
static _Thread_local int wide_fail_at=-1;
static _Thread_local unsigned wide_alloc_calls;
static bool wide_should_fail(size_t count) {
    CHECK(!pthread_mutex_lock(&allocation_lock)); if(count>wide_max_request) wide_max_request=count;
    CHECK(!pthread_mutex_unlock(&allocation_lock));
    unsigned call=wide_alloc_calls++;
    return count>1024*1024 || (wide_fail_at>=0 && call==(unsigned)wide_fail_at);
}
static void *wide_malloc(size_t size) {
    if(wide_should_fail(size)) return NULL;
    void *value=malloc(size); CHECK(value);
    CHECK(!pthread_mutex_lock(&allocation_lock)); CHECK(wide_live<128); wide_allocations[wide_live++]=value;
    CHECK(!pthread_mutex_unlock(&allocation_lock)); return value;
}
static void *wide_calloc(size_t n,size_t size) {
    if(size && n>SIZE_MAX/size) return NULL;
    void *value=wide_malloc(n*size); if(value) memset(value,0,n*size); return value;
}
static void *wide_realloc(void *old,size_t size) {
    if(!old) return wide_malloc(size);
    if(wide_should_fail(size)) return NULL;
    CHECK(!pthread_mutex_lock(&allocation_lock)); unsigned index=0;
    while(index<wide_live && wide_allocations[index]!=old) ++index; CHECK(index<wide_live);
    void *value=realloc(old,size); CHECK(value); wide_allocations[index]=value;
    CHECK(!pthread_mutex_unlock(&allocation_lock)); return value;
}
static void wide_free(void *value) {
    if(!value) return;
    CHECK(!pthread_mutex_lock(&allocation_lock)); unsigned index=0;
    while(index<wide_live && wide_allocations[index]!=value) ++index; CHECK(index<wide_live);
    wide_allocations[index]=wide_allocations[--wide_live]; CHECK(!pthread_mutex_unlock(&allocation_lock)); free(value);
}
'''
    header = (ROOT / "include/stdio.h").read_text()
    prototypes = "\n".join(line for line in header.splitlines()
                           if re.match(r"int (?:v?s(?:n)?printf|v?fprintf|printf|v?asprintf)\(", line))
    code += rename(prototypes) + "\n"
    code += rename((ROOT / "user/lib/printf_float.h").read_text()) + "\n"
    math = (ROOT / "user/lib/math.c").read_text()
    libc = (ROOT / "user/lib/libc.c").read_text()
    wchar = (ROOT / "user/lib/wchar.c").read_text()
    for text, signature in ((math, "long double frexpl("), (libc, "size_t strnlen("),
                            (wchar, "wint_t btowc("), (wchar, "int wctob(")):
        code += rename(function_definition(text, signature)) + "\n"
    code += rename((ROOT / "user/lib/printf_float.c").read_text()) + "\n"
    start = libc.index("static size_t file_write_bytes_unlocked(FILE *stream,")
    end = libc.index("#endif /* TTF_HOST_BUILD */", start)
    code += rename(libc[start:end]) + "\n"
    code += rename((ROOT / "user/lib/wide_stdio.c").read_text()) + r'''

static void make_format(const char *ascii,native_wchar_t *native,wchar_t *host) {
    size_t index=0;
    do { if(native) native[index]=(unsigned char)ascii[index]; if(host) host[index]=(unsigned char)ascii[index]; }
    while(ascii[index++]);
}
static void expect_ascii(const native_wchar_t *actual,const char *expected) {
    size_t index=0; do { CHECK(actual[index]==(unsigned char)expected[index]); } while(expected[index++]);
}
static void compare_format(const char *ascii,...) {
    native_wchar_t *format=calloc(128,sizeof(*format)), *actual=calloc(2048,sizeof(*actual));
    wchar_t *host_format=calloc(128,sizeof(*host_format)), *expected=calloc(2048,sizeof(*expected));
    CHECK(format && actual && host_format && expected); make_format(ascii,format,host_format);
    va_list args,copy; va_start(args,ascii); va_copy(copy,args);
    int wanted=vswprintf(expected,2048,host_format,args); va_end(args); CHECK(wanted>=0 && wanted<2048);
    int got=native_vswprintf(actual,2048,format,copy); va_end(copy);
    if(got!=wanted) { fprintf(stderr,"wide format count %s got%d want%d\n",ascii,got,wanted); abort(); }
    for(int i=0;i<=wanted;++i) if(actual[i]!=(uint32_t)expected[i]) {
        fprintf(stderr,"wide format unit %s index%d got%04x want%04x\n",ascii,i,actual[i],(unsigned)expected[i]); abort();
    }
    for(size_t capacity=0;capacity<8;++capacity) {
        for(unsigned i=0;i<16;++i) actual[i]=0xa5a5;
        va_start(args,ascii); got=native_vswprintf(actual,capacity,format,args); va_end(args);
        size_t copied=capacity ? ((size_t)wanted<capacity-1 ? (size_t)wanted : capacity-1) : 0;
        CHECK((size_t)wanted<capacity ? got==wanted : got<0);
        if(capacity) { for(size_t i=0;i<copied;++i) CHECK(actual[i]==(uint32_t)expected[i]); CHECK(actual[copied]==0); }
        for(size_t i=capacity;i<16;++i) CHECK(actual[i]==0xa5a5);
    }
    CHECK(!wide_live); free(expected); free(host_format); free(actual); free(format);
}
static void buffer_formatting(void) {
    compare_format("%+08d/%#o/%#X/%zu",-42,9u,0x1au,(size_t)1234);
    compare_format("%hhd/%hhu/%hd/%hu/%ld/%lld/%jd/%td",(int)(signed char)-128,(unsigned)255,
                   (int)(short)-32768,(unsigned)65535,LONG_MIN,LLONG_MIN,INTMAX_MIN,(ptrdiff_t)-23);
    compare_format("%15.4s/%c/%%","abcdef",'Q');
    compare_format("%*.*g/%.*e/%#.0f",-17,9,0.0001,12,-1.25,3.0);
    compare_format("%+#020.4a/%G/%.21Lf",1.25,100000.0,1.0L/3.0L);
    native_wchar_t output[64];
    static const native_wchar_t units[]={0x03a9,0xd83d,0xde00,0x4e2d,0};
    static const native_wchar_t format[]={0x2603,'[','%','8','.','3','l','s',']',0};
    CHECK(native_swprintf(output,64,format,units)==11);
    CHECK(output[0]==0x2603 && output[1]=='[');
    for(unsigned i=2;i<7;++i) CHECK(output[i]==' ');
    CHECK(output[7]==0x03a9 && output[8]==0xd83d && output[9]==0xde00 && output[10]==']' && !output[11]);
    native_wchar_t simple[32]; make_format("[%4lc]",simple,NULL);
    CHECK(native_swprintf(output,64,simple,(native_wint_t)0x20ac)==6 && output[4]==0x20ac);
    make_format("%lc",simple,NULL);
    CHECK(native_swprintf(output,64,simple,(native_wint_t)0)==1 && output[0]==0 && output[1]==0);
    CHECK(native_swprintf(output,64,simple,(native_wint_t)0x10041)==-1 && test_errno==EILSEQ);
    make_format("%c",simple,NULL); CHECK(native_swprintf(output,64,simple,0xff)==-1 && test_errno==EILSEQ);
    make_format("%s",simple,NULL); CHECK(native_swprintf(output,64,simple,"\xc3\xa9")==-1 && test_errno==EILSEQ);
    make_format("%.1s",simple,NULL); CHECK(native_swprintf(output,64,simple,"A\xff")==1 && output[0]=='A');
    make_format("%ls%n%ls",simple,NULL);
    union { int count; native_wchar_t text[4]; } alias={.text={'A','B',0,0}};
    CHECK(native_swprintf(output,64,simple,alias.text,&alias.count,alias.text)==3);
    CHECK(output[0]=='A' && output[1]=='B' && output[2]==2 && !output[3] && alias.count==2);
    make_format("%hhn%hn%n%ln%lln%zn%tn%jn",simple,NULL);
    signed char hh=-1; short h=-1; int n=-1; long l=-1; long long ll=-1; ssize_t z=-1; ptrdiff_t t=-1; intmax_t j=-1;
    CHECK(native_swprintf(output,64,simple,&hh,&h,&n,&l,&ll,&z,&t,&j)==0);
    CHECK(!hh && !h && !n && !l && !ll && !z && !t && !j);
}
static void precision_guards_and_failures(void) {
    long page=sysconf(_SC_PAGESIZE); CHECK(page>0);
    unsigned char *memory=mmap(NULL,(size_t)page*2,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
    CHECK(memory!=MAP_FAILED && !mprotect(memory+page,(size_t)page,PROT_NONE));
    native_wchar_t *tail=(native_wchar_t *)(memory+page-4); tail[0]=0x1234; tail[1]=0xabcd;
    native_wchar_t format[32],output[16]; make_format("%.2ls",format,NULL);
    CHECK(native_swprintf(output,16,format,tail)==2 && output[0]==0x1234 && output[1]==0xabcd);
    make_format("%.0ls%.0s",format,NULL);
    CHECK(native_swprintf(output,16,format,(native_wchar_t *)(memory+page),(char *)(memory+page))==0);
    CHECK(native_snprintf((char *)output,16,"%.0ls",(native_wchar_t *)(memory+page))==0);
    tail[0]='A'; tail[1]='B'; char narrow[16];
    CHECK(native_snprintf(narrow,sizeof(narrow),"%.2ls",tail)==2 && !strcmp(narrow,"AB"));
    CHECK(native_snprintf(narrow,sizeof(narrow),"%lc",(native_wint_t)0x10041)==-1 && test_errno==EILSEQ);
    CHECK(!munmap(memory,(size_t)page*2));
    make_format("%*d",format,NULL); wide_max_request=0;
    CHECK(native_swprintf(output,4,format,INT_MAX,1)==-1 && test_errno==EOVERFLOW);
    CHECK(output[0]==' ' && output[1]==' ' && output[2]==' ' && !output[3] && wide_max_request<4096);
    make_format("%.*g",format,NULL);
    CHECK(native_swprintf(output,16,format,INT_MAX,1.0)==1 && output[0]=='1');
    make_format("%f",format,NULL);
    for(int failure=0;failure<4;++failure) {
        wide_alloc_calls=0; wide_fail_at=failure; test_errno=0;
        CHECK(native_swprintf(output,16,format,1.25)==-1 && test_errno==ENOMEM && !wide_live);
    }
    wide_fail_at=-1; output[0]=0x1234;
    CHECK(native_swprintf(output,0,format,1.25)==-1 && output[0]==0x1234);
    CHECK(native_swprintf(NULL,1,format,1.25)==-1 && test_errno==EINVAL);
    make_format("%.1Lf",format,NULL); CHECK(!fesetround(FE_UPWARD));
    CHECK(native_swprintf(output,16,format,1.25L)==3); expect_ascii(output,"1.3"); CHECK(!fesetround(FE_TONEAREST));
}
static void stream_contracts(void) {
    native_FILE *stream=open_stream("r+","ab\n\x80z",true); model_file_t *file=model_file(stream->fd);
    test_errno=77; CHECK(native_fwide(stream,0)==0 && test_errno==77);
    CHECK(native_fgetwc(stream)=='a' && native_fwide(stream,0)>0);
    CHECK(native_fwide(stream,-1)>0 && test_errno==77);
    CHECK(native_ungetwc('X',stream)=='X' && native_ftell(stream)==0);
    CHECK(native_ungetwc('Y',stream)==NATIVE_WEOF);
    CHECK(native_fgetc(stream)==EOF && test_errno==EINVAL && file->position==1);
    native_clearerr(stream); CHECK(native_fgetwc(stream)=='X');
    native_wchar_t line[16]; CHECK(native_fgetws(line,16,stream)==line); expect_ascii(line,"b\n");
    CHECK(native_fgetwc(stream)==NATIVE_WEOF && test_errno==EILSEQ && native_ferror(stream) && !native_feof(stream));
    native_clearerr(stream); CHECK(native_fgetwc(stream)=='z' && native_fgetwc(stream)==NATIVE_WEOF && native_feof(stream));
    CHECK(native_ungetwc(NATIVE_WEOF,stream)==NATIVE_WEOF && native_feof(stream));
    CHECK(native_ungetwc('Q',stream)=='Q' && !native_feof(stream));
    CHECK(native_ungetwc(0x03a9,stream)==NATIVE_WEOF && test_errno==EILSEQ);
    native_clearerr(stream); CHECK(native_fgetwc(stream)=='Q');
    CHECK(native_fseek(stream,0,SEEK_SET)==0 && native_fwide(stream,0)>0);
    CHECK(native_fgetc(stream)==EOF && test_errno==EINVAL && file->position==0);
    CHECK(native_fclose(stream)==0);
    stream=open_stream("r","abc",true); file=model_file(stream->fd);
    CHECK(native_fgetc(stream)=='a' && native_fwide(stream,1)<0);
    CHECK(native_fgetwc(stream)==NATIVE_WEOF && test_errno==EINVAL && file->position==1); CHECK(native_fclose(stream)==0);

    stream=open_stream("w+","",true); file=model_file(stream->fd);
    native_wchar_t format[64],word[]={'o','k',0}; make_format("%ls:%04d/%.2Lf",format,NULL);
    CHECK(native_fwprintf(stream,format,word,7,1.25L)==12 && !memcmp(file->data,"ok:0007/1.25",12));
    CHECK(native_fputwc('!',stream)=='!' && native_fwide(stream,0)>0);
    CHECK(native_fputwc(0x03a9,stream)==NATIVE_WEOF && test_errno==EILSEQ && native_ferror(stream));
    native_clearerr(stream); CHECK(native_fputws(word,stream)==0);
    unsigned writes=file->write_calls;
    CHECK(native_fprintf(stream,"")==-1 && test_errno==EINVAL && file->write_calls==writes);
    native_clearerr(stream); make_format("%ls",format,NULL);
    native_wchar_t unicode[]={0x20ac,0};
    CHECK(native_fwprintf(stream,format,unicode)==-1 && test_errno==EILSEQ && native_ferror(stream));
    native_clearerr(stream); wide_fail_at=0; wide_alloc_calls=0;
    CHECK(native_fputws(word,stream)==EOF && test_errno==ENOMEM && !wide_live); wide_fail_at=-1;
    CHECK(!held_stream && native_fclose(stream)==0);
    stream=open_stream("r","a",false); CHECK(native_getwc(stream)=='a' && native_ungetwc('Z',stream)=='Z');
    CHECK(native_fflush(stream)==EOF && test_errno==ESPIPE && native_getwc(stream)=='Z'); CHECK(native_fclose(stream)==0);
}
typedef struct { native_FILE *stream; native_wchar_t format[32]; pthread_t thread; unsigned index; } wide_writer_t;
static void *wide_writer(void *argument) {
    wide_writer_t *worker=argument;
    for(unsigned i=0;i<64;++i) CHECK(native_fwprintf(worker->stream,worker->format,worker->index)==10);
    return NULL;
}
static void concurrent_wide_records(void) {
    native_FILE *stream=open_stream("w","",true); model_file_t *file=model_file(stream->fd);
    file->write_chunk=1; file->yield_io=true;
    wide_writer_t *workers=calloc(8,sizeof(*workers)); CHECK(workers);
    for(unsigned i=0;i<8;++i) {
        workers[i].stream=stream; workers[i].index=i; make_format("[%08u]",workers[i].format,NULL);
        CHECK(!pthread_create(&workers[i].thread,NULL,wide_writer,&workers[i]));
    }
    for(unsigned i=0;i<8;++i) CHECK(!pthread_join(workers[i].thread,NULL));
    CHECK(file->size==5120);
    for(size_t position=0;position<file->size;position+=10) {
        CHECK(file->data[position]=='[' && file->data[position+9]==']');
        for(unsigned i=1;i<8;++i) CHECK(file->data[position+i]=='0');
        CHECK(file->data[position+8]>='0' && file->data[position+8]<='7');
    }
    CHECK(native_fclose(stream)==0); free(workers);
}
int main(void) {
    CHECK(sizeof(native_wchar_t)==2); buffer_formatting(); precision_guards_and_failures(); stream_contracts(); concurrent_wide_records();
    CHECK(!wide_live && !model_file_allocations && !held_stream);
    for(unsigned i=0;i<64;++i) if(files[i]) { CHECK(!files[i]->opened); free(files[i]->data); free(files[i]); }
    puts("production16-bit wide stdio, native numeric formatting, orientation, ASCII encoding and concurrent records passed");
    return 0;
}
'''
    previous = os.environ.get("HOST_CC")
    os.environ["HOST_CC"] = shlex.join(shlex.split(previous or "cc") + ["-pthread", "-frounding-math"])
    try:
        compile_and_run("wide-stdio", code)
    finally:
        if previous is None:
            os.environ.pop("HOST_CC", None)
        else:
            os.environ["HOST_CC"] = previous
    print("wide stdio and formatting contracts passed")


if __name__ == "__main__":
    main()
