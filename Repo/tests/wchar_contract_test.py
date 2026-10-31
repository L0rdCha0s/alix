#!/usr/bin/env python3
"""Exercise real Alix wide APIs with the native 16-bit ABI under host sanitizers."""
from pathlib import Path
import os
import re
import shlex
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[1]
HARNESS=r'''
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include "wchar.h"
#include "wctype.h"
static int fail_malloc;
void *wide_test_malloc(size_t size) { if(fail_malloc) return NULL; return malloc(size); }

static void test_ascii_and_state(void)
{
    assert(sizeof(wchar_t)==2 && sizeof(mbstate_t)==8 && WCHAR_MAX==65535);
    mbstate_t state={0};
    for(unsigned c=0;c<256;++c)
    {
        char input=(char)c,output='#';wchar_t wide=0x4444;
        errno=EDOM;
        assert(btowc((int)c)==(c<128 ? c : WEOF) && errno==EDOM);
        size_t result=mbrtowc(&wide,&input,1,&state);
        if(c<128)
        {
            assert(result==(c ? 1u : 0u) && wide==c && errno==EDOM);
            assert(wcrtomb(&output,wide,&state)==1 && (unsigned char)output==c);
            assert(mbtowc(&wide,&input,1)==(c ? 1 : 0));
        }
        else assert(result==(size_t)-1 && errno==EILSEQ && wide==0x4444);
        assert(mbsinit(&state));
    }
    for(unsigned c=0;c<=65535;++c)
    {
        char output='#';errno=EDOM;
        assert(wctob(c)==(c<128 ? (int)c : -1) && errno==EDOM);
        size_t n=wcrtomb(&output,(wchar_t)c,&state);
        if(c<128) assert(n==1 && (unsigned char)output==c && errno==EDOM);
        else assert(n==(size_t)-1 && errno==EILSEQ && output=='#');
        int ascii=c<128;
#define CLASS(wide,narrow) assert(!!wide(c)==(ascii && !!narrow((int)c)))
        CLASS(iswalnum,isalnum);CLASS(iswalpha,isalpha);CLASS(iswblank,isblank);CLASS(iswcntrl,iscntrl);
        CLASS(iswdigit,isdigit);CLASS(iswgraph,isgraph);CLASS(iswlower,islower);CLASS(iswprint,isprint);
        CLASS(iswpunct,ispunct);CLASS(iswspace,isspace);CLASS(iswupper,isupper);CLASS(iswxdigit,isxdigit);
        assert(towlower(c)==(ascii ? (unsigned)tolower((int)c) : c));
        assert(towupper(c)==(ascii ? (unsigned)toupper((int)c) : c));
        assert(!!iswctype(c,wctype("alpha"))==!!iswalpha(c));
        assert(towctrans(c,wctrans("tolower"))==towlower(c));
    }
    assert(!iswalpha(WEOF) && !iswcntrl(WEOF) && towupper(WEOF)==WEOF && wctob(WEOF)==-1 && btowc(-1)==WEOF);
    assert(!wctype("unknown") && !wctrans("unknown") && !iswctype('a',0));
    wchar_t out=0x4444;errno=EDOM;
    assert(mbrtowc(&out,"a",0,&state)==(size_t)-2 && out==0x4444 && errno==EDOM);
    state.count=1;assert(!mbsinit(&state));
    assert(mbrtowc(&out,"a",1,&state)==(size_t)-1 && errno==EINVAL && out==0x4444);
    assert(mbrtowc(&out,NULL,0,&state)==0 && out==0x4444 && mbsinit(&state));
    state.value=10;assert(wcrtomb(NULL,0xffff,&state)==1 && mbsinit(&state));
    assert(mbsinit(NULL) && mbrlen(NULL,0,NULL)==0 && mbtowc(NULL,NULL,100)==0 && wctomb(NULL,0xffff)==0);
    assert(mbtowc(&out,"a",0)==-1 && errno==EILSEQ && mblen("",1)==0);
}

static void test_source_pointers(void)
{
    const char input[]="abc",bad[]={'a','b',(char)0x80,'c',0};
    const char *source=input;wchar_t out[8]={0x5555};mbstate_t state={0};
    assert(mbsrtowcs(NULL,&source,0,&state)==3 && source==input);
    assert(mbsnrtowcs(NULL,&source,2,0,&state)==2 && source==input);
    assert(mbsrtowcs(out,&source,3,&state)==3 && source==input+3 && out[0]=='a' && out[2]=='c');
    assert(mbsrtowcs(out,&source,0,&state)==0 && source==input+3);
    assert(mbsrtowcs(out,&source,1,&state)==0 && source==NULL && out[0]==0);
    source=bad;assert(mbsrtowcs(out,&source,2,&state)==2 && source==bad+2);
    out[2]=0x5555;assert(mbsrtowcs(out+2,&source,1,&state)==(size_t)-1 && source==bad+2 && out[2]==0x5555 && errno==EILSEQ);
    source=bad;assert(mbsrtowcs(NULL,&source,0,&state)==(size_t)-1 && source==bad);
    const wchar_t wide[]={L'a',L'b',L'c',0},invalid[]={L'a',0xd800,L'b',0};
    const wchar_t *cursor=wide;char bytes[8]={'#'};
    assert(wcsrtombs(NULL,&cursor,0,&state)==3 && cursor==wide);
    assert(wcsnrtombs(NULL,&cursor,2,0,&state)==2 && cursor==wide);
    assert(wcsrtombs(bytes,&cursor,3,&state)==3 && cursor==wide+3 && !memcmp(bytes,"abc",3));
    assert(wcsrtombs(bytes,&cursor,1,&state)==0 && cursor==NULL && bytes[0]==0);
    cursor=invalid;assert(wcsnrtombs(bytes,&cursor,1,8,&state)==1 && cursor==invalid+1);
    bytes[1]='#';assert(wcsrtombs(bytes+1,&cursor,8,&state)==(size_t)-1 && cursor==invalid+1 && bytes[1]=='#');
    cursor=invalid;assert(wcsrtombs(NULL,&cursor,0,&state)==(size_t)-1 && cursor==invalid);
    assert(mbstowcs(out,"hello",6)==5 && !wcscmp(out,L"hello"));
    assert(wcstombs(bytes,L"hello",6)==5 && !strcmp(bytes,"hello"));
}

static void test_guards_and_strings(void)
{
    size_t page=(size_t)sysconf(_SC_PAGESIZE);
    char *memory=mmap(NULL,page*2,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);assert(memory!=MAP_FAILED);
    assert(!mprotect(memory+page,page,PROT_NONE));
    const char *source=memory+page-1;memory[page-1]='x';wchar_t wide=0;mbstate_t state={0};
    assert(mbsnrtowcs(&wide,&source,1,1,&state)==1 && wide=='x' && source==memory+page);
    assert(mbrtowc(&wide,memory+page,0,&state)==(size_t)-2);
    assert(mbsnrtowcs(&wide,&source,0,1,&state)==0);
    wchar_t *last=(wchar_t *)(memory+page-sizeof(wchar_t));*last='y';const wchar_t *cursor=last;char byte=0;
    assert(wcsnrtombs(&byte,&cursor,1,1,&state)==1 && byte=='y' && cursor==last+1);
    assert(wcsnrtombs(&byte,&cursor,0,1,&state)==0);
    *last=0;assert(wcslen(last)==0 && wcschr(last,0)==last && !wcsstr(last,L"x") && wcsrchr(last,0)==last);
    assert(wcsnlen((wchar_t *)(memory+page),0)==0 && wmemcmp(last,last,0)==0);
    assert(wcpncpy(NULL,NULL,0)==NULL);
    assert(!munmap(memory,page*2));
    wchar_t units[]={0x100,0xff,0xd800,0xdc00,0xffff,0};wchar_t copy[12];
    assert(wcscpy(copy,units)==copy && wcslen(copy)==5 && !wmemcmp(copy,units,6));
    assert(wmemcmp(units,units+1,1)>0); /* bytewise memcmp would give the opposite order. */
    assert(wcschr(units,0xd800)==units+2 && wcsrchr(units,0xffff)==units+4);
    assert(wcsstr(units,units+2)==units+2 && wcsspn(units,units)==5 && wcscspn(units,units+2)==2);
    assert(wcspbrk(units,units+3)==units+3);
    for(unsigned length=0;length<12;++length)
    {
        wmemset(copy,0x5555,12);wcsncpy(copy,units,length);
        for(unsigned i=0;i<length;++i) assert(copy[i]==(i<5 ? units[i] : 0));
        if(length<12) assert(copy[length]==0x5555);
    }
    wchar_t moved[16],expected[16];
    for(unsigned shift=0;shift<8;++shift)
    {
        for(unsigned i=0;i<16;++i) moved[i]=expected[i]=(wchar_t)(i+0x100);
        memmove(expected+shift,expected,8*sizeof(*expected));wmemmove(moved+shift,moved,8);assert(!memcmp(moved,expected,sizeof(moved)));
        memmove(expected,expected+shift,8*sizeof(*expected));wmemmove(moved,moved+shift,8);assert(!memcmp(moved,expected,sizeof(moved)));
    }
    wchar_t split[]=L",one,,two,";wchar_t *saved=NULL;
    assert(!wcscmp(wcstok(split,L",",&saved),L"one"));
    assert(!wcscmp(wcstok(NULL,L",",&saved),L"two") && !wcstok(NULL,L",",&saved));
    assert(wcsxfrm(NULL,units,0)==5 && wcscoll(units,units+1)>0);
    assert(wcsxfrm(copy,units,12)==5 && !wmemcmp(copy,units,6));
    wchar_t *duplicate=wcsdup(units);assert(duplicate && !wmemcmp(duplicate,units,6));free(duplicate);
}

static void test_numbers_and_time(void)
{
    wchar_t *end;errno=EDOM;
    assert(wcstoll(L" -9223372036854775808!",&end,10)==LLONG_MIN && *end=='!' && errno==EDOM);
    assert(wcstoull(L"18446744073709551616!",&end,10)==ULLONG_MAX && *end=='!' && errno==ERANGE);
    wchar_t terminated[]={L'4',L'2',0xd800,L'9',0};errno=EDOM;
    assert(wcstol(terminated,&end,10)==42 && end==terminated+2 && errno==EDOM);
    assert(wcstoul(L"0xff!",&end,0)==255 && *end=='!');
    assert(wcstof(L"1.25f",&end)==1.25f && *end=='f');
    assert(wcstod(L"-0x1.ap2!",&end)==-6.5 && *end=='!');
    assert(wcstold(L"3.125L",&end)==3.125L && *end=='L');
    fail_malloc=1;const wchar_t *number=L"42";
    assert(wcstol(number,&end,10)==0 && end==number && errno==ENOMEM);
    assert(!wcsdup(number) && errno==ENOMEM);fail_malloc=0;
    struct tm date={.tm_year=124,.tm_mon=1,.tm_mday=29,.tm_wday=4,.tm_yday=59,.tm_isdst=0,.tm_gmtoff=0,.tm_zone="UTC"};
    wchar_t text[64];
    assert(wcsftime(text,64,L"\u2603 %F %V %z",&date)==21 && !wcscmp(text,L"\u2603 2024-02-29 09 +0000"));
    assert(!wcsftime(text,4,L"%Y",&date) && text[0]==0);
    date.tm_zone="\x80";assert(!wcsftime(text,64,L"%Z",&date) && errno==EILSEQ);
}

int main(void)
{
    test_ascii_and_state();test_source_pointers();test_guards_and_strings();test_numbers_and_time();
    puts("Native16-bit wchar contracts: PASS codeunits=65536 ASCII=256 guards=1 pointers=1 numeric=1");
}
'''

with tempfile.TemporaryDirectory(prefix="alix-wchar-") as temporary:
    work=Path(temporary)
    wchar=(ROOT/"include/wchar.h").read_text().replace("typedef struct FILE FILE;","#include <stdio.h>")
    wctype=(ROOT/"include/wctype.h").read_text()
    symbols=sorted(set(re.findall(r"\b([a-z_][a-z_0-9]*)\([^;{}]*\);",wchar+wctype))|
                   {"strftime","wint_t","mbstate_t","wctype_t","wctrans_t"})
    def renamed(text):
        # Darwin intentionally poisons calls to its 32-bit wide ABI when
        # -fshort-wchar is used. Rename our production symbols before parsing,
        # never call Darwin's wide functions or suppress that ABI protection.
        text=re.sub(r"\b("+"|".join(symbols)+r")\b",lambda m:"alix_test_"+m.group(),text)
        return text.replace('"alix_test_wctype.h"','"wctype.h"')
    wchar=renamed(wchar).replace('#include "time.h"','#include <time.h>\nsize_t alix_test_strftime(char *,size_t,const char *,const struct tm *);')
    (work/"wchar.h").write_text(wchar);(work/"wctype.h").write_text(renamed(wctype))
    (work/"types.h").write_text("#include <stdint.h>\n#include <stddef.h>\n#include <stdbool.h>\n#include <sys/types.h>\n")
    compiler=shlex.split(os.environ.get("HOST_CC","cc"))
    flags=["-std=c11","-D_DARWIN_C_SOURCE","-D_GNU_SOURCE","-D_DEFAULT_SOURCE","-fshort-wchar","-fno-builtin",
           "-Wall","-Wextra","-Werror","-g","-fsanitize=address,undefined","-I"+str(work)]
    objects=[]
    for name in ("wchar","wcstofloat","calendar_format"):
        source=work/(name+".c");source.write_text(renamed((ROOT/"user/lib"/(name+".c")).read_text()))
        obj=source.with_suffix(".o");objects.append(str(obj))
        subprocess.run(compiler+flags+["-Dmalloc=wide_test_malloc","-c",str(source),"-o",str(obj)],check=True)
    harness=work/"test.c";harness.write_text(renamed(HARNESS));binary=work/"test"
    subprocess.run(compiler+flags+[str(harness)]+objects+["-o",str(binary)],check=True)
    subprocess.run([str(binary)],check=True)
