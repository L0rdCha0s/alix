#include "userlib.h"
#include "wchar.h"
#include "wctype.h"
#include "errno.h"
#include "sys/mman.h"
#include "serial.h"

#define WORKERS 8u
#define CHECK(condition,label) do { if(!(condition)) { \
    serial_printf("WCHAR_TEST: FAIL %s\n",label);return 1; } } while(0)
_Static_assert(sizeof(wchar_t)==2 && sizeof(mbstate_t)==8 && WCHAR_MAX==65535,"native wide ABI");

typedef struct
{
    alix_thread_t thread;
    unsigned index,failed,cpu_mask,checks;
    mbstate_t state;
    char output;
    wchar_t wide;
} wide_worker_t;

static void wide_worker(void *argument)
{
    wide_worker_t *worker=argument;
    if(sys_thread_set_affinity(worker->index) || sys_thread_cpu()!=worker->index) worker->failed=1;
    unsigned cpu=sys_thread_cpu();
    if(cpu<32) worker->cpu_mask=1u<<cpu; else worker->failed=1;
    for(unsigned value=worker->index;value<65536;value+=WORKERS)
    {
        worker->output='#';errno=EDOM;
        size_t bytes=wcrtomb(&worker->output,(wchar_t)value,&worker->state);
        if(value<128)
        {
            if(bytes!=1 || (unsigned char)worker->output!=value || errno!=EDOM || wctob(value)!=(int)value) worker->failed=1;
            worker->wide=0xffff;
            size_t decoded=mbrtowc(&worker->wide,&worker->output,1,&worker->state);
            if(decoded!=(value ? 1u : 0u) || worker->wide!=value) worker->failed=1;
        }
        else if(bytes!=(size_t)-1 || errno!=EILSEQ || worker->output!='#' || wctob(value)!=-1) worker->failed=1;
        int alpha=(value>='a' && value<='z') || (value>='A' && value<='Z');
        if(!!iswalpha(value)!=alpha || !!iswctype(value,wctype("alpha"))!=alpha || !mbsinit(&worker->state)) worker->failed=1;
        wint_t upper=value>='a' && value<='z' ? value-32 : value;
        if(towupper(value)!=upper || towctrans(value,wctrans("toupper"))!=upper) worker->failed=1;
        ++worker->checks;
    }
}

int main(void)
{
    wchar_t *wide=calloc(32,sizeof(*wide));char *bytes=calloc(32,1);mbstate_t *state=calloc(1,sizeof(*state));
    CHECK(wide && bytes && state,"private buffers");
    const char *input="abc";const char *origin=input;
    CHECK(mbsrtowcs(NULL,&input,0,state)==3 && input==origin,"count query source preservation");
    CHECK(mbsrtowcs(wide,&input,2,state)==2 && input==origin+2 && wide[1]=='b',"bounded decode");
    CHECK(mbsrtowcs(wide+2,&input,2,state)==1 && !input && !wcscmp(wide,L"abc"),"NUL source completion");
    const wchar_t *source=wide;
    CHECK(wcsrtombs(bytes,&source,3,state)==3 && source==wide+3 && !memcmp(bytes,"abc",3),"bounded encode");
    CHECK(wcsrtombs(bytes+3,&source,1,state)==0 && !source && !strcmp(bytes,"abc"),"encode NUL completion");
    state->count=1;CHECK(!mbsinit(state) && mbrtowc(wide,"a",1,state)==(size_t)-1 && errno==EINVAL,"invalid conversion state");
    CHECK(wcrtomb(NULL,0xffff,state)==1 && mbsinit(state),"stateless reset");
    const wchar_t raw[]={0x100,0xff,0xd800,0xdc00,0xffff,0};
    CHECK(wcscpy(wide,raw)==wide && wcslen(wide)==5 && wmemcmp(wide,wide+1,1)>0,"16-bit element ordering");
    CHECK(wcsstr(wide,raw+2)==wide+2 && wcschr(wide,0xffff)==wide+4 && wcscoll(wide,raw)==0,"raw codeunit strings");
    wmemmove(wide+1,wide,6);CHECK(!wmemcmp(wide+1,raw,6),"overlap move");
    wchar_t *end=NULL;
    CHECK(wcstoll(L"-9223372036854775808!",&end,10)==(-9223372036854775807LL-1) && *end=='!',"wide integer boundary");
    struct tm *date=calloc(1,sizeof(*date));CHECK(date,"calendar object");
    date->tm_year=124;date->tm_mon=1;date->tm_mday=29;date->tm_wday=4;date->tm_yday=59;date->tm_zone="UTC";
    CHECK(wcsftime(wide,32,L"\u2603 %F %V %z",date)==21 && !wcscmp(wide,L"\u2603 2024-02-29 09 +0000"),"wide calendar formatting");
    free(date);
    char *pages=mmap(NULL,8192,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    CHECK(pages!=MAP_FAILED && mprotect(pages+4096,4096,PROT_NONE)==0,"guard allocation");
    pages[4095]='x';input=pages+4095;
    CHECK(mbsnrtowcs(wide,&input,1,1,state)==1 && wide[0]=='x' && input==pages+4096,"bounded guard decode");
    CHECK(mbrtowc(wide,pages+4096,0,state)==(size_t)-2,"zero-length guard access");
    wchar_t *last=(wchar_t *)(pages+4094);*last='y';source=last;
    CHECK(wcsnrtombs(bytes,&source,1,1,state)==1 && bytes[0]=='y' && source==last+1,"bounded guard encode");
    CHECK(munmap(pages,8192)==0,"guard cleanup");
    wide_worker_t *workers=calloc(WORKERS,sizeof(*workers));CHECK(workers,"worker allocation");
    for(unsigned i=0;i<WORKERS;++i)
    {
        workers[i].index=i;
        CHECK(alix_thread_create(&workers[i].thread,"wide",wide_worker,&workers[i])==0,"worker creation");
    }
    unsigned mask=0,count=0;
    for(unsigned i=0;i<WORKERS;++i)
    {
        CHECK(alix_thread_join(workers[i].thread,NULL)==0 && !workers[i].failed,"worker conversions");
        mask|=workers[i].cpu_mask;count+=workers[i].checks;
    }
    CHECK(mask==0xff && count==65536,"complete codeunit coverage");
    free(workers);free(state);free(bytes);free(wide);
    serial_printf("WCHAR_TEST: PASS workers=8 cpu_mask=0xFF codeunits=65536 ascii=1 guards=1 pointers=1\n");
    return 0;
}
