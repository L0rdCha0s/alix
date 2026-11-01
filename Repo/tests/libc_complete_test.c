#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "math.h"
#include "complex.h"
#include "fenv.h"
#include "threads.h"
#include "uchar.h"
#include "errno.h"
#include "unistd.h"
#include "usyscall.h"
#include "wchar.h"
#include "serial.h"
#include <stdint.h>
#include <stdatomic.h>
#include <float.h>
#include <limits.h>

#define CHECK(test) do { if (!(test)) { serial_printf("LIBC_COMPLETE_TEST: FAIL line=%d expression=%s errno=%d", __LINE__, #test, errno); return false; } } while (0)
static bool close_to(long double actual, long double expected, long double tolerance)
{ return fabsl(actual-expected) <= tolerance * fmaxl(1, fabsl(expected)); }


#include "fixtures/libc_math_vectors.h"

static bool math_tests(void)
{
    CHECK(math_vector_tests());
    CHECK(pow(-2,3)==-8 && pow(0,0)==1);
    CHECK(isinf(floor(INFINITY)) && isnan(ceil(NAN)));
    CHECK(signbit(fabs(-0.0))==0 && signbit(copysign(0,-1)));
    CHECK(sqrt(4)==2 && sqrtf(4)==2 && sqrtl(4)==2);
    CHECK(close_to(sin(1e100),-0.38063773100502866607L,2e-15L));
    CHECK(close_to(expl(1),2.718281828459045235360287L,3e-19L));
    CHECK(close_to(logl(2),0.693147180559945309417232L,2e-19L));
    CHECK(close_to(atan2l(1,-1),2.356194490192344928846982L,3e-19L));
    CHECK(fmal(1+0x1p-32L,1-0x1p-32L,-1)==-0x1p-64L);
    CHECK(fma(1+0x1p-27,1-0x1p-27,-1)==-0x1p-54);
    CHECK(nextafterl(1,2)>1 && nextafterl(1,2)<1+0x1p-53L);
    CHECK(scalbnl(1,10000)>DBL_MAX && isfinite(scalbnl(1,10000)));
    CHECK(tgammal(6)==120 && close_to(erfl(1),0.84270079294971486934L,4e-19L));
    CHECK(hypotl(0x1p10000L,0x1p10000L)>0x1p10000L);
    CHECK(close_to(cbrtl(27),3,2e-19L));
    for (int i=-500; i<=500; ++i)
    {
        long double x=i/100.0L;
        CHECK(close_to(sinl(x)*sinl(x)+cosl(x)*cosl(x),1,1e-18L));
        CHECK(close_to(logl(expl(x)),x,1e-18L));
        long double complex z=CMPLXL(x,0.125L);
        long double complex back=cexpl(clogl(z));
        CHECK(close_to(creall(back),x,2e-18L) && close_to(cimagl(back),0.125L,2e-18L));
        long double complex roundtrip=csinl(casinl(z));
        CHECK(close_to(creall(roundtrip),x,4e-18L) && close_to(cimagl(roundtrip),0.125L,4e-18L));
    }
    CHECK(creall(cexpl(CMPLXL(1+0x1p-60L,0)))>creall(cexpl(CMPLXL(1,0))));
    CHECK(cimagl(csinhl(CMPLXL(1,0x1p-10000L)))>0);
    CHECK(cimagl(ccoshl(CMPLXL(1,0x1p-10000L)))>0);
    CHECK(close_to(creall(ctanhl(CMPLXL(1,0))),tanhl(1),2e-19L));
    CHECK(isfinite(creall(csqrtl(CMPLXL(LDBL_MAX,LDBL_MAX)))));
    return true;
}

static bool environment_tests(void)
{
    fenv_t original, held;
    CHECK(fegetenv(&original)==0);
    CHECK(feclearexcept(FE_ALL_EXCEPT)==0 && fetestexcept(FE_ALL_EXCEPT)==0);
    CHECK(feraiseexcept(FE_INVALID|FE_DIVBYZERO)==0);
    CHECK((fetestexcept(FE_ALL_EXCEPT)&(FE_INVALID|FE_DIVBYZERO))==(FE_INVALID|FE_DIVBYZERO));
    fexcept_t flags;
    CHECK(fegetexceptflag(&flags,FE_INVALID)==0);
    CHECK(feholdexcept(&held)==0 && fetestexcept(FE_ALL_EXCEPT)==0);
    CHECK(fesetexceptflag(&flags,FE_INVALID)==0 && fetestexcept(FE_INVALID));
    CHECK(feupdateenv(&held)==0 && fetestexcept(FE_DIVBYZERO));
    static double (*const rounding[])(double)={ceil,floor,round,trunc,rint,nearbyint};
    union {uint64_t bits;double value;} signaling={.bits=UINT64_C(0x7ff0000000000001)};
    for(unsigned i=0;i<sizeof(rounding)/sizeof(*rounding);++i)
    {
        CHECK(feclearexcept(FE_ALL_EXCEPT)==0);
        double quiet=rounding[i](signaling.value);
        CHECK(fetestexcept(FE_ALL_EXCEPT)==FE_INVALID && isnan(quiet));
    }
    int modes[]={FE_TONEAREST,FE_UPWARD,FE_DOWNWARD,FE_TOWARDZERO};
    for(unsigned i=0;i<4;++i)
    {
        CHECK(fesetround(modes[i])==0 && fegetround()==modes[i]);
        CHECK(feclearexcept(FE_ALL_EXCEPT)==0);
        volatile double input=1.5;
        double result=nearbyint(input);
        CHECK(result==(i<2?2:1) && !fetestexcept(FE_INEXACT));
    }
    CHECK(fesetenv(&original)==0);
    return true;
}

static bool scan_tests(void)
{
    struct { char before, value, after; } character={'a',0,'z'};
    CHECK(sscanf("Q","%c",&character.value)==1);
    CHECK(character.before=='a' && character.value=='Q' && character.after=='z');
    signed char small=0; short medium=0; long long large=0; size_t size=0; int n=-1;
    CHECK(sscanf("-12 -1234 -9223372036854775807 42!","%hhd %hd %lld %zu%n",&small,&medium,&large,&size,&n)==4);
    CHECK(small==-12 && medium==-1234 && large==-9223372036854775807LL && size==42 && n==33);
    char word[12]; unsigned hex=0;
    CHECK(sscanf("abc-XYZ 0xff","%[a-z]-XYZ %i",word,&hex)==2 && !strcmp(word,"abc") && hex==255);
    long double floating=0; double second=0;
    CHECK(sscanf("0x1.000000000000001p0 inf","%La %lf",&floating,&second)==2);
    CHECK(floating>1 && isinf(second));
    CHECK(sscanf("", "%d", &n)==EOF && sscanf("x", "%d", &n)==0);
    CHECK(sscanf("12 a", "%*d %c", &character.value)==1 && character.value=='a');
    wchar_t wide_character=0;
    CHECK(swscanf(L"\u03b1 12.5",L"%lc %Lf",&wide_character,&floating)==2);
    CHECK(wide_character==0x03b1 && floating==12.5L);
    char *end;
    CHECK(strtod("  -0x1.8p2!",&end)==-6 && *end=='!');
    CHECK(strtod("100er",&end)==100 && !strcmp(end,"er"));
    CHECK(strtold("1.000000000000000001",&end)>1 && !*end);
    CHECK(isnan(strtod("nan(payload)",&end)) && !*end);
    CHECK(isnan(strtod("nan(abcdefghijklmnopqrstuvwxyz0123456789!",&end)) && *end=='(');
    return true;
}

static const char *append_path;
static int append_worker(void *opaque)
{
    unsigned index=(unsigned)(uintptr_t)opaque;
    if(sys_thread_set_affinity(index)) return -1;
    FILE *stream=fopen(append_path,"ab");
    char *record=malloc(2);
    if(!stream || !record) return -2;
    record[0]=(char)('0'+index);record[1]='\n';
    for(unsigned i=0;i<40;++i)
        if(fwrite(record,1,2,stream)!=2) return -3;
    free(record);
    return fclose(stream);
}
static bool file_tests(void)
{
    FILE *stream=tmpfile();
    CHECK(stream && fwrite("123 45.5!",1,9,stream)==9);
    rewind(stream);
    int value=0; double number=0;
    CHECK(fscanf(stream,"%d %lf",&value,&number)==2 && value==123 && number==45.5);
    CHECK(fgetc(stream)=='!' && fclose(stream)==0);
    char *first=malloc(L_tmpnam), *second=malloc(L_tmpnam);
    CHECK(first && second && tmpnam(first) && tmpnam(second));
    stream=fopen(first,"w+x");
    CHECK(stream && fputs("old",stream)>=0 && fflush(stream)==0);
    errno=0;
    CHECK(!fopen(first,"wx") && errno==EEXIST);
    CHECK(rename(first,second)==0);
    CHECK(remove(second)==0);
    rewind(stream);
    char data[8];
    CHECK(fread(data,1,3,stream)==3 && !memcmp(data,"old",3));
    CHECK(freopen(first,"w+",stream)==stream);
    CHECK(fputs("new",stream)>=0 && fclose(stream)==0 && remove(first)==0);
    append_path=first;
    thrd_t *append_threads=calloc(8,sizeof(*append_threads));CHECK(append_threads);
    for(unsigned i=0;i<8;++i) CHECK(thrd_create(&append_threads[i],append_worker,(void *)(uintptr_t)i)==thrd_success);
    for(unsigned i=0;i<8;++i){int status;CHECK(thrd_join(append_threads[i],&status)==thrd_success && status==0);}
    stream=fopen(first,"r");CHECK(stream);
    unsigned counts[8]={0};
    for(unsigned i=0;i<320;++i)
    {
        int id=fgetc(stream);CHECK(id>='0' && id<='7' && fgetc(stream)=='\n');++counts[id-'0'];
    }
    CHECK(fgetc(stream)==EOF && fclose(stream)==0 && remove(first)==0);
    for(unsigned i=0;i<8;++i) CHECK(counts[i]==40);
    free(append_threads);append_path=NULL;
    free(first);free(second);
    return true;
}

typedef struct { mtx_t mutex; cnd_t condition, start_condition; once_flag once; tss_t key; unsigned count, once_count, arrived; bool start; atomic_uint destructors, ready, cpu_mask; } shared_t;
static shared_t shared={.once=ONCE_FLAG_INIT};
typedef struct { uint64_t count, inverse; } pair_t;
typedef struct { uint64_t first, second, checksum; } blob_t;
static _Atomic(pair_t) atomic_pair;
static _Atomic(blob_t) atomic_blob;
static void once_function(void) { ++shared.once_count; }
static void destructor(void *value) { if(value) atomic_fetch_add(&shared.destructors,1); }
static int worker(void *argument)
{
    int identity=(int)(intptr_t)argument;
    if(sys_thread_set_affinity((unsigned)identity-1) || sys_thread_cpu()!=(unsigned)identity-1) return -108;
    atomic_fetch_or(&shared.cpu_mask,1u<<sys_thread_cpu());
    if(fegetround()!=FE_TOWARDZERO || !fetestexcept(FE_DIVBYZERO)) return -113;
    if(tss_set(shared.key,argument)!=thrd_success) return -100;
    call_once(&shared.once,once_function);
    if(fesetround(identity%2?FE_UPWARD:FE_DOWNWARD)) return -101;
    if(mtx_lock(&shared.mutex)!=thrd_success) return -109;
    ++shared.arrived;
    if(cnd_signal(&shared.condition)!=thrd_success) return -110;
    while(!shared.start)
        if(cnd_wait(&shared.start_condition,&shared.mutex)!=thrd_success) return -111;
    if(mtx_unlock(&shared.mutex)!=thrd_success) return -112;
    for(unsigned i=0;i<300;++i)
    {
        pair_t previous=atomic_load(&atomic_pair), next;
        do {
            if(previous.inverse!=~previous.count) return -106;
            next=(pair_t){previous.count+1,~(previous.count+1)};
        } while(!atomic_compare_exchange_weak(&atomic_pair,&previous,next));
        blob_t incoming={(uint64_t)identity,i,(uint64_t)identity^i};
        blob_t outgoing=atomic_exchange(&atomic_blob,incoming);
        if(outgoing.checksum!=(outgoing.first^outgoing.second)) return -107;
        if(mtx_lock(&shared.mutex)!=thrd_success) return -102;
        ++shared.count;
        if(mtx_unlock(&shared.mutex)!=thrd_success) return -103;
        if(nearbyint(1.5)!=(identity%2?2:1)) return -104;
        if(tss_get(shared.key)!=argument) return -105;
    }
    atomic_fetch_add(&shared.ready,1);
    if(identity==8) thrd_exit(-8);
    return -identity;
}
static int detached_worker(void *argument)
{
    return tss_set(shared.key,argument)==thrd_success ? 0 : -1;
}
static bool thread_tests(void)
{
    atomic_store(&atomic_pair,((pair_t){0,~(uint64_t)0}));
    atomic_store(&atomic_blob,((blob_t){0,0,0}));
    CHECK(mtx_init(&shared.mutex,mtx_plain|mtx_timed)==thrd_success);
    CHECK(cnd_init(&shared.start_condition)==thrd_success);
    CHECK(cnd_init(&shared.condition)==thrd_success && tss_create(&shared.key,destructor)==thrd_success);
    thrd_t *threads=calloc(8,sizeof(*threads)); CHECK(threads);
    fenv_t creator_environment;CHECK(fegetenv(&creator_environment)==0);
    CHECK(fesetround(FE_TOWARDZERO)==0 && feclearexcept(FE_ALL_EXCEPT)==0 && feraiseexcept(FE_DIVBYZERO)==0);
    for(int i=0;i<8;++i) CHECK(thrd_create(&threads[i],worker,(void *)(intptr_t)(i+1))==thrd_success);
    CHECK(fesetenv(&creator_environment)==0);
    CHECK(mtx_lock(&shared.mutex)==thrd_success);
    while(shared.arrived<8) CHECK(cnd_wait(&shared.condition,&shared.mutex)==thrd_success);
    shared.start=true;
    CHECK(cnd_broadcast(&shared.start_condition)==thrd_success);
    CHECK(mtx_unlock(&shared.mutex)==thrd_success);
    for(int i=0;i<8;++i) { int status=0;CHECK(thrd_join(threads[i],&status)==thrd_success && status==-i-1); }
    CHECK(shared.count==2400 && atomic_load(&shared.cpu_mask)==255 && shared.once_count==1 && atomic_load(&shared.destructors)==8);
    pair_t final_pair=atomic_load(&atomic_pair);
    CHECK(final_pair.count==2400 && final_pair.inverse==~final_pair.count);
    CHECK(!atomic_is_lock_free(&atomic_pair) && !atomic_is_lock_free(&atomic_blob));
    CHECK(thrd_equal(thrd_current(),thrd_current()));
    CHECK(mtx_lock(&shared.mutex)==thrd_success && mtx_trylock(&shared.mutex)==thrd_busy);
    struct timespec deadline; CHECK(timespec_get(&deadline,TIME_UTC)==TIME_UTC);
    CHECK(mtx_timedlock(&shared.mutex,&deadline)==thrd_timedout);
    CHECK(cnd_timedwait(&shared.condition,&shared.mutex,&deadline)==thrd_timedout);
    CHECK(mtx_unlock(&shared.mutex)==thrd_success);
    mtx_t recursive; CHECK(mtx_init(&recursive,mtx_recursive|mtx_timed)==thrd_success);
    CHECK(mtx_lock(&recursive)==thrd_success && mtx_trylock(&recursive)==thrd_success);
    CHECK(mtx_unlock(&recursive)==thrd_success && mtx_unlock(&recursive)==thrd_success);
    mtx_destroy(&recursive);
    for(unsigned i=0;i<32;++i)
    {
        thrd_t detached;
        CHECK(thrd_create(&detached,detached_worker,(void *)(intptr_t)1)==thrd_success);
        CHECK(thrd_detach(detached)==thrd_success);
    }
    struct timespec pause={0,1000000};
    for(unsigned tries=0;atomic_load(&shared.destructors)<40 && tries<5000;++tries) CHECK(thrd_sleep(&pause,NULL)==0);
    CHECK(atomic_load(&shared.destructors)==40);
    CHECK(fegetround()==FE_TONEAREST);
    tss_delete(shared.key);cnd_destroy(&shared.condition);cnd_destroy(&shared.start_condition);mtx_destroy(&shared.mutex);
    free(threads);
    return true;
}
static bool character_tests(void)
{
    char16_t c16=0;char32_t c32=0;mbstate_t state={0};char byte=0;
    CHECK(mbrtoc16(&c16,"A",1,&state)==1 && c16=='A');
    CHECK(mbrtoc32(&c32,"B",1,&state)==1 && c32=='B');
    CHECK(c16rtomb(&byte,c16,&state)==1 && byte=='A');
    CHECK(c32rtomb(&byte,0x10000,&state)==(size_t)-1 && errno==EILSEQ);
    char text[]="one,two";
    CHECK(!strcmp(strtok(text,","),"one") && !strcmp(strtok(NULL,","),"two") && !strtok(NULL,","));
    CHECK(strspn("abba!","ab")==4 && strcspn("abc!","!")==3 && *strpbrk("ab!","!")=='!');
    return true;
}
static unsigned quick_stage;
static void forbidden_normal_exit(void) { serial_printf("LIBC_QUICK_EXIT: FAIL normal handler"); }
static void quick_first(void)
{
    if(quick_stage!=2) { serial_printf("LIBC_QUICK_EXIT: FAIL order"); _Exit(1); }
    serial_printf("LIBC_QUICK_EXIT: PASS lifo=1 normal_handlers=0 flush=0");
}
static void quick_second(void) { quick_stage=2; }
int main(int argc, char **argv)
{
    if(argc>1 && !strcmp(argv[1],"quick"))
    {
        if(atexit(forbidden_normal_exit) || at_quick_exit(quick_first) || at_quick_exit(quick_second)) return 1;
        if(setvbuf(stdout,NULL,_IOFBF,128) || fputs("FORBIDDEN_QUICK_FLUSH",stdout)<0) return 1;
        quick_exit(23);
    }
    if(!math_tests() || !environment_tests() || !scan_tests() || !character_tests() || !thread_tests() || !file_tests()) return 1;
    if(!system(NULL) || system("echo libc_system_test")!=0)
    { serial_printf("LIBC_COMPLETE_TEST: FAIL native shell service errno=%d",errno); return 1; }
    serial_printf("LIBC_COMPLETE_TEST: PASS math=1 complex80=1 fenv=1 scanf=1 uchar=1 threads=8 cpu_mask=0xFF fp_inherit=1 atomic=1 files=1 append=320");
    return 0;
}
