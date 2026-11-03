#include "dlfcn.h"
#include "pthread.h"
#include "unistd.h"
#include "stdlib.h"
#include "string.h"
#include "stdio.h"
#include "serial.h"
#include "usyscall.h"
#include "math.h"

#define ROOT "/tmp/libalix-loader-plugin.so"
#define CHECK(c,label) do {if(!(c)){char*error=dlerror();serial_printf("DYNAMIC_LOADER_TEST: FAIL %s line=%u error=%s\n",label,__LINE__,error?error:"none");return 1;}}while(0)
static unsigned events[32],event_count;
__asm__(".globl loader_zero_symbol\n.set loader_zero_symbol,0");
static void *pinned_code;
static Dl_info pinned_information;
static void pinned_exit_check(void)
{
    if(event_count==2 && events[0]==30 && events[1]==31 && dladdr(pinned_code,&pinned_information)==1)
        serial_printf("DYNAMIC_LOADER_PIN_EXIT: PASS finalizer=1 code_resident=1\n");
    else serial_printf("DYNAMIC_LOADER_TEST: FAIL pinned exit events=%u\n",event_count);
}
static int startup_math;
__attribute__((constructor)) static void check_initial_exec_math(void)
{
    extern _Thread_local int __signgam;
    double value=lgamma(-0.5);startup_math=value>1 && value<2 && __signgam==-1;
}
_Thread_local int loader_host_tls=7;
void loader_event(int event)
{
    unsigned index=__atomic_fetch_add(&event_count,1u,__ATOMIC_RELAXED);
    if(index<32)events[index]=(unsigned)event;
}
typedef struct fixture fixture_t;
typedef struct {
    fixture_t *fixture;
    pthread_t thread;
    unsigned cpu,failed;
} job_t;
struct fixture {job_t jobs[8];unsigned ready,start,destructors,leave;int(*register_destructor)(int);};
static void *destructor_worker(void *opaque)
{
    job_t *job=opaque;fixture_t *test=job->fixture;
    if(sys_thread_set_affinity(job->cpu) || sys_thread_cpu()!=job->cpu || test->register_destructor((int)job->cpu))job->failed=1;
    __atomic_add_fetch(&test->destructors,1u,__ATOMIC_RELEASE);
    while(!__atomic_load_n(&test->leave,__ATOMIC_ACQUIRE))sys_yield();
    return NULL;
}
static int destructor_test(bool exiting)
{
    fixture_t *test=calloc(1,sizeof(*test));Dl_info *info=calloc(1,sizeof(*info));CHECK(test && info,"destructor fixture");
    if(exiting)CHECK(!atexit(pinned_exit_check),"pinned exit verifier");
    void *handle=dlopen("/tmp/libalix-loader-destructor.so",RTLD_NOW);CHECK(handle,"C++ shared object");
    test->register_destructor=(int(*)(int))dlsym(handle,"loader_register_destructor");
    CHECK(test->register_destructor && event_count==1 && events[0]==30,"C++ constructor");
    for(unsigned cpu=0;cpu<8;++cpu){job_t *job=&test->jobs[cpu];job->fixture=test;job->cpu=cpu;CHECK(!pthread_create(&job->thread,NULL,destructor_worker,job),"C++ destructor thread");}
    uint64_t deadline=sys_monotonic_millis()+5000;
    while(__atomic_load_n(&test->destructors,__ATOMIC_ACQUIRE)!=8 && sys_monotonic_millis()<deadline)sys_yield();
    CHECK(__atomic_load_n(&test->destructors,__ATOMIC_ACQUIRE)==8 && !dlclose(handle) && event_count==1 &&
        dladdr((void *)test->register_destructor,info)==1,"destructor pins preserve code after dlclose");
    if(exiting)
    {
        pinned_code=(void *)test->register_destructor;free(info);
        /* Workers still own this heap fixture until process-wide termination. */
        return 0;
    }
    __atomic_store_n(&test->leave,1u,__ATOMIC_RELEASE);
    for(unsigned cpu=0;cpu<8;++cpu)CHECK(!pthread_join(test->jobs[cpu].thread,NULL) && !test->jobs[cpu].failed,"join C++ destructor thread");
    CHECK(event_count==10 && events[9]==31 && dladdr((void *)test->register_destructor,info)==0,"last destructor releases code and finalizer");
    unsigned seen=0;for(unsigned index=1;index<9;++index){CHECK(events[index]>=100 && events[index]<108,"C++ destructor event");seen|=1u<<(events[index]-100);}
    CHECK(seen==255,"every C++ destructor ran");free(info);free(test);
    serial_printf("DYNAMIC_LOADER_DTORS: PASS cpus=8 dtors=8 deferred_unload=1 code_lifetime=1 finalizer=1\n");return 0;
}
static void *worker(void *opaque)
{
    job_t *job=opaque;fixture_t *test=job->fixture;
    if(sys_thread_set_affinity(job->cpu) || sys_thread_cpu()!=job->cpu)job->failed=1;
    __atomic_add_fetch(&test->ready,1u,__ATOMIC_RELEASE);
    while(!__atomic_load_n(&test->start,__ATOMIC_ACQUIRE))sys_yield();
    void *handle=dlopen(ROOT,RTLD_NOW);
    int(*increment)(void)=handle?(int(*)(void))dlsym(handle,"loader_plugin_tls_increment"):NULL;
    int *plugin_tls=handle?(int *)dlsym(handle,"loader_plugin_tls"):NULL;
    int *host_tls=(int *)dlsym(RTLD_DEFAULT,"loader_host_tls");
    if(!handle || !increment || !plugin_tls || *plugin_tls!=3 || host_tls!=&loader_host_tls || *host_tls!=7)job->failed=2;
    if(host_tls)*host_tls=(int)job->cpu+100;
    for(unsigned round=0;round<64 && !job->failed;++round)
    {
        if(increment()!=(int)round+4 || *plugin_tls!=(int)round+4 || *host_tls!=(int)job->cpu+100)job->failed=3;
        if((round&7u)==0)sys_yield();
    }
    if(handle && dlclose(handle))job->failed=4;
    (void)dlsym(RTLD_DEFAULT,"loader_thread_missing");
    sys_yield();char *error=dlerror();
    if(!error || !strstr(error,"loader_thread_missing") || dlerror())job->failed=5;
    return NULL;
}
static void exit_check(void)
{
    if(event_count==12 && events[8]==10 && events[9]==20 && events[10]==21 && events[11]==11)
        serial_printf("DYNAMIC_LOADER_EXIT: PASS nodelete=1 finalizers=1\n");
    else serial_printf("DYNAMIC_LOADER_TEST: FAIL exit events=%u\n",event_count);
}
int main(int argc,char **argv)
{
    CHECK(startup_math,"initial-exec math TLS before main");
    if(argc>1 && !strcmp(argv[1],"destructors"))return destructor_test(false);
    if(argc>1 && !strcmp(argv[1],"exit-with-pins"))return destructor_test(true);
    if(argc>1 && (!strcmp(argv[1],"fault-relro") || !strcmp(argv[1],"fault-text")))
    {
        void *handle=dlopen(ROOT,RTLD_NOW);CHECK(handle,"permission fixture");
        void *target=dlsym(handle,!strcmp(argv[1],"fault-relro")?"loader_relro_pointer":"loader_plugin_value");CHECK(target,"permission target");
        serial_printf("VM_FAULT_TEST: armed write address=0x%llX\n",(unsigned long long)(uintptr_t)target);
        sys_sleep_ms(100);*(volatile unsigned char *)target=0;return 9;
    }
    fixture_t *test=calloc(1,sizeof(*test));CHECK(test,"owned fixture");
    CHECK(!atexit(exit_check),"exit verifier");
    void *self=dlopen(NULL,RTLD_NOW);CHECK(self,"running executable handle");
    CHECK(dlsym(self,"malloc")== (void *)malloc && dlsym(RTLD_DEFAULT,"loader_event")== (void *)loader_event,"real main exports");
    CHECK(dlsym(self,"loader_zero_symbol")==NULL && dlerror()==NULL,"defined null symbol has no lookup error");
    Dl_info *info=calloc(1,sizeof(*info));CHECK(info,"address metadata");
    CHECK(dladdr((void *)loader_event,info)==1 && info->dli_fname && !strcmp(info->dli_fname,"/tmp/test.elf") &&
        info->dli_sname && !strcmp(info->dli_sname,"loader_event") && info->dli_saddr==(void *)loader_event && info->dli_fbase,"main address lookup");
    CHECK(!dlclose(self) && !dlopen("/tmp/loader-bad.elf",RTLD_NOW) && dlerror() && !dlerror(),"malformed ELF rejection");
    CHECK(!dlopen("/tmp/libalix-loader-unresolved.so",RTLD_NOW) && dlerror() && event_count==0,"failed relocation rollback before constructors");
    CHECK(!dlopen("/tmp/loader-not-found.so",RTLD_NOW) && dlerror(),"missing library error");
    void *handle=dlopen(ROOT,RTLD_NOW|RTLD_GLOBAL);CHECK(handle,"mapped root and dependency");
    int(*value)(void)=(int(*)(void))dlsym(handle,"loader_plugin_value");
    CHECK(value && value()==42 && event_count==2 && events[0]==10 && events[1]==20,"relocations, libc imports and constructor order");
    CHECK(dlsym(RTLD_DEFAULT,"loader_plugin_value")== (void *)value && dladdr((void *)value,info)==1 &&
        !strcmp(info->dli_fname,ROOT) && info->dli_sname && !strcmp(info->dli_sname,"loader_plugin_value"),"global scope and DSO address lookup");
    void *again=dlopen(ROOT,RTLD_NOW|RTLD_NOLOAD);CHECK(again==handle && !dlclose(again) && value()==42 && event_count==2,"reference count and NOLOAD");
    CHECK(dlsym((void *)1,"malloc")==NULL && dlerror() && dlclose((void *)1)==-1 && dlerror(),"invalid handles");
    for(unsigned cpu=0;cpu<8;++cpu){job_t *job=&test->jobs[cpu];job->fixture=test;job->cpu=cpu;CHECK(!pthread_create(&job->thread,NULL,worker,job),"create pinned loader worker");}
    uint64_t deadline=sys_monotonic_millis()+5000;
    while(__atomic_load_n(&test->ready,__ATOMIC_ACQUIRE)!=8 && sys_monotonic_millis()<deadline)sys_yield();
    CHECK(__atomic_load_n(&test->ready,__ATOMIC_ACQUIRE)==8,"loader worker readiness");__atomic_store_n(&test->start,1u,__ATOMIC_RELEASE);
    for(unsigned cpu=0;cpu<8;++cpu){CHECK(!pthread_join(test->jobs[cpu].thread,NULL),"join loader worker");if(test->jobs[cpu].failed){serial_printf("DYNAMIC_LOADER_TEST: FAIL cpu=%u stage=%u\n",cpu,test->jobs[cpu].failed);return 1;}}
    CHECK(loader_host_tls==7 && !dlclose(handle) && event_count==4 && events[2]==21 && events[3]==11,"TLS cleanup and reverse finalizer order");
    CHECK(dladdr((void *)value,info)==0 && dlsym(RTLD_DEFAULT,"loader_plugin_value")==NULL && dlerror(),"unload removes code and symbols");
    void *provider=dlopen("/tmp/libalix-loader-provider.so",RTLD_NOW|RTLD_GLOBAL);CHECK(provider,"global provider");
    void *provider_code=dlsym(provider,"loader_provider_value");CHECK(provider_code,"provider symbol");
    void *consumer=dlopen("/tmp/libalix-loader-consumer.so",RTLD_NOW);CHECK(consumer,"local consumer without DT_NEEDED edge");
    int(*consume)(void)=(int(*)(void))dlsym(consumer,"loader_consumer_value");
    CHECK(consume && !dlclose(provider) && dladdr(provider_code,info)==1 && consume()==42 &&
        !dlclose(consumer) && dladdr(provider_code,info)==0 && event_count==8 &&
        events[4]==40 && events[5]==50 && events[6]==51 && events[7]==41,"relocation binding retains global provider");
    handle=dlopen(ROOT,RTLD_NOW|RTLD_NODELETE);CHECK(handle && !dlclose(handle) && event_count==10,"reload and NODELETE");
    CHECK(dladdr(dlsym(RTLD_DEFAULT,"loader_event"),info)==1,"main remains resident");
    free(info);free(test);
    serial_printf("DYNAMIC_LOADER_TEST: PASS cpus=8 tls_updates=512 elf=1 imports=1 dependencies=1 constructors=1 finalizers=1 scopes=1 errors=1 unload=1\n");return 0;
}
