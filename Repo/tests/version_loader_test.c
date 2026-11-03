#include "dlfcn.h"
#include "pthread.h"
#include "usyscall.h"
#include "stdlib.h"
#include "string.h"
#include "serial.h"
#include "errno.h"
__attribute__((visibility("default"))) int version_events;
__attribute__((visibility("default"))) int version_constructor_calls;
#define CHECK(c) do{if(!(c)){serial_printf("VERSION_LOADER_TEST: FAIL line=%u errno=%d loader=%s\n",__LINE__,errno,dlerror());return 1;}}while(0)
typedef struct{pthread_t thread;void*handle;unsigned cpu,failed;int *old,*current;}job_t;
static void*worker(void*context)
{
    job_t*j=context;if(sys_thread_set_affinity(j->cpu)||sys_thread_cpu()!=j->cpu){j->failed=1;return NULL;}
    j->old=dlvsym(j->handle,"versioned_tls","ALIX_1");j->current=dlvsym(j->handle,"versioned_tls","ALIX_2");
    if(!j->old||!j->current||*j->old!=101||*j->current!=202){j->failed=2;return NULL;}
    for(unsigned i=0;i<64;++i){++*j->old;++*j->current;}
    if(*j->old!=165||*j->current!=266)j->failed=3;
    return NULL;
}
int main(void)
{
    CHECK(!dlopen("/tmp/libversion_bad.so",RTLD_NOW|RTLD_LOCAL));
    char*error=dlerror();CHECK(error&&strstr(error,"version")&&version_events==0&&version_constructor_calls==0);
    CHECK(!dlopen("/tmp/libversion_provider.so",RTLD_NOW|RTLD_NOLOAD)&&dlerror());
    void*provider=dlopen("/tmp/libversion_provider.so",RTLD_NOW|RTLD_GLOBAL);CHECK(provider&&version_events==10&&version_constructor_calls==1);
    int(*value)(void)=dlsym(provider,"versioned_value");CHECK(value&&value()==22);
    value=dlvsym(provider,"versioned_value","ALIX_1");CHECK(value&&value()==11);
    value=dlvsym(provider,"versioned_value","ALIX_2");CHECK(value&&value()==22);
    CHECK(*(int*)dlsym(provider,"versioned_data")==7);
    CHECK(*(int*)dlvsym(provider,"versioned_data","ALIX_1")==3);
    CHECK(!dlvsym(provider,"versioned_value","ALIX_9")&&dlerror());
    void*consumer=dlopen("/tmp/libversion_consumer.so",RTLD_NOW|RTLD_LOCAL);CHECK(consumer&&version_events==110&&version_constructor_calls==2);
    value=dlsym(consumer,"version_consumer_value");CHECK(value&&value()==43);
    CHECK(!dlclose(consumer)&&version_events==10);
    job_t*jobs=calloc(8,sizeof(*jobs));CHECK(jobs);
    for(unsigned i=0;i<8;++i){jobs[i].cpu=i;jobs[i].handle=provider;CHECK(!pthread_create(&jobs[i].thread,NULL,worker,&jobs[i]));}
    for(unsigned i=0;i<8;++i){CHECK(!pthread_join(jobs[i].thread,NULL));if(jobs[i].failed)serial_printf("VERSION_WORKER: cpu=%u stage=%u\n",i,jobs[i].failed);CHECK(!jobs[i].failed);}
    free(jobs);CHECK(!dlclose(provider)&&version_events==0);
    CHECK(!dlopen("/tmp/libversion_provider.so",RTLD_NOW|RTLD_NOLOAD)&&dlerror());
    serial_printf("VERSION_LOADER_TEST: PASS cpus=8 tls_updates=1024 default=1 legacy=1 data=1 requirements=1 missing_rejected=1 constructors=1 unload=1\n");return 0;
}
