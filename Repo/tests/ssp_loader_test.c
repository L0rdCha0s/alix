#include "types.h"
#include "dlfcn.h"
#include "stdlib.h"
#include "string.h"
#include "pthread.h"
#include "usyscall.h"
#include "serial.h"
extern uintptr_t __stack_chk_guard;
#define CHECK(c,label) do{if(!(c)){serial_printf("SSP_LOADER_TEST: FAIL %s line=%u\n",label,__LINE__);return 1;}}while(0)
typedef int (*check_fn)(const char *,size_t);
typedef struct {pthread_t thread;check_fn check;unsigned cpu,failed;} job_t;
typedef struct {job_t jobs[8];char corrupt[128];} fixture_t;
static void *worker(void *opaque)
{
    job_t *j=opaque;
    if(sys_thread_set_affinity(j->cpu) || sys_thread_cpu()!=j->cpu)j->failed=1;
    for(unsigned n=0;n<64;++n)if(j->check("shared-runtime",15)!=1)j->failed=2;
    return NULL;
}
int main(int argc,char **argv)
{
    fixture_t *f=calloc(1,sizeof(*f));CHECK(f && __stack_chk_guard,"initialized process guard");
    CHECK(!setenv("SSP_LOADER_ENV","shared",1),"native environment");
    void *library=dlopen("/tmp/libalix-ssp-plugin.so",RTLD_NOW|RTLD_LOCAL);
    if(!library){serial_printf("SSP_LOADER_TEST: FAIL dlopen=%s\n",dlerror());return 1;}
    uintptr_t (*guard)(void)=(void *)dlsym(library,"ssp_plugin_guard");
    int (*ready)(void)=(void *)dlsym(library,"ssp_plugin_ready");
    int (*environment)(void)=(void *)dlsym(library,"ssp_plugin_environment");
    check_fn check=(void *)dlsym(library,"ssp_plugin_check");
    CHECK(guard && ready && environment && check && !dlerror(),"plugin symbols");
    CHECK(guard()==__stack_chk_guard && ready()==1 && environment()==1,"shared guard, protected constructor and custom runtime imports");
    if(argc>1 && !strcmp(argv[1],"corrupt")) {
        memset(f->corrupt,'s',sizeof(f->corrupt));
        serial_printf("SSP_LOADER_TEST: corrupt armed\n");
        (void)check(f->corrupt,sizeof(f->corrupt));return 3;
    }
    for(unsigned cpu=0;cpu<8;++cpu) {
        f->jobs[cpu].cpu=cpu;f->jobs[cpu].check=check;
        CHECK(!pthread_create(&f->jobs[cpu].thread,NULL,worker,&f->jobs[cpu]),"create protected plugin caller");
    }
    for(unsigned cpu=0;cpu<8;++cpu)CHECK(!pthread_join(f->jobs[cpu].thread,NULL) && !f->jobs[cpu].failed,"join protected plugin caller");
    CHECK(!dlclose(library),"unload protected plugin");
    serial_printf("SSP_LOADER_TEST: PASS cpus=8 calls=512 shared_guard=1 constructor=1 environment=1\n");
    free(f);return 0;
}
