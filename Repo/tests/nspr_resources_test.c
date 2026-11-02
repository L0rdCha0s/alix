#include "primpl.h"
#include "prrng.h"
#include "prsystem.h"
#include "serial.h"
#include "stdlib.h"
#include "string.h"
#include "unistd.h"
#include "fcntl.h"
#include "pthread.h"
#include "usyscall.h"
#include "sys/mman.h"

/* Instrument the NSPR error sink without claiming full NSPR initialization. */
static _Thread_local PRErrorCode captured_error;
static _Thread_local PRInt32 captured_os_error;
PR_IMPLEMENT(void) PR_SetError(PRErrorCode error, PRInt32 os_error)
{ captured_error=error; captured_os_error=os_error; }

#define CHECK(c,label) do {if(!(c)){serial_printf("NSPR_RESOURCES_TEST: FAIL %s line=%u errno=%d\n",label,__LINE__,errno);return 1;}}while(0)
typedef struct fixture fixture_t;
typedef struct {
    fixture_t *fixture;
    pthread_t thread;
    unsigned cpu, failed;
    unsigned char samples[2][256];
} worker_t;
struct fixture {
    worker_t workers[8];
    unsigned ready, start;
    uint64_t physical;
    int descriptors[256];
    unsigned char bytes[1026];
};
static bool filled(const unsigned char *bytes,size_t count,unsigned char value)
{ for(size_t i=0;i<count;++i)if(bytes[i]!=value)return false;return true; }
static void *worker(void *opaque)
{
    worker_t *job=opaque;fixture_t *test=job->fixture;
    if(sys_thread_set_affinity(job->cpu) || sys_thread_cpu()!=job->cpu)job->failed=1;
    __atomic_add_fetch(&test->ready,1u,__ATOMIC_RELEASE);
    while(!__atomic_load_n(&test->start,__ATOMIC_ACQUIRE))sys_yield();
    for(unsigned round=0;round<64 && !job->failed;++round)
    {
        unsigned char *next=job->samples[round&1u], *previous=job->samples[(round&1u)^1u];
        captured_error=PR_WOULD_BLOCK_ERROR;captured_os_error=EAGAIN;
        if(PR_GetRandomNoise(next,256)!=256 || filled(next,256,0) ||
            (round && !memcmp(next,previous,256)) || PR_GetPhysicalMemorySize()!=test->physical ||
            PR_GetNumberOfProcessors()!=8 || sys_thread_cpu()!=job->cpu)job->failed=2;
        if(PR_GetRandomNoise(NULL,16)!=0 || captured_error!=PR_ACCESS_FAULT_ERROR || captured_os_error!=EFAULT)job->failed=3;
        sys_yield();
        if(captured_error!=PR_ACCESS_FAULT_ERROR || captured_os_error!=EFAULT)job->failed=4;
    }
    return NULL;
}
int main(int argc,char **argv)
{
    fixture_t *test=calloc(1,sizeof(*test));CHECK(test,"owned fixture");
    captured_error=PR_WOULD_BLOCK_ERROR;captured_os_error=EAGAIN;
    CHECK(!PR_GetRandomNoise(NULL,0) && captured_error==PR_WOULD_BLOCK_ERROR && captured_os_error==EAGAIN,"empty noise request");
    test->physical=PR_GetPhysicalMemorySize();
    CHECK(test->physical>0 && test->physical==(uint64_t)sysconf(_SC_PHYS_PAGES)*(uint64_t)sysconf(_SC_PAGESIZE) &&
        PR_GetNumberOfProcessors()==8,"actual physical memory and CPU count");
    if(argc>1 && !strcmp(argv[1],"unsupported"))
    {
        memset(test->bytes,0x5a,sizeof(test->bytes));
        CHECK(PR_GetRandomNoise(test->bytes,512)==0 && captured_error==PR_NOT_IMPLEMENTED_ERROR &&
            captured_os_error==ENOSYS && filled(test->bytes,sizeof(test->bytes),0x5a),"unavailable entropy has no clock fallback");
        serial_printf("NSPR_RESOURCES_TEST: unsupported PASS error=1 output_unchanged=1 memory=1 cpus=8\n");
        free(test);return 0;
    }
    static const size_t lengths[]={1,255,256,257,1024};
    for(unsigned i=0;i<sizeof(lengths)/sizeof(lengths[0]);++i)
    {
        size_t length=lengths[i],expected=length>256?256:length;
        memset(test->bytes,0x5a,sizeof(test->bytes));
        CHECK(PR_GetRandomNoise(test->bytes+1,length)==expected && test->bytes[0]==0x5a &&
            filled(test->bytes+1+expected,sizeof(test->bytes)-1-expected,0x5a),"native short-result bounds");
    }
    CHECK(PR_GetRandomNoise(NULL,32)==0 && captured_error==PR_ACCESS_FAULT_ERROR && captured_os_error==EFAULT,"null output error mapping");
    void *page=mmap(NULL,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    CHECK(page!=MAP_FAILED,"protected output allocation");memset(page,0x5a,4096);
    CHECK(!mprotect(page,4096,PROT_READ) && PR_GetRandomNoise(page,32)==0 &&
        captured_error==PR_ACCESS_FAULT_ERROR && captured_os_error==EFAULT && filled(page,4096,0x5a) &&
        !munmap(page,4096),"protected output remains unchanged");
    unsigned count=0;
    while(count<256)
    {
        int fd=dup(1);if(fd<0)break;test->descriptors[count++]=fd;
    }
    CHECK(count>0 && count<256 && errno==EMFILE && PR_GetRandomNoise(test->bytes,256)==256,"no descriptor dependency");
    for(unsigned i=0;i<count;++i)CHECK(!close(test->descriptors[i]),"release descriptor pressure");
    for(unsigned cpu=0;cpu<8;++cpu)
    {
        worker_t *job=&test->workers[cpu];job->fixture=test;job->cpu=cpu;
        CHECK(!pthread_create(&job->thread,NULL,worker,job),"create pinned worker");
    }
    uint64_t deadline=sys_monotonic_millis()+5000;
    while(__atomic_load_n(&test->ready,__ATOMIC_ACQUIRE)!=8 && sys_monotonic_millis()<deadline)sys_yield();
    CHECK(__atomic_load_n(&test->ready,__ATOMIC_ACQUIRE)==8,"worker readiness");
    __atomic_store_n(&test->start,1u,__ATOMIC_RELEASE);
    for(unsigned cpu=0;cpu<8;++cpu)CHECK(!pthread_join(test->workers[cpu].thread,NULL) && !test->workers[cpu].failed,"join resource worker");
    serial_printf("NSPR_RESOURCES_TEST: PASS cpus=8 samples=512 memory=1 native_entropy=1 short_results=1 fd_pressure=1 checked_copy=1\n");
    free(test);return 0;
}
