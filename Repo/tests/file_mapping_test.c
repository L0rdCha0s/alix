#include "sys/mman.h"
#include "sys/stat.h"
#include "sys/wait.h"
#include "fcntl.h"
#include "unistd.h"
#include "pthread.h"
#include "spawn.h"
#include "signal.h"
#include "stdlib.h"
#include "string.h"
#include "stdio.h"
#include "errno.h"
#include "serial.h"
#include "usyscall.h"

#define PATH "/tmp/map-disk/mapped.bin"
#define RENAMED "/tmp/map-disk/renamed.bin"
#define FILE_BYTES (32768u+17u)
#define MAP_BYTES 36864u
#define CHECK(c,label) do {if(!(c)){serial_printf("FILE_MAPPING_TEST: FAIL %s line=%u errno=%d\n",label,__LINE__,errno);return 1;}}while(0)
typedef struct fixture fixture_t;
typedef struct {fixture_t *fixture;pthread_t thread;unsigned cpu,failed;} job_t;
struct fixture {
    job_t jobs[8];unsigned ready,start;
    unsigned char *shared,*alias,*private;
    unsigned char bytes[MAP_BYTES];
    struct stat metadata;
    char executable[4096];char *arguments[4];char *environment[1];pid_t child;int status;
};
static bool until(unsigned *value,unsigned expected)
{
    uint64_t deadline=sys_monotonic_millis()+8000;
    while(__atomic_load_n(value,__ATOMIC_ACQUIRE)!=expected && sys_monotonic_millis()<deadline)sys_yield();
    return __atomic_load_n(value,__ATOMIC_ACQUIRE)==expected;
}
static void *writer(void *opaque)
{
    job_t *job=opaque;fixture_t *t=job->fixture;
    if(sys_thread_set_affinity(job->cpu) || sys_thread_cpu()!=job->cpu)job->failed=1;
    int fd=open(PATH,O_RDWR|O_CLOEXEC);
    unsigned char *map=fd<0?MAP_FAILED:mmap(NULL,MAP_BYTES,PROT_READ|PROT_WRITE,MAP_SHARED,fd,0);
    if(map==MAP_FAILED || close(fd))job->failed=2;
    __atomic_add_fetch(&t->ready,1u,__ATOMIC_RELEASE);
    while(!__atomic_load_n(&t->start,__ATOMIC_ACQUIRE))sys_yield();
    if(job->failed)return NULL;
    for(unsigned round=0;round<64;++round) {
        __atomic_add_fetch((uint64_t *)(map+job->cpu*4096),1u,__ATOMIC_RELAXED);
        __atomic_add_fetch((uint64_t *)(map+8),1u,__ATOMIC_RELAXED);
    }
    memset(map+job->cpu*4096+64,(int)job->cpu+1,4096-64);
    if(munmap(map,MAP_BYTES))job->failed=3;
    return NULL;
}
static bool payload(const unsigned char *bytes)
{
    for(unsigned cpu=0;cpu<8;++cpu) {
        if(*(const uint64_t *)(bytes+cpu*4096)!=64)return false;
        for(unsigned j=64;j<4096;++j)
            if(bytes[cpu*4096+j]!=(cpu==1 && j==100?0x5a:cpu+1))return false;
    }
    return *(const uint64_t *)(bytes+8)==512 &&
        *(const uint64_t *)(bytes+32768)==0x123456789abcdef0ULL &&
        *(const uint64_t *)(bytes+32776)==2 && bytes[32784]==0xa5;
}
int main(int argc,char **argv)
{
    fixture_t *t=calloc(1,sizeof(*t));CHECK(t,"heap fixture");
    if(argc>1 && !strcmp(argv[1],"read")) {
        int fd=open("/root/renamed.bin",O_RDONLY|O_CLOEXEC);
        CHECK(fd>=0 && !fstat(fd,&t->metadata) && t->metadata.st_size==FILE_BYTES &&
            read(fd,t->bytes,FILE_BYTES)==FILE_BYTES && payload(t->bytes) && !close(fd),"independent remount data and exact size");
        serial_printf("FILE_MAPPING_REMOUNT: PASS bytes=32785 msync=1 fsync=0\n");free(t);return 0;
    }
    if(argc>1 && !strcmp(argv[1],"child")) {
        int fd=open(RENAMED,O_RDWR|O_CLOEXEC);
        unsigned char *map=fd<0?MAP_FAILED:mmap(NULL,4096,PROT_READ|PROT_WRITE,MAP_SHARED,fd,32768);
        CHECK(map!=MAP_FAILED && !close(fd),"child independent mapping");
        *(uint64_t *)map=0x123456789abcdef0ULL;map[16]=0xa5;
        __atomic_store_n((uint64_t *)(map+8),argc>2?2u:1u,__ATOMIC_RELEASE);
        if(argc>2)for(;;)sys_yield();
        CHECK(!munmap(map,4096),"child unmap");free(t);return 0;
    }
    int fd=open(PATH,O_CREAT|O_EXCL|O_RDWR|O_CLOEXEC);
    CHECK(fd>=0 && !ftruncate(fd,FILE_BYTES),"initial file length");
    CHECK(lseek(fd,123,SEEK_SET)==123,"source position");
    t->shared=mmap(NULL,MAP_BYTES,PROT_READ|PROT_WRITE,MAP_SHARED,fd,0);
    t->alias=mmap(NULL,MAP_BYTES,PROT_READ|PROT_WRITE,MAP_SHARED,fd,0);
    CHECK(t->shared!=MAP_FAILED && t->alias!=MAP_FAILED && t->shared!=t->alias &&
        lseek(fd,0,SEEK_CUR)==123,"shared aliases preserve source position");
    int readonly=open(PATH,O_RDONLY|O_CLOEXEC),writeonly=open(PATH,O_WRONLY|O_CLOEXEC);
    CHECK(readonly>=0 && writeonly>=0,"access mode fixtures");
    CHECK(mmap(NULL,4096,PROT_READ|PROT_WRITE,MAP_SHARED,readonly,0)==MAP_FAILED && errno==EACCES &&
        mmap(NULL,4096,PROT_READ,MAP_PRIVATE,writeonly,0)==MAP_FAILED && errno==EACCES,"mapping access checks");
    unsigned char *ro=mmap(NULL,4096,PROT_READ,MAP_SHARED,readonly,0);
    CHECK(ro!=MAP_FAILED && mprotect(ro,4096,PROT_READ|PROT_WRITE)==-1 && errno==EACCES && !munmap(ro,4096),"protection cannot escalate readonly description");
    t->private=mmap(NULL,MAP_BYTES,PROT_READ|PROT_WRITE,MAP_PRIVATE,readonly,0);
    CHECK(t->private!=MAP_FAILED && !close(readonly) && !close(writeonly),"private writable copy from readonly file");
    t->private[64]=0x77;
    CHECK(t->shared[64]==0 && !msync(t->private,MAP_BYTES,MS_SYNC),"private writes do not reach shared pages");
    CHECK(mmap(NULL,4096,PROT_READ,MAP_SHARED,fd,1)==MAP_FAILED && errno==EINVAL &&
        mmap(NULL,4096,PROT_READ,MAP_SHARED|MAP_PRIVATE,fd,0)==MAP_FAILED && errno==EINVAL &&
        mmap(NULL,4096,PROT_READ,MAP_SHARED,fd,MAP_BYTES)==MAP_FAILED && errno==ENXIO,"offset mode and EOF validation");
    CHECK(ftruncate(fd,1)==-1 && errno==EBUSY,"live mapping shrink is explicitly rejected");
    CHECK(open(PATH,O_RDWR|O_TRUNC)==-1 && errno==EBUSY && !fstat(fd,&t->metadata) &&
        t->metadata.st_size==FILE_BYTES,"truncate-on-open preserves live mappings");
    CHECK(!msync(t->shared,MAP_BYTES,MS_ASYNC|MS_INVALIDATE) &&
        msync(t->shared+1,1,MS_SYNC)==-1 && errno==EINVAL &&
        msync(t->shared,4096,MS_SYNC|MS_ASYNC)==-1 && errno==EINVAL,"sync modes and alignment");
    for(unsigned cpu=0;cpu<8;++cpu) {t->jobs[cpu].fixture=t;t->jobs[cpu].cpu=cpu;CHECK(!pthread_create(&t->jobs[cpu].thread,NULL,writer,&t->jobs[cpu]),"create map writer");}
    CHECK(until(&t->ready,8),"writers mapped");__atomic_store_n(&t->start,1u,__ATOMIC_RELEASE);
    for(unsigned cpu=0;cpu<8;++cpu)CHECK(!pthread_join(t->jobs[cpu].thread,NULL) && !t->jobs[cpu].failed,"join pinned map writer");
    CHECK(*(uint64_t *)(t->alias+8)==512 && t->private[64]==0x77,"shared atomic visibility and private isolation");
    CHECK(pread(fd,t->bytes,32768,0)==32768 && *(uint64_t *)(t->bytes+8)==512,"read sees CPU stores before msync");
    t->bytes[0]=0x5a;
    CHECK(lseek(fd,4096+100,SEEK_SET)==4196 && write(fd,t->bytes,1)==1 && t->alias[4196]==0x5a,"VFS write updates mapped page");
    CHECK(!rename(PATH,RENAMED),"rename preserves backing identity");
    CHECK(alix_get_executable_path(t->executable,sizeof(t->executable))>0,"child executable");
    t->arguments[0]=t->executable;t->arguments[1]="child";
    CHECK(!posix_spawn(&t->child,t->executable,NULL,NULL,t->arguments,t->environment) &&
        waitpid(t->child,&t->status,0)==t->child && WIFEXITED(t->status) && WEXITSTATUS(t->status)==0 &&
        *(uint64_t *)(t->alias+32768)==0x123456789abcdef0ULL,"cross-process shared physical pages");
    t->arguments[2]="wait";
    CHECK(!posix_spawn(&t->child,t->executable,NULL,NULL,t->arguments,t->environment),"spawn mapped child to kill");
    uint64_t deadline=sys_monotonic_millis()+8000;
    while(__atomic_load_n((uint64_t *)(t->alias+32776),__ATOMIC_ACQUIRE)!=2 && sys_monotonic_millis()<deadline)sys_yield();
    CHECK(*(uint64_t *)(t->alias+32776)==2 && !kill(t->child,SIGKILL) && waitpid(t->child,&t->status,0)==t->child &&
        WIFSIGNALED(t->status) && WTERMSIG(t->status)==SIGKILL,"killed mapping owner cleanup");
    CHECK(!close(fd) && !mprotect(t->shared+4096,4096,PROT_NONE) &&
        !mprotect(t->shared+4096,4096,PROT_READ|PROT_WRITE) && t->shared[4196]==0x5a,"closed FD and protection splits retain pages");
    CHECK(mmap(t->shared,4096,PROT_READ,MAP_SHARED|MAP_FIXED_NOREPLACE,-1,0)==MAP_FAILED,"invalid FD cannot replace live mapping");
    CHECK(!munmap(t->private,MAP_BYTES),"private mapping teardown");
    unsigned char *hole=mmap(NULL,12288,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    CHECK(hole!=MAP_FAILED && !munmap(hole+4096,4096) && msync(hole,12288,MS_SYNC)==-1 && errno==ENOMEM &&
        !munmap(hole,12288),"sync validates entire range before I/O");
    CHECK(t->shared[FILE_BYTES]==0,"partial final page zero filled");t->shared[FILE_BYTES]=0xcc;
    CHECK(!msync(t->shared,MAP_BYTES,MS_SYNC) && payload(t->alias),"synchronous persistence and tail excluded");
    CHECK(!munmap(t->shared+4096,4096) && !munmap(t->shared,4096) && !munmap(t->shared+8192,MAP_BYTES-8192) &&
        !munmap(t->alias,MAP_BYTES),"partial unmap retains unaffected aliases");
    fd=open(RENAMED,O_RDWR|O_CLOEXEC);
    CHECK(fd>=0 && !fstat(fd,&t->metadata) && t->metadata.st_size==FILE_BYTES && !close(fd),"mapping does not extend file");
    serial_printf("FILE_MAPPING_TEST: PASS cpus=8 atomic_updates=512 aliases=1 private=1 close=1 offset=1 permissions=1 split=1 process=1 killed_owner=1 coherence=1 msync=1 tail=1\n");
    free(t);return 0;
}
