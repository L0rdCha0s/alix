#include "sys/resource.h"
#include "sys/mman.h"
#include "sys/wait.h"
#include "sys/socket.h"
#include "fcntl.h"
#include "unistd.h"
#include "stdlib.h"
#include "stdio.h"
#include "string.h"
#include "pthread.h"
#include "spawn.h"
#include "serial.h"
#include "usyscall.h"
#include "errno.h"

#define HIGH_FD 90
#define CHECK(c,label) do {if(!(c)){serial_printf("FD_LIMITS_TEST: FAIL %s line=%u errno=%d\n",label,__LINE__,errno);return 1;}}while(0)
typedef struct fixture fixture_t;
typedef struct {
    fixture_t *fixture;
    pthread_t thread;
    unsigned cpu,failed;
    int pair[2];
    char data[4];
} worker_t;
struct fixture {
    struct rlimit initial,limit,actual;
    worker_t workers[8];
    unsigned ready,start;
    int pair[2],status;
    pid_t child;
    char bytes[8],executable[4096];
    char *arguments[3],*environment[1];
};
static void *worker(void *opaque)
{
    worker_t *job=opaque;fixture_t *test=job->fixture;
    if(sys_thread_set_affinity(job->cpu) || sys_thread_cpu()!=job->cpu)job->failed=1;
    __atomic_add_fetch(&test->ready,1u,__ATOMIC_RELEASE);
    while(!__atomic_load_n(&test->start,__ATOMIC_ACQUIRE))sys_yield();
    for(unsigned round=0;round<64 && !job->failed;++round)
    {
        if(!job->cpu)
        {
            struct rlimit value={round%2?16:24,test->initial.rlim_max};
            if(setrlimit(RLIMIT_NOFILE,&value))job->failed=2;
        }
        else if(job->cpu<5)
        {
            int fd=dup(HIGH_FD);
            if(fd<0 || fd>=24 || close(fd))job->failed=3;
        }
        else if(job->cpu<7)
        {
            if(pipe2(job->pair,O_CLOEXEC) || job->pair[0]>=24 || job->pair[1]>=24 ||
                write(job->pair[1],"pipe",4)!=4 || read(job->pair[0],job->data,4)!=4 ||
                memcmp(job->data,"pipe",4) || close(job->pair[0]) || close(job->pair[1]))job->failed=4;
        }
        else
        {
            int fd=open("/tmp/fd-limits-file",O_RDONLY|O_CLOEXEC);
            if(fd<0 || fd>=24 || read(fd,job->data,4)!=4 || memcmp(job->data,"data",4) || close(fd))job->failed=5;
        }
        sys_yield();
    }
    return NULL;
}
static int child_test(fixture_t *test)
{
    CHECK(!getrlimit(RLIMIT_NOFILE,&test->actual) && test->actual.rlim_cur==4 && test->actual.rlim_max==256,"inherited limits");
    CHECK(read(HIGH_FD,test->bytes,4)==4 && !memcmp(test->bytes,"data",4),"inherited high descriptor");
    int fd=dup(HIGH_FD);CHECK(fd==3 && dup(HIGH_FD)==-1 && errno==EMFILE,"child allocation limit");
    CHECK(fcntl(HIGH_FD,F_DUPFD,4)==-1 && errno==EINVAL,"child minimum bound");
    test->limit=(struct rlimit){0,8};CHECK(!setrlimit(RLIMIT_NOFILE,&test->limit),"child hard reduction");
    CHECK(dup2(HIGH_FD,HIGH_FD)==HIGH_FD && dup2(HIGH_FD,3)==-1 && errno==EBADF && !close(fd),"child existing slots survive reduction");
    serial_printf("FD_LIMITS_CHILD_TEST: PASS inherited=1 high_slots=1 allocation=1 isolated_hard=1\n");return 0;
}
int main(int argc,char **argv)
{
    fixture_t *test=calloc(1,sizeof(*test));CHECK(test,"owned fixture");
    if(argc>1 && !strcmp(argv[1],"child")){int result=child_test(test);free(test);return result;}
    errno=EDOM;CHECK(!getrlimit(RLIMIT_NOFILE,&test->initial) && test->initial.rlim_cur==256 && test->initial.rlim_max==256 && errno==EDOM,"actual initial FD limits");
    CHECK(!getrlimit(RLIMIT_AS,&test->actual) && test->actual.rlim_cur==RLIM_INFINITY && test->actual.rlim_max==RLIM_INFINITY,"address-space policy");
    CHECK(getrlimit(RLIMIT_NOFILE,NULL)==-1 && errno==EFAULT && setrlimit(RLIMIT_NOFILE,NULL)==-1 && errno==EFAULT,"null limit pointers");
    CHECK(getrlimit(-1,&test->actual)==-1 && errno==EINVAL && setrlimit(RLIMIT_AS,&test->actual)==-1 && errno==ENOTSUP,"unsupported resource policy");
    test->limit=(struct rlimit){257,256};CHECK(setrlimit(RLIMIT_NOFILE,&test->limit)==-1 && errno==EINVAL,"soft exceeds hard");
    test->limit=(struct rlimit){256,257};CHECK(setrlimit(RLIMIT_NOFILE,&test->limit)==-1 && errno==EPERM,"physical hard ceiling");
    CHECK(sys_file_io(SYSCALL_FILE_GET_LIMIT,RLIMIT_NOFILE,(uintptr_t)&test->actual,15,0)==-EINVAL &&
        sys_file_io(SYSCALL_FILE_SET_LIMIT,RLIMIT_NOFILE,(uintptr_t)&test->initial,16,1)==-EINVAL,"raw wire validation");
    unsigned char *pages=mmap(NULL,8192,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);CHECK(pages!=MAP_FAILED,"copy fixture mapping");
    memcpy(pages,&test->initial,sizeof(test->initial));
    CHECK(!mprotect(pages,4096,PROT_READ) && getrlimit(RLIMIT_NOFILE,(void *)pages)==-1 && errno==EFAULT &&
        !memcmp(pages,&test->initial,sizeof(test->initial)) && !setrlimit(RLIMIT_NOFILE,(void *)pages),"checked output and read-only input");
    CHECK(!mprotect(pages,4096,PROT_READ|PROT_WRITE) && !mprotect(pages+4096,4096,PROT_NONE),"cross-page input setup");
    *((uint64_t *)(pages+4088))=0;
    CHECK(setrlimit(RLIMIT_NOFILE,(void *)(pages+4088))==-1 && errno==EFAULT &&
        !getrlimit(RLIMIT_NOFILE,&test->actual) && !memcmp(&test->actual,&test->initial,sizeof(test->actual)) && !munmap(pages,8192),"partial input copy cannot mutate limits");
    int source=open("/tmp/fd-limits-file",O_CREAT|O_EXCL|O_RDWR|O_CLOEXEC);
    CHECK(source==3 && write(source,"data",4)==4 && lseek(source,0,SEEK_SET)==0 && dup2(source,HIGH_FD)==HIGH_FD && !close(source),"high descriptor setup");
    test->limit=(struct rlimit){3,256};CHECK(!setrlimit(RLIMIT_NOFILE,&test->limit),"reduce below existing high slot");
    CHECK(open("/tmp/fd-limits-file",O_TRUNC|O_RDWR)==-1 && errno==EMFILE &&
        pread(HIGH_FD,test->bytes,4,0)==4 && !memcmp(test->bytes,"data",4),"limit admission precedes truncation");
    test->pair[0]=91;test->pair[1]=92;
    CHECK(pipe(test->pair)==-1 && errno==EMFILE && test->pair[0]==91 && test->pair[1]==92,"failed pipe publication is atomic");
    CHECK(socket(AF_INET,SOCK_STREAM,0)==-1 && errno==EMFILE,"socket admission limit");
    CHECK(dup(HIGH_FD)==-1 && errno==EMFILE && fcntl(HIGH_FD,F_DUPFD,3)==-1 && errno==EINVAL,"dup and minimum errors");
    test->limit.rlim_cur=4;CHECK(!setrlimit(RLIMIT_NOFILE,&test->limit),"one free low slot");
    CHECK(pipe(test->pair)==-1 && errno==EMFILE && dup(HIGH_FD)==3 && !close(3),"pipe reserves both slots or none");
    test->limit.rlim_cur=5;CHECK(!setrlimit(RLIMIT_NOFILE,&test->limit) && !pipe(test->pair) && test->pair[0]==3 && test->pair[1]==4 &&
        !close(test->pair[0]) && !close(test->pair[1]),"pipe grows within limit");
    CHECK(fcntl(HIGH_FD,F_DUPFD_CLOEXEC,4)==4 && fcntl(4,F_GETFD)==FD_CLOEXEC && !close(4),"minimum and slot flags");
    test->limit.rlim_cur=0;CHECK(!setrlimit(RLIMIT_NOFILE,&test->limit) && dup2(HIGH_FD,HIGH_FD)==HIGH_FD &&
        fcntl(HIGH_FD,F_GETFL)>=0 && dup2(HIGH_FD,3)==-1 && errno==EBADF,"zero limit preserves existing access");
    test->limit.rlim_cur=4;CHECK(!setrlimit(RLIMIT_NOFILE,&test->limit),"child limit setup");
    CHECK(alix_get_executable_path(test->executable,sizeof(test->executable))>0,"native executable discovery");
    test->arguments[0]=test->executable;test->arguments[1]="child";
    CHECK(!posix_spawn(&test->child,test->executable,NULL,NULL,test->arguments,test->environment) &&
        waitpid(test->child,&test->status,0)==test->child && WIFEXITED(test->status) && !WEXITSTATUS(test->status),"spawn under reduced FD limit");
    CHECK(!getrlimit(RLIMIT_NOFILE,&test->actual) && test->actual.rlim_cur==4 && test->actual.rlim_max==256 &&
        lseek(HIGH_FD,0,SEEK_CUR)==4,"child limit isolation and inherited shared offset");
    test->limit.rlim_cur=24;CHECK(!setrlimit(RLIMIT_NOFILE,&test->limit),"concurrent limit setup");
    for(unsigned cpu=0;cpu<8;++cpu){worker_t *job=&test->workers[cpu];job->fixture=test;job->cpu=cpu;CHECK(!pthread_create(&job->thread,NULL,worker,job),"create pinned limit worker");}
    uint64_t deadline=sys_monotonic_millis()+5000;
    while(__atomic_load_n(&test->ready,__ATOMIC_ACQUIRE)!=8 && sys_monotonic_millis()<deadline)sys_yield();
    CHECK(__atomic_load_n(&test->ready,__ATOMIC_ACQUIRE)==8,"limit worker readiness");__atomic_store_n(&test->start,1u,__ATOMIC_RELEASE);
    for(unsigned cpu=0;cpu<8;++cpu){CHECK(!pthread_join(test->workers[cpu].thread,NULL),"join limit worker");if(test->workers[cpu].failed){serial_printf("FD_LIMITS_TEST: FAIL cpu=%u stage=%u\n",cpu,test->workers[cpu].failed);return 1;}}
    CHECK(!setrlimit(RLIMIT_NOFILE,&test->initial) && !close(HIGH_FD) && !unlink("/tmp/fd-limits-file"),"restore limits and release file");
    serial_printf("FD_LIMITS_TEST: PASS cpus=8 operations=512 enforced=1 pipes=1 sockets=1 truncate_preserved=1 high_slots=1 spawn=1 checked_copy=1\n");
    free(test);return 0;
}
