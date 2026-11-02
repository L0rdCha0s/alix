#include "sys/ioctl.h"
#include "fcntl.h"
#include "poll.h"
#include "pthread.h"
#include "unistd.h"
#include "usyscall.h"
#include "stdlib.h"
#include "string.h"
#include "errno.h"
#include "serial.h"
#include "stdio.h"

#define CHECK(c,label) do { if(!(c)){serial_printf("IOCTL_TEST: FAIL %s line=%u errno=%d\n",label,__LINE__,errno);return 1;} }while(0)
typedef struct { uint32_t before; int count; uint32_t after; } guarded_t;
typedef struct {
    pthread_t thread;
    unsigned cpu, failed;
    int pair[2], alias, enabled;
    guarded_t query;
    struct pollfd poll;
    unsigned char bytes[32];
} job_t;
typedef struct {
    job_t jobs[8];
    int pair[2], enabled;
    guarded_t query;
    struct pollfd poll;
    unsigned char bytes[16384];
} fixture_t;
static const int readonly_one = 1;
static void *worker(void *opaque)
{
    job_t *job = opaque;
#define MUST(c) do { if(!(c)){job->failed=__LINE__;goto finished;} }while(0)
    MUST(!sys_thread_set_affinity(job->cpu) && sys_thread_cpu()==job->cpu);
    MUST(!pipe2(job->pair,O_CLOEXEC)); job->alias=dup(job->pair[0]); MUST(job->alias>=0);
    job->query=(guarded_t){0x13579bdf,0,0x2468ace0};
    for(unsigned sequence=0;sequence<32;++sequence)
    {
        for(unsigned i=0;i<16;++i)job->bytes[i]=(unsigned char)(i+sequence+job->cpu);
        MUST(write(job->pair[1],job->bytes,16)==16);
        MUST(!ioctl(job->pair[0],FIONREAD,&job->query.count) && job->query.count==16);
        MUST(!ioctl(job->pair[1],FIONREAD,&job->query.count) && job->query.count==16);
        MUST(read(job->alias,job->bytes,7)==7);
        MUST(!ioctl(job->pair[0],FIONREAD,&job->query.count) && job->query.count==9);
        MUST(job->query.before==0x13579bdf && job->query.after==0x2468ace0);
        job->enabled=1;MUST(!ioctl(job->alias,FIONBIO,&job->enabled));
        MUST((fcntl(job->pair[0],F_GETFL)&O_NONBLOCK)!=0);
        MUST(read(job->pair[0],job->bytes,9)==9);
        MUST(read(job->pair[0],job->bytes,1)==-1 && errno==EAGAIN);
        job->enabled=0;MUST(!ioctl(job->pair[0],FIONBIO,&job->enabled));
        MUST(!(fcntl(job->alias,F_GETFL)&O_NONBLOCK));
    }
    MUST(!close(job->alias));job->alias=-1;MUST(!close(job->pair[1]));job->pair[1]=-1;
    job->poll=(struct pollfd){.fd=job->pair[0],.events=POLLIN};
    MUST(poll(&job->poll,1,5000)==1 && (job->poll.revents&POLLHUP));
    MUST(!ioctl(job->pair[0],FIONREAD,&job->query.count) && job->query.count==0);
    MUST(read(job->pair[0],job->bytes,1)==0);
finished:
    if(job->alias>=0)close(job->alias);
    if(job->pair[0]>=0)close(job->pair[0]);
    if(job->pair[1]>=0)close(job->pair[1]);
    return NULL;
#undef MUST
}
int main(void)
{
    fixture_t *test=calloc(1,sizeof(*test));CHECK(test,"heap fixture");
    test->query=(guarded_t){0x13579bdf,-1,0x2468ace0};
    int fd=open("/tmp/ioctl-native-file",O_CREAT|O_TRUNC|O_RDWR|O_APPEND|O_CLOEXEC);
    CHECK(fd>=0,"regular file");int alias=dup(fd);CHECK(alias>=0,"alias");
    CHECK(!ioctl(fd,FIONCLEX) && !fcntl(fd,F_GETFD),"clear close-on-exec");
    CHECK(!ioctl(fd,FIOCLEX) && fcntl(fd,F_GETFD)==FD_CLOEXEC && !fcntl(alias,F_GETFD),"descriptor-specific close-on-exec");
    CHECK(!ioctl(alias,FIOCLEX) && !ioctl(fd,FIONCLEX) && fcntl(alias,F_GETFD)==FD_CLOEXEC && !fcntl(fd,F_GETFD),"independent alias flags");
    CHECK(!ioctl(alias,FIONBIO,(void *)&readonly_one),"read-only input accepted");
    CHECK(fcntl(fd,F_GETFL)==(O_RDWR|O_APPEND|O_NONBLOCK),"atomic nonblock preserves access and append");
    test->enabled=0;CHECK(!ioctl(fd,FIONBIO,&test->enabled) && fcntl(alias,F_GETFL)==(O_RDWR|O_APPEND),"clear shared nonblock only");
    CHECK(write(fd,"abcdefgh",8)==8 && lseek(fd,2,SEEK_SET)==2,"file position");
    CHECK(!ioctl(alias,FIONREAD,&test->query.count) && test->query.count==6,"remaining regular bytes");
    CHECK(lseek(fd,0,SEEK_CUR)==2,"query preserves offset");
    CHECK(read(alias,test->bytes,1)==1 && test->bytes[0]=='c' && !ioctl(fd,FIONREAD,&test->query.count) && test->query.count==5,"alias offset snapshot");
    CHECK(lseek(fd,((int64_t)1<<33)+7,SEEK_SET)>0 && !ioctl(fd,FIONREAD,&test->query.count) && !test->query.count,"past eof count");
    CHECK(test->query.before==0x13579bdf && test->query.after==0x2468ace0,"exact 32-bit output");
    CHECK(ioctl(fd,FIONREAD,NULL)==-1 && errno==EFAULT,"null output");
    CHECK(ioctl(fd,FIONREAD,(void *)&readonly_one)==-1 && errno==EFAULT,"read-only output");
    CHECK(ioctl(fd,FIONBIO,(void *)1)==-1 && errno==EFAULT && fcntl(fd,F_GETFL)==(O_RDWR|O_APPEND),"bad input leaves flags");
    CHECK(sys_file_io(SYSCALL_FILE_IOCTL,fd,FIONREAD,(uintptr_t)&test->query.count,8)==-EINVAL,"wrong wire size");
    CHECK(sys_file_io(SYSCALL_FILE_IOCTL,fd,FIOCLEX,1,0)==-EINVAL,"no-argument control rejects payload");
    CHECK(ioctl(fd,0x7fffffffUL)==-1 && errno==ENOTTY,"unknown request");
    CHECK(ioctl(fd,TIOCGWINSZ,NULL)==-1 && errno==ENOTTY,"no fabricated tty");
    CHECK(ioctl(-1,FIONREAD,&test->query.count)==-1 && errno==EBADF,"invalid fd");
    CHECK(!close(alias) && !close(fd) && !unlink("/tmp/ioctl-native-file"),"file cleanup");
    CHECK(!pipe2(test->pair,O_NONBLOCK|O_CLOEXEC),"full pipe");
    CHECK(write(test->pair[1],test->bytes,sizeof(test->bytes))==sizeof(test->bytes),"fill pipe");
    CHECK(!ioctl(test->pair[0],FIONREAD,&test->query.count) && test->query.count==sizeof(test->bytes),"full count");
    CHECK(write(test->pair[1],test->bytes,1)==-1 && errno==EAGAIN,"nonblocking full writer");
    CHECK(ioctl(test->pair[0],FIONREAD,(void *)&readonly_one)==-1 && errno==EFAULT,"failed pipe output");
    CHECK(!ioctl(test->pair[0],FIONREAD,&test->query.count) && test->query.count==sizeof(test->bytes),"query never consumes bytes");
    CHECK(read(test->pair[0],test->bytes,sizeof(test->bytes))==sizeof(test->bytes),"drain pipe");
    CHECK(!close(test->pair[0]) && !close(test->pair[1]),"pipe cleanup");
    for(unsigned cpu=0;cpu<8;++cpu)
    {
        job_t *job=&test->jobs[cpu];job->cpu=cpu;job->pair[0]=job->pair[1]=job->alias=-1;
        CHECK(!pthread_create(&job->thread,NULL,worker,job),"spawn pinned ioctl worker");
    }
    for(unsigned cpu=0;cpu<8;++cpu)
    {
        CHECK(!pthread_join(test->jobs[cpu].thread,NULL),"join pinned worker");
        if(test->jobs[cpu].failed){serial_printf("IOCTL_TEST: FAIL cpu=%u line=%u\n",cpu,test->jobs[cpu].failed);return 1;}
    }
    serial_printf("IOCTL_TEST: PASS cpus=8 snapshots=768 pipes=1 files=1 nonblock=1 cloexec=1 exact_copy=1 errors=1 eof=1\n");
    free(test);return 0;
}
