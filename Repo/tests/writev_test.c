#include "sys/uio.h"
#include "sys/mman.h"
#include "fcntl.h"
#include "unistd.h"
#include "pthread.h"
#include "signal.h"
#include "stdlib.h"
#include "string.h"
#include "stdio.h"
#include "errno.h"
#include "serial.h"
#include "usyscall.h"

#define WORKERS 8u
#define RECORDS 64u
#define CHECK(c,label) do{if(!(c)){serial_printf("WRITEV_TEST: FAIL %s line=%u errno=%d\n",label,__LINE__,errno);return 1;}}while(0)
typedef struct {uint32_t magic,cpu,sequence;unsigned char data[116];} packet_t;
typedef struct fixture fixture_t;
typedef struct {fixture_t *fixture;pthread_t thread;unsigned cpu,failed;int fd;packet_t packet;struct iovec vectors[4];} job_t;
struct fixture {
    job_t jobs[WORKERS];unsigned ready,start;
    bool seen[WORKERS*RECORDS];
    packet_t packet;
    struct iovec vectors[4];
    int descriptors[2];
    unsigned char bytes[131072];
};
static volatile sig_atomic_t caught;
static void sigpipe_handler(int number){if(number==SIGPIPE)++caught;}
static bool until(unsigned *p,unsigned value)
{
    uint64_t deadline=sys_monotonic_millis()+8000;
    while(__atomic_load_n(p,__ATOMIC_ACQUIRE)!=value && sys_monotonic_millis()<deadline)sys_yield();
    return __atomic_load_n(p,__ATOMIC_ACQUIRE)==value;
}
static void *writer(void *opaque)
{
    job_t *j=opaque;fixture_t *f=j->fixture;
    if(sys_thread_set_affinity(j->cpu) || sys_thread_cpu()!=j->cpu)j->failed=1;
    unsigned char *p=(void *)&j->packet;
    j->vectors[0]=(struct iovec){p,7};j->vectors[1]=(struct iovec){(void *)1,0};
    j->vectors[2]=(struct iovec){p+7,53};j->vectors[3]=(struct iovec){p+60,sizeof(j->packet)-60};
    __atomic_add_fetch(&f->ready,1u,__ATOMIC_RELEASE);
    while(!__atomic_load_n(&f->start,__ATOMIC_ACQUIRE))sys_yield();
    for(unsigned n=0;n<RECORDS && !j->failed;++n) {
        j->packet.magic=0xc0decafe;j->packet.cpu=j->cpu;j->packet.sequence=n;
        memset(j->packet.data,(int)(j->cpu*RECORDS+n),sizeof(j->packet.data));
        if(writev(j->fd,j->vectors,4)!=sizeof(j->packet))j->failed=2;
    }
    if(close(j->fd))j->failed=3;
    return NULL;
}
static int launch(fixture_t *f,int source,bool file)
{
    memset(f->seen,0,sizeof(f->seen));f->ready=f->start=0;
    for(unsigned cpu=0;cpu<WORKERS;++cpu) {
        job_t *j=&f->jobs[cpu];memset(j,0,sizeof(*j));j->fixture=f;j->cpu=cpu;
        j->fd=file?open("/tmp/writev-append",O_WRONLY|O_APPEND|O_CLOEXEC):dup(source);
        CHECK(j->fd>=0 && !pthread_create(&j->thread,NULL,writer,j),"launch pinned vector writer");
    }
    CHECK(until(&f->ready,WORKERS),"writers ready");__atomic_store_n(&f->start,1u,__ATOMIC_RELEASE);
    return 0;
}
static int join_all(fixture_t *f)
{
    for(unsigned cpu=0;cpu<WORKERS;++cpu)CHECK(!pthread_join(f->jobs[cpu].thread,NULL) && !f->jobs[cpu].failed,"join vector writer");
    return 0;
}
static bool record(fixture_t *f)
{
    packet_t *p=&f->packet;
    if(p->magic!=0xc0decafe || p->cpu>=WORKERS || p->sequence>=RECORDS || f->seen[p->cpu*RECORDS+p->sequence])return false;
    f->seen[p->cpu*RECORDS+p->sequence]=true;
    for(unsigned i=0;i<sizeof(p->data);++i)if(p->data[i]!=(unsigned char)(p->cpu*RECORDS+p->sequence))return false;
    return true;
}
int main(void)
{
    fixture_t *f=calloc(1,sizeof(*f));CHECK(f,"heap fixture");
    int fd=open("/tmp/writev-errors",O_CREAT|O_TRUNC|O_RDWR|O_CLOEXEC);CHECK(fd>=0,"file fixture");
    f->vectors[0]=(struct iovec){"safe",4};f->vectors[1]=(struct iovec){(void *)1,1};
    CHECK(writev(fd,f->vectors,2)==-1 && errno==EFAULT && lseek(fd,0,SEEK_CUR)==0,"failed later input does not write prefix");
    CHECK(writev(fd,(void *)1,1)==-1 && errno==EFAULT && writev(fd,NULL,-1)==-1 && errno==EINVAL &&
        writev(fd,f->vectors,IOV_MAX+1)==-1 && errno==EINVAL,"vector header and count validation");
    f->vectors[0].iov_len=INT64_MAX;f->vectors[1].iov_len=1;
    CHECK(writev(fd,f->vectors,2)==-1 && errno==EINVAL && lseek(fd,0,SEEK_CUR)==0,"sum overflow before copy or I/O");
    errno=EDOM;CHECK(writev(fd,NULL,0)==0 && errno==EDOM,"zero vector and errno preservation");
    unsigned char *pages=mmap(NULL,8192,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    CHECK(pages!=MAP_FAILED && !mprotect(pages+4096,4096,PROT_NONE),"checked-copy mapping");
    CHECK(writev(fd,(void *)(pages+4096-8),1)==-1 && errno==EFAULT,"cross-page vector header");
    f->vectors[0]=(struct iovec){pages+4096-4,8};
    CHECK(writev(fd,f->vectors,1)==-1 && errno==EFAULT && lseek(fd,0,SEEK_CUR)==0 && !munmap(pages,8192),"cross-page payload rollback");
    memset(f->bytes,0x5b,sizeof(f->bytes));f->vectors[0]=(struct iovec){f->bytes,100000};
    ssize_t written=writev(fd,f->vectors,1);
    CHECK(written>4096 && written<=65536 && lseek(fd,0,SEEK_CUR)==written,"bounded large vector prefix");
    memset(f->bytes,0,sizeof(f->bytes));size_t got=0;
    while(got<(size_t)written) {
        size_t n=(size_t)written-got;if(n>16384)n=16384;
        CHECK(pread(fd,f->bytes+got,n,(off_t)got)==(ssize_t)n,"large vector readback");got+=n;
    }
    for(size_t n=0;n<got;++n)CHECK(f->bytes[n]==0x5b,"large vector order");
    CHECK(!close(fd),"close large vector file");
    CHECK(!pipe2(f->descriptors,O_CLOEXEC) && !launch(f,f->descriptors[1],false) && !close(f->descriptors[1]),"atomic pipe vector writers");
    for(unsigned n=0;n<WORKERS*RECORDS;++n) {
        CHECK(read(f->descriptors[0],&f->packet,sizeof(f->packet))==sizeof(f->packet) && record(f),"pipe vector record atomicity");
    }
    CHECK(!join_all(f) && read(f->descriptors[0],f->bytes,1)==0 && !close(f->descriptors[0]),"pipe vector EOF");
    fd=open("/tmp/writev-append",O_CREAT|O_TRUNC|O_RDWR|O_CLOEXEC);CHECK(fd>=0,"append fixture");
    CHECK(!launch(f,0,true) && !join_all(f),"atomic append vector writers");
    for(unsigned n=0;n<WORKERS*RECORDS;++n)
        CHECK(read(fd,&f->packet,sizeof(f->packet))==sizeof(f->packet) && record(f),"append vector record atomicity");
    CHECK(read(fd,f->bytes,1)==0 && !close(fd),"exact append byte count");
    CHECK(!pipe2(f->descriptors,O_NONBLOCK),"nonblocking vector pipe");
    memset(f->bytes,0x6c,16384);CHECK(write(f->descriptors[1],f->bytes,16384)==16384 && read(f->descriptors[0],f->bytes,1)==1,"fill pipe with one byte free");
    f->vectors[0]=(struct iovec){f->bytes,2000};f->vectors[1]=(struct iovec){f->bytes+2000,2096};
    CHECK(writev(f->descriptors[1],f->vectors,2)==-1 && errno==EAGAIN,"atomic vector cannot partially fill small gap");
    CHECK(read(f->descriptors[0],f->bytes,16384)==16383 && !close(f->descriptors[0]) && !close(f->descriptors[1]),"failed atomic vector preserves pipe contents");
    CHECK(signal(SIGPIPE,sigpipe_handler)!=SIG_ERR && !pipe(f->descriptors) && !close(f->descriptors[0]),"SIGPIPE fixture");
    sys_sleep_ms(30);f->vectors[0]=(struct iovec){"x",1};
    CHECK(writev(f->descriptors[1],f->vectors,1)==-1 && errno==EPIPE && caught==1 && !close(f->descriptors[1]),"vector write raises caught SIGPIPE");
    serial_printf("WRITEV_TEST: PASS cpus=8 pipe_records=512 append_records=512 checked_copy=1 overflow=1 short_prefix=1 nonblock=1 sigpipe=1\n");
    free(f);return 0;
}
