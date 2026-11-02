#include "fcntl.h"
#include "unistd.h"
#include "stdlib.h"
#include "string.h"
#include "stdio.h"
#include "pthread.h"
#include "serial.h"
#include "usyscall.h"
#include "sys/stat.h"
#include "sys/ioctl.h"
#include "errno.h"

#define WRITE_PATH "/tmp/sync-disk/synchronous/records.bin"
#define READ_PATH "/root/synchronous/records.bin"
#define RECORD_BYTES 512u
#define RECORD_COUNT 64u
#define CHECK(c,label) do {if(!(c)){serial_printf("SYNCHRONOUS_FILE_TEST: FAIL %s line=%u errno=%d\n",label,__LINE__,errno);return 1;}}while(0)
typedef struct fixture fixture_t;
typedef struct {
    fixture_t *fixture;
    pthread_t thread;
    int fd;
    unsigned cpu, failed;
    unsigned char record[RECORD_BYTES];
} worker_t;
struct fixture {
    worker_t workers[8];
    unsigned ready,start;
    bool seen[RECORD_COUNT];
    unsigned char data[RECORD_BYTES*RECORD_COUNT];
    struct stat metadata;
};
static unsigned char pattern(unsigned cpu,unsigned round,unsigned index)
{ return (unsigned char)(cpu*31u+round*17u+index*37u+0x5a); }
static bool verify(fixture_t *test)
{
    memset(test->seen,0,sizeof(test->seen));
    for(unsigned record=0;record<RECORD_COUNT;++record)
    {
        const unsigned char *data=test->data+record*RECORD_BYTES;
        unsigned cpu=data[0],round=data[1];
        if(cpu>=8 || round>=8 || test->seen[cpu*8+round])return false;
        test->seen[cpu*8+round]=true;
        for(unsigned index=2;index<RECORD_BYTES;++index)if(data[index]!=pattern(cpu,round,index))return false;
    }
    return true;
}
static void *writer(void *opaque)
{
    worker_t *job=opaque;fixture_t *test=job->fixture;
    if(sys_thread_set_affinity(job->cpu) || sys_thread_cpu()!=job->cpu)job->failed=1;
    __atomic_add_fetch(&test->ready,1u,__ATOMIC_RELEASE);
    while(!__atomic_load_n(&test->start,__ATOMIC_ACQUIRE))sys_yield();
    for(unsigned round=0;round<8 && !job->failed;++round)
    {
        job->record[0]=(unsigned char)job->cpu;job->record[1]=(unsigned char)round;
        for(unsigned index=2;index<RECORD_BYTES;++index)job->record[index]=pattern(job->cpu,round,index);
        if(write(job->fd,job->record,RECORD_BYTES)!=RECORD_BYTES || !(fcntl(job->fd,F_GETFL)&O_SYNC))job->failed=2;
    }
    return NULL;
}
int main(int argc,char **argv)
{
    fixture_t *test=calloc(1,sizeof(*test));CHECK(test,"owned fixture");
    if(argc>1 && !strcmp(argv[1],"read"))
    {
        int fd=open(READ_PATH,O_RDONLY|O_CLOEXEC);
        CHECK(fd>=0 && !fstat(fd,&test->metadata) && test->metadata.st_size==sizeof(test->data) &&
            read(fd,test->data,sizeof(test->data))==(ssize_t)sizeof(test->data) && verify(test) && !close(fd),"independent remount payload and metadata");
        serial_printf("SYNCHRONOUS_FILE_REMOUNT_TEST: PASS bytes=32768 records=64 explicit_fsync=0\n");
        free(test);return 0;
    }
    int plain=open("/tmp/synchronous-plain",O_CREAT|O_EXCL|O_RDWR|O_NONBLOCK|O_CLOEXEC);
    CHECK(plain>=0 && (fcntl(plain,F_GETFL)&O_NONBLOCK),"native nonblocking open flag");
    CHECK(!fcntl(plain,F_SETFL,fcntl(plain,F_GETFL)|O_SYNC) && !(fcntl(plain,F_GETFL)&O_SYNC) && !close(plain),"F_SETFL cannot enable sync");
    CHECK(!mkdir("/tmp/sync-disk/synchronous",0700),"persistent parent");
    int fd=open(WRITE_PATH,O_CREAT|O_EXCL|O_RDWR|O_APPEND|O_SYNC|O_CLOEXEC);
    CHECK(fd>=0 && (fcntl(fd,F_GETFL)&O_SYNC),"synchronous open status");
    int status=fcntl(fd,F_GETFL);
    CHECK(!fcntl(fd,F_SETFL,(status&~O_SYNC)|O_NONBLOCK) && (fcntl(fd,F_GETFL)&O_SYNC),"F_SETFL cannot clear sync");
    int *nonblock=calloc(1,sizeof(*nonblock));CHECK(nonblock,"owned control value");
    CHECK(!ioctl(fd,FIONBIO,nonblock) && (fcntl(fd,F_GETFL)&O_SYNC) && !(fcntl(fd,F_GETFL)&O_NONBLOCK),"partial flag control preserves sync");free(nonblock);
    CHECK(write(fd,(void *)1,8)==-1 && errno==EFAULT && lseek(fd,0,SEEK_CUR)==0,"checked input preserves offset");
    CHECK(write(fd,NULL,0)==0,"empty synchronous write");
    int readonly=open(WRITE_PATH,O_RDONLY|O_SYNC|O_CLOEXEC);
    CHECK(readonly>=0 && write(readonly,"x",1)==-1 && errno==EBADF && !close(readonly),"sync preserves access mode");
    for(unsigned cpu=0;cpu<8;++cpu)
    {
        worker_t *job=&test->workers[cpu];job->fixture=test;job->cpu=cpu;job->fd=dup(fd);
        CHECK(job->fd>=0 && !pthread_create(&job->thread,NULL,writer,job),"start pinned sync writer");
    }
    uint64_t deadline=sys_monotonic_millis()+5000;
    while(__atomic_load_n(&test->ready,__ATOMIC_ACQUIRE)!=8 && sys_monotonic_millis()<deadline)sys_yield();
    CHECK(__atomic_load_n(&test->ready,__ATOMIC_ACQUIRE)==8,"writer readiness");__atomic_store_n(&test->start,1u,__ATOMIC_RELEASE);
    for(unsigned cpu=0;cpu<8;++cpu)CHECK(!pthread_join(test->workers[cpu].thread,NULL) && !test->workers[cpu].failed && !close(test->workers[cpu].fd),"join sync writer");
    CHECK(!fstat(fd,&test->metadata) && test->metadata.st_size==sizeof(test->data) &&
        lseek(fd,0,SEEK_CUR)==sizeof(test->data) && pread(fd,test->data,sizeof(test->data),0)==(ssize_t)sizeof(test->data) && verify(test),"shared offset and complete records");
    /* No explicit fsync: each successful O_SYNC write already committed its
     * payload/metadata. Closing only releases the owned description. */
    CHECK(!close(fd),"close synchronous description");
    serial_printf("SYNCHRONOUS_FILE_TEST: PASS cpus=8 writes=64 bytes=32768 append=1 aliases=1 immutable=1 checked_copy=1 nonblock_open=1\n");
    free(test);return 0;
}
