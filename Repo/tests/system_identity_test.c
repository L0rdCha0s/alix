#include "sys/utsname.h"
#include "sys/stat.h"
#include "pwd.h"
#include "fcntl.h"
#include "unistd.h"
#include "usyscall.h"
#include "pthread.h"
#include "stdlib.h"
#include "string.h"
#include "serial.h"
#include "errno.h"
#include "stdio.h"

#define CONFIG "/etc/hostname"
#define NEXT "/etc/hostname-native-next"
#define CHECK(c,label) do { if(!(c)){serial_printf("SYSTEM_IDENTITY_TEST: FAIL %s line=%u errno=%d\n",label,__LINE__,errno);return 1;} }while(0)
typedef struct fixture fixture_t;
typedef struct {
    fixture_t *fixture;
    pthread_t thread;
    unsigned cpu, failed;
    unsigned char before[8];
    struct utsname info;
    unsigned char after[8];
    char hostname[65];
} job_t;
struct fixture {
    job_t jobs[8];
    pthread_t writer;
    uint32_t start, ready;
    unsigned writer_failed;
    struct utsname initial, scratch;
    char output[128], invalid[4097], password_buffer[65542];
    struct passwd account;
    struct passwd *account_result;
    struct stat metadata;
    char *original;
    size_t original_size;
    bool existed;
};
static int publish(const void *bytes,size_t count)
{
    int fd=open(NEXT,O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC, 0666);
    if(fd<0)return -1;
    ssize_t wrote=count?write(fd,bytes,count):0;
    int result=wrote==(ssize_t)count?0:-1;
    if(close(fd))result=-1;
    if(!result)result=rename(NEXT,CONFIG);
    return result;
}
static bool same_immutable(const struct utsname *a,const struct utsname *b)
{
    return !strcmp(a->sysname,b->sysname) && !strcmp(a->release,b->release) &&
        !strcmp(a->version,b->version) && !strcmp(a->machine,b->machine);
}
static void *reader(void *opaque)
{
    job_t *job=opaque;fixture_t *test=job->fixture;
    if(sys_thread_set_affinity(job->cpu) || sys_thread_cpu()!=job->cpu)job->failed=1;
    __atomic_add_fetch(&test->ready,1u,__ATOMIC_RELEASE);
    while(!__atomic_load_n(&test->start,__ATOMIC_ACQUIRE))sys_yield();
    for(unsigned i=0;i<32 && !job->failed;++i)
    {
        memset(job->before,0x5a,sizeof(job->before));memset(job->after,0xa5,sizeof(job->after));
        if(uname(&job->info) || gethostname(job->hostname,sizeof(job->hostname)))job->failed=2;
        else if(!same_immutable(&test->initial,&job->info) ||
            (strcmp(job->info.nodename,"native-host-A") && strcmp(job->info.nodename,"native-host-B")) ||
            (strcmp(job->hostname,"native-host-A") && strcmp(job->hostname,"native-host-B")))job->failed=3;
        else if(getuid()!=geteuid() || getgid()!=getegid() || getgid()!=test->account.pw_gid)job->failed=4;
        for(unsigned index=0;index<8;++index)if(job->before[index]!=0x5a || job->after[index]!=0xa5)job->failed=5;
    }
    return NULL;
}
static void *writer(void *opaque)
{
    fixture_t *test=opaque;
    while(!__atomic_load_n(&test->start,__ATOMIC_ACQUIRE))sys_yield();
    for(unsigned i=0;i<64;++i)if(publish(i%2?"native-host-A\n":"native-host-B\n",14))test->writer_failed=1;
    return NULL;
}
int main(void)
{
    fixture_t *test=calloc(1,sizeof(*test));CHECK(test,"heap fixture");
    int original=open(CONFIG,O_RDONLY|O_CLOEXEC);
    if(original>=0)
    {
        test->existed=true;CHECK(!fstat(original,&test->metadata) && test->metadata.st_size<=4096,"original hostname bound");
        test->original_size=test->metadata.st_size;test->original=malloc(test->original_size+1);CHECK(test->original,"original hostname copy");
        CHECK(read(original,test->original,test->original_size)==(ssize_t)test->original_size && !close(original),"preserve original hostname");
    }
    else CHECK(errno==ENOENT,"hostname lookup");
    CHECK(!uname(&test->initial),"initial uname");
    CHECK(!strcmp(test->initial.sysname,"Alix") && !strcmp(test->initial.release,"development") &&
        !strcmp(test->initial.machine,"x86_64") && !strncmp(test->initial.version,"build:",6) && strlen(test->initial.version)==46,"running kernel identity");
    CHECK(!gethostname(test->output,sizeof(test->output)) && !strcmp(test->output,test->initial.nodename),"hostname agrees with uname");
    CHECK(!getpwuid_r(getuid(),&test->account,test->password_buffer,sizeof(test->password_buffer),&test->account_result) &&
        test->account_result==&test->account && getgid()==test->account.pw_gid,"actual primary credentials");
    CHECK(sys_process(SYSCALL_PROCESS_GETGID,1,0,0)==-EINVAL,"credential selector reserved arguments");
    serial_printf("SYSTEM_IDENTITY_KERNEL: sysname=%s release=%s machine=%s version=%s uid=%u gid=%u\n",test->initial.sysname,test->initial.release,test->initial.machine,test->initial.version,getuid(),getgid());
    CHECK(uname(NULL)==-1 && errno==EFAULT,"null uname reply");
    CHECK(uname((void *)"readonly")==-1 && errno==EFAULT,"read-only uname reply");
    CHECK(gethostname(NULL,65)==-1 && errno==EFAULT,"null hostname reply");
    CHECK(gethostname((char *)"readonly",65)==-1 && errno==EFAULT,"read-only hostname reply");
    CHECK(gethostname(test->output,0)==-1 && errno==ENAMETOOLONG,"zero hostname capacity");
    CHECK(sys_file_io(SYSCALL_FILE_SYSTEM_INFO,(uintptr_t)&test->scratch,sizeof(test->scratch)-1,0,0)==-EINVAL,"uname wire size");
    CHECK(sys_file_io(SYSCALL_FILE_HOSTNAME,(uintptr_t)test->output,sizeof(test->output),1,0)==-EINVAL,"hostname reserved argument");
    CHECK(!publish(" \tzen-alix\r\n ",13) && !uname(&test->scratch) && !strcmp(test->scratch.nodename,"zen-alix"),"configured hostname trimming");
    memset(test->output,0x5a,sizeof(test->output));
    CHECK(gethostname(test->output,8)==-1 && errno==ENAMETOOLONG && test->output[0]==0x5a,"short reply unchanged");
    CHECK(!gethostname(test->output,9) && !strcmp(test->output,"zen-alix"),"exact hostname capacity");
    CHECK(!gethostname(test->output,SIZE_MAX) && !strcmp(test->output,"zen-alix"),"large caller capacity is bounded");
    CHECK(!publish("",0) && !uname(&test->scratch) && !strcmp(test->scratch.nodename,"alix"),"empty config fallback");
    CHECK(!publish(" \t\n\r",4) && !gethostname(test->output,sizeof(test->output)) && !strcmp(test->output,"alix"),"blank config fallback");
    memset(test->invalid,'x',sizeof(test->invalid));
    CHECK(!publish(test->invalid,64) && !gethostname(test->output,65) && strlen(test->output)==64,"maximum hostname");
    CHECK(!publish(test->invalid,65),"overlong hostname setup");memset(&test->scratch,0x5a,sizeof(test->scratch));
    CHECK(uname(&test->scratch)==-1 && errno==ENAMETOOLONG,"overlong name rejected");
    for(size_t i=0;i<sizeof(test->scratch);++i)CHECK(((unsigned char *)&test->scratch)[i]==0x5a,"failed uname leaves output");
    CHECK(!publish("a\0b",3) && uname(&test->scratch)==-1 && errno==EINVAL,"embedded nul rejected");
    CHECK(!publish(test->invalid,sizeof(test->invalid)) && uname(&test->scratch)==-1 && errno==EFBIG,"config snapshot bounded");
    CHECK(!unlink(CONFIG) && !uname(&test->scratch) && !strcmp(test->scratch.nodename,"alix"),"missing config fallback");
    CHECK(!publish("native-host-A\n",14),"concurrent hostname setup");
    for(unsigned cpu=0;cpu<8;++cpu)
    {
        job_t *job=&test->jobs[cpu];job->fixture=test;job->cpu=cpu;
        CHECK(!pthread_create(&job->thread,NULL,reader,job),"start pinned identity reader");
    }
    CHECK(!pthread_create(&test->writer,NULL,writer,test),"start atomic hostname publisher");
    uint64_t deadline=sys_monotonic_millis()+5000;
    while(__atomic_load_n(&test->ready,__ATOMIC_ACQUIRE)!=8 && sys_monotonic_millis()<deadline)sys_sleep_ms(1);
    CHECK(test->ready==8,"readers ready");__atomic_store_n(&test->start,1u,__ATOMIC_RELEASE);
    for(unsigned cpu=0;cpu<8;++cpu)
    {
        CHECK(!pthread_join(test->jobs[cpu].thread,NULL),"join reader");
        if(test->jobs[cpu].failed){serial_printf("SYSTEM_IDENTITY_TEST: FAIL cpu=%u stage=%u\n",cpu,test->jobs[cpu].failed);return 1;}
    }
    CHECK(!pthread_join(test->writer,NULL) && !test->writer_failed,"join publisher");
    if(test->existed)CHECK(!publish(test->original,test->original_size),"restore hostname");
    else CHECK(!unlink(CONFIG),"remove temporary hostname");
    CHECK(!uname(&test->scratch) && !memcmp(&test->scratch,&test->initial,sizeof(test->initial)),"restored system identity");
    serial_printf("SYSTEM_IDENTITY_TEST: PASS cpus=8 snapshots=512 replacements=64 hostname=1 credentials=1 checked_copy=1 bounds=1 build_id=1\n");
    free(test->original);free(test);return 0;
}
