#include "serial.h"
#include "stdio.h"
#include "pthread.h"
#include "sys/wait.h"
#include "sys/stat.h"
#include "usyscall.h"

#define BASE "/tmp/nspr-native-spawn"
#define CHECK(c,label) do {if(!(c)){serial_printf("NSPR_SPAWN_TEST: FAIL %s line=%u errno=%d\n",label,__LINE__,errno);return 1;}}while(0)
static char *startup_cwd,*startup_value,*startup_inherit;
__attribute__((constructor)) static void startup(void)
{
    startup_cwd=getcwd(NULL,0);
    const char *value=getenv("NSPR_NATIVE_VALUE");if(value)startup_value=strdup(value);
    value=getenv("NSPR_INHERIT_FDS");if(value)startup_inherit=strdup(value);
}
typedef struct fixture fixture_t;
typedef struct {
    fixture_t *fixture;
    pthread_t thread;
    unsigned cpu,failed;
    pid_t pid;
    int status,pipes[3][2];
    PRProcessAttr attr;
    PRFileDesc files[3];
    PRFilePrivate secrets[3];
    char numbers[3][16],data[128],observed[128];
    char *arguments[8],*explicit_env[3],*empty_env[1];
} job_t;
struct fixture {
    job_t jobs[8],special;
    unsigned ready,start;
    char executable[4096],observed[128];
    int saved[2],pressure[256];
};
static int child(int argc,char **argv)
{
    CHECK(argc==7 && startup_cwd && !strcmp(startup_cwd,BASE),"child cwd before main");
    CHECK(startup_inherit && !strcmp(startup_inherit,"native-nspr"),"NSPR inheritance environment before main");
    CHECK(!strcmp(argv[2],"absent")?!startup_value:startup_value&&!strcmp(startup_value,argv[2]),"explicit/inherited environment before main");
    for(unsigned index=0;index<3;++index)
    {
        CHECK(!(fcntl((int)index,F_GETFL)&O_NONBLOCK),"blocking child stdio");
        int original=atoi(argv[3+index]);CHECK(original<3 || (fcntl(original,F_GETFD)==-1 && errno==EBADF),"redirect sources closed after actions");
    }
    char *bytes=malloc(16);CHECK(bytes,"child data");
    CHECK(read(0,bytes,10)==10 && !memcmp(bytes,"nspr-input",10),"redirected input");
    CHECK(fputs("nspr-output\n",stdout)>=0 && !fflush(stdout) && fputs("nspr-error\n",stderr)>=0 && !fflush(stderr),"redirected output/error");
    free(bytes);free(startup_cwd);free(startup_value);free(startup_inherit);return 23;
}
static bool prepare(job_t *job)
{
    memset(&job->attr,0,sizeof(job->attr));
    for(unsigned index=0;index<3;++index)job->pipes[index][0]=job->pipes[index][1]=-1;
    for(unsigned index=0;index<3;++index)if(pipe2(job->pipes[index],O_CLOEXEC))return false;
    for(unsigned index=0;index<3;++index)
    {
        int source=job->pipes[index][index?1:0];
        if(fcntl(source,F_SETFL,O_NONBLOCK))return false;
        job->files[index].secret=&job->secrets[index];job->secrets[index].md.osfd=source;
        snprintf(job->numbers[index],sizeof(job->numbers[index]),"%d",source);
    }
    job->attr.stdinFd=&job->files[0];job->attr.stdoutFd=&job->files[1];job->attr.stderrFd=&job->files[2];
    job->attr.currentDirectory=BASE;job->attr.fdInheritBuffer="NSPR_INHERIT_FDS=native-nspr";
    job->arguments[0]=job->fixture->executable;job->arguments[1]="child";job->arguments[2]="inherited";
    for(unsigned index=0;index<3;++index)job->arguments[3+index]=job->numbers[index];
    job->arguments[6]="checked";job->arguments[7]=NULL;
    job->explicit_env[0]="NSPR_NATIVE_VALUE=explicit";job->explicit_env[1]="NSPR_INHERIT_FDS=obsolete";job->explicit_env[2]=NULL;
    return write(job->pipes[0][1],"nspr-input",10)==10 && !close(job->pipes[0][1]) && (job->pipes[0][1]=-1,true);
}
static void release(job_t *job)
{ for(unsigned index=0;index<3;++index)for(unsigned end=0;end<2;++end)if(job->pipes[index][end]>=0){close(job->pipes[index][end]);job->pipes[index][end]=-1;} }
static bool read_output(job_t *job,int fd,const char *expected)
{
    size_t used=0;
    for(;;){ssize_t got=read(fd,job->data+used,sizeof(job->data)-used-1);if(got<0)return false;if(!got)break;used+=(size_t)got;if(used==sizeof(job->data)-1)return false;}
    job->data[used]=0;return !strcmp(job->data,expected);
}
static bool finish(job_t *job)
{
    for(unsigned index=0;index<3;++index)
    {
        int source=job->pipes[index][index?1:0];
        if((fcntl(source,F_GETFL)&O_NONBLOCK) || fcntl(source,F_GETFD)!=FD_CLOEXEC || close(source))return false;
        job->pipes[index][index?1:0]=-1;
    }
    bool ok=read_output(job,job->pipes[1][0],"nspr-output\n") && read_output(job,job->pipes[2][0],"nspr-error\n") &&
        waitpid(job->pid,&job->status,0)==job->pid && WIFEXITED(job->status) && WEXITSTATUS(job->status)==23;
    release(job);return ok;
}
static void *worker(void *opaque)
{
    job_t *job=opaque;fixture_t *test=job->fixture;
    if(sys_thread_set_affinity(job->cpu) || sys_thread_cpu()!=job->cpu)job->failed=1;
    __atomic_add_fetch(&test->ready,1u,__ATOMIC_RELEASE);
    while(!__atomic_load_n(&test->start,__ATOMIC_ACQUIRE))sys_yield();
    for(unsigned round=0;round<3 && !job->failed;++round)
    {
        if(!prepare(job)){job->failed=2;break;}
        job->arguments[2]=round==0?"inherited":round==1?"explicit":"absent";
        char **environment=round==0?NULL:round==1?job->explicit_env:job->empty_env;
        if(_MD_alix_spawn(&job->pid,test->executable,job->arguments,environment,&job->attr) || !finish(job))job->failed=3;
        if(!getcwd(job->observed,sizeof(job->observed)) || strcmp(job->observed,test->observed) ||
            strcmp(getenv("NSPR_INHERIT_FDS"),"parent-inherit"))job->failed=4;
    }
    return NULL;
}
int main(int argc,char **argv)
{
    if(argc>1)return child(argc,argv);
    fixture_t *test=calloc(1,sizeof(*test));CHECK(test,"owned fixture");
    CHECK(alix_get_executable_path(test->executable,sizeof(test->executable))>0 && getcwd(test->observed,sizeof(test->observed)) && !mkdir(BASE,0700),"native process setup");
    CHECK(!setenv("NSPR_NATIVE_VALUE","inherited",1) && !setenv("NSPR_INHERIT_FDS","parent-inherit",1),"parent environment");
    job_t *special=&test->special;special->fixture=test;
    CHECK(prepare(special),"crossed stdio fixture");
    test->saved[0]=fcntl(0,F_DUPFD_CLOEXEC,3);test->saved[1]=fcntl(1,F_DUPFD_CLOEXEC,3);
    CHECK(test->saved[0]>=0 && test->saved[1]>=0 && dup2(special->pipes[1][1],0)==0 && dup2(special->pipes[0][0],1)==1,"crossed parent aliases");
    special->secrets[0].md.osfd=1;special->secrets[1].md.osfd=0;
    int crossed=_MD_alix_spawn(&special->pid,test->executable,special->arguments,NULL,&special->attr);
    CHECK(dup2(test->saved[0],0)==0 && dup2(test->saved[1],1)==1 && !close(test->saved[0]) && !close(test->saved[1]),"restore parent standard slots");
    CHECK(!crossed && finish(special),"crossed stdio and close-on-exec sources");
    CHECK(prepare(special),"failed launch fixture");special->pid=-777;
    CHECK(_MD_alix_spawn(&special->pid,"/nspr-native-missing",special->arguments,NULL,&special->attr)==ENOENT && special->pid==-777,"missing executable failure");
    for(unsigned index=0;index<3;++index)CHECK(fcntl(special->pipes[index][index?1:0],F_GETFL)&O_NONBLOCK,"failed spawn restores nonblocking status");
    special->attr.currentDirectory="/nspr-native-missing";
    CHECK(_MD_alix_spawn(&special->pid,test->executable,special->arguments,NULL,&special->attr)==ENOENT && special->pid==-777,"missing cwd failure");
    for(unsigned index=0;index<3;++index)CHECK(fcntl(special->pipes[index][index?1:0],F_GETFL)&O_NONBLOCK,"failed cwd restores nonblocking status");
    special->attr.currentDirectory=BASE;special->secrets[0].md.osfd=1024;
    CHECK(_MD_alix_spawn(&special->pid,test->executable,special->arguments,NULL,&special->attr)==EBADF && special->pid==-777,"invalid redirected descriptor");release(special);
    for(unsigned cpu=0;cpu<8;++cpu){job_t *job=&test->jobs[cpu];job->fixture=test;job->cpu=cpu;CHECK(!pthread_create(&job->thread,NULL,worker,job),"create pinned NSPR launcher");}
    uint64_t deadline=sys_monotonic_millis()+5000;
    while(__atomic_load_n(&test->ready,__ATOMIC_ACQUIRE)!=8 && sys_monotonic_millis()<deadline)sys_yield();
    CHECK(__atomic_load_n(&test->ready,__ATOMIC_ACQUIRE)==8,"launchers ready");__atomic_store_n(&test->start,1u,__ATOMIC_RELEASE);
    for(unsigned cpu=0;cpu<8;++cpu){CHECK(!pthread_join(test->jobs[cpu].thread,NULL),"join NSPR launcher");if(test->jobs[cpu].failed){serial_printf("NSPR_SPAWN_TEST: FAIL cpu=%u stage=%u\n",cpu,test->jobs[cpu].failed);return 1;}}
    unsigned count=0;while(count<256){int fd=dup(1);if(fd<0)break;test->pressure[count++]=fd;}
    CHECK(count==253 && errno==EMFILE,"no temporary descriptor leak");for(unsigned index=0;index<count;++index)CHECK(!close(test->pressure[index]),"release descriptor pressure");
    serial_printf("NSPR_SPAWN_TEST: PASS cpus=8 children=25 stdio=1 crossed=1 cloexec=1 environment=1 cwd=1 before_main=1 failure_restore=1 no_fd_leak=1\n");
    free(startup_cwd);free(startup_value);free(startup_inherit);free(test);return 0;
}
