#include "spawn.h"
#include "unistd.h"
#include "fcntl.h"
#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "pthread.h"
#include "sys/stat.h"
#include "sys/wait.h"
#include "serial.h"
#include "usyscall.h"
#include "errno.h"

#define BASE "/tmp/spawn-cwd-actions"
#define CHECK(c,label) do {if(!(c)){serial_printf("SPAWN_CWD_TEST: FAIL %s line=%u errno=%d\n",label,__LINE__,errno);return 1;}}while(0)
static char *startup_cwd;
__attribute__((constructor)) static void capture_startup_cwd(void) { startup_cwd=getcwd(NULL,0); }
typedef struct fixture fixture_t;
typedef struct {
    fixture_t *fixture;
    pthread_t thread;
    unsigned cpu,failed;
    posix_spawn_file_actions_t actions;
    pid_t pid;
    int status;
    char directory[128],expected[144],path_copy[128],observed[144];
    char before[32],after[32],path[192],data[8];
    char *arguments[4],*environment[1];
} job_t;
struct fixture {
    job_t jobs[8];
    unsigned ready,start;
    posix_spawn_file_actions_t actions;
    pid_t pid;
    int status;
    char executable[4096],observed[128];
    char *arguments[3],*environment[1];
};
static int run_child(int argc,char **argv)
{
    char *cwd=getcwd(NULL,0);
    CHECK(argc==3 && cwd && startup_cwd && !strcmp(cwd,argv[2]) && !strcmp(startup_cwd,argv[2]),"child cwd before main");
    CHECK(write(10,"before",6)==6 && write(11,"after",5)==5,"ordered relative open actions");
    free(cwd);free(startup_cwd);return 23;
}
static bool read_file(job_t *job,const char *path,const char *expected,size_t bytes)
{
    int fd=open(path,O_RDONLY|O_CLOEXEC);if(fd<0)return false;
    ssize_t got=read(fd,job->data,sizeof(job->data));int closed=close(fd);
    return got==(ssize_t)bytes && !memcmp(job->data,expected,bytes) && !closed;
}
static void *worker(void *opaque)
{
    job_t *job=opaque;fixture_t *test=job->fixture;
    if(sys_thread_set_affinity(job->cpu) || sys_thread_cpu()!=job->cpu)job->failed=1;
    __atomic_add_fetch(&test->ready,1u,__ATOMIC_RELEASE);
    while(!__atomic_load_n(&test->start,__ATOMIC_ACQUIRE))sys_yield();
    for(unsigned round=0;round<3 && !job->failed;++round)
    {
        strcpy(job->path_copy,job->directory);
        snprintf(job->before,sizeof(job->before),"before-%u",round);snprintf(job->after,sizeof(job->after),"after-%u",round);
        errno=EDOM;
        if(posix_spawn_file_actions_init(&job->actions) ||
            posix_spawn_file_actions_addchdir_np(&job->actions,job->path_copy) ||
            posix_spawn_file_actions_addopen(&job->actions,10,job->before,O_WRONLY|O_CREAT|O_EXCL,0600) ||
            posix_spawn_file_actions_addchdir_np(&job->actions,"nested") ||
            posix_spawn_file_actions_addopen(&job->actions,11,job->after,O_WRONLY|O_CREAT|O_EXCL,0600))job->failed=2;
        job->path_copy[0]=0; /* addchdir owns an independent copy. */
        if(job->failed)break;
        int error=round==2 ? posix_spawnp(&job->pid,"test.elf",&job->actions,NULL,job->arguments,job->environment) :
            posix_spawn(&job->pid,round==1?"../../../test.elf":test->executable,&job->actions,NULL,job->arguments,job->environment);
        if(error || errno!=EDOM || waitpid(job->pid,&job->status,0)!=job->pid || !WIFEXITED(job->status) || WEXITSTATUS(job->status)!=23)job->failed=3;
        if(posix_spawn_file_actions_destroy(&job->actions) || !getcwd(job->observed,sizeof(job->observed)) || strcmp(job->observed,BASE))job->failed=4;
        snprintf(job->path,sizeof(job->path),"%s/%s",job->directory,job->before);
        if(!read_file(job,job->path,"before",6))job->failed=5;
        snprintf(job->path,sizeof(job->path),"%s/%s",job->expected,job->after);
        if(!read_file(job,job->path,"after",5))job->failed=6;
    }
    return NULL;
}
int main(int argc,char **argv)
{
    if(argc>1)return run_child(argc,argv);
    fixture_t *test=calloc(1,sizeof(*test));CHECK(test && startup_cwd,"owned fixture and constructor cwd");
    CHECK(alix_get_executable_path(test->executable,sizeof(test->executable))>0 && !mkdir(BASE,0700) && !chdir(BASE),"parent cwd setup");
    CHECK(!setenv("PATH","../../..:/spawn-cwd-missing",1),"relative PATH setup");
    for(unsigned cpu=0;cpu<8;++cpu)
    {
        job_t *job=&test->jobs[cpu];job->fixture=test;job->cpu=cpu;
        snprintf(job->directory,sizeof(job->directory),BASE "/worker%u",cpu);
        snprintf(job->expected,sizeof(job->expected),"%s/nested",job->directory);
        CHECK(!mkdir(job->directory,0700) && !mkdir(job->expected,0700),"worker directories");
        job->arguments[0]=test->executable;job->arguments[1]="child";job->arguments[2]=job->expected;
        CHECK(!pthread_create(&job->thread,NULL,worker,job),"start pinned spawn worker");
    }
    uint64_t deadline=sys_monotonic_millis()+5000;
    while(__atomic_load_n(&test->ready,__ATOMIC_ACQUIRE)!=8 && sys_monotonic_millis()<deadline)sys_yield();
    CHECK(__atomic_load_n(&test->ready,__ATOMIC_ACQUIRE)==8,"spawn worker readiness");__atomic_store_n(&test->start,1u,__ATOMIC_RELEASE);
    for(unsigned cpu=0;cpu<8;++cpu)
    {
        CHECK(!pthread_join(test->jobs[cpu].thread,NULL),"join spawn worker");
        if(test->jobs[cpu].failed){serial_printf("SPAWN_CWD_TEST: FAIL cpu=%u stage=%u\n",cpu,test->jobs[cpu].failed);return 1;}
    }
    CHECK(getcwd(test->observed,sizeof(test->observed)) && !strcmp(test->observed,BASE),"parent cwd unchanged");
    CHECK(!posix_spawn_file_actions_init(&test->actions) && posix_spawn_file_actions_addchdir_np(&test->actions,NULL)==EINVAL,"null directory action");
    CHECK(!posix_spawn_file_actions_addchdir_np(&test->actions,"/spawn-cwd-missing"),"missing directory action");
    test->arguments[0]=test->executable;test->pid=-77;errno=EDOM;
    CHECK(posix_spawn(&test->pid,test->executable,&test->actions,NULL,test->arguments,test->environment)==ENOENT && test->pid==-77 && errno==EDOM && !posix_spawn_file_actions_destroy(&test->actions),"missing cwd failure preserves pid and errno");
    int fd=open("not-a-directory",O_CREAT|O_EXCL|O_WRONLY, 0666);CHECK(fd>=0 && !close(fd),"non-directory fixture");
    CHECK(!posix_spawn_file_actions_init(&test->actions) && !posix_spawn_file_actions_addchdir_np(&test->actions,"not-a-directory") &&
        posix_spawn(&test->pid,test->executable,&test->actions,NULL,test->arguments,test->environment)==ENOTDIR && test->pid==-77 &&
        !posix_spawn_file_actions_destroy(&test->actions),"non-directory cwd rejection");
    CHECK(getcwd(test->observed,sizeof(test->observed)) && !strcmp(test->observed,BASE) && !chdir(startup_cwd),"failure leaves parent cwd intact");
    serial_printf("SPAWN_CWD_TEST: PASS cpus=8 children=24 ordered=1 parent_unchanged=1 owned_paths=1 relative_exec=1 PATH=1 before_main=1 failures=1\n");
    free(startup_cwd);free(test);return 0;
}
