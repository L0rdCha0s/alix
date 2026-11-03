#include "signal.h"
#include "pthread.h"
#include "usyscall.h"
#include "unistd.h"
#include "stdlib.h"
#include "string.h"
#include "stdio.h"
#include "errno.h"
#include "sys/mman.h"
#include "sys/wait.h"
#include "spawn.h"
#include "fcntl.h"
#include "serial.h"

#define CHECK(c,label) do {if(!(c)){serial_printf("SIGWAIT_TEST: FAIL %s line=%u errno=%d\n",label,__LINE__,errno);return 1;}}while(0)
typedef struct fixture fixture_t;
typedef struct {
    fixture_t *fixture;
    pthread_t thread;
    unsigned cpu,kind,failed,received;
    uint32_t before;
    int number;
    uint32_t after;
    sigset_t mask;
} job_t;
struct fixture {
    job_t jobs[8];
    sigset_t set,old,other,pending,mask;
    struct sigaction action,observed;
    unsigned ready,start,finished,caught,user_handlers,nested_entered,nested_done;
    int number,nested_number,nested_error,status,pipes[2];
    pid_t child;
    posix_spawn_file_actions_t actions;
    char executable[4096],bytes[16];
    char *arguments[3],*environment[1];
};
static fixture_t *active;
static void wanted_handler(int number){(void)number;__atomic_add_fetch(&active->user_handlers,1u,__ATOMIC_RELAXED);}
static void other_handler(int number){(void)number;__atomic_add_fetch(&active->caught,1u,__ATOMIC_RELEASE);errno=EIO;}
static void nested_handler(int number)
{
    (void)number;int saved=errno;
    __atomic_store_n(&active->nested_entered,1u,__ATOMIC_RELEASE);
    active->nested_error=sigwait(&active->set,&active->nested_number);
    __atomic_store_n(&active->nested_done,1u,__ATOMIC_RELEASE);errno=saved;
}
static bool until(unsigned *value,unsigned expected)
{
    uint64_t deadline=sys_monotonic_millis()+5000;
    while(__atomic_load_n(value,__ATOMIC_ACQUIRE)!=expected && sys_monotonic_millis()<deadline)sys_yield();
    return __atomic_load_n(value,__ATOMIC_ACQUIRE)==expected;
}
static void *waiter(void *opaque)
{
    job_t *job=opaque;fixture_t *test=job->fixture;
    if(sys_thread_set_affinity(job->cpu) || sys_thread_cpu()!=job->cpu)job->failed=1;
    if(job->kind==3 && pthread_sigmask(SIG_UNBLOCK,&test->set,NULL))job->failed=2;
    __atomic_add_fetch(&test->ready,1u,__ATOMIC_RELEASE);
    while(!__atomic_load_n(&test->start,__ATOMIC_ACQUIRE))sys_yield();
    if(job->kind==3)
    {
        while(!__atomic_load_n(&test->nested_done,__ATOMIC_ACQUIRE))sys_yield();
        if(pthread_sigmask(SIG_SETMASK,NULL,&job->mask) || sigismember(&job->mask,SIGUSR1)!=0)job->failed=3;
        return NULL;
    }
    unsigned rounds=job->kind==0?64:1;
    for(unsigned round=0;round<rounds && !job->failed;++round)
    {
        job->before=0x12345678;job->after=0x87654321;job->number=-1;errno=EDOM;
        int result=sigwait(&test->set,&job->number);
        if(result || job->number!=SIGUSR1 || errno!=EDOM || job->before!=0x12345678 || job->after!=0x87654321)job->failed=4;
        if(pthread_sigmask(SIG_SETMASK,NULL,&job->mask) || sigismember(&job->mask,SIGUSR1)!=1)job->failed=5;
        __atomic_store_n(&job->received,round+1,__ATOMIC_RELEASE);
        if(job->kind==1)__atomic_add_fetch(&test->finished,1u,__ATOMIC_RELEASE);
    }
    return NULL;
}
static int launch(fixture_t *test,unsigned count,unsigned kind)
{
    test->ready=test->start=test->finished=0;
    for(unsigned cpu=0;cpu<count;++cpu)
    {
        job_t *job=&test->jobs[cpu];memset(job,0,sizeof(*job));job->fixture=test;job->cpu=cpu;job->kind=kind;
        CHECK(!pthread_create(&job->thread,NULL,waiter,job),"create pinned signal waiter");
    }
    CHECK(until(&test->ready,count),"signal waiters ready");__atomic_store_n(&test->start,1u,__ATOMIC_RELEASE);return 0;
}
static int join_all(fixture_t *test,unsigned count)
{
    for(unsigned cpu=0;cpu<count;++cpu)
    {
        CHECK(!pthread_join(test->jobs[cpu].thread,NULL),"join signal waiter");
        if(test->jobs[cpu].failed){serial_printf("SIGWAIT_TEST: FAIL cpu=%u kind=%u stage=%u\n",cpu,test->jobs[cpu].kind,test->jobs[cpu].failed);return 1;}
    }
    return 0;
}
int main(int argc,char **argv)
{
    fixture_t *test=calloc(1,sizeof(*test));CHECK(test,"owned fixture");active=test;
    CHECK(!sigemptyset(&test->set) && !sigaddset(&test->set,SIGUSR1),"wait mask");
    test->action=(struct sigaction){.sa_handler=wanted_handler,.sa_flags=SA_RESETHAND};
    CHECK(!sigaction(SIGUSR1,&test->action,NULL) && !pthread_sigmask(SIG_BLOCK,&test->set,&test->old),"block wanted signal");
    if(argc>1 && !strcmp(argv[1],"child-wait"))
    {
        CHECK(write(1,"ready",5)==5,"child waiter readiness");
        (void)sigwait(&test->set,&test->number);return 19;
    }
    errno=EDOM;
    CHECK(!raise(SIGUSR1) && !raise(SIGUSR1) && sigwait(&test->set,(void *)"readonly")==EFAULT && errno==EDOM &&
        !sigpending(&test->pending) && sigismember(&test->pending,SIGUSR1)==1,"failed output preserves queued signal");
    unsigned char *pages=mmap(NULL,8192,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);CHECK(pages!=MAP_FAILED,"cross-page fixture");
    CHECK(!mprotect(pages+4096,4096,PROT_NONE) && sigwait(&test->set,(void *)(pages+4094))==EFAULT &&
        !sigpending(&test->pending) && sigismember(&test->pending,SIGUSR1)==1 && !munmap(pages,8192),"partial output copy does not consume");
    CHECK(sigwait((void *)1,&test->number)==EFAULT && sigwait(NULL,&test->number)==EFAULT &&
        sigwait(&test->set,NULL)==EFAULT && !sigwait(&test->set,&test->number) && test->number==SIGUSR1 &&
        !sigpending(&test->pending) && !sigismember(&test->pending,SIGUSR1),"safe arguments and coalesced delivery");
    CHECK(!sigaction(SIGUSR1,NULL,&test->observed) && test->observed.sa_handler==wanted_handler &&
        (test->observed.sa_flags&SA_RESETHAND),"synchronous acceptance preserves disposition");
    test->other=0;CHECK(sigwait(&test->other,&test->number)==EINVAL,"empty mask rejected");
    test->other=UINT64_C(1)<<63;CHECK(sigwait(&test->other,&test->number)==EINVAL,"unknown mask bits rejected");
    test->other=UINT64_C(1)<<(SIGCONT-1);CHECK(sigwait(&test->other,&test->number)==EINVAL,"unsupported job-control wait rejected");
    test->other=UINT64_C(1)<<(SIGUSR2-1);CHECK(sigwait(&test->other,&test->number)==EINVAL,"unblocked wait mask rejected");
    CHECK(sys_sigwait(&test->set,&test->number,7,0)==-EINVAL && sys_sigwait(&test->set,&test->number,8,1)==-EINVAL,"raw wire fields");
    test->other=test->set|(UINT64_C(1)<<(SIGKILL-1));CHECK(!raise(SIGUSR1) && !sigwait(&test->other,&test->number) && test->number==SIGUSR1,"unblockable signal removed from set");
    test->action.sa_flags=SA_RESTART;CHECK(!sigaction(SIGUSR1,&test->action,NULL),"persistent signal disposition");
    CHECK(!launch(test,8,0),"directed wait launch");
    for(unsigned round=0;round<64;++round)
    {
        for(unsigned cpu=0;cpu<8;++cpu)CHECK(!pthread_kill(test->jobs[cpu].thread,SIGUSR1),"send directed blocked signal");
        for(unsigned cpu=0;cpu<8;++cpu)CHECK(until(&test->jobs[cpu].received,round+1),"directed signal acknowledgement");
    }
    CHECK(!join_all(test,8),"directed wait completion");
    CHECK(!launch(test,8,1),"process-wide wait launch");
    for(unsigned accepted=1;accepted<=8;++accepted)
    {
        CHECK(!kill(getpid(),SIGUSR1) && until(&test->finished,accepted),"one waiter accepts each process signal");
        sys_sleep_ms(1);CHECK(__atomic_load_n(&test->finished,__ATOMIC_ACQUIRE)==accepted,"process signal is not consumed twice");
    }
    CHECK(!join_all(test,8),"process-wide wait completion");
    test->action=(struct sigaction){.sa_handler=other_handler};CHECK(!sigaction(SIGUSR2,&test->action,NULL),"caught outside signal");
    CHECK(!launch(test,1,2) && !pthread_kill(test->jobs[0].thread,SIGUSR2) && until(&test->caught,1) &&
        !pthread_kill(test->jobs[0].thread,SIGUSR1) && !join_all(test,1),"caught-signal delivery retries sigwait without EINTR");
    test->action=(struct sigaction){.sa_handler=nested_handler,.sa_mask=test->set};CHECK(!sigaction(SIGUSR2,&test->action,NULL),"NSPR-style suspension handler");
    CHECK(!launch(test,1,3) && !pthread_kill(test->jobs[0].thread,SIGUSR2) && until(&test->nested_entered,1) &&
        !pthread_kill(test->jobs[0].thread,SIGUSR1) && !join_all(test,1) && !test->nested_error && test->nested_number==SIGUSR1,"sigwait inside masked signal handler");
    CHECK(!pipe2(test->pipes,O_CLOEXEC) && alix_get_executable_path(test->executable,sizeof(test->executable))>0,"killed-waiter fixture");
    CHECK(!posix_spawn_file_actions_init(&test->actions) && !posix_spawn_file_actions_adddup2(&test->actions,test->pipes[1],1),"child readiness action");
    test->arguments[0]=test->executable;test->arguments[1]="child-wait";
    CHECK(!posix_spawn(&test->child,test->executable,&test->actions,NULL,test->arguments,test->environment) &&
        !close(test->pipes[1]) && read(test->pipes[0],test->bytes,5)==5 && !memcmp(test->bytes,"ready",5),"child is entering sigwait");
    sys_sleep_ms(10);CHECK(!kill(test->child,SIGKILL) && waitpid(test->child,&test->status,0)==test->child &&
        WIFSIGNALED(test->status) && WTERMSIG(test->status)==SIGKILL && !close(test->pipes[0]) &&
        !posix_spawn_file_actions_destroy(&test->actions),"killed waiter teardown");
    CHECK(!test->user_handlers && !pthread_sigmask(SIG_SETMASK,&test->old,NULL),"blocked signals never invoked their handler");
    serial_printf("SIGWAIT_TEST: PASS cpus=8 directed=512 process_waiters=8 no_handlers=1 coalescing=1 checked_copy=1 retry=1 nested_handler=1 killed_waiter=1\n");
    free(test);return 0;
}
