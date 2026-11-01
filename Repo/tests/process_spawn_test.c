#include "alix_process.h"
#include "unistd.h"
#include "sys/wait.h"
#include "sys/mman.h"
#include "fcntl.h"
#include "pthread.h"
#include "stdlib.h"
#include "stdio.h"
#include "string.h"
#include "signal.h"
#include "errno.h"
#include "usyscall.h"
#include "serial.h"

#define CHECK(c,label) do {if(!(c)){serial_printf("PROCESS_SPAWN_TEST: FAIL %s errno=%d\n",label,errno);return 1;}}while(0)
#define PROGRAM "/tmp/test.elf"
typedef struct {pthread_t thread;pid_t pid,result;int status,error;unsigned cpu;} waiter_t;

static void *waiter(void *argument)
{
    waiter_t *work=argument;
    if(sys_thread_set_affinity(work->cpu)||sys_thread_cpu()!=work->cpu){work->error=EIO;return NULL;}
    work->status=0x5a5a5a5a;
    work->result=waitpid(work->pid,&work->status,0);
    if(work->result<0)work->error=errno;
    return NULL;
}

static int child(int argc,char **argv)
{
    if(!strcmp(argv[1],"check"))
    {
        char *buffer=malloc(4096);CHECK(buffer,"child heap");
        CHECK(argc==3&&!strcmp(argv[2],"space and \xc3\xa9"),"copied argv bytes");
        CHECK(getcwd(buffer,4096)&&!strcmp(buffer,"/tmp/process-native-cwd"),"captured child cwd");
        CHECK(read(3,buffer,2)==2&&!memcmp(buffer,"ab",2),"shared open description");
        CHECK(fcntl(4,F_GETFD)==-1&&errno==EBADF&&fcntl(5,F_GETFD)==-1&&errno==EBADF,"CLOEXEC filtering");
        CHECK(fcntl(3,F_SETFD,FD_CLOEXEC)==0,"independent child descriptor flags");
        CHECK(chdir("/")==0&&write(6,"CHILD",5)==5,"child pipe and independent cwd");
        /* Exit deliberately leaves writer 6 open. The kernel must close it
         * without waiting for the parent's later waitpid call. */
        free(buffer);return 37;
    }
    if(!strcmp(argv[1],"slow")){sys_sleep_ms(1000);return 5;}
    if(!strcmp(argv[1],"signal")){raise(SIGPIPE);return 1;}
    if(!strcmp(argv[1],"exit"))return argc>2?atoi(argv[2]):0;
    if(!strcmp(argv[1],"orphan")){sys_sleep_ms(500);CHECK(argc>2&&write(atoi(argv[2]),"ORPHAN",6)==6,"orphan output");return 0;}
    if(!strcmp(argv[1],"orphan-parent")||!strcmp(argv[1],"wait-parent"))
    {
        char **arguments=calloc(4,sizeof(*arguments));int *status=malloc(sizeof(*status));CHECK(arguments&&status,"orphan argv");
        arguments[0]=PROGRAM;arguments[1]="orphan";arguments[2]=argv[2];
        pid_t descendant=alix_spawn_argv(PROGRAM,arguments);CHECK(descendant>0,"grandchild creation");
        if(!strcmp(argv[1],"wait-parent"))
        {
            CHECK(write(atoi(argv[2]),"WAITING",7)==7,"waiting owner marker");
            (void)waitpid(descendant,status,0);
            CHECK(0,"killed wait owner resumed");
        }
        free(status);free(arguments);return 0;
    }
    CHECK(0,"unknown child mode");
}

int main(int argc,char **argv)
{
    if(argc>1)return child(argc,argv);
    char **arguments=calloc(4,sizeof(*arguments));char *buffer=malloc(4096),*original=getcwd(NULL,0);
    int *pipes=calloc(2,sizeof(*pipes)),*status=malloc(sizeof(*status));
    CHECK(arguments&&buffer&&original&&pipes&&status,"parent heap");
    arguments[0]=PROGRAM;arguments[1]="check";arguments[2]="space and \xc3\xa9";
    CHECK(sys_mkdir("/tmp/process-native-cwd")==0&&chdir("/tmp/process-native-cwd")==0,"parent cwd");
    int shared=open("shared",O_RDWR|O_CREAT|O_TRUNC);
    int hidden=open("hidden",O_RDWR|O_CREAT|O_TRUNC|O_CLOEXEC);
    CHECK(shared==3&&hidden==4&&write(shared,"abcdef",6)==6&&lseek(shared,0,SEEK_SET)==0,"inheritance files");
    CHECK(pipe(pipes)==0&&pipes[0]==5&&pipes[1]==6&&fcntl(5,F_SETFD,FD_CLOEXEC)==0,"inheritance pipe");
    pid_t pid=alix_spawn_argv(PROGRAM,arguments);CHECK(pid>0,"native user child");
    CHECK(close(pipes[1])==0&&read(pipes[0],buffer,5)==5&&!memcmp(buffer,"CHILD",5),"child output");
    CHECK(read(pipes[0],buffer,1)==0,"pipe EOF before reaping child");
    CHECK(read(shared,buffer,2)==2&&!memcmp(buffer,"cd",2)&&fcntl(shared,F_GETFD)==0,"shared offset and independent flags");
    CHECK(getcwd(buffer,4096)&&!strcmp(buffer,"/tmp/process-native-cwd"),"child chdir preserves parent cwd");
    CHECK(waitpid(pid,status,0)==pid&&WIFEXITED(*status)&&WEXITSTATUS(*status)==37,"child exit status");
    *status=0x5a5a5a5a;CHECK(waitpid(pid,status,0)==-1&&errno==ECHILD&&*status==0x5a5a5a5a,"exactly one reap");
    CHECK(close(pipes[0])==0&&close(shared)==0&&close(hidden)==0&&chdir(original)==0,"release inheritance state");
    arguments[1]="slow";arguments[2]=NULL;
    pid=alix_spawn_argv(PROGRAM,arguments);CHECK(pid>0,"slow child");
    *status=0x5a5a5a5a;CHECK(waitpid(pid,status,WNOHANG)==0&&*status==0x5a5a5a5a,"WNOHANG preserves output");
    CHECK(waitpid(pid,(int*)1,0)==-1&&errno==EFAULT,"invalid wait output");
    CHECK(waitpid(pid,status,0)==pid&&WIFEXITED(*status)&&WEXITSTATUS(*status)==5,"blocking wait");
    arguments[1]="exit";arguments[2]="91";
    pid=alix_spawn_argv(PROGRAM,arguments);CHECK(pid>0,"copyout child");
    void *readonly=mmap(NULL,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    CHECK(readonly!=MAP_FAILED&&mprotect(readonly,4096,PROT_READ)==0,"protected result mapping");
    CHECK(waitpid(pid,readonly,0)==-1&&errno==EFAULT,"failed status copy does not reap");
    CHECK(waitpid(pid,status,0)==pid&&WEXITSTATUS(*status)==91&&munmap(readonly,4096)==0,"claim rollback after copy failure");
    arguments[2]="141";pid=alix_spawn_argv(PROGRAM,arguments);
    CHECK(pid>0&&waitpid(pid,status,0)==pid&&WIFEXITED(*status)&&WEXITSTATUS(*status)==141,"normal exit 141");
    arguments[1]="signal";arguments[2]=NULL;pid=alix_spawn_argv(PROGRAM,arguments);
    CHECK(pid>0&&waitpid(pid,status,0)==pid&&WIFSIGNALED(*status)&&WTERMSIG(*status)==SIGPIPE,"signal termination 13");
    arguments[1]="exit";arguments[2]="7";pid_t first=alix_spawn_argv(PROGRAM,arguments);
    arguments[2]="9";pid_t second=alix_spawn_argv(PROGRAM,arguments);CHECK(first>0&&second>0&&first!=second,"two children");
    pid_t found=waitpid(-1,status,0);CHECK((found==first&&WEXITSTATUS(*status)==7)||(found==second&&WEXITSTATUS(*status)==9),"wait any first");
    pid_t next=waitpid(-1,status,0);CHECK(next!=found&&((next==first&&WEXITSTATUS(*status)==7)||(next==second&&WEXITSTATUS(*status)==9)),"wait any second");
    arguments[1]="slow";arguments[2]=NULL;pid=alix_spawn_argv(PROGRAM,arguments);CHECK(pid>0,"shared wait child");
    waiter_t *waiters=calloc(8,sizeof(*waiters));CHECK(waiters,"waiter heap");
    for(unsigned index=0;index<8;++index){waiters[index].pid=pid;waiters[index].cpu=index;CHECK(!pthread_create(&waiters[index].thread,NULL,waiter,&waiters[index]),"create waiter");}
    unsigned winners=0,losers=0;
    for(unsigned index=0;index<8;++index){CHECK(!pthread_join(waiters[index].thread,NULL),"join waiter");
        if(waiters[index].result==pid&&WEXITSTATUS(waiters[index].status)==5)++winners;
        else if(waiters[index].result==-1&&waiters[index].error==ECHILD&&waiters[index].status==0x5a5a5a5a)++losers;}
    CHECK(winners==1&&losers==7,"eight-CPU exactly once wait");free(waiters);
    arguments[1]="exit";arguments[2]="0";
    CHECK(alix_spawn_argv("/tmp/native-spawn-missing",arguments)==-1&&errno==ENOENT,"failed launch");
    CHECK(waitpid(-1,status,WNOHANG)==-1&&errno==ECHILD,"failed launch leaves no child");
    CHECK(sys_process(SYSCALL_PROCESS_SPAWN,(uintptr_t)PROGRAM,1,0)==-EFAULT,"bad argv copy");
    CHECK(waitpid(-1,status,WNOHANG)==-1&&errno==ECHILD,"bad argv leaves no reservation");
    /* Keep only the write end in a descendant, then reap its parent first. */
    CHECK(pipe(pipes)==0&&pipes[0]==3&&pipes[1]==4&&
          fcntl(3,F_SETFD,FD_CLOEXEC)==0,"orphan pipe");
    arguments[1]="orphan-parent";arguments[2]="4";
    pid=alix_spawn_argv(PROGRAM,arguments);CHECK(pid>0&&close(4)==0&&waitpid(pid,status,0)==pid&&WEXITSTATUS(*status)==0,"reap parent before descendant");
    CHECK(read(3,buffer,6)==6&&!memcmp(buffer,"ORPHAN",6)&&read(3,buffer,1)==0&&close(3)==0,"orphan survives parent teardown");
    CHECK(pipe(pipes)==0&&pipes[0]==3&&pipes[1]==4&&fcntl(3,F_SETFD,FD_CLOEXEC)==0,"killed wait owner pipe");
    arguments[1]="wait-parent";pid=alix_spawn_argv(PROGRAM,arguments);
    CHECK(pid>0&&close(4)==0&&read(3,buffer,7)==7&&!memcmp(buffer,"WAITING",7),"owner entered wait");
    sys_sleep_ms(30);
    syscall_process_info_t *snapshot=calloc(256,sizeof(*snapshot));CHECK(snapshot,"process snapshot heap");
    bool blocked=false;
    for(unsigned attempt=0;attempt<20&&!blocked;++attempt)
    {
        ssize_t count=sys_proc_snapshot(snapshot,256);CHECK(count>=0&&count<=256,"waiting owner snapshot");
        for(ssize_t index=0;index<count;++index)
            if(snapshot[index].pid==(uint64_t)pid&&snapshot[index].thread_state==SYSCALL_THREAD_STATE_BLOCKED)blocked=true;
        if(!blocked)sys_sleep_ms(1);
    }
    free(snapshot);CHECK(blocked,"owner is blocked before kill");
    CHECK(kill(pid,SIGKILL)==0&&waitpid(pid,status,0)==pid&&WIFSIGNALED(*status)&&WTERMSIG(*status)==SIGKILL,"kill blocked wait owner");
    CHECK(read(3,buffer,6)==6&&!memcmp(buffer,"ORPHAN",6)&&read(3,buffer,1)==0&&close(3)==0,"abandoned wait leaves live orphan and safe EOF");
    free(status);free(pipes);free(original);free(buffer);free(arguments);
    serial_printf("PROCESS_SPAWN_TEST: PASS private_inherit=1 argv=1 cwd=1 EOF_before_wait=1 status=1 WNOHANG=1 copy_rollback=1 waiters=8 orphan=1 killed_waiter=1\n");
    return 0;
}
