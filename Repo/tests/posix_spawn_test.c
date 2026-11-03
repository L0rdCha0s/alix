#include "spawn.h"
#include "alix_process.h"
#include "unistd.h"
#include "sys/wait.h"
#include "sys/stat.h"
#include "fcntl.h"
#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "errno.h"
#include "usyscall.h"
#include "serial.h"

#define CHECK(c,label) do{if(!(c)){serial_printf("POSIX_SPAWN_TEST: FAIL %s errno=%d\n",label,errno);return 1;}}while(0)
#define ENV_VALUE "value with = and \xc3\xa9"
static int environment_before_main;
__attribute__((constructor)) static void check_constructor_environment(void)
{
    const char *value=getenv("SPAWN_ENV_TEST");
    environment_before_main=value&&!strcmp(value,ENV_VALUE);
}
static void parent_handler(int number){(void)number;}

static int child(const char *mode)
{
    if (!strcmp(mode, "default"))
    {
        for (int fd = 0; fd < 256; ++fd)
            CHECK(fd == 41 ? fcntl(fd, F_GETFD) == 0 : fcntl(fd, F_GETFD) == -1 && errno == EBADF,
                  "default CLOEXEC retains only explicit action");
        CHECK(write(41, "DEFAULT", 7) == 7, "default action source retained before filtering");
        return 29;
    }
    struct sigaction *action=calloc(1,sizeof(*action));sigset_t *mask=calloc(1,sizeof(*mask));
    CHECK(action&&mask,"child signal heap");
    CHECK(sigprocmask(SIG_SETMASK,NULL,mask)==0,"child mask query");
    if(!strcmp(mode,"actions"))
    {
        CHECK(environment_before_main&&getenv("EMPTY")&&!getenv("EMPTY")[0]&&!getenv("PARENT_ONLY")&&
              !strcmp(getenv("DUP"),"first"),"environment before constructors and exact values");
        CHECK(sigismember(mask,SIGHUP)==1&&sigismember(mask,SIGKILL)==0&&sigismember(mask,SIGUSR2)==0,"spawn mask override");
        CHECK(sigaction(SIGUSR1,NULL,action)==0&&action->sa_handler==SIG_DFL,"spawn default override");
        CHECK(sigaction(SIGUSR2,NULL,action)==0&&action->sa_handler==SIG_DFL,"caught disposition reset");
        CHECK(fcntl(3,F_GETFD)==-1&&errno==EBADF&&fcntl(9,F_GETFD)==0&&fcntl(4,F_GETFD)==0,"actions before CLOEXEC filtering and self dup");
        CHECK(fcntl(11,F_GETFD)==-1&&errno==EBADF,"OPEN preserves requested CLOEXEC");
        char *bytes=malloc(16);CHECK(bytes,"child read heap");
        CHECK(read(9,bytes,2)==2&&!memcmp(bytes,"ab",2)&&write(10,"ACTIONS",7)==7,"duplicate and relative exclusive open");
        CHECK(fputs("POSIX_CHILD_OUTPUT\n",stdout)>=0&&fflush(stdout)==0,"redirected child stdout");
        free(bytes);free(mask);free(action);return 23;
    }
    CHECK(sigismember(mask,SIGUSR2)==1&&sigismember(mask,SIGTERM)==1,"caller signal mask inherited");
    CHECK(sigaction(SIGUSR1,NULL,action)==0&&action->sa_handler==SIG_IGN,"ignored disposition inherited");
    CHECK(sigaction(SIGUSR2,NULL,action)==0&&action->sa_handler==SIG_DFL,"caught disposition defaults after exec");
    if(!strcmp(mode,"inherit"))CHECK(environment_before_main&&getenv("PARENT_ONLY"),"copied current environment");
    else CHECK(!environment_before_main&&!getenv("PARENT_ONLY"),"explicit empty environment");
    free(mask);free(action);return 17;
}

int main(int argc,char **argv)
{
    if(argc>1)return child(argv[1]);
    posix_spawn_file_actions_t *actions=malloc(sizeof(*actions));posix_spawnattr_t *attributes=malloc(sizeof(*attributes));
    char **arguments=calloc(3,sizeof(*arguments)),**environment=calloc(6,sizeof(*environment));
    char *buffer=malloc(4096),*cwd=getcwd(NULL,0);int *pipes=calloc(2,sizeof(*pipes)),*status=malloc(sizeof(*status));
    sigset_t *mask=calloc(1,sizeof(*mask)),*defaults=calloc(1,sizeof(*defaults)),*oldmask=calloc(1,sizeof(*oldmask));
    struct stat *metadata=malloc(sizeof(*metadata));
    CHECK(actions&&attributes&&arguments&&environment&&buffer&&cwd&&pipes&&status&&mask&&defaults&&oldmask&&metadata,"parent heap");
    CHECK(setenv("PARENT_ONLY","parent",1)==0&&setenv("SPAWN_ENV_TEST",ENV_VALUE,1)==0&&setenv("PATH","/spawn-missing:/tmp",1)==0,"parent environment");
    CHECK(signal(SIGUSR1,SIG_IGN)!=SIG_ERR&&signal(SIGUSR2,parent_handler)!=SIG_ERR,"parent dispositions");
    CHECK(sigemptyset(mask)==0&&sigaddset(mask,SIGUSR2)==0&&sigaddset(mask,SIGTERM)==0&&sigprocmask(SIG_BLOCK,mask,oldmask)==0,"parent blocked signals");
    CHECK(sys_mkdir("/tmp/spawn-actions-cwd")==0&&chdir("/tmp/spawn-actions-cwd")==0,"file action cwd");
    int source=open("source",O_RDWR|O_CREAT|O_TRUNC|O_CLOEXEC, 0666),self=open("self",O_RDWR|O_CREAT|O_TRUNC|O_CLOEXEC, 0666);
    CHECK(source==3&&self==4&&write(source,"abcdef",6)==6&&lseek(source,0,SEEK_SET)==0,"CLOEXEC sources");
    CHECK(pipe2(pipes,O_CLOEXEC)==0&&pipes[0]==5&&pipes[1]==6,"CLOEXEC transport");
    CHECK(!posix_spawn_file_actions_init(actions)&&!posix_spawnattr_init(attributes),"spawn object init");
    CHECK(!posix_spawn_file_actions_adddup2(actions,3,9)&&!posix_spawn_file_actions_addclose(actions,3)&&
          !posix_spawn_file_actions_adddup2(actions,4,4)&&!posix_spawn_file_actions_adddup2(actions,6,1)&&
          !posix_spawn_file_actions_addclose(actions,50),"ordered descriptor actions");
    CHECK(!posix_spawn_file_actions_addopen(actions,10,"spawn-exclusive",O_WRONLY|O_CREAT|O_EXCL,0600)&&
          !posix_spawn_file_actions_addopen(actions,11,"spawn-closed",O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC,0600),"relative open actions");
    CHECK(!sigemptyset(mask)&&!sigaddset(mask,SIGHUP)&&!sigaddset(mask,SIGKILL)&&
          !sigemptyset(defaults)&&!sigaddset(defaults,SIGUSR1),"child signal sets");
    CHECK(!posix_spawnattr_setsigmask(attributes,mask)&&!posix_spawnattr_setsigdefault(attributes,defaults)&&
          !posix_spawnattr_setflags(attributes,POSIX_SPAWN_SETSIGMASK|POSIX_SPAWN_SETSIGDEF|POSIX_SPAWN_RESETIDS),"spawn attributes");
    arguments[0]="test.elf";arguments[1]="actions";
    environment[0]="SPAWN_ENV_TEST=" ENV_VALUE;environment[1]="EMPTY=";environment[2]="PATH=/not-the-parent-path";
    environment[3]="DUP=first";environment[4]="DUP=second";
    pid_t pid=-123;errno=EDOM;
    CHECK(posix_spawnp(&pid,"test.elf",actions,attributes,arguments,environment)==0&&pid>0&&errno==EDOM,"PATH search with one set of file actions");
    CHECK(close(6)==0,"parent transport writer close");
    size_t received=0;const char *expected="POSIX_CHILD_OUTPUT\n";
    while(received<strlen(expected)){ssize_t bytes=read(5,buffer+received,strlen(expected)-received);CHECK(bytes>0,"child stdout read");received+=(size_t)bytes;}
    CHECK(!memcmp(buffer,expected,received)&&read(5,buffer,1)==0&&close(5)==0,"redirected output and EOF");
    CHECK(waitpid(pid,status,0)==pid&&WIFEXITED(*status)&&WEXITSTATUS(*status)==23,"spawned child status");
    CHECK(read(source,buffer,2)==2&&!memcmp(buffer,"cd",2)&&fcntl(source,F_GETFD)==FD_CLOEXEC&&
          fcntl(self,F_GETFD)==FD_CLOEXEC&&fcntl(9,F_GETFD)==-1&&errno==EBADF,"parent descriptors untouched");
    CHECK(stat("spawn-exclusive",metadata)==0&&metadata->st_size==7&&stat("spawn-closed",metadata)==0,"file actions applied once");
    CHECK(close(source)==0&&close(self)==0&&!posix_spawn_file_actions_destroy(actions)&&!posix_spawnattr_destroy(attributes),"spawn objects cleanup");
    arguments[1]="inherit";char **snapshot=alix_environment_copy();CHECK(snapshot,"environment snapshot");
    CHECK(!posix_spawn(&pid,"/tmp/test.elf",NULL,NULL,arguments,snapshot)&&waitpid(pid,status,0)==pid&&WEXITSTATUS(*status)==17,"environment/signal inheritance");
    alix_environment_free(snapshot);arguments[1]="empty";
    CHECK(!posix_spawn(&pid,"/tmp/test.elf",NULL,NULL,arguments,NULL)&&waitpid(pid,status,0)==pid&&WEXITSTATUS(*status)==17,"empty environment");
    CHECK(!posix_spawnattr_init(attributes)&&!posix_spawnattr_setflags(attributes,POSIX_SPAWN_SETPGROUP),"unsupported group request");
    pid=-123;errno=E2BIG;CHECK(posix_spawn(&pid,"/tmp/test.elf",NULL,attributes,arguments,NULL)==ENOTSUP&&pid==-123&&errno==E2BIG,"unsupported capability reports error");
    CHECK(!posix_spawnattr_destroy(attributes)&&!posix_spawn_file_actions_init(actions)&&
          !posix_spawn_file_actions_adddup2(actions,99,0),"invalid source action");
    pid=-123;CHECK(posix_spawn(&pid,"/tmp/test.elf",actions,NULL,arguments,NULL)==EBADF&&pid==-123,"bad action does not publish child");
    CHECK(waitpid(-1,NULL,WNOHANG)==-1&&errno==ECHILD,"no failed-spawn child");
    CHECK(!posix_spawn_file_actions_destroy(actions)&&sigprocmask(SIG_SETMASK,oldmask,NULL)==0&&chdir(cwd)==0,"restore parent state");
    source = open("/tmp/spawn-default", O_RDWR | O_CREAT | O_TRUNC, 0666);
    CHECK(source >= 3 && !fcntl(source, F_SETFD, 0), "ordinary non-CLOEXEC parent source");
    CHECK(!posix_spawn_file_actions_init(actions) && !posix_spawnattr_init(attributes) &&
          !posix_spawnattr_setflags(attributes, POSIX_SPAWN_CLOEXEC_DEFAULT) &&
          !posix_spawn_file_actions_adddup2(actions, source, 41), "default CLOEXEC setup");
    arguments[1] = "default"; errno = EDOM;
    CHECK(!posix_spawn(&pid, "/tmp/test.elf", actions, attributes, arguments, NULL) && errno == EDOM &&
          waitpid(pid, status, 0) == pid && WEXITSTATUS(*status) == 29, "native close-default launch");
    CHECK(fcntl(source, F_GETFD) == 0 && !lseek(source, 0, SEEK_SET) &&
          read(source, buffer, 7) == 7 && !memcmp(buffer, "DEFAULT", 7) &&
          fcntl(0, F_GETFD) == 0 && fcntl(1, F_GETFD) == 0 && fcntl(2, F_GETFD) == 0,
          "close-default leaves parent snapshot untouched");
    CHECK(!close(source) && !posix_spawn_file_actions_destroy(actions) &&
          !posix_spawnattr_destroy(attributes), "default CLOEXEC cleanup");
    serial_printf("POSIX_SPAWN_DEFAULT: PASS child_snapshot=1 source_before_filter=1 parent_untouched=1\n");
    free(metadata);free(oldmask);free(defaults);free(mask);free(status);free(pipes);free(cwd);free(buffer);free(environment);free(arguments);free(attributes);free(actions);
    serial_printf("POSIX_SPAWN_TEST: PASS environment_before_main=1 actions=1 cloexec_order=1 self_dup=1 PATH=1 signals=1 errors=1\n");
    return 0;
}
