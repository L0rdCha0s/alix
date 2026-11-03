#include "fcntl.h"
#include "unistd.h"
#include "sys/wait.h"
#include "sys/mman.h"
#include "sys/stat.h"
#include "sys/time.h"
#include "spawn.h"
#include "pthread.h"
#include "signal.h"
#include "stdlib.h"
#include "string.h"
#include "errno.h"
#include "serial.h"
#include "stdio.h"
#include "usyscall.h"
#define PATH "/tmp/record-lock-file"
#define CHECK(c) do{if(!(c)){serial_printf("RECORD_LOCK_TEST: FAIL line=%u errno=%d\n",__LINE__,errno);return 1;}}while(0)
typedef struct {int command;unsigned ready;struct flock lock;} command_t;
typedef struct {int result,error;struct flock lock;} reply_t;
typedef struct {pid_t pid;int send,receive;int commands[2],replies[2];posix_spawn_file_actions_t actions;char *arguments[3];} child_t;
typedef struct {pthread_t thread;unsigned cpu,failed;int fd,error,result;struct flock lock;} worker_t;
typedef struct {
    child_t children[3];command_t command;reply_t reply;struct flock lock;
    worker_t workers[8];struct stat metadata;struct timeval times[2];int status;
} fixture_t;
static int transfer(int fd,void*bytes,size_t length,bool writing)
{
    size_t done=0;while(done<length){ssize_t n=writing?write(fd,(char*)bytes+done,length-done):read(fd,(char*)bytes+done,length-done);
        if(n<0&&errno==EINTR)continue;if(n<=0)return -1;done+=(size_t)n;}return 0;
}
static int child_main(void)
{
    fixture_t*f=calloc(1,sizeof(*f));CHECK(f);int fd=open(PATH,O_RDWR|O_CLOEXEC);CHECK(fd>=3);
    for(;;){CHECK(!transfer(20,&f->command,sizeof(f->command),false));if(!f->command.command)break;
        if(f->command.ready)CHECK(write(21,"B",1)==1);
        f->reply.lock=f->command.lock;errno=0;
        f->reply.result=fcntl(fd,f->command.command,&f->reply.lock);f->reply.error=errno;
        CHECK(!transfer(21,&f->reply,sizeof(f->reply),true));}
    CHECK(!close(fd));free(f);return 0;
}
static int launch(child_t*c)
{
    CHECK(!pipe2(c->commands,O_CLOEXEC)&&!pipe2(c->replies,O_CLOEXEC));
    CHECK(!posix_spawn_file_actions_init(&c->actions));
    CHECK(!posix_spawn_file_actions_adddup2(&c->actions,c->commands[0],20));
    CHECK(!posix_spawn_file_actions_adddup2(&c->actions,c->replies[1],21));
    c->arguments[0]="/tmp/test.elf";c->arguments[1]="child";
    CHECK(!posix_spawn(&c->pid,c->arguments[0],&c->actions,NULL,c->arguments,NULL));
    CHECK(!posix_spawn_file_actions_destroy(&c->actions)&&!close(c->commands[0])&&!close(c->replies[1]));
    c->send=c->commands[1];c->receive=c->replies[0];return 0;
}
static int remote(fixture_t*f,unsigned child,int command,int type,int64_t start,int64_t length,bool ready)
{
    f->command=(command_t){.command=command,.ready=ready,.lock={.l_start=start,.l_len=length,.l_type=type,.l_whence=SEEK_SET}};
    CHECK(!transfer(f->children[child].send,&f->command,sizeof(f->command),true));
    if(ready){unsigned char*byte=malloc(1);CHECK(byte&&read(f->children[child].receive,byte,1)==1&&*byte=='B');free(byte);}
    else CHECK(!transfer(f->children[child].receive,&f->reply,sizeof(f->reply),false));
    return 0;
}
static int local(fixture_t*f,int fd,int type,int whence,int64_t start,int64_t length)
{f->lock=(struct flock){.l_start=start,.l_len=length,.l_type=type,.l_whence=whence};return fcntl(fd,F_SETLK,&f->lock);}
static int stop_child(fixture_t*f,unsigned child,bool killed)
{
    child_t*c=&f->children[child];
    if(killed)CHECK(!kill(c->pid,SIGKILL));
    else {f->command=(command_t){0};CHECK(!transfer(c->send,&f->command,sizeof(f->command),true));}
    CHECK(waitpid(c->pid,&f->status,0)==c->pid);
    CHECK(killed?(WIFSIGNALED(f->status)&&WTERMSIG(f->status)==SIGKILL):(WIFEXITED(f->status)&&WEXITSTATUS(f->status)==0));
    CHECK(!close(c->send)&&!close(c->receive));return 0;
}
static void *worker(void*argument)
{
    worker_t*w=argument;if(sys_thread_set_affinity(w->cpu)||sys_thread_cpu()!=w->cpu){w->failed=1;return NULL;}
    for(unsigned i=0;i<64;++i){w->lock=(struct flock){.l_start=10000+w->cpu*128,.l_len=64,.l_type=F_WRLCK,.l_whence=SEEK_SET};
        if(fcntl(w->fd,F_SETLK,&w->lock)){w->failed=2;w->error=errno;return NULL;}
        w->result=fcntl(w->fd,F_GETLK,&w->lock);
        if(w->result||w->lock.l_type!=F_UNLCK){w->failed=3;w->error=errno;return NULL;}
        if(fcntl(w->fd,F_SETLK,&w->lock)){w->failed=4;w->error=errno;return NULL;}}
    return NULL;
}
int main(int argc,char**argv)
{
    if(argc==2&&!strcmp(argv[1],"child"))return child_main();
    fixture_t*f=calloc(1,sizeof(*f));CHECK(f);
    int fd=open(PATH,O_CREAT|O_EXCL|O_RDWR|O_CLOEXEC,0600);CHECK(fd>=3&&!ftruncate(fd,512));
    f->times[0]=(struct timeval){.tv_sec=123456789,.tv_usec=123456};
    f->times[1]=(struct timeval){.tv_sec=123456790,.tv_usec=999999};
    CHECK(!utimes(PATH,f->times)&&!stat(PATH,&f->metadata)&&f->metadata.st_atime==123456789&&f->metadata.st_mtime==123456790);
    f->times[0].tv_usec=1000000;CHECK(utimes(PATH,f->times)==-1&&errno==EINVAL);
    CHECK(utimes(PATH,(void*)1)==-1&&errno==EFAULT);CHECK(!utimes(PATH,NULL));
    CHECK(!launch(&f->children[0])&&!launch(&f->children[1]));
    CHECK(!local(f,fd,F_WRLCK,SEEK_SET,0,100));
    CHECK(!remote(f,0,F_GETLK,F_WRLCK,20,1,false)&&!f->reply.result&&f->reply.lock.l_type==F_WRLCK&&
          f->reply.lock.l_pid==getpid()&&f->reply.lock.l_start==0&&f->reply.lock.l_len==100);
    CHECK(!remote(f,0,F_SETLK,F_RDLCK,0,100,false)&&f->reply.result==-1&&f->reply.error==EAGAIN);
    int other=open(PATH,O_RDONLY);CHECK(other>=3);
    f->lock=(struct flock){.l_type=F_WRLCK,.l_whence=SEEK_SET};
    CHECK(!fcntl(other,F_GETLK,&f->lock)&&f->lock.l_type==F_UNLCK);
    CHECK(!close(other)); /* close-any-FD releases */
    CHECK(!remote(f,0,F_SETLK,F_RDLCK,0,100,false)&&!f->reply.result);
    CHECK(!remote(f,1,F_SETLK,F_RDLCK,0,100,false)&&!f->reply.result);
    CHECK(local(f,fd,F_WRLCK,SEEK_SET,0,100)==-1&&errno==EAGAIN);
    CHECK(!remote(f,0,F_SETLK,F_UNLCK,0,0,false)&&!f->reply.result);
    CHECK(!remote(f,1,F_SETLK,F_UNLCK,0,0,false)&&!f->reply.result);
    CHECK(!local(f,fd,F_WRLCK,SEEK_SET,0,100)&&!local(f,fd,F_UNLCK,SEEK_SET,20,20));
    CHECK(!remote(f,0,F_GETLK,F_WRLCK,30,1,false)&&!f->reply.result&&f->reply.lock.l_type==F_UNLCK);
    CHECK(!remote(f,0,F_SETLK,F_WRLCK,20,20,false)&&!f->reply.result);
    CHECK(local(f,fd,F_RDLCK,SEEK_SET,25,1)==-1&&errno==EAGAIN);
    CHECK(!remote(f,0,F_SETLK,F_UNLCK,0,0,false)&&!f->reply.result);
    CHECK(!local(f,fd,F_UNLCK,SEEK_SET,0,0)&&lseek(fd,200,SEEK_SET)==200);
    CHECK(!local(f,fd,F_RDLCK,SEEK_CUR,-10,25));
    CHECK(!remote(f,0,F_GETLK,F_WRLCK,200,1,false)&&!f->reply.result&&f->reply.lock.l_type==F_RDLCK&&
          f->reply.lock.l_start==190&&f->reply.lock.l_len==25&&f->reply.lock.l_whence==SEEK_SET);
    CHECK(!local(f,fd,F_WRLCK,SEEK_END,-5,-5)&&lseek(fd,0,SEEK_CUR)==200);
    CHECK(!remote(f,0,F_GETLK,F_WRLCK,504,1,false)&&!f->reply.result&&f->reply.lock.l_start==502&&f->reply.lock.l_len==5);
    CHECK(!local(f,fd,F_UNLCK,SEEK_SET,0,0));
    CHECK(fcntl(fd,F_SETLK,(void*)1)==-1&&errno==EFAULT);
    CHECK(local(f,fd,99,SEEK_SET,0,1)==-1&&errno==EINVAL);
    CHECK(local(f,fd,F_WRLCK,99,0,1)==-1&&errno==EINVAL);
    CHECK(local(f,fd,F_WRLCK,SEEK_SET,INT64_MAX,2)==-1&&errno==EOVERFLOW);
    CHECK(local(f,fd,F_WRLCK,SEEK_SET,0,-1)==-1&&errno==EINVAL);
    struct flock*readonly=mmap(NULL,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);CHECK(readonly!=MAP_FAILED);
    *readonly=(struct flock){.l_type=F_WRLCK,.l_whence=SEEK_SET};CHECK(!mprotect(readonly,4096,PROT_READ));
    CHECK(fcntl(fd,F_GETLK,readonly)==-1&&errno==EFAULT&& !munmap(readonly,4096));
    CHECK(!local(f,fd,F_WRLCK,SEEK_SET,0,100));
    CHECK(!remote(f,0,F_SETLKW,F_WRLCK,0,100,true));sys_sleep_ms(50);CHECK(!kill(f->children[0].pid,0));
    CHECK(!remote(f,1,F_GETLK,F_WRLCK,0,1,false)&&!f->reply.result&&f->reply.lock.l_pid==getpid());
    CHECK(!local(f,fd,F_UNLCK,SEEK_SET,0,100));
    CHECK(!transfer(f->children[0].receive,&f->reply,sizeof(f->reply),false)&&!f->reply.result);
    CHECK(!remote(f,1,F_SETLK,F_RDLCK,0,100,false)&&f->reply.result==-1&&f->reply.error==EAGAIN);
    CHECK(!stop_child(f,0,true));
    int acquired=-1;for(unsigned i=0;i<300;++i){acquired=local(f,fd,F_WRLCK,SEEK_SET,0,100);if(!acquired)break;CHECK(errno==EAGAIN);sys_sleep_ms(10);}CHECK(!acquired);
    CHECK(!launch(&f->children[2])&&!remote(f,2,F_SETLKW,F_RDLCK,0,100,true));sys_sleep_ms(50);
    CHECK(!stop_child(f,2,true)&&!local(f,fd,F_UNLCK,SEEK_SET,0,100));
    CHECK(!remote(f,1,F_SETLK,F_WRLCK,0,100,false)&&!f->reply.result);
    CHECK(!remote(f,1,F_SETLK,F_UNLCK,0,0,false)&&!f->reply.result);
    CHECK(!local(f,fd,F_WRLCK,SEEK_SET,0,100));int alias=dup(fd);CHECK(alias>=3&&dup2(fd,alias)==alias);
    CHECK(!remote(f,1,F_SETLK,F_WRLCK,0,100,false)&&!f->reply.result);
    CHECK(!close(alias)&&!stop_child(f,1,false));
    for(unsigned cpu=0;cpu<8;++cpu){f->workers[cpu].cpu=cpu;f->workers[cpu].fd=open(PATH,O_RDWR|O_CLOEXEC);CHECK(f->workers[cpu].fd>=3);
        CHECK(!pthread_create(&f->workers[cpu].thread,NULL,worker,&f->workers[cpu]));}
    for(unsigned cpu=0;cpu<8;++cpu){CHECK(!pthread_join(f->workers[cpu].thread,NULL));
        if(f->workers[cpu].failed)serial_printf("RECORD_LOCK_WORKER: cpu=%u stage=%u result=%d errno=%d type=%d owner=%d start=%lld len=%lld\n",cpu,f->workers[cpu].failed,f->workers[cpu].result,f->workers[cpu].error,f->workers[cpu].lock.l_type,f->workers[cpu].lock.l_pid,(long long)f->workers[cpu].lock.l_start,(long long)f->workers[cpu].lock.l_len);
        CHECK(!f->workers[cpu].failed);}
    for(unsigned cpu=0;cpu<8;++cpu)CHECK(!close(f->workers[cpu].fd));
    CHECK(!close(fd)&&!unlink(PATH));free(f);
    serial_printf("RECORD_LOCK_TEST: PASS cpus=8 operations=512 children=3 getlk=1 shared=1 split=1 offsets=1 close_any=1 dup2=1 killed_holder=1 killed_waiter=1 fresh_progress=1 copy_checks=1 utimes=1\n");
    return 0;
}
