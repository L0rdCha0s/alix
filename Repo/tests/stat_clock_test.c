#include "unistd.h"
#include "fcntl.h"
#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "errno.h"
#include "time.h"
#include "pthread.h"
#include "sys/stat.h"
#include "sys/mman.h"
#include "usyscall.h"
#include "serial.h"
#include "limits.h"

#define WORKERS 8u
#define CHECK(c,label) do { if (!(c)) { serial_printf("STAT_CLOCK_TEST: FAIL %s errno=%d\n",label,errno); return 1; } } while(0)
typedef struct shared shared_t;
typedef struct {shared_t *shared;pthread_t thread;unsigned cpu,failed;uint64_t checksum;struct stat metadata;} worker_t;
struct shared {worker_t workers[WORKERS];uint32_t ready,start,mask;};

static void *worker(void *argument)
{
    worker_t *work=argument;
    if(sys_thread_set_affinity(work->cpu)||sys_thread_cpu()!=work->cpu)work->failed=1;
    __atomic_add_fetch(&work->shared->ready,1,__ATOMIC_RELEASE);
    while(!__atomic_load_n(&work->shared->start,__ATOMIC_ACQUIRE))sys_yield();
    uint64_t end=sys_monotonic_millis()+250,value=work->cpu+1;
    do {
        for(unsigned i=0;i<4096;++i){value=value*UINT64_C(6364136223846793005)+i;__asm__ volatile("":"+r"(value));}
    }while(sys_monotonic_millis()<end);
    work->checksum=value;
    for(unsigned i=0;i<32;++i)
        if(stat("/tmp/stat-clock-file",&work->metadata)||!S_ISREG(work->metadata.st_mode)||work->metadata.st_size!=2)work->failed=2;
    __atomic_fetch_or(&work->shared->mask,1u<<work->cpu,__ATOMIC_RELEASE);
    return NULL;
}

int main(void)
{
    struct stat *metadata=malloc(sizeof(*metadata)),*before=malloc(sizeof(*before));
    char *buffer=malloc(PATH_MAX+1),*saved=getcwd(NULL,0);
    CHECK(metadata&&before&&buffer&&saved,"heap state and initial cwd");
    CHECK(PATH_MAX==4096&&sys_mkdir("/tmp/stat-clock-directory")==0,"path limit and fixture directory");
    CHECK(stat("/tmp",metadata)==0&&S_ISDIR(metadata->st_mode),"directory metadata without opening");
    CHECK(lstat("/tmp/vfs-owned-test/alias",metadata)==0&&S_ISLNK(metadata->st_mode)&&metadata->st_size==3,"native lstat final link");
    CHECK(stat("/tmp/vfs-owned-test/alias",metadata)==0&&S_ISDIR(metadata->st_mode),"native stat follows directory link");
    CHECK(lstat("/tmp/vfs-owned-test/alias/leaf",metadata)==0&&S_ISLNK(metadata->st_mode)&&
          metadata->st_size==strlen("../../zones/Area/City"),"native intermediate symlink");
    CHECK(stat("/tmp/vfs-owned-test/link",metadata)==-1&&errno==ENOENT,"stat follows dangling link");
    CHECK(lstat("/tmp/vfs-owned-test/link",metadata)==0&&S_ISLNK(metadata->st_mode)&&metadata->st_size==18,"lstat dangling link");
    CHECK(stat("/tmp/vfs-owned-test/loop",metadata)==-1&&errno==ELOOP,"stat loop detection");
    memset(metadata,0xa5,sizeof(*metadata));memcpy(before,metadata,sizeof(*before));
    CHECK(stat("/tmp/stat-clock-absent",metadata)==-1&&errno==ENOENT&&!memcmp(metadata,before,sizeof(*before)),"stat preserves output on failure");
    CHECK(stat((const char*)1,metadata)==-1&&errno==EFAULT&&!memcmp(metadata,before,sizeof(*before)),"bad path copy");
    CHECK(stat("/tmp",NULL)==-1&&errno==EFAULT,"null stat output");
    int fd=open("/tmp/stat-clock-file",O_RDWR|O_CREAT|O_TRUNC),output=dup(STDOUT_FILENO);
    CHECK(fd>=3&&output>=3&&dup2(fd,STDOUT_FILENO)==STDOUT_FILENO,"redirect putchar");
    CHECK(putchar(0x1ff)==0xff&&putc('X',stdout)=='X'&&fflush(stdout)==0,"standard character output");
    CHECK(dup2(output,STDOUT_FILENO)==STDOUT_FILENO&&close(output)==0,"restore stdout");
    CHECK(lseek(fd,0,SEEK_SET)==0&&read(fd,buffer,2)==2&&(unsigned char)buffer[0]==0xff&&buffer[1]=='X',"buffered putchar bytes");
    CHECK(stat("/tmp/stat-clock-file",metadata)==0&&fstat(fd,before)==0&&metadata->st_size==2&&
          metadata->st_mode==before->st_mode&&metadata->st_mtime==before->st_mtime&&close(fd)==0,"path stat agrees with fstat");
    FILE *input=fopen("/tmp/stat-clock-file","r");
    CHECK(input&&putc('x',input)==EOF&&ferror(input)&&fclose(input)==0,"putc write error");
    CHECK(stat("/tmp/stat-clock-file/",metadata)==-1&&errno==ENOTDIR,"trailing separator requires directory");
    memset(buffer,'x',PATH_MAX);buffer[PATH_MAX]=0;
    CHECK(stat(buffer,metadata)==-1&&errno==ENAMETOOLONG,"bounded path");
    CHECK(chdir("/tmp/stat-clock-directory")==0&&getcwd(buffer,PATH_MAX)==buffer&&!strcmp(buffer,"/tmp/stat-clock-directory"),"owned chdir/getcwd");
    memset(buffer,0x5a,8);
    CHECK(getcwd(buffer,2)==NULL&&errno==ERANGE&&(unsigned char)buffer[0]==0x5a,"no truncated cwd success");
    CHECK(getcwd(buffer,0)==NULL&&errno==EINVAL,"zero cwd capacity");
    CHECK(chdir("/tmp/stat-clock-file")==-1&&errno==ENOTDIR&&getcwd(buffer,PATH_MAX)==buffer&&
          !strcmp(buffer,"/tmp/stat-clock-directory"),"failed chdir preserves cwd");
    fd=open("relative",O_RDWR|O_CREAT|O_TRUNC);
    CHECK(fd>=3&&write(fd,"cwd",3)==3&&close(fd)==0&&stat("relative",metadata)==0&&metadata->st_size==3,"relative stat uses new cwd");
    CHECK(chdir(saved)==0,"restore initial cwd");
    int *aliases=calloc(253,sizeof(*aliases));CHECK(aliases,"capacity heap");
    for(unsigned i=0;i<253;++i){aliases[i]=dup(1);CHECK(aliases[i]==(int)i+3,"fill descriptors");}
    errno=EDOM;
    CHECK(stat("/tmp/stat-clock-file",metadata)==0&&metadata->st_size==2&&errno==EDOM&&
          getcwd(buffer,PATH_MAX)==buffer,"metadata/cwd do not allocate descriptors");
    for(unsigned i=0;i<253;++i)CHECK(close(aliases[i])==0,"release descriptors");free(aliases);
    void *readonly=mmap(NULL,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    CHECK(readonly!=MAP_FAILED&&mprotect(readonly,4096,PROT_READ)==0,"read-only result mapping");
    CHECK(sys_file_io(SYSCALL_FILE_STAT_PATH,(uintptr_t)"/tmp",(uintptr_t)readonly,0,0)==-EFAULT,"safe kernel metadata copyout");
    CHECK(munmap(readonly,4096)==0&&stat("/tmp",metadata)==0,"fresh request after copyout error");
    shared_t *shared=calloc(1,sizeof(*shared));CHECK(shared,"CPU fixture state");
    errno=EDOM;clock_t start=clock();CHECK(start>=0&&errno==EDOM,"native clock snapshot");
    uint64_t wall=sys_monotonic_millis();sys_sleep_ms(200);
    clock_t after_sleep=clock();uint64_t elapsed=sys_monotonic_millis()-wall;
    CHECK(after_sleep>=start&&(uint64_t)(after_sleep-start)<elapsed/2+50,"clock excludes sleeping time");
    for(unsigned i=0;i<WORKERS;++i){shared->workers[i].shared=shared;shared->workers[i].cpu=i;CHECK(!pthread_create(&shared->workers[i].thread,NULL,worker,&shared->workers[i]),"create CPU worker");}
    while(__atomic_load_n(&shared->ready,__ATOMIC_ACQUIRE)!=WORKERS)sys_yield();
    __atomic_store_n(&shared->start,1,__ATOMIC_RELEASE);
    for(unsigned i=0;i<WORKERS;++i)CHECK(!pthread_join(shared->workers[i].thread,NULL)&&!shared->workers[i].failed,"join CPU/metadata worker");
    CHECK(shared->mask==0xff&&clock()>after_sleep+20,"process CPU time and stat on eight CPUs");
    free(shared);free(saved);free(buffer);free(before);free(metadata);
    serial_printf("STAT_CLOCK_TEST: PASS stat=1 lstat=1 full_table=1 cwd=1 putchar=1 clock=1 workers=8\n");
    return 0;
}
