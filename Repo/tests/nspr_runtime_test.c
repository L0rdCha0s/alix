#include "prinit.h"
#include "prthread.h"
#include "prlock.h"
#include "prcvar.h"
#include "prenv.h"
#include "prmem.h"
#include "prio.h"
#include "prerror.h"
#include "prsystem.h"
#include "prproces.h"
#include "dlfcn.h"
#include "stdlib.h"
#include "string.h"
#include "errno.h"
#include "serial.h"
#include "usyscall.h"
#include "netinet/in.h"
#include "unistd.h"
#include "sys/stat.h"

#define APIS(X) \
 X(init,PR_Init) X(cleanup,PR_Cleanup) X(version,PR_GetVersion) \
 X(new_lock,PR_NewLock) X(destroy_lock,PR_DestroyLock) X(lock,PR_Lock) X(unlock,PR_Unlock) \
 X(new_cond,PR_NewCondVar) X(destroy_cond,PR_DestroyCondVar) X(wait_cond,PR_WaitCondVar) X(notify_all,PR_NotifyAllCondVar) \
 X(create_thread,PR_CreateThread) X(join_thread,PR_JoinThread) X(current_thread,PR_GetCurrentThread) \
 X(new_private,PR_NewThreadPrivateIndex) X(set_private,PR_SetThreadPrivate) X(get_private,PR_GetThreadPrivate) \
 X(call_once,PR_CallOnceWithArg) X(sleep,PR_Sleep) \
 X(duplicate_environment,PR_DuplicateEnvironment) X(free,PR_Free) \
 X(create_pipe,PR_CreatePipe) X(writev,PR_Writev) X(read,PR_Read) X(write,PR_Write) X(close,PR_Close) X(poll,PR_Poll) \
 X(new_tcp,PR_NewTCPSocket) X(connect,PR_Connect) X(recv,PR_Recv) \
 X(new_event,PR_NewPollableEvent) X(set_event,PR_SetPollableEvent) X(wait_event,PR_WaitForPollableEvent) X(destroy_event,PR_DestroyPollableEvent) \
 X(open,PR_Open) X(mkdir,PR_MkDir) X(rmdir,PR_RmDir) X(seek,PR_Seek64) X(new_map,PR_CreateFileMap) X(map,PR_MemMap) X(sync_map,PR_SyncMemMap) X(unmap,PR_MemUnmap) X(close_map,PR_CloseFileMap) \
 X(error,PR_GetError) X(os_error,PR_GetOSError) X(cpus,PR_GetNumberOfProcessors)
/* Process entry points exercise the actual NSPR wait daemon as well as the
 * already verified native spawn helper. */
typedef struct {
#define FIELD(field,name) __typeof__(&name) field;
    APIS(FIELD)
    __typeof__(&PR_CreateProcess) create_process;
    __typeof__(&PR_WaitProcess) wait_process;
#undef FIELD
} api_t;
typedef struct fixture fixture_t;
typedef struct {fixture_t *fixture;PRThread *thread;unsigned cpu,failed;} job_t;
struct fixture {
    api_t api;
    job_t jobs[8];
    PRLock *lock;
    PRCondVar *condition;
    PRCallOnceType once;
    PRUintn key;
    unsigned ready,start,total,once_count,destructors;
    PRFileDesc *reader,*writer,*event,*file;
    PRFileDesc *socket;
    PRNetAddr address;
    PRPollDesc poll;
    PRIOVec vectors[3];
    PRFileMap *file_map;
    unsigned char bytes[8192];
    char executable[4096];char *arguments[3];
    PRProcess *child;PRInt32 child_status;
    struct stat metadata;
};
static fixture_t *active;
#define CHECK(c,label) do{if(!(c)){serial_printf("NSPR_RUNTIME_TEST: FAIL %s line=%u errno=%d pr=%d os=%d\n",label,__LINE__,errno,active&&active->api.error?active->api.error():0,active&&active->api.os_error?active->api.os_error():0);return 1;}}while(0)
static void PR_CALLBACK thread_destructor(void *opaque)
{
    job_t *job=opaque;__atomic_add_fetch(&job->fixture->destructors,1u,__ATOMIC_RELEASE);
}
static PRStatus PR_CALLBACK initialize_once(void *opaque)
{
    fixture_t *f=opaque;__atomic_add_fetch(&f->once_count,1u,__ATOMIC_RELAXED);return PR_SUCCESS;
}
static void PR_CALLBACK worker(void *opaque)
{
    job_t *job=opaque;fixture_t *f=job->fixture;
    if(sys_thread_set_affinity(job->cpu) || sys_thread_cpu()!=job->cpu || !f->api.current_thread())job->failed=1;
    if(f->api.set_private(f->key,job)!=PR_SUCCESS || f->api.get_private(f->key)!=job)job->failed=2;
    f->api.lock(f->lock);
    __atomic_add_fetch(&f->ready,1u,__ATOMIC_RELEASE);
    while(!f->start && !job->failed)
        if(f->api.wait_cond(f->condition,PR_INTERVAL_NO_TIMEOUT)!=PR_SUCCESS)job->failed=3;
    f->api.unlock(f->lock);
    for(unsigned n=0;n<64 && !job->failed;++n) {
        if(f->api.call_once(&f->once,initialize_once,f)!=PR_SUCCESS)job->failed=4;
        f->api.lock(f->lock);++f->total;f->api.unlock(f->lock);
        if(f->api.sleep(PR_INTERVAL_NO_WAIT)!=PR_SUCCESS)job->failed=5;
    }
}
int main(int argc,char **argv)
{
    fixture_t *f=calloc(1,sizeof(*f));active=f;CHECK(f,"owned fixture");
    bool child=argc==2 && !strcmp(argv[1],"child");
    if(child)CHECK(getenv("NSPR_FULL_RUNTIME") && !strcmp(getenv("NSPR_FULL_RUNTIME"),"live"),"inherited native environment");
    else CHECK(argc==2 && atoi(argv[1])>0 && !setenv("NSPR_FULL_RUNTIME","live",1),"host TCP endpoint and environment");
    void *library=dlopen("/tmp/libnspr4.so",RTLD_NOW|RTLD_GLOBAL|RTLD_NODELETE);
    if(!library){serial_printf("NSPR_RUNTIME_TEST: FAIL dlopen=%s\n",dlerror());return 1;}
#define LOAD(field,name) f->api.field=(__typeof__(f->api.field))dlsym(library,#name);CHECK(f->api.field,#name);
    APIS(LOAD)
    LOAD(create_process,PR_CreateProcess)
    LOAD(wait_process,PR_WaitProcess)
#undef LOAD
    CHECK(!dlerror(),"API symbol lookup");
    serial_printf("NSPR_RUNTIME_TEST: stage=loaded\n");
    f->api.init(PR_USER_THREAD,PR_PRIORITY_NORMAL,1);
    serial_printf("NSPR_RUNTIME_TEST: stage=initialized version=%s\n",f->api.version());
    CHECK(f->api.cpus()==8,"actual NSPR processor query");
    char **environment=f->api.duplicate_environment();CHECK(environment,"actual native NSPR environment snapshot");
    bool found=false;
    for(size_t i=0;environment[i];++i) {
        if(!strcmp(environment[i],"NSPR_FULL_RUNTIME=live"))found=true;
        f->api.free(environment[i]);
    }
    f->api.free(environment);CHECK(found,"NSPR sees native environment changes");
    if(child) {
        CHECK(f->api.cleanup()==PR_SUCCESS && !dlclose(library),"child NSPR initialization cleanup");
        serial_printf("NSPR_RUNTIME_CHILD: PASS environment=1 initialized=1\n");
        free(f);active=NULL;return 37;
    }
    f->lock=f->api.new_lock();f->condition=f->lock?f->api.new_cond(f->lock):NULL;
    CHECK(f->lock && f->condition && f->api.new_private(&f->key,thread_destructor)==PR_SUCCESS,"NSPR locks conditions and private key");
    for(unsigned cpu=0;cpu<8;++cpu) {
        job_t *j=&f->jobs[cpu];j->fixture=f;j->cpu=cpu;
        j->thread=f->api.create_thread(PR_USER_THREAD,worker,j,PR_PRIORITY_NORMAL,PR_GLOBAL_THREAD,PR_JOINABLE_THREAD,0);
        CHECK(j->thread,"actual NSPR thread creation");
    }
    uint64_t deadline=sys_monotonic_millis()+15000;
    while(__atomic_load_n(&f->ready,__ATOMIC_ACQUIRE)!=8 && sys_monotonic_millis()<deadline)sys_yield();
    CHECK(f->ready==8,"eight NSPR waiters ready");
    f->api.lock(f->lock);f->start=1;CHECK(f->api.notify_all(f->condition)==PR_SUCCESS,"NSPR condition notification");f->api.unlock(f->lock);
    for(unsigned cpu=0;cpu<8;++cpu) {
        CHECK(f->api.join_thread(f->jobs[cpu].thread)==PR_SUCCESS,"NSPR join");
        if(f->jobs[cpu].failed){serial_printf("NSPR_RUNTIME_TEST: FAIL cpu=%u stage=%u\n",cpu,f->jobs[cpu].failed);return 1;}
    }
    CHECK(f->total==512 && f->once_count==1 && f->destructors==8,"NSPR mutex once and TLS destructor lifetime");
    f->api.destroy_cond(f->condition);f->api.destroy_lock(f->lock);
    CHECK(f->api.create_pipe(&f->reader,&f->writer)==PR_SUCCESS,"NSPR pipe");
    f->vectors[0]=(PRIOVec){(char *)"native",6};f->vectors[1]=(PRIOVec){(char *)"-",1};f->vectors[2]=(PRIOVec){(char *)"nspr",4};
    CHECK(f->api.write(f->writer,"native-nspr",11)==11,"NSPR pipe write");
    f->poll=(PRPollDesc){.fd=f->reader,.in_flags=PR_POLL_READ};
    CHECK(f->api.poll(&f->poll,1,PR_INTERVAL_NO_WAIT)==1 && (f->poll.out_flags&PR_POLL_READ) &&
        f->api.read(f->reader,f->bytes,11)==11 && !memcmp(f->bytes,"native-nspr",11),"NSPR pipe polling and readback");
    CHECK(f->api.close(f->reader)==PR_SUCCESS && f->api.close(f->writer)==PR_SUCCESS,"NSPR pipe close");
    f->socket=f->api.new_tcp();CHECK(f->socket,"NSPR TCP socket");
    f->address.inet.family=PR_AF_INET;f->address.inet.port=htons((uint16_t)atoi(argv[1]));
    f->address.inet.ip=htonl(0x0a000202u);
    CHECK(f->api.connect(f->socket,&f->address,PR_INTERVAL_NO_TIMEOUT)==PR_SUCCESS,"NSPR real TCP connection");
    CHECK(f->api.writev(f->socket,f->vectors,3,PR_INTERVAL_NO_TIMEOUT)==11,"NSPR TCP gathered write");
    size_t received=0;
    while(received<11) {
        PRInt32 n=f->api.recv(f->socket,f->bytes+received,11-received,0,PR_INTERVAL_NO_TIMEOUT);
        CHECK(n>0,"NSPR TCP echo receive");received+=(size_t)n;
    }
    CHECK(!memcmp(f->bytes,"native-nspr",11) && f->api.close(f->socket)==PR_SUCCESS,"NSPR TCP echo contents");
    f->event=f->api.new_event();CHECK(f->event,"NSPR pollable event");
    CHECK(f->api.set_event(f->event)==PR_SUCCESS,"NSPR event signal");
    f->poll=(PRPollDesc){.fd=f->event,.in_flags=PR_POLL_READ};
    CHECK(f->api.poll(&f->poll,1,PR_INTERVAL_NO_WAIT)==1 && (f->poll.out_flags&PR_POLL_READ) &&
        f->api.wait_event(f->event)==PR_SUCCESS && f->api.destroy_event(f->event)==PR_SUCCESS,"NSPR pollable event lifecycle");
    mode_t previous_mask=umask(0027);
    f->file=f->api.open("/tmp/nspr-full-runtime",PR_RDWR|PR_CREATE_FILE|PR_EXCL,0600);
    CHECK(f->file && !stat("/tmp/nspr-full-runtime",&f->metadata) && (f->metadata.st_mode&0777)==0600,
          "NSPR requested file mode reaches native open ABI");
    CHECK(f->api.mkdir("/tmp/nspr-mode-directory",0700)==PR_SUCCESS &&
          !stat("/tmp/nspr-mode-directory",&f->metadata) && (f->metadata.st_mode&0777)==0700 &&
          f->api.rmdir("/tmp/nspr-mode-directory")==PR_SUCCESS && umask(previous_mask)==0027,
          "NSPR requested directory mode and mask");
    serial_printf("NSPR_RUNTIME_MODES: PASS open=1 mkdir=1 umask=1\n");
    CHECK(f->file && f->api.seek(f->file,8191,PR_SEEK_SET)==8191 && f->api.write(f->file,"",1)==1,"NSPR file sizing");
    f->file_map=f->api.new_map(f->file,8192,PR_PROT_READWRITE);CHECK(f->file_map,"NSPR file map creation");
    unsigned char *mapped=f->api.map(f->file_map,0,8192),*alias=f->api.map(f->file_map,4096,4096);
    CHECK(mapped && alias,"NSPR shared file mapping");strcpy((char *)mapped,"full nspr mappings");mapped[4096+7]=0x5b;
    CHECK(alias[7]==0x5b && f->api.sync_map(f->file,mapped,8192)==PR_SUCCESS,"NSPR shared synchronization");
    CHECK(f->api.unmap(mapped,8192)==PR_SUCCESS && f->api.unmap(alias,4096)==PR_SUCCESS &&
        f->api.close_map(f->file_map)==PR_SUCCESS && f->api.close(f->file)==PR_SUCCESS,"NSPR mapping cleanup");
    f->file=f->api.open("/tmp/nspr-full-runtime",PR_RDONLY,0);
    CHECK(f->file && f->api.read(f->file,f->bytes,19)==19 && !memcmp(f->bytes,"full nspr mappings",19) &&
        f->api.close(f->file)==PR_SUCCESS,"NSPR mapped file readback");
    CHECK(alix_get_executable_path(f->executable,sizeof(f->executable))>0,"native executable identity");
    f->arguments[0]=f->executable;f->arguments[1]="child";
    f->child=f->api.create_process(f->executable,f->arguments,NULL,NULL);
    CHECK(f->child && f->api.wait_process(f->child,&f->child_status)==PR_SUCCESS && f->child_status==37,"NSPR spawn and wait daemon status");
    CHECK(f->api.cleanup()==PR_SUCCESS,"full NSPR cleanup");
    CHECK(!dlclose(library),"release process-lifetime NSPR library handle");
    serial_printf("NSPR_RUNTIME_TEST: PASS cpus=8 updates=512 threads=1 locks=1 condvars=1 once=1 tls_dtors=8 environment=1 writev=1 tcp=1 poll=1 events=1 maps=1 spawn=1 wait_daemon=1 cleanup=1\n");
    free(f);active=NULL;return 0;
}
