#include "netdb.h"
#include "netdb_internal.h"
#include "arpa/inet.h"
#include "stdlib.h"
#include "string.h"
#include "stdio.h"
#include "pthread.h"
#include "unistd.h"
#include "usyscall.h"
#include "errno.h"
#include "serial.h"
#include "alix_process.h"
#include "signal.h"
#include "sys/wait.h"
#define CHECK(c) do { if (!(c)) { job->failed = __LINE__; job->error = errno; goto finished; } } while (0)
#define REQUIRE(c) do { if (!(c)) { serial_printf("NETDB_TEST: FAIL line=%u errno=%d\n",__LINE__,errno); return 1; } } while (0)
typedef struct {
    unsigned index, failed; int error, socket;
    pthread_t thread; uint16_t port;
    unsigned *ready, *start;
    struct addrinfo hints, *addresses;
    struct hostent entry, *host, *tls_host;
    char service[6], bytes[32], host_name[64], service_name[16], scratch[512];
    int host_error;
} job_t;
typedef struct {
    job_t jobs[8]; unsigned ready, start;
    struct addrinfo hints, *addresses;
    syscall_dns_reply_t reply;
    int pipes[2], status;
    char marker[16], dns_port[16];
    char **arguments;
} fixture_t;
static int lookup(const char *name, const char *service, uint16_t port, struct addrinfo *hints, struct addrinfo **result)
{
    return __alix_getaddrinfo_at(name, service, hints, 0x0a000202, port, result);
}
static void *worker(void *context)
{
    job_t *job = context;
    CHECK(!sys_thread_set_affinity(job->index) && sys_thread_cpu() == job->index);
    job->hints = (struct addrinfo){ .ai_family=AF_INET, .ai_socktype=SOCK_STREAM, .ai_flags=AI_NUMERICHOST | AI_NUMERICSERV };
    CHECK(!getaddrinfo("10.1.2.3", "443", &job->hints, &job->addresses));
    CHECK(ntohl(((struct sockaddr_in *)job->addresses->ai_addr)->sin_addr.s_addr) == 0x0a010203);
    freeaddrinfo(job->addresses); job->addresses = NULL;
    CHECK(getaddrinfo("alias.test", "443", &job->hints, &job->addresses) == EAI_NONAME && !job->addresses);
    job->hints.ai_flags = AI_CANONNAME;
    CHECK(!lookup("alias.test", "https", job->port, &job->hints, &job->addresses));
    CHECK(job->addresses && job->addresses->ai_next && !job->addresses->ai_next->ai_next &&
          !strcmp(job->addresses->ai_canonname,"canonical.test") && !job->addresses->ai_next->ai_canonname);
    CHECK(ntohl(((struct sockaddr_in *)job->addresses->ai_addr)->sin_addr.s_addr) == 0x0a010203 &&
          ntohl(((struct sockaddr_in *)job->addresses->ai_next->ai_addr)->sin_addr.s_addr) == 0x0a010204 &&
          ntohs(((struct sockaddr_in *)job->addresses->ai_addr)->sin_port) == 443);
    freeaddrinfo(job->addresses); job->addresses = NULL;
    CHECK(!lookup("hop.test", NULL, job->port, &job->hints, &job->addresses) &&
          !strcmp(job->addresses->ai_canonname,"canonical.test"));
    freeaddrinfo(job->addresses); job->addresses = NULL;
    CHECK(!gethostbyname_r("localhost", &job->entry, job->scratch, sizeof(job->scratch), &job->host, &job->host_error) &&
          job->host == &job->entry && !job->host_error && job->host->h_addrtype == AF_INET && job->host->h_length == 4);
    CHECK(gethostbyname_r("localhost", &job->entry, job->scratch, 1, &job->host, &job->host_error) == ERANGE && !job->host);
    CHECK(getprotobyname("tcp") && getprotobyname("tcp")->p_proto == 6 &&
          getservbyname("https", "tcp") && ntohs((uint16_t)getservbyname("https", "tcp")->s_port) == 443);
    job->tls_host = gethostbyname("localhost"); CHECK(job->tls_host && !strcmp(job->tls_host->h_name,"localhost"));
    __atomic_add_fetch(job->ready, 1u, __ATOMIC_SEQ_CST);
    while (!__atomic_load_n(job->start, __ATOMIC_SEQ_CST)) sys_sleep_ms(1);
    CHECK(!strcmp(job->tls_host->h_name,"localhost"));
    job->hints.ai_flags = 0;
    CHECK(!lookup("connect.test", job->service, job->port, &job->hints, &job->addresses));
    CHECK(!getnameinfo(job->addresses->ai_addr, job->addresses->ai_addrlen, job->host_name, sizeof(job->host_name),
                      job->service_name, sizeof(job->service_name), NI_NUMERICHOST | NI_NUMERICSERV) &&
          !strcmp(job->host_name,"10.0.2.2") && !strcmp(job->service_name,job->service));
    job->socket = socket(job->addresses->ai_family, job->addresses->ai_socktype | SOCK_CLOEXEC, job->addresses->ai_protocol);
    CHECK(job->socket >= 0 && !connect(job->socket, job->addresses->ai_addr, job->addresses->ai_addrlen));
    CHECK(send(job->socket,"DNS",3,MSG_NOSIGNAL) == 3);
    size_t total = 0;
    while (total < 8) { ssize_t count=recv(job->socket,job->bytes+total,8-total,0); CHECK(count>0 && (size_t)count<=8-total); total+=(size_t)count; }
    CHECK(!memcmp(job->bytes,"resolved",8));
finished:
    if (job->socket >= 0) close(job->socket);
    freeaddrinfo(job->addresses); job->addresses = NULL;
    return NULL;
}
static int canceled_lookup(fixture_t *test, uint16_t port)
{
    REQUIRE(!pipe(test->pipes));
    test->arguments = calloc(5,sizeof(*test->arguments)); REQUIRE(test->arguments);
    snprintf(test->dns_port,sizeof(test->dns_port),"%u",(unsigned)port);
    snprintf(test->marker,sizeof(test->marker),"%d",test->pipes[1]);
    test->arguments[0]=strdup("/tmp/test.elf");test->arguments[1]=strdup("dns-child");
    test->arguments[2]=strdup(test->dns_port);test->arguments[3]=strdup(test->marker);
    REQUIRE(test->arguments[0]&&test->arguments[1]&&test->arguments[2]&&test->arguments[3]);
    pid_t child=alix_spawn_argv(test->arguments[0],test->arguments);
    for(unsigned index=0;index<4;++index) free(test->arguments[index]);free(test->arguments);test->arguments=NULL;
    REQUIRE(child>0&&!close(test->pipes[1])&&read(test->pipes[0],test->marker,1)==1&&test->marker[0]=='R'&&!close(test->pipes[0]));
    bool observed=false;
    for(unsigned attempt=0;attempt<50&&!observed;++attempt)
    {
        REQUIRE(!lookup("observed.test",NULL,port,&test->hints,&test->addresses));
        observed=ntohl(((struct sockaddr_in*)test->addresses->ai_addr)->sin_addr.s_addr)==0x0a141e02;
        freeaddrinfo(test->addresses);test->addresses=NULL;
        if(!observed)sys_sleep_ms(1);
    }
    REQUIRE(observed&&!kill(child,SIGKILL)&&waitpid(child,&test->status,0)==child&&WIFSIGNALED(test->status)&&WTERMSIG(test->status)==SIGKILL);
    uint64_t started=sys_monotonic_millis();
    REQUIRE(!lookup("fresh.test",NULL,port,&test->hints,&test->addresses));
    REQUIRE(sys_monotonic_millis()-started<2000);
    freeaddrinfo(test->addresses);test->addresses=NULL;
    sys_sleep_ms(4500);
    REQUIRE(!lookup("fresh.test",NULL,port,&test->hints,&test->addresses));
    freeaddrinfo(test->addresses);test->addresses=NULL;
    return 0;
}
int main(int argc,char **argv)
{
    fixture_t *test=calloc(1,sizeof(*test)); REQUIRE(test);
    test->hints=(struct addrinfo){.ai_family=AF_INET,.ai_socktype=SOCK_STREAM,.ai_flags=AI_CANONNAME};
    if(argc==4&&!strcmp(argv[1],"dns-child"))
    {
        REQUIRE(write(atoi(argv[3]),"R",1)==1);
        (void)lookup("blocked.test",NULL,(uint16_t)atoi(argv[2]),&test->hints,&test->addresses);
        REQUIRE(false);
    }
    REQUIRE(argc==3);uint16_t dns_port=(uint16_t)atoi(argv[1]);
    REQUIRE(lookup("missing.test",NULL,dns_port,&test->hints,&test->addresses)==EAI_NONAME&&!test->addresses);
    REQUIRE(lookup("temporary.test",NULL,dns_port,&test->hints,&test->addresses)==EAI_AGAIN&&!test->addresses);
    REQUIRE(lookup("invalid.test",NULL,dns_port,&test->hints,&test->addresses)==EAI_FAIL&&!test->addresses);
    REQUIRE(lookup("truncated.test",NULL,dns_port,&test->hints,&test->addresses)==EAI_AGAIN&&!test->addresses);
    REQUIRE(!lookup("wrong-question.test",NULL,dns_port,&test->hints,&test->addresses));
    freeaddrinfo(test->addresses);test->addresses=NULL;
    uint64_t endpoint=(UINT64_C(0x0a000202)<<32)|dns_port;
    REQUIRE(sys_file_io(SYSCALL_FILE_DNS_RESOLVE,0,(uintptr_t)&test->reply,sizeof(test->reply),endpoint)==-EFAULT);
    REQUIRE(__alix_dns_query4("fresh.test",0x0a000202,dns_port,(syscall_dns_reply_t*)"readonly")==-1&&errno==EFAULT);
    for(unsigned index=0;index<8;++index)
    {
        job_t *job=&test->jobs[index];job->index=index;job->port=dns_port;job->socket=-1;job->ready=&test->ready;job->start=&test->start;
        snprintf(job->service,sizeof(job->service),"%u",(unsigned)(uint16_t)atoi(argv[2]));
        REQUIRE(!pthread_create(&job->thread,NULL,worker,job));
    }
    uint64_t deadline=sys_monotonic_millis()+8000;
    while(__atomic_load_n(&test->ready,__ATOMIC_SEQ_CST)!=8&&sys_monotonic_millis()<deadline)sys_sleep_ms(1);
    bool ready=__atomic_load_n(&test->ready,__ATOMIC_SEQ_CST)==8;
    if(ready)for(unsigned left=0;left<8;++left)for(unsigned right=left+1;right<8;++right)if(test->jobs[left].tls_host==test->jobs[right].tls_host)ready=false;
    __atomic_store_n(&test->start,1u,__ATOMIC_SEQ_CST);
    unsigned failures=ready?0:1;
    for(unsigned index=0;index<8;++index){REQUIRE(!pthread_join(test->jobs[index].thread,NULL));if(test->jobs[index].failed){++failures;serial_printf("NETDB_TEST: FAIL cpu=%u line=%u errno=%d\n",index,test->jobs[index].failed,test->jobs[index].error);}}
    REQUIRE(!failures&&!canceled_lookup(test,dns_port));
    free(test);
    serial_printf("NETDB_TEST: PASS cpus=8 multi_a=1 cname=1 negatives=1 tls=1 tcp=1 copy_checks=1 canceled_caller=1\n");
    return 0;
}
