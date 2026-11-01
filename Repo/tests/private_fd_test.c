#include "usyscall.h"
#include "pthread.h"
#include "stdlib.h"
#include "string.h"
#include "serial.h"
#include "errno.h"

#define CHECK(c,label) do { if (!(c)) { serial_printf("PRIVATE_FD_TEST: FAIL %s\n",label); return 1; } } while (0)
#define PTR(p) ((uint64_t)(uintptr_t)(p))
#define CALL(op,a,b,c,d) sys_file_io((op),(uint64_t)(a),(uint64_t)(b),(uint64_t)(c),(uint64_t)(d))
#define RECORDS 512u
#define WORKERS 8u
typedef struct shared shared_t;
typedef struct
{
    shared_t *shared;
    pthread_t thread;
    int fd;
    unsigned cpu,failed;
    uint32_t value;
} reader_t;
struct shared
{
    reader_t readers[WORKERS];
    uint32_t seen[RECORDS], mask;
};

static void *reader(void *argument)
{
    reader_t *record = argument;
    if (sys_thread_set_affinity(record->cpu) || sys_thread_cpu() != record->cpu)
    { record->failed = 1; return NULL; }
    for (;;)
    {
        int64_t bytes = CALL(SYSCALL_FILE_READ,record->fd,PTR(&record->value),sizeof(record->value),0);
        if (!bytes) break;
        if (bytes != sizeof(record->value) || record->value >= RECORDS) { record->failed = 2; break; }
        __atomic_add_fetch(&record->shared->seen[record->value],1u,__ATOMIC_RELAXED);
    }
    __atomic_fetch_or(&record->shared->mask,1u<<record->cpu,__ATOMIC_RELEASE);
    return NULL;
}

static int capture_child(void)
{
    int copy = (int)CALL(SYSCALL_FILE_DUP,1,0,0,0);
    CHECK(copy >= 3 && CALL(SYSCALL_FILE_CLOSE,1,0,0,0) == 0, "capture child duplicates stdout");
    static const char captured[] = "PRIVATE_CAPTURE_ONLY\n";
    CHECK(CALL(SYSCALL_FILE_WRITE,copy,PTR(captured),sizeof(captured)-1,0) == sizeof(captured)-1,
          "capture output after original close");
    CHECK(CALL(SYSCALL_FILE_CLOSE,copy,0,0,0) == 0, "capture child closes alias");
    return 0;
}

int main(int argc, char **argv)
{
    if (argc > 1 && !strcmp(argv[1],"capture-child")) return capture_child();
    char *buffer = calloc(1,128);
    syscall_stat_t *stat = calloc(1,sizeof(*stat));
    CHECK(buffer && stat, "heap buffers");
    CHECK(CALL(SYSCALL_FILE_READ,0,PTR(buffer),1,0) == 0, "owned stdin EOF");
    CHECK(CALL(SYSCALL_FILE_STAT,1,PTR(stat),0,0) == 0 && stat->type == SYSCALL_NODE_TYPE_CHARACTER,
          "owned stdout character metadata");
    int fd = (int)CALL(SYSCALL_FILE_OPEN,PTR("/tmp/private-fd-basic"),
                       SYSCALL_OPEN_READ|SYSCALL_OPEN_WRITE|SYSCALL_OPEN_CREATE|SYSCALL_OPEN_TRUNCATE|SYSCALL_OPEN_CLOEXEC,0,0);
    CHECK(fd == 3, "private lowest fd after stdio");
    CHECK(CALL(SYSCALL_FILE_GETFD,fd,0,0,0) == SYSCALL_FILE_CLOEXEC, "open CLOEXEC");
    static const char text[] = "alpha beta gamma";
    CHECK(CALL(SYSCALL_FILE_WRITE,fd,PTR(text),sizeof(text)-1,0) == sizeof(text)-1, "owned write");
    CHECK(CALL(SYSCALL_FILE_SEEK,fd,0,SYSCALL_SEEK_SET,0) == 0, "seek start");
    int copy = (int)CALL(SYSCALL_FILE_DUP,fd,0,0,0);
    CHECK(copy == 4 && CALL(SYSCALL_FILE_GETFD,copy,0,0,0) == 0, "dup resets descriptor flags");
    CHECK(CALL(SYSCALL_FILE_READ,fd,PTR(buffer),3,0) == 3 && !memcmp(buffer,"alp",3), "original read");
    CHECK(CALL(SYSCALL_FILE_READ,copy,PTR(buffer),2,0) == 2 && !memcmp(buffer,"ha",2), "dup shares offset");
    CHECK(CALL(SYSCALL_FILE_PREAD,copy,PTR(buffer),5,0) == 5 && !memcmp(buffer,"alpha",5), "pread bytes");
    CHECK(CALL(SYSCALL_FILE_SEEK,fd,0,SYSCALL_SEEK_CUR,0) == 5, "pread keeps shared offset");
    CHECK(CALL(SYSCALL_FILE_SETFD,copy,SYSCALL_FILE_CLOEXEC,0,0) == 0 &&
          CALL(SYSCALL_FILE_GETFD,fd,0,0,0) == SYSCALL_FILE_CLOEXEC, "independent flags");
    CHECK(CALL(SYSCALL_FILE_SETFD,copy,2,0,0) == -EINVAL && CALL(SYSCALL_FILE_GETFD,copy,0,0,0) == 1,
          "invalid flags preserve slot");
    CHECK(CALL(SYSCALL_FILE_DUP2,copy,copy,0,0) == copy && CALL(SYSCALL_FILE_GETFD,copy,0,0,0) == 1,
          "dup2 self preserves flags");
    CHECK(CALL(SYSCALL_FILE_DUP3,copy,copy,1,0) == -EINVAL, "dup3 self rejected");
    CHECK(CALL(SYSCALL_FILE_CLOSE,fd,0,0,0) == 0, "close original");
    int replacement = (int)CALL(SYSCALL_FILE_OPEN,PTR("/tmp/private-fd-replacement"),
                               SYSCALL_OPEN_READ|SYSCALL_OPEN_WRITE|SYSCALL_OPEN_CREATE|SYSCALL_OPEN_TRUNCATE,0,0);
    CHECK(replacement == fd, "closed slot reused");
    CHECK(CALL(SYSCALL_FILE_DUP2,copy,replacement,0,0) == replacement &&
          CALL(SYSCALL_FILE_GETFD,replacement,0,0,0) == 0, "dup2 atomically replaces and clears flags");
    CHECK(CALL(SYSCALL_FILE_READ,replacement,PTR(buffer),5,0) == 5 && !memcmp(buffer," beta",5), "replaced alias old description");
    CHECK(CALL(SYSCALL_FILE_CLOSE,copy,0,0,0) == 0 && CALL(SYSCALL_FILE_CLOSE,replacement,0,0,0) == 0,
          "close aliases");
    CHECK(CALL(SYSCALL_FILE_READ,copy,PTR(buffer),1,0) == -EBADF &&
          CALL(SYSCALL_FILE_GETFD,UINT64_C(0x100000001),0,0,0) == -EBADF, "invalid fd is not truncated/fallback");
    CHECK(CALL(SYSCALL_FILE_OPEN,PTR("/tmp/private-fd-does-not-exist"),SYSCALL_OPEN_READ,0,0) == -ENOENT,
          "failed open");
    fd = (int)CALL(SYSCALL_FILE_OPEN,PTR("/tmp/private-fd-full-protection"),
                   SYSCALL_OPEN_READ|SYSCALL_OPEN_WRITE|SYSCALL_OPEN_CREATE|SYSCALL_OPEN_TRUNCATE,0,0);
    CHECK(fd == 3, "failed open releases reservation before return");
    CHECK(CALL(SYSCALL_FILE_WRITE,fd,PTR("KEEP"),4,0) == 4 && CALL(SYSCALL_FILE_CLOSE,fd,0,0,0) == 0,
          "save capacity fixture");
    int *aliases = calloc(253,sizeof(*aliases));
    CHECK(aliases, "heap aliases");
    for (unsigned index = 0; index < 253; ++index)
    {
        aliases[index] = (int)CALL(SYSCALL_FILE_DUP,2,0,0,0);
        CHECK(aliases[index] == (int)index + 3, "private table capacity");
    }
    CHECK(CALL(SYSCALL_FILE_DUP,2,0,0,0) == -EMFILE, "dup full table");
    CHECK(CALL(SYSCALL_FILE_OPEN,PTR("/tmp/private-fd-full-protection"),SYSCALL_OPEN_WRITE|SYSCALL_OPEN_TRUNCATE,0,0) == -EMFILE,
          "open full table before truncate");
    for (unsigned index = 0; index < 253; ++index) CHECK(CALL(SYSCALL_FILE_CLOSE,aliases[index],0,0,0) == 0, "release capacity");
    fd = (int)CALL(SYSCALL_FILE_OPEN,PTR("/tmp/private-fd-full-protection"),SYSCALL_OPEN_READ,0,0);
    CHECK(fd == 3 && CALL(SYSCALL_FILE_READ,fd,PTR(buffer),4,0) == 4 && !memcmp(buffer,"KEEP",4),
          "failed truncating open preserved file");
    CHECK(CALL(SYSCALL_FILE_CLOSE,fd,0,0,0) == 0, "close preserved fixture");
    fd = (int)CALL(SYSCALL_FILE_OPEN,PTR("/tmp/private-fd-records"),
                   SYSCALL_OPEN_READ|SYSCALL_OPEN_WRITE|SYSCALL_OPEN_CREATE|SYSCALL_OPEN_TRUNCATE,0,0);
    uint32_t *records = malloc(RECORDS*sizeof(*records));
    shared_t *shared = calloc(1,sizeof(*shared));
    CHECK(fd == 3 && records && shared, "concurrent state");
    for (unsigned index = 0; index < RECORDS; ++index) records[index] = index;
    CHECK(CALL(SYSCALL_FILE_WRITE,fd,PTR(records),RECORDS*sizeof(*records),0) == RECORDS*sizeof(*records) &&
          CALL(SYSCALL_FILE_SEEK,fd,0,SYSCALL_SEEK_SET,0) == 0, "record fixture");
    for (unsigned index = 0; index < WORKERS; ++index)
    {
        reader_t *record = &shared->readers[index];record->shared=shared;record->cpu=index;
        record->fd = (int)CALL(SYSCALL_FILE_DUP,fd,0,0,0);
        CHECK(record->fd >= 4 && pthread_create(&record->thread,NULL,reader,record) == 0, "start shared reader");
    }
    for (unsigned index = 0; index < WORKERS; ++index)
    {
        reader_t *record = &shared->readers[index];
        CHECK(pthread_join(record->thread,NULL) == 0 && !record->failed, "join shared reader");
        CHECK(CALL(SYSCALL_FILE_CLOSE,record->fd,0,0,0) == 0, "close shared alias");
    }
    CHECK(shared->mask == 0xff, "all CPUs");
    for (unsigned index = 0; index < RECORDS; ++index) CHECK(shared->seen[index] == 1, "shared offset exactly once");
    CHECK(CALL(SYSCALL_FILE_CLOSE,fd,0,0,0) == 0, "close records");
    CHECK(CALL(SYSCALL_FILE_CLOSE,1,0,0,0) == 0 && CALL(SYSCALL_FILE_WRITE,1,PTR("x"),1,0) == -EBADF,
          "missing private stdout never uses legacy console");
    CHECK(CALL(SYSCALL_FILE_DUP2,2,1,0,0) == 1, "restore stdout from shared stderr");
    static const char once[] = "PRIVATE_STDIO_ONCE\n";
    CHECK(CALL(SYSCALL_FILE_WRITE,1,PTR(once),sizeof(once)-1,0) == sizeof(once)-1, "owned stdout write");
    CHECK(argc == 2 && atoi(argv[1]) > 0, "HTTP test port");
    int socket = (int)CALL(SYSCALL_FILE_SOCKET_OPEN,0,0,0,0);
    CHECK(socket == 3, "private socket open");
    CHECK(CALL(SYSCALL_FILE_STAT,socket,PTR(stat),0,0) == 0 && stat->type == SYSCALL_NODE_TYPE_SOCKET, "socket metadata");
    copy = (int)CALL(SYSCALL_FILE_DUP,socket,0,0,0);
    CHECK(copy == 4 && CALL(SYSCALL_FILE_CLOSE,socket,0,0,0) == 0, "duplicate keeps owned socket");
    CHECK(CALL(SYSCALL_FILE_SOCKET_CONNECT,copy,PTR("10.0.2.2"),(unsigned)atoi(argv[1]),0) == 0,
          "DNS-to-TCP request handoff");
    static const char request[] = "GET /private HTTP/1.0\r\nHost: alix-test\r\nConnection: close\r\n\r\n";
    CHECK(CALL(SYSCALL_FILE_WRITE,copy,PTR(request),sizeof(request)-1,0) == sizeof(request)-1, "private socket write");
    char *response = malloc(65536);
    CHECK(response, "heap network response");
    size_t received = 0;
    for (;;)
    {
        CHECK(received <= 65535u - 4096u, "bounded response");
        int64_t bytes = CALL(SYSCALL_FILE_READ,copy,PTR(response+received),4096u,0);
        CHECK(bytes >= 0, "private socket read");
        if (!bytes) break;
        received += (size_t)bytes;
    }
    response[received] = 0;
    CHECK(received >= 12 && !memcmp(response,"HTTP/1.0 200",12), "private HTTP status");
    char *body = strstr(response,"\r\n\r\n");
    CHECK(body, "private HTTP headers");body += 4;
    CHECK(received - (size_t)(body-response) == 16384u, "complete private HTTP body");
    for (unsigned index = 0; index < 16384; ++index)
        CHECK((unsigned char)body[index] == (unsigned char)(index*73u+19u), "private HTTP body bytes");
    CHECK(CALL(SYSCALL_FILE_CLOSE,copy,0,0,0) == 0, "close final private socket alias");
    int session = sys_shell_open();
    CHECK(session > 0, "capture session");
    static const char child_command[] = "runelf /tmp/test.elf capture-child";
    CHECK(sys_shell_exec((uint32_t)session,child_command,sizeof(child_command)-1) == 0, "run capture child");
    int *state = calloc(2,sizeof(*state));
    CHECK(state, "heap capture status");
    size_t output_bytes = 0;
    uint64_t deadline = sys_monotonic_millis() + 10000;
    for (;;)
    {
        CHECK(output_bytes < 65535u, "bounded capture");
        ssize_t bytes = sys_shell_poll((uint32_t)session,response+output_bytes,65536u-output_bytes,&state[0],&state[1]);
        CHECK(bytes >= 0, "poll child capture");
        output_bytes += (size_t)bytes;
        if (!state[1]) break;
        CHECK(sys_monotonic_millis() < deadline, "capture deadline");
        sys_sleep_ms(1);
    }
    response[output_bytes] = 0;
    CHECK(state[0] == 0, "capture child completion");
    char *captured = strstr(response,"PRIVATE_CAPTURE_ONLY");
    CHECK(captured && !strstr(captured+1,"PRIVATE_CAPTURE_ONLY"), "explicit capture output exactly once");
    CHECK(sys_shell_close((uint32_t)session) == 0, "close capture session");
    free(state);free(response);
    free(shared);free(records);free(aliases);free(stat);free(buffer);
    serial_printf("PRIVATE_FD_TEST: PASS workers=8 mask=0xFF records=512 dup=1 flags=1 capacity256=1 no_fallback=1 failed_truncate_preserved=1 HTTP=16384 capture_once=1\n");
    return 0;
}
