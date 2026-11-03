#include "arpa/inet.h"
#include "errno.h"
#include "pthread.h"
#include "pwd.h"
#include "serial.h"
#include "stdlib.h"
#include "string.h"
#include "unistd.h"
#include "usyscall.h"

#define CHECK(c, label) do { if (!(c)) { serial_printf("BASE_ACCOUNTS_INET_TEST: FAIL %s line=%u errno=%d\n", label, __LINE__, errno); return 1; } } while (0)
typedef struct fixture fixture_t;
typedef struct
{
    fixture_t *fixture;
    pthread_t thread;
    unsigned cpu, failed;
    uintptr_t entry_address, text_address;
} job_t;
struct fixture
{
    job_t jobs[8];
    unsigned ready, release;
    uid_t uid;
    struct passwd *main_entry;
    char name[256], home[4096];
};
static const struct { const char *text; uint32_t value; } valid[] = {
    {"127.0.0.1",0x7f000001u}, {"127.1",0x7f000001u}, {"127.0.1",0x7f000001u},
    {"0x7f000001",0x7f000001u}, {"0177.0.0.1",0x7f000001u},
    {"2130706433",0x7f000001u}, {"1.16777215",0x01ffffffu},
    {"0",0}, {"255.255.255.255",0xffffffffu}, {"4294967295",0xffffffffu},
};
static const char *invalid[] = {"", "-1", "+1", "256.0.0.1", "1.2.65536", "1.2.3.4.5", "08.1.1.1", "1..1", " 127.1", "127.1 ", "0x100000000", "999999999999999999999999999999999999"};
static void *worker(void *context)
{
    job_t *job = context; fixture_t *fixture = job->fixture;
    if (sys_thread_set_affinity(job->cpu) || sys_thread_cpu() != job->cpu) { job->failed = 1; return NULL; }
    struct passwd *entry = getpwuid(fixture->uid);
    struct in_addr address = { htonl(0x0a000001u + job->cpu) };
    char *text = inet_ntoa(address);
    if (!entry || !text) { job->failed = 2; return NULL; }
    job->entry_address = (uintptr_t)entry; job->text_address = (uintptr_t)text;
    __atomic_add_fetch(&fixture->ready, 1u, __ATOMIC_RELEASE);
    while (!__atomic_load_n(&fixture->release, __ATOMIC_ACQUIRE)) sys_yield();
    for (unsigned round = 0; round < 64 && !job->failed; ++round)
    {
        errno = EDOM;
        entry = getpwuid(fixture->uid);
        if (!entry || (uintptr_t)entry != job->entry_address || entry->pw_uid != fixture->uid ||
            strcmp(entry->pw_name, fixture->name) || strcmp(entry->pw_dir, fixture->home) || errno != EDOM) { job->failed = 3; break; }
        entry = getpwnam(entry->pw_name);
        if (!entry || entry->pw_uid != fixture->uid || strcmp(entry->pw_dir, fixture->home) || errno != EDOM) { job->failed = 4; break; }
        struct in_addr parsed;
        if (!inet_aton(text, &parsed) || parsed.s_addr != address.s_addr || inet_addr(text) != address.s_addr || errno != EDOM) job->failed = 5;
    }
    return NULL;
}

int main(void)
{
    fixture_t *fixture = calloc(1, sizeof(*fixture)); CHECK(fixture, "heap fixture");
    fixture->uid = getuid(); errno = EDOM;
    fixture->main_entry = getpwuid(fixture->uid);
    CHECK(fixture->main_entry && fixture->main_entry->pw_uid == fixture->uid && errno == EDOM &&
          fixture->main_entry->pw_dir[0] == '/', "native current account");
    CHECK(strlen(fixture->main_entry->pw_name) < sizeof(fixture->name) &&
          strlen(fixture->main_entry->pw_dir) < sizeof(fixture->home), "account fixture bounds");
    strcpy(fixture->name, fixture->main_entry->pw_name); strcpy(fixture->home, fixture->main_entry->pw_dir);
    for (unsigned index = 0; index < sizeof(valid) / sizeof(valid[0]); ++index)
    {
        struct in_addr parsed; errno = EDOM;
        CHECK(inet_aton(valid[index].text, &parsed) && ntohl(parsed.s_addr) == valid[index].value &&
              inet_addr(valid[index].text) == parsed.s_addr && errno == EDOM, "legacy IPv4 integer forms");
    }
    for (unsigned index = 0; index < sizeof(invalid) / sizeof(invalid[0]); ++index)
    {
        struct in_addr parsed = { 0x12345678u }; errno = EDOM;
        CHECK(!inet_aton(invalid[index], &parsed) && parsed.s_addr == 0x12345678u &&
              inet_addr(invalid[index]) == INADDR_NONE && errno == EDOM, "invalid IPv4 form leaves output unchanged");
    }
    CHECK(!inet_pton(AF_INET, "127.1", &fixture->ready), "inet_pton remains strict");
    for (unsigned cpu = 0; cpu < 8; ++cpu)
    {
        fixture->jobs[cpu].cpu = cpu; fixture->jobs[cpu].fixture = fixture;
        CHECK(!pthread_create(&fixture->jobs[cpu].thread, NULL, worker, &fixture->jobs[cpu]), "lookup worker");
    }
    uint64_t deadline = sys_monotonic_millis() + 10000;
    while (__atomic_load_n(&fixture->ready, __ATOMIC_ACQUIRE) != 8 && sys_monotonic_millis() < deadline) sys_sleep_ms(1);
    CHECK(fixture->ready == 8, "all cached lookup states live");
    for (unsigned cpu = 0; cpu < 8; ++cpu)
    {
        CHECK(fixture->jobs[cpu].entry_address != (uintptr_t)fixture->main_entry, "main account state isolated");
        for (unsigned prior = 0; prior < cpu; ++prior)
            CHECK(fixture->jobs[cpu].entry_address != fixture->jobs[prior].entry_address &&
                  fixture->jobs[cpu].text_address != fixture->jobs[prior].text_address, "per-thread account and address storage");
    }
    __atomic_store_n(&fixture->release, 1u, __ATOMIC_RELEASE);
    for (unsigned cpu = 0; cpu < 8; ++cpu)
        CHECK(!pthread_join(fixture->jobs[cpu].thread, NULL) && !fixture->jobs[cpu].failed, "concurrent lookup completion");
    errno = EDOM;
    CHECK(!getpwnam("codex-missing-account-438572") && errno == EDOM && !getpwuid((uid_t)-1) && errno == EDOM, "missing account contract");
    CHECK(!getpwnam(NULL) && errno == EINVAL, "invalid account name");
    free(fixture);
    serial_printf("BASE_ACCOUNTS_INET_TEST: PASS cpus=8 lookups=1024 legacy_ipv4=10 invalid_ipv4=12 tls_storage=1 byte_order=1\n");
    return 0;
}
