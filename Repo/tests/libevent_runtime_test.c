#include "event2/event.h"
#include "event2/util.h"
#include "errno.h"
#include "fcntl.h"
#include "net/if.h"
#include "pthread.h"
#include "serial.h"
#include "stdlib.h"
#include "string.h"
#include "unistd.h"
#include "usyscall.h"

#define CHECK(c, label) do { if (!(c)) { serial_printf("LIBEVENT_TEST: FAIL %s line=%u errno=%d\n", label, __LINE__, errno); return 1; } } while (0)
typedef struct
{
    pthread_t thread;
    unsigned cpu, phase, ready, failed, bytes, timers;
    int pipes[2];
    struct event_base *base;
    struct event *reader, *timer, *deadline;
    struct timeval interval, limit;
    char buffer[16];
} event_job_t;
typedef struct
{
    event_job_t jobs[8];
    syscall_net_stats_t interfaces[8];
    unsigned char entropy_a[32], entropy_b[32];
    char name[IF_NAMESIZE];
} event_fixture_t;

static void maybe_done(event_job_t *job)
{
    if (job->bytes == 4 && job->timers >= 2) event_base_loopbreak(job->base);
}
static void readable(evutil_socket_t fd, short events, void *context)
{
    event_job_t *job = context;
    ssize_t count = read(fd, job->buffer, sizeof(job->buffer));
    if (!(events & EV_READ) || count <= 0) { job->failed = 1; event_base_loopbreak(job->base); return; }
    job->bytes += (unsigned)count; maybe_done(job);
}
static void timer(evutil_socket_t fd, short events, void *context)
{
    (void)fd;
    event_job_t *job = context;
    if (!(events & EV_TIMEOUT)) job->failed = 1;
    ++job->timers; maybe_done(job);
}
static void expired(evutil_socket_t fd, short events, void *context)
{
    (void)fd; (void)events;
    event_job_t *job = context; job->failed = 1; event_base_loopbreak(job->base);
}
static void *event_worker(void *context)
{
    event_job_t *job = context;
    struct event_config *config = event_config_new();
    if (!config || sys_thread_set_affinity(job->cpu) || sys_thread_cpu() != job->cpu) goto failed;
    if (job->phase && event_config_avoid_method(config, "poll")) goto failed;
    job->base = event_base_new_with_config(config); event_config_free(config); config = NULL;
    if (!job->base || strcmp(event_base_get_method(job->base), job->phase ? "select" : "poll") ||
        pipe2(job->pipes, O_NONBLOCK | O_CLOEXEC)) goto failed;
    job->reader = event_new(job->base, job->pipes[0], EV_READ | EV_PERSIST, readable, job);
    job->timer = event_new(job->base, -1, EV_PERSIST, timer, job);
    job->deadline = evtimer_new(job->base, expired, job);
    job->interval.tv_usec = 20000; job->limit.tv_sec = 3;
    if (!job->reader || !job->timer || !job->deadline || event_add(job->reader, NULL) ||
        event_add(job->timer, &job->interval) || event_add(job->deadline, &job->limit)) goto failed;
    __atomic_store_n(&job->ready, 1, __ATOMIC_RELEASE);
    if (event_base_dispatch(job->base) < 0 || job->bytes != 4 || job->timers < 2) job->failed = 1;
    event_free(job->deadline); event_free(job->timer); event_free(job->reader); event_base_free(job->base);
    close(job->pipes[0]); close(job->pipes[1]);
    return NULL;
failed:
    if (config) event_config_free(config);
    job->failed = 1; __atomic_store_n(&job->ready, 2, __ATOMIC_RELEASE);
    return NULL;
}
int main(void)
{
    event_fixture_t *test = calloc(1, sizeof(*test)); CHECK(test, "heap fixture");
    ssize_t count = sys_net_snapshot(test->interfaces, 8); CHECK(count > 0 && count <= 8, "native interfaces");
    for (ssize_t index = 0; index < count; ++index)
    {
        if (!test->interfaces[index].present) continue;
        errno = EDOM;
        CHECK(if_nametoindex(test->interfaces[index].name) == (unsigned)index + 1 && errno == EDOM &&
              if_indextoname((unsigned)index + 1, test->name) == test->name && errno == EDOM &&
              !strcmp(test->name, test->interfaces[index].name), "real interface index roundtrip");
    }
    CHECK(!if_nametoindex("missing-interface") && errno == ENXIO &&
          !if_indextoname(99, test->name) && errno == ENXIO, "unknown interface errors");
    CHECK(!evutil_secure_rng_init(), "native entropy initialization");
    evutil_secure_rng_get_bytes(test->entropy_a, sizeof(test->entropy_a));
    evutil_secure_rng_get_bytes(test->entropy_b, sizeof(test->entropy_b));
    CHECK(memcmp(test->entropy_a, test->entropy_b, sizeof(test->entropy_a)), "kernel entropy reaches libevent");
    for (unsigned phase = 0; phase < 2; ++phase)
    {
        memset(test->jobs, 0, sizeof(test->jobs));
        for (unsigned cpu = 0; cpu < 8; ++cpu)
        {
            event_job_t *job = &test->jobs[cpu]; job->cpu = cpu; job->phase = phase;
            CHECK(!pthread_create(&job->thread, NULL, event_worker, job), "event worker creation");
        }
        for (unsigned cpu = 0; cpu < 8; ++cpu)
        {
            event_job_t *job = &test->jobs[cpu]; uint64_t limit = sys_monotonic_millis() + 5000;
            while (!__atomic_load_n(&job->ready, __ATOMIC_ACQUIRE) && sys_monotonic_millis() < limit) sys_sleep_ms(1);
            CHECK(__atomic_load_n(&job->ready, __ATOMIC_ACQUIRE) == 1 && write(job->pipes[1], "WAKE", 4) == 4, "cross-thread pipe wake");
        }
        for (unsigned cpu = 0; cpu < 8; ++cpu)
            CHECK(!pthread_join(test->jobs[cpu].thread, NULL) && !test->jobs[cpu].failed, "native event loop completion");
    }
    free(test);
    serial_printf("LIBEVENT_TEST: PASS cpus=8 poll=8 select=8 timers=1 pipe_wake=1 entropy=1 interface_names=1\n");
    return 0;
}
