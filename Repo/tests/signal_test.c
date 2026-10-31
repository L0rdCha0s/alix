#include "signal.h"
#include "pthread.h"
#include "stdlib.h"
#include "string.h"
#include "serial.h"
#include "errno.h"
#include "usyscall.h"

#define WORKERS 8u
#define RAISES 256u
static volatile uint32_t handled;
static volatile uint32_t failed;
static volatile uint32_t nested;
static _Thread_local uint64_t caller_tid;

typedef struct { pthread_t tid; } worker_t;

static void handle_interrupt(int number)
{
    if (number != SIGINT || sys_thread_self() != caller_tid)
        __atomic_store_n(&failed, 1, __ATOMIC_RELEASE);
    __atomic_add_fetch(&handled, 1, __ATOMIC_ACQ_REL);
}

static void handle_term(int number)
{
    if (number != SIGTERM) __atomic_store_n(&failed, 1, __ATOMIC_RELEASE);
    __atomic_add_fetch(&nested, 1, __ATOMIC_ACQ_REL);
}

static void handle_fpe(int number)
{
    if (number != SIGFPE || raise(SIGTERM) != 0)
        __atomic_store_n(&failed, 1, __ATOMIC_RELEASE);
}

static void handle_abort(int number)
{
    serial_printf("SIGNAL_TEST: abort-handler %s\n", number == SIGABRT ? "PASS" : "FAIL");
}

static void *worker_main(void *unused)
{
    (void)unused;
    caller_tid = sys_thread_self();
    for (unsigned index = 0; index < RAISES; ++index)
        if (raise(SIGINT) != 0) __atomic_store_n(&failed, 1, __ATOMIC_RELEASE);
    return NULL;
}

#define CHECK(condition, label) do { if (!(condition)) { \
    serial_printf("SIGNAL_TEST: FAIL %s\n", label); return 1; } } while (0)

int main(int argc, char **argv)
{
    if (argc > 1 && strcmp(argv[1], "default-fpe") == 0)
    {
        serial_printf("SIGNAL_TEST: default-fpe armed\n");
        raise(SIGFPE);
        serial_printf("SIGNAL_TEST: FAIL default returned\n");
        return 1;
    }
    if (argc > 1 && strcmp(argv[1], "abort-handler") == 0)
    {
        CHECK(signal(SIGABRT, handle_abort) == SIG_DFL, "abort registration");
        abort();
    }
    if (argc > 1 && strcmp(argv[1], "abort-ignored") == 0)
    {
        CHECK(signal(SIGABRT, SIG_IGN) == SIG_DFL, "abort ignore registration");
        serial_printf("SIGNAL_TEST: abort-ignored armed\n");
        abort();
    }
    CHECK(signal(SIGINT, handle_interrupt) == SIG_DFL, "initial registration");
    CHECK(signal(SIGINT, SIG_IGN) == handle_interrupt && raise(SIGINT) == 0 && handled == 0,
          "ignored disposition");
    CHECK(signal(SIGINT, handle_interrupt) == SIG_IGN, "previous disposition");
    CHECK(signal(SIGFPE, handle_fpe) == SIG_DFL && signal(SIGTERM, handle_term) == SIG_DFL,
          "nested registration");
    CHECK(raise(SIGFPE) == 0 && raise(SIGFPE) == 0 && nested == 2 && !failed,
          "persistent nested handlers");
    CHECK(signal(SIGINT, SIG_ERR) == SIG_ERR && errno == EINVAL &&
          signal(-1, SIG_IGN) == SIG_ERR && errno == EINVAL &&
          raise(32) == -1 && errno == EINVAL, "invalid signal and handler");
    worker_t *workers = calloc(WORKERS, sizeof(*workers));
    CHECK(workers != NULL, "worker allocation");
    for (unsigned index = 0; index < WORKERS; ++index)
        CHECK(pthread_create(&workers[index].tid, NULL, worker_main, NULL) == 0, "worker create");
    for (unsigned index = 0; index < WORKERS; ++index)
        CHECK(pthread_join(workers[index].tid, NULL) == 0, "worker join");
    free(workers);
    CHECK(handled == WORKERS * RAISES && !failed, "calling-thread signal delivery");
    serial_printf("SIGNAL_TEST: PASS handlers=2048 nested=2 persistent=1\n");
    return 0;
}
