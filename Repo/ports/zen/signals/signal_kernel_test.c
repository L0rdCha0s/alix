#include "errno.h"
#include "fenv.h"
#include "pthread.h"
#include "serial.h"
#include "signal.h"
#include "sys/mman.h"
#include "ucontext.h"
#include "userlib.h"
#include <stddef.h>
#include <stdint.h>

#define WORKERS 8u
#define CHECK(c, tag)                                                                                        \
    do                                                                                                       \
    {                                                                                                        \
        if (!(c))                                                                                            \
        {                                                                                                    \
            serial_printf("SIGNAL_KERNEL_TEST: FAIL %s\n", tag);                                             \
            return 1;                                                                                        \
        }                                                                                                    \
    } while (0)
typedef struct
{
    uint64_t registers[16], expected_rsp, flags, vectors[16][2];
    long double extended;
    uint32_t mxcsr;
} result_t;
_Static_assert(offsetof(result_t, vectors) == 144 && offsetof(result_t, extended) == 400 &&
                   offsetof(result_t, mxcsr) == 416,
               "assembly result ABI");
extern void signal_pf_probe(void *, result_t *), signal_ud_probe(void *, result_t *),
    signal_async_probe(void *, result_t *);
extern const char signal_pf_fault[], signal_pf_resume[], signal_ud_fault[], signal_ud_resume[],
    signal_async_fault[], signal_async_resume[];
extern void signal_clobber_fp(void);
extern void signal_edit_stack_probe(void *);
extern const char signal_edit_stack_fault[], signal_edit_stack_resume[];
typedef struct
{
    uintptr_t original_rsp, requested_rsp;
} edit_stack_t;
typedef struct shared shared_t;
typedef struct
{
    volatile uint32_t done, ready;
    shared_t *shared;
    pthread_t thread;
    unsigned index, fail, signals, nested, cpu_mask;
    unsigned expected_code, mode, depth;
    void *page, *alt;
    result_t *result;
    stack_t query;
    alix_signal_frame_t *frame, *scratch;
    edit_stack_t edit;
} worker_t;
struct shared
{
    worker_t workers[WORKERS];
    volatile uint32_t barrier, release;
    volatile uintptr_t frames[WORKERS];
};
static _Thread_local worker_t *self;
static void fail(unsigned code)
{
    if (self && !self->fail)
        self->fail = code;
}
static void handler(int number, siginfo_t *info, void *argument)
{
    worker_t *w = self;
    ucontext_t *context = argument;
    if (!w || !context || !info)
        sys_exit(91);
    uintptr_t here = (uintptr_t)&w;
    if (here < (uintptr_t)w->alt || here >= (uintptr_t)w->alt + SIGSTKSZ)
        fail(10);
    uint64_t flags;
    __asm__ volatile("pushfq; pop %0" : "=r"(flags));
    if (flags & 0x400)
        fail(11);
    if (sys_sigaltstack(NULL, &w->query, sizeof(w->query)) || w->query.ss_flags != SS_ONSTACK)
        fail(12);
    ++w->depth;
    ++w->signals;
    if (w->mode == 3 && number == SIGILL)
    {
        if (context->uc_mcontext.rip != (uintptr_t)signal_edit_stack_fault ||
            info->si_addr != (void *)signal_edit_stack_fault)
            fail(50);
        context->uc_mcontext.rip = (uintptr_t)signal_edit_stack_resume;
        context->uc_mcontext.rsp = w->edit.requested_rsp;
        --w->depth;
        signal_clobber_fp();
        return;
    }
    if (w->mode == 4 && (here >= w->edit.requested_rsp - 128 || context->uc_stack.ss_flags != SS_ONSTACK))
        fail(51);
    if (number == SIGUSR2)
    {
        if (w->depth != 2)
            fail(13);
        ++w->nested;
        --w->depth;
        signal_clobber_fp();
        return;
    }
    if (w->depth != 1)
        fail(14);
    if (number == SIGUSR1)
    {
        if (context->uc_mcontext.rip < (uintptr_t)signal_async_fault ||
            context->uc_mcontext.rip >= (uintptr_t)signal_async_resume)
            fail(15);
        const uint64_t *red = (void *)(uintptr_t)(context->uc_mcontext.rsp - 128);
        for (unsigned i = 0; i < 16; ++i)
            if (red[i] != UINT64_C(0x1111111111111111))
                fail(16);
        __atomic_store_n(&w->done, 1u, __ATOMIC_RELEASE);
    }
    else
    {
        if (info->si_signo != number)
            fail(17);
        if (number == SIGSEGV)
        {
            if (context->uc_mcontext.rip != (uintptr_t)signal_pf_fault || info->si_addr != w->page ||
                info->si_code != (int)w->expected_code)
                fail(18);
            context->uc_mcontext.rip = (uintptr_t)signal_pf_resume;
        }
        else if (number == SIGILL)
        {
            if (context->uc_mcontext.rip != (uintptr_t)signal_ud_fault ||
                info->si_addr != (void *)signal_ud_fault || info->si_code != ILL_ILLOPC)
                fail(19);
            context->uc_mcontext.rip = (uintptr_t)signal_ud_resume;
        }
        else
            fail(20);
        if ((context->uc_mcontext.rflags & 0x601) != 0x601)
            fail(21);
        if (raise(SIGUSR2) != 0)
            fail(22);
        alix_signal_frame_t *frame = (void *)((uint8_t *)context - offsetof(alix_signal_frame_t, context));
        w->frame = frame;
        uint64_t sequence = frame->sequence;
        frame->sequence++;
        if (sys_sigreturn((uintptr_t)frame) != -EINVAL)
            fail(23);
        frame->sequence = sequence;
        uint64_t cs = context->uc_mcontext.cs;
        context->uc_mcontext.cs = 8;
        if (sys_sigreturn((uintptr_t)frame) != -EINVAL)
            fail(24);
        context->uc_mcontext.cs = cs;
        uint32_t *mxcsr = (void *)(context->uc_mcontext.fpregs + 24), value = *mxcsr;
        *mxcsr |= 0x80000000u;
        if (sys_sigreturn((uintptr_t)frame) != -EINVAL)
            fail(25);
        *mxcsr = value;
        memcpy(w->scratch, frame, sizeof(*frame));
        if (sys_sigreturn((uintptr_t)w->scratch) != -EPERM)
            fail(26);
        if (w->mode == 0)
        {
            __atomic_store_n(&w->shared->frames[w->index], (uintptr_t)frame, __ATOMIC_RELEASE);
            __atomic_add_fetch(&w->shared->barrier, 1u, __ATOMIC_RELEASE);
            while (__atomic_load_n(&w->shared->barrier, __ATOMIC_ACQUIRE) != WORKERS)
                sys_yield();
            uintptr_t other = __atomic_load_n(&w->shared->frames[(w->index + 1) % WORKERS], __ATOMIC_ACQUIRE);
            if (sys_sigreturn(other) != -EPERM)
                fail(27);
            if (sys_thread_set_affinity((w->index + 1) % WORKERS))
                fail(28);
        }
    }
    --w->depth;
    signal_clobber_fp();
}
static bool verify_result(worker_t *w, void *argument, bool flags)
{
    result_t *r = w->result;
    for (unsigned i = 0; i < 15; ++i)
    {
        uint64_t expected = UINT64_C(0x1111111111111111) * (i + 1u);
        if (i == 13)
            expected = (uintptr_t)argument;
        if (r->registers[i] != expected)
        {
            fail(30 + i);
            return false;
        }
    }
    if (r->registers[15] != r->expected_rsp || (flags && (r->flags & 0x601) != 0x601))
    {
        fail(45);
        return false;
    }
    for (unsigned i = 0; i < 16; ++i)
        if (r->vectors[i][0] != UINT64_C(0x0123456789abcdef) + i ||
            r->vectors[i][1] != UINT64_C(0xfedcba9876543210) - i)
        {
            fail(46);
            return false;
        }
    if (r->extended != 1.0L + 0x1p-60L || fegetround() != FE_UPWARD || (r->mxcsr & 0x6000) != 0x4000)
    {
        fail(47);
        return false;
    }
    return true;
}
void signal_edited_stack_callback(edit_stack_t *edit)
{
    worker_t *w = self;
    if (edit != &w->edit || sigaltstack(NULL, &w->query) || w->query.ss_flags != SS_ONSTACK)
        fail(52);
    stack_t disabled = {.ss_flags = SS_DISABLE};
    if (sigaltstack(&disabled, NULL) != -1 || errno != EPERM)
        fail(53);
    w->mode = 4;
    signal_ud_probe(w->page, w->result);
    verify_result(w, w->page, true);
}
static void *worker(void *arg)
{
    worker_t *w = arg;
    self = w;
    if (sys_thread_set_affinity(w->index))
        fail(1);
    w->cpu_mask = 1u << sys_thread_cpu();
    stack_t stack = {.ss_sp = w->alt, .ss_size = SIGSTKSZ};
    if (sigaltstack(&stack, NULL) || fesetround(FE_UPWARD))
        fail(2);
    w->mode = 0;
    w->expected_code = SEGV_ACCERR;
    signal_pf_probe(w->page, w->result);
    verify_result(w, w->page, true);
    w->cpu_mask |= 1u << sys_thread_cpu();
    w->mode = 1;
    signal_ud_probe(w->page, w->result);
    verify_result(w, w->page, true);
    /* A protected nonpresent PTE after discard remains an access violation. */
    if (mprotect(w->page, 4096, PROT_READ | PROT_WRITE))
        fail(3);
    *(volatile unsigned char *)w->page = 0x5a;
    if (mprotect(w->page, 4096, PROT_READ) || madvise(w->page, 4096, MADV_DONTNEED))
        fail(4);
    signal_pf_probe(w->page, w->result);
    verify_result(w, w->page, true);
    void *old = w->page;
    if (munmap(old, 4096))
        fail(5);
    w->expected_code = SEGV_MAPERR;
    signal_pf_probe(old, w->result);
    verify_result(w, old, true);
    w->page = NULL;
    w->mode = 2;
    signal_async_probe(w, w->result);
    verify_result(w, w, false);
    w->mode = 3;
    w->edit.requested_rsp = ((uintptr_t)w->alt + SIGSTKSZ / 2) & ~(uintptr_t)15;
    signal_edit_stack_probe(&w->edit);
    stack.ss_flags = SS_DISABLE;
    if (sigaltstack(&stack, NULL))
        fail(6);
    if (w->signals != 12 || w->nested != 5)
        fail(7);
    return NULL;
}
extern void signal_main_stack_probe(void), signal_badframe_probe(void);
extern const char signal_main_stack_fault[], signal_main_stack_resume[];
static volatile unsigned main_stack_handled;
static void main_stack_handler(int number, siginfo_t *info, void *argument)
{
    ucontext_t *context = argument;
    if (number != SIGILL || info->si_addr != (void *)signal_main_stack_fault ||
        context->uc_mcontext.rip != (uintptr_t)signal_main_stack_fault)
        sys_exit(92);
    context->uc_mcontext.rip = (uintptr_t)signal_main_stack_resume;
    ++main_stack_handled;
}
typedef struct
{
    pthread_t target;
    volatile unsigned handled;
    int status;
    struct timespec request, remaining;
} sleep_state_t;
static sleep_state_t *sleep_state;
static void sleep_handler(int number)
{
    if (number == SIGUSR1)
        __atomic_add_fetch(&sleep_state->handled, 1u, __ATOMIC_RELEASE);
}
static void *sleep_sender(void *argument)
{
    sleep_state_t *state = argument;
    sys_sleep_ms(20);
    state->status = pthread_kill(state->target, SIGUSR1);
    return NULL;
}
static int mask_sleep_test(void)
{
    sleep_state = calloc(1, sizeof(*sleep_state));
    CHECK(sleep_state, "sleep state");
    sleep_state->target = pthread_self();
    CHECK(signal(SIGUSR1, sleep_handler) != SIG_ERR, "sleep action");
    sigset_t set, pending;
    CHECK(sigemptyset(&set) == 0 && sigaddset(&set, SIGUSR1) == 0 &&
              pthread_sigmask(SIG_BLOCK, &set, NULL) == 0,
          "block");
    CHECK(raise(SIGUSR1) == 0 && raise(SIGUSR1) == 0 && sleep_state->handled == 0 &&
              sigpending(&pending) == 0 && sigismember(&pending, SIGUSR1) == 1,
          "pending coalescing");
    CHECK(pthread_sigmask(SIG_UNBLOCK, &set, NULL) == 0 && sleep_state->handled == 1, "unblock delivery");
    pthread_t sender;
    CHECK(pthread_create(&sender, NULL, sleep_sender, sleep_state) == 0, "sleep sender");
    sleep_state->request = (struct timespec){.tv_sec = 2, .tv_nsec = 123};
    CHECK(nanosleep(&sleep_state->request, &sleep_state->remaining) == -1 && errno == EINTR,
          "sleep interrupt");
    CHECK(sleep_state->remaining.tv_sec >= 0 && sleep_state->remaining.tv_sec <= 2 &&
              sleep_state->remaining.tv_nsec >= 0 && sleep_state->remaining.tv_nsec < 1000000000L &&
              (sleep_state->remaining.tv_sec < 2 || sleep_state->remaining.tv_nsec <= 123),
          "sleep remaining");
    CHECK(pthread_join(sender, NULL) == 0 && sleep_state->status == 0 && sleep_state->handled == 2,
          "sleep callback");
    free(sleep_state);
    sleep_state = NULL;
    return 0;
}
int main(int argc, char **argv)
{
    if (argc > 1 && strcmp(argv[1], "default") == 0)
    {
        serial_printf("SIGNAL_KERNEL_TEST: DEFAULT_ARMED pid=%d tid=%llu signo=15 status=143 vector=0 "
                      "site=0x0000000000000000\n",
                      sys_getpid(), (unsigned long long)sys_thread_self());
        sys_sleep_ms(20);
        raise(SIGTERM);
        serial_printf("SIGNAL_KERNEL_TEST: FAIL default returned\n");
        return 2;
    }
    if (argc > 1 && strcmp(argv[1], "badframe") == 0)
    {
        self = calloc(1, sizeof(*self));
        CHECK(self != NULL, "badframe state allocation");
        self->alt = mmap(NULL, SIGSTKSZ, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        CHECK(self->alt != MAP_FAILED, "badframe alternate mapping");
        stack_t alt = {.ss_sp = self->alt, .ss_size = SIGSTKSZ};
        struct sigaction action = {.sa_sigaction = handler, .sa_flags = SA_SIGINFO | SA_ONSTACK};
        CHECK(sigaltstack(&alt, NULL) == 0 && sigaction(SIGILL, &action, NULL) == 0, "badframe setup");
        serial_printf(
            "SIGNAL_KERNEL_TEST: BADFRAME_ARMED pid=%d tid=%llu signo=4 status=132 vector=6 site=0x%016llX\n",
            sys_getpid(), (unsigned long long)sys_thread_self(),
            (unsigned long long)(uintptr_t)signal_badframe_probe);
        sys_sleep_ms(20);
        signal_badframe_probe();
        serial_printf("SIGNAL_KERNEL_TEST: FAIL badframe returned\n");
        return 2;
    }
    struct sigaction main_action = {.sa_sigaction = main_stack_handler, .sa_flags = SA_SIGINFO};
    CHECK(sigaction(SIGILL, &main_action, NULL) == 0, "main stack action");
    signal_main_stack_probe();
    CHECK(main_stack_handled == 1, "fresh main stack signal frame");
    shared_t *s = calloc(1, sizeof(*s));
    CHECK(s, "shared allocation");
    struct sigaction action = {.sa_sigaction = handler, .sa_flags = SA_SIGINFO | SA_ONSTACK};
    CHECK(sigemptyset(&action.sa_mask) == 0 && sigaction(SIGSEGV, &action, NULL) == 0 &&
              sigaction(SIGILL, &action, NULL) == 0 && sigaction(SIGUSR1, &action, NULL) == 0 &&
              sigaction(SIGUSR2, &action, NULL) == 0,
          "actions");
    CHECK(sys_sigreturn(0) == -EPERM, "unowned sigreturn");
    sigset_t mask;
    CHECK(sigemptyset(&mask) == 0 && sigaddset(&mask, SIGKILL) == 0 &&
              pthread_sigmask(SIG_BLOCK, &mask, NULL) == 0 &&
              pthread_sigmask(SIG_SETMASK, NULL, &mask) == 0 && sigismember(&mask, SIGKILL) == 0,
          "unblockable mask");
    for (unsigned i = 0; i < WORKERS; ++i)
    {
        worker_t *w = &s->workers[i];
        w->index = i;
        w->shared = s;
        w->alt = malloc(SIGSTKSZ);
        w->result = calloc(1, sizeof(*w->result));
        w->scratch = calloc(1, sizeof(*w->scratch));
        w->page = mmap(NULL, 4096, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        CHECK(w->alt && w->result && w->scratch && w->page != MAP_FAILED, "worker allocation");
        CHECK(pthread_create(&w->thread, NULL, worker, w) == 0, "thread create");
    }
    uint64_t deadline = sys_monotonic_millis() + 10000;
    for (;;)
    {
        unsigned ready = 0;
        for (unsigned i = 0; i < WORKERS; ++i)
            ready += __atomic_load_n(&s->workers[i].ready, __ATOMIC_ACQUIRE) != 0;
        if (ready == WORKERS)
            break;
        CHECK(sys_monotonic_millis() < deadline, "async preparation timeout");
        sys_yield();
    }
    for (unsigned i = 0; i < WORKERS; ++i)
        CHECK(pthread_kill(s->workers[i].thread, SIGUSR1) == 0, "async queue");
    unsigned cpu_mask = 0, signals = 0;
    for (unsigned i = 0; i < WORKERS; ++i)
    {
        worker_t *w = &s->workers[i];
        CHECK(pthread_join(w->thread, NULL) == 0, "join");
        if (w->fail)
        {
            serial_printf("SIGNAL_KERNEL_TEST: FAIL worker=%u code=%u\n", i, w->fail);
            return 1;
        }
        cpu_mask |= w->cpu_mask;
        signals += w->signals;
        free(w->result);
        free(w->scratch);
        free(w->alt);
    }
    CHECK(cpu_mask == 0xff && signals == 96, "completion counts");
    free(s);
    CHECK(mask_sleep_test() == 0, "mask sleep test");
    serial_printf("SIGNAL_KERNEL_TEST: PASS workers=8 cpu_mask=0xFF signals=96 gpr=15 xmm=16 x87=1 alt=1 "
                  "nested=1 forged=1 redzone=1 async=1 masks=1 sleep=1 stack=1 edited_rsp=1\n");
    return 0;
}
