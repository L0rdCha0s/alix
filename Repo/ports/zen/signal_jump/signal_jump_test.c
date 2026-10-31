#include "errno.h"
#include "fenv.h"
#include "limits.h"
#include "pthread.h"
#include "serial.h"
#include "setjmp.h"
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
            serial_printf("SIGNAL_JUMP_TEST: FAIL %s\n", tag);                                               \
            return 1;                                                                                        \
        }                                                                                                    \
    } while (0)
_Static_assert(sizeof(jmp_buf) == 64 && sizeof(sigjmp_buf) == 128, "separate native jump ABIs");
enum
{
    P_PENDING = 1,
    P_RETIRED,
    P_ALL,
    P_ANCESTOR,
    P_HARDWARE
};
typedef struct shared shared_t;
typedef struct
{
    shared_t *shared;
    pthread_t thread;
    unsigned index, failed, mode, mask, cpu_mask;
    unsigned pending_calls, outer_calls, inner_calls, ancestor_returns, outer_done, hardware_calls, repeats;
    sigjmp_buf base, inside, retired, cross, bad;
    void *alt;
    sigset_t queried, empty, usr1, usr2;
    stack_t stack;
} worker_t;
struct shared
{
    worker_t workers[WORKERS];
    volatile unsigned cross_ready, cross_done;
};
static _Thread_local worker_t *self;
extern void signal_jump_ud2(void);
static void fail(unsigned code)
{
    if (self && !self->failed)
        self->failed = code;
}
static void current_fp(int mode)
{
    if (fesetround(mode))
        fail(70);
    __asm__ volatile("fnclex; fldz; fldz; fdivp; fstp %%st(0)" ::: "memory");
    uint32_t mxcsr;
    __asm__ volatile("stmxcsr %0" : "=m"(mxcsr));
    mxcsr |= FE_INVALID | FE_INEXACT;
    __asm__ volatile("ldmxcsr %0" ::"m"(mxcsr));
}
static void verify_fp(int mode)
{
    uint16_t cw, sw;
    uint32_t mxcsr;
    __asm__ volatile("fnstcw %0; fnstsw %1; stmxcsr %2" : "=m"(cw), "=m"(sw), "=m"(mxcsr));
    if (fegetround() != mode || (cw & 0xc00) != (unsigned)mode || !(sw & FE_INVALID) || !(mxcsr & FE_INVALID))
        fail(71);
}
static int raw_restore(sigjmp_buf environment, int value)
{
    return sys_signal_jump(ALIX_SIGJUMP_RESTORE, environment, sizeof(sigjmp_buf), value);
}
static void handler(int number, siginfo_t *info, void *opaque)
{
    worker_t *w = self;
    ucontext_t *context = opaque;
    if (!w || !info || !context)
        sys_exit(94);
    uintptr_t local = (uintptr_t)&w;
    if (local < (uintptr_t)w->alt || local >= (uintptr_t)w->alt + SIGSTKSZ)
        fail(10);
    if (w->mode == P_PENDING)
    {
        if (number != SIGUSR1)
            fail(11);
        ++w->pending_calls;
        return;
    }
    if (w->mode == P_RETIRED)
    {
        if (number != SIGUSR1)
            fail(12);
        switch (sigsetjmp(w->retired, 1))
        {
        case 0:
            ++w->outer_calls;
            return;
        default:
            fail(13);
            return;
        }
    }
    if (w->mode == P_HARDWARE)
    {
        if (number != SIGILL || info->si_addr != (void *)signal_jump_ud2 ||
            context->uc_mcontext.rip != (uintptr_t)signal_jump_ud2)
            fail(14);
        ++w->hardware_calls;
        current_fp(FE_TOWARDZERO);
        siglongjmp(w->base, 4);
    }
    if (number == SIGUSR2)
    {
        ++w->inner_calls;
        current_fp(FE_DOWNWARD);
        if (w->mode == P_ALL)
            siglongjmp(w->base, 37);
        if (w->mode == P_ANCESTOR)
            siglongjmp(w->inside, 41);
        fail(15);
        return;
    }
    if (number != SIGUSR1)
    {
        fail(16);
        return;
    }
    ++w->outer_calls;
    if (w->mode == P_ALL)
    {
        if (raise(SIGUSR2))
            fail(17);
        fail(18);
        return;
    }
    if (w->mode == P_ANCESTOR)
    {
        switch (sigsetjmp(w->inside, 1))
        {
        case 0:
            if (raise(SIGUSR2))
                fail(19);
            fail(20);
            return;
        case 41:
            ++w->ancestor_returns;
            verify_fp(FE_DOWNWARD);
            if (pthread_sigmask(SIG_SETMASK, NULL, &w->queried) || sigismember(&w->queried, SIGUSR1) != 1 ||
                sigismember(&w->queried, SIGUSR2) != 0)
                fail(21);
            if (sigaltstack(NULL, &w->stack) || w->stack.ss_flags != SS_ONSTACK)
                fail(22);
            if (w->ancestor_returns < 3)
            {
                if (raise(SIGUSR2))
                    fail(23);
                fail(24);
                return;
            }
            ++w->outer_done;
            return;
        default:
            fail(25);
            return;
        }
    }
    fail(26);
}
static void *worker(void *argument)
{
    worker_t *w = argument;
    self = w;
    if (sys_thread_set_affinity(w->index))
        fail(1);
    w->cpu_mask = 1u << sys_thread_cpu();
    w->stack = (stack_t){.ss_sp = w->alt, .ss_size = SIGSTKSZ};
    if (sigaltstack(&w->stack, NULL))
        fail(2);
    sigemptyset(&w->empty);
    w->usr1 = w->usr2 = w->empty;
    sigaddset(&w->usr1, SIGUSR1);
    sigaddset(&w->usr2, SIGUSR2);
    if (pthread_sigmask(SIG_SETMASK, &w->empty, NULL))
        fail(3);
    switch (sigsetjmp(w->base, 0))
    {
    case 0:
        current_fp(FE_DOWNWARD);
        siglongjmp(w->base, -7);
    case -7:
        verify_fp(FE_DOWNWARD);
        siglongjmp(w->base, -1);
    case -1:
        siglongjmp(w->base, INT_MIN);
    case INT_MIN:
        verify_fp(FE_DOWNWARD);
        break;
    default:
        fail(30);
        break;
    }
    switch (sigsetjmp(w->base, 1))
    {
    case 0:
        siglongjmp(w->base, 0);
    case 1:
        if (++w->repeats < 64)
            siglongjmp(w->base, 0);
        break;
    default:
        fail(31);
        break;
    }
    /* savemask=0 retains the mask at siglongjmp, not the capture mask. */
    if (pthread_sigmask(SIG_SETMASK, &w->usr2, NULL))
        fail(32);
    switch (sigsetjmp(w->base, 0))
    {
    case 0:
        if (pthread_sigmask(SIG_BLOCK, &w->usr1, NULL))
            fail(33);
        siglongjmp(w->base, 8);
    case 8:
        if (pthread_sigmask(SIG_SETMASK, NULL, &w->queried) || sigismember(&w->queried, SIGUSR1) != 1 ||
            sigismember(&w->queried, SIGUSR2) != 1)
            fail(34);
        break;
    default:
        fail(35);
        break;
    }
    /* Restoring a saved mask delivers newly unblocked pending signals at the
     * saved continuation, before sigsetjmp's nonzero return is observed. */
    if (pthread_sigmask(SIG_SETMASK, &w->usr2, NULL))
        fail(36);
    w->mode = P_PENDING;
    switch (sigsetjmp(w->base, 1))
    {
    case 0:
        if (pthread_sigmask(SIG_BLOCK, &w->usr1, NULL) || raise(SIGUSR1) || w->pending_calls)
            fail(37);
        siglongjmp(w->base, 9);
    case 9:
        if (w->pending_calls != 1 || pthread_sigmask(SIG_SETMASK, NULL, &w->queried) || w->queried != w->usr2)
            fail(38);
        break;
    default:
        fail(39);
        break;
    }
    if (pthread_sigmask(SIG_SETMASK, &w->empty, NULL))
        fail(40);
    switch (sigsetjmp(w->cross, 1))
    {
    case 0:
        break;
    default:
        fail(41);
        break;
    }
    __atomic_add_fetch(&w->shared->cross_ready, 1u, __ATOMIC_RELEASE);
    while (__atomic_load_n(&w->shared->cross_ready, __ATOMIC_ACQUIRE) != WORKERS)
        sys_yield();
    worker_t *other = &w->shared->workers[(w->index + 1) % WORKERS];
    if (!w->cross[0].epoch || w->cross[0].epoch == other->cross[0].epoch ||
        w->cross[0].owner_tid == other->cross[0].owner_tid || raw_restore(other->cross, 1) != -EPERM)
        fail(42);
    __atomic_add_fetch(&w->shared->cross_done, 1u, __ATOMIC_RELEASE);
    while (__atomic_load_n(&w->shared->cross_done, __ATOMIC_ACQUIRE) != WORKERS)
        sys_yield();
    w->mode = P_RETIRED;
    if (raise(SIGUSR1))
        fail(43);
    if (!w->retired[0].frame_sequence || raw_restore(w->retired, 1) != -EINVAL)
        fail(44);
    w->mode = P_ALL;
    switch (sigsetjmp(w->base, 1))
    {
    case 0:
        if (raise(SIGUSR1))
            fail(45);
        fail(46);
        break;
    case 37:
        if (sigsetjmp(w->bad, 0) != 0)
            fail(62);
        if (w->bad[0].frame_sequence != 0)
            fail(62);
        verify_fp(FE_DOWNWARD);
        if (pthread_sigmask(SIG_SETMASK, NULL, &w->queried) || w->queried != w->empty)
            fail(47);
        break;
    default:
        fail(48);
        break;
    }
    /* With savemask=0, automatic blocks from abandoned handlers stay in the
     * current mask; only frame ownership and the continuation are unwound. */
    switch (sigsetjmp(w->base, 0))
    {
    case 0:
        if (raise(SIGUSR1))
            fail(64);
        fail(65);
        break;
    case 37:
        if (pthread_sigmask(SIG_SETMASK, NULL, &w->queried) || w->queried != (w->usr1 | w->usr2))
            fail(66);
        if (pthread_sigmask(SIG_SETMASK, &w->empty, NULL))
            fail(67);
        break;
    default:
        fail(68);
        break;
    }
    w->mode = P_ANCESTOR;
    if (raise(SIGUSR1))
        fail(49);
    if (w->outer_done != 1 || w->ancestor_returns != 3 || raw_restore(w->inside, 1) != -EINVAL)
        fail(50);
    w->mode = P_HARDWARE;
    switch (sigsetjmp(w->base, 0))
    {
    case 0:
        signal_jump_ud2();
        fail(51);
        break;
    case 4:
        if (sigsetjmp(w->bad, 0) != 0)
            fail(63);
        if (w->bad[0].frame_sequence != 0)
            fail(63);
        verify_fp(FE_TOWARDZERO);
        if (w->hardware_calls < 8)
            signal_jump_ud2();
        break;
    default:
        fail(52);
        break;
    }
    if (pthread_sigmask(SIG_SETMASK, NULL, &w->queried) || w->queried)
        fail(53);
    memcpy(w->bad, w->base, sizeof(w->bad));
    w->bad[0].epoch++;
    if (raw_restore(w->bad, 1) != -EPERM)
        fail(54);
    memcpy(w->bad, w->base, sizeof(w->bad));
    w->bad[0].reserved_words[1] = 1;
    if (raw_restore(w->bad, 1) != -EINVAL)
        fail(55);
    void *none = mmap(NULL, 4096, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (none == MAP_FAILED || sys_signal_jump(ALIX_SIGJUMP_RESTORE, none, sizeof(sigjmp_buf), 1) != -EFAULT)
        fail(56);
    if (none != MAP_FAILED && munmap(none, 4096))
        fail(57);
    w->stack.ss_flags = SS_DISABLE;
    if (sigaltstack(&w->stack, NULL))
        fail(58);
    jmp_buf plain;
    switch (setjmp(plain))
    {
    case 0:
        longjmp(plain, 13);
    case 13:
        break;
    default:
        fail(59);
        break;
    }
    if (w->base[0].owner_tid != pthread_self() || !w->base[0].epoch ||
        w->base[0].epoch != w->cross[0].epoch || w->inside[0].epoch != w->base[0].epoch || w->repeats != 64 ||
        w->hardware_calls != 8)
        fail(60);
    if (fesetround(FE_TONEAREST))
        fail(61);
    return NULL;
}
int main(void)
{
    shared_t *state = calloc(1, sizeof(*state));
    CHECK(state, "state allocation");
    struct sigaction action = {.sa_sigaction = handler, .sa_flags = SA_SIGINFO | SA_ONSTACK};
    CHECK(sigaction(SIGUSR1, &action, NULL) == 0 && sigaction(SIGUSR2, &action, NULL) == 0, "actions");
    action.sa_flags |= SA_NODEFER;
    CHECK(sigaction(SIGILL, &action, NULL) == 0, "hardware action");
    for (unsigned i = 0; i < WORKERS; ++i)
    {
        worker_t *w = &state->workers[i];
        w->shared = state;
        w->index = i;
        w->alt = malloc(SIGSTKSZ);
        CHECK(w->alt, "alternate allocation");
        CHECK(pthread_create(&w->thread, NULL, worker, w) == 0, "worker creation");
    }
    unsigned cpus = 0, hardware = 0, repeats = 0;
    for (unsigned i = 0; i < WORKERS; ++i)
    {
        worker_t *w = &state->workers[i];
        CHECK(pthread_join(w->thread, NULL) == 0, "join");
        if (w->failed)
        {
            serial_printf("SIGNAL_JUMP_TEST: FAIL worker=%u code=%u\n", i, w->failed);
            return 1;
        }
        cpus |= w->cpu_mask;
        hardware += w->hardware_calls;
        repeats += w->repeats;
        free(w->alt);
    }
    CHECK(cpus == 0xff && hardware == 64 && repeats == 512, "counts");
    free(state);
    serial_printf("SIGNAL_JUMP_TEST: PASS workers=8 cpu_mask=0xFF hardware=64 repeats=512 value0=1 "
                  "negative=1 mask0=1 mask1=1 pending=1 nested=1 ancestor=1 fp=1 stale=1 owner=1\n");
    return 0;
}
