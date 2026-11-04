#include "interrupts.h"
#include "signal_abi.h"
#include "syscall.h"
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define GDT_SELECTOR_USER_CODE 0x28u
#define GDT_SELECTOR_USER_DATA 0x30u
#define RFLAGS_DEFAULT 0x202u
#define USER_ADDRESS_SPACE_BASE 0x100000000ULL
#define USER_ADDRESS_SPACE_LIMIT 0x7FFFFFFFFFFFULL
#define USER_STUB_CODE_BASE 0x3FFFFFFFE000ULL
#define USER_PREEMPT_STUB_BASE (USER_STUB_CODE_BASE + 4096u)
#define PROCESS_MAGIC 0xCAFEu
#define PROCESS_LIFETIME_ALIVE 1
#define PROCESS_STATE_ZOMBIE 2

typedef struct
{
    unsigned wakeups;
    int lock;
    struct thread *head,*tail;
} wait_queue_t;
typedef int spinlock_t;
typedef struct process process_t;
typedef struct thread
{
    process_t *process;
    struct thread *process_next;
    bool is_user, exited, pending_destroy;
    uint64_t tid;
    void *io_request;
    bool io_interruptible;
    bool futex_waiting, futex_interrupted, futex_notified;
    wait_queue_t futex_queue;
    unsigned time_slice_remaining;
    alix_sigset_t signal_mask, signal_pending;
    alix_siginfo_t signal_info[ALIX_SIGNAL_COUNT];
    alix_stack_t signal_altstack;
    struct process_signal_frame *signal_frames;
    uint64_t signal_sequence;
    uint64_t signal_jump_epoch;
    uint32_t signal_depth;
    int signal_fault_number;
    bool signal_onstack, signal_sleeping, signal_sleep_interrupted;
    wait_queue_t signal_wait_queue;
    alix_sigset_t sigwait_mask;
    bool sigwait_active;
    wait_queue_t sigwait_queue;
    wait_queue_t *waiting_queue;
    struct thread *wait_queue_next;
    unsigned state;
    uint8_t fpu_state[512] __attribute__((aligned(16)));
} thread_t;
struct process
{
    struct process *next;
    thread_t *threads;
    spinlock_t threads_lock;
    bool is_user;
    unsigned uid, magic, lifetime_state, state;
    uint32_t join_waiters;
    uint64_t pid;
    uint64_t alarm_deadline;
    struct process *alarm_next;
    alix_sigaction_t signal_actions[ALIX_SIGNAL_COUNT];
    alix_sigset_t signal_pending;
    alix_siginfo_t signal_info[ALIX_SIGNAL_COUNT];
};
static thread_t *model_current;
#define THREAD_STATE_BLOCKED 1u
static bool thread_in_run_queue_load(const thread_t *thread) { (void)thread; return false; }
static void remove_from_run_queue_locked(thread_t *thread) { (void)thread; }
static void thread_remove_from_wait_queue(thread_t *thread) { thread->waiting_queue=NULL; }
static void (*model_schedule_hook)(void);
static void scheduler_schedule(bool force)
{
    (void)force;
    assert(model_schedule_hook);
    model_schedule_hook();
}
static void process_io_cancel_thread_locked(thread_t *thread) { (void)thread; abort(); }
static process_t *g_process_list;
static spinlock_t g_process_lock;
static uint64_t model_flags = RFLAGS_DEFAULT;
static unsigned model_lock, model_guard, model_live;
static int model_fail_alloc = -1, model_copy_fail = -1;
static bool model_prepare = true;
static uint8_t model_fp[512];
static uint8_t *model_user;
static size_t model_user_size;
static uint64_t model_ticks;
static bool model_interrupt_wait;
static int model_exit_status, model_kill_status;
static jmp_buf model_exit_jump;
static void *model_calloc(size_t count, size_t size)
{
    if (model_fail_alloc == 0)
        return NULL;
    if (model_fail_alloc > 0)
        --model_fail_alloc;
    void *p = calloc(count, size);
    if (p)
        ++model_live;
    return p;
}
static void model_free(void *p)
{
    if (p)
    {
        assert(model_live);
        --model_live;
        free(p);
    }
}
static bool user_ptr_range_valid(const void *p, size_t n)
{
    uintptr_t a = (uintptr_t)p;
    return a >= USER_ADDRESS_SPACE_BASE && n && n - 1 <= USER_ADDRESS_SPACE_LIMIT - a &&
           a <= USER_ADDRESS_SPACE_LIMIT;
}
static bool model_copy_ok(const void *p, size_t n)
{
    if (model_copy_fail == 0)
        return false;
    if (model_copy_fail > 0)
        --model_copy_fail;
    uintptr_t a = (uintptr_t)p, b = (uintptr_t)model_user;
    return a >= b && a - b <= model_user_size && n <= model_user_size - (a - b);
}
static bool user_copy_from_user(void *dst, const void *src, size_t n)
{
    if (!model_copy_ok(src, n))
        return false;
    memcpy(dst, src, n);
    return true;
}
static bool user_copy_to_user(void *dst, const void *src, size_t n)
{
    if (!model_copy_ok(dst, n))
        return false;
    memcpy(dst, src, n);
    return true;
}
static bool model_address_mapped;
static bool process_signal_address_mapped(process_t *p, uintptr_t a)
{
    (void)p;
    (void)a;
    return model_address_mapped;
}
static bool process_signal_prepare_user_frame(process_t *p, uintptr_t a, size_t n)
{
    (void)p;
    return model_prepare && model_copy_ok((void *)a, n);
}
static thread_t *current_thread_local(void)
{
    return model_current;
}
static bool thread_lifetime_active(thread_t *t)
{
    return !t->exited;
}
static uint64_t cpu_save_flags(void)
{
    return model_flags;
}
static void cpu_cli(void)
{
    model_flags &= ~0x200ULL;
}
static void cpu_restore_flags(uint64_t f)
{
    model_flags = f;
}
static uint64_t scheduler_lock_acquire(const char *reason)
{
    (void)reason;
    assert(!model_lock);
    ++model_lock;
    uint64_t f = cpu_save_flags();
    cpu_cli();
    return f;
}
static void scheduler_lock_release(uint64_t f)
{
    assert(model_lock == 1);
    --model_lock;
    cpu_restore_flags(f);
}
static void spinlock_lock(spinlock_t *p)
{
    assert(!*p);
    *p = 1;
}
static void spinlock_unlock(spinlock_t *p)
{
    assert(*p);
    *p = 0;
}
static uint64_t spinlock_lock_irqsave(spinlock_t *p)
{
    uint64_t f = cpu_save_flags();
    cpu_cli();
    spinlock_lock(p);
    return f;
}
static void spinlock_unlock_irqrestore(spinlock_t *p, uint64_t f)
{
    spinlock_unlock(p);
    cpu_restore_flags(f);
}
static void spinlock_preempt_disable(void)
{
    ++model_guard;
}
static void spinlock_preempt_enable(void)
{
    assert(model_guard);
    --model_guard;
}
static void wait_queue_init(wait_queue_t *q)
{
    memset(q, 0, sizeof(*q));
}
static void wait_queue_wake_all_locked(wait_queue_t *q)
{
    assert(model_lock);
    ++q->wakeups;
}
static void smp_broadcast_schedule_ipi(bool wait)
{
    assert(!wait);
}
static void fpu_restore_state(const void *p)
{
    memcpy(model_fp, p, 512);
}
static _Noreturn void process_exit(int n)
{
    assert(!model_lock && !model_guard);
    model_exit_status = n;
    longjmp(model_exit_jump, 1);
}
static _Noreturn void process_exit_signal(int number) { process_exit(128+number); }
static bool process_kill_signal(process_t *p, int n)
{
    p->state = PROCESS_STATE_ZOMBIE;
    model_kill_status = 128+n;
    return true;
}
static void process_release_reference(process_t *p)
{
    assert(p->join_waiters);
    --p->join_waiters;
}
static void serial_printf(const char *format, ...)
{
    (void)format;
}
static uint64_t timer_frequency(void)
{
    return 1000;
}
static uint64_t timer_ticks(void)
{
    return model_ticks;
}
static bool wait_queue_wait_timeout(wait_queue_t *q, bool (*pred)(void *), void *arg, uint64_t ticks)
{
    (void)q;
    if (pred(arg))
        return true;
    if (model_interrupt_wait)
    {
        model_ticks += ticks / 3;
        model_current->signal_pending |= 1ULL << (ALIX_SIGUSR1 - 1);
        model_current->signal_info[ALIX_SIGUSR1].si_signo = ALIX_SIGUSR1;
        model_current->signal_sleep_interrupted = true;
    }
    else
        model_ticks += ticks;
    return pred(arg);
}
#define calloc model_calloc
#define free model_free
