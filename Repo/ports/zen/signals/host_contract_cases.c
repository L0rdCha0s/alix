#undef calloc
#undef free
static process_t *process;
static thread_t *first, *second;
static unsigned checks;
#define CHECK(expr)                                                                                          \
    do                                                                                                       \
    {                                                                                                        \
        ++checks;                                                                                            \
        if (!(expr))                                                                                         \
        {                                                                                                    \
            fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #expr);                                          \
            abort();                                                                                         \
        }                                                                                                    \
    } while (0)
static void reset_state(void)
{
    process_signal_thread_cleanup(first);
    process_signal_thread_cleanup(second);
    CHECK(model_live == 0);
    memset(first, 0, sizeof(*first));
    memset(second, 0, sizeof(*second));
    memset(process, 0, sizeof(*process));
    memset(model_user, 0, model_user_size);
    memset(model_fp, 0, sizeof(model_fp));
    uint32_t csr = 0x1f80, mask = 0xffff;
    memcpy(model_fp + 24, &csr, 4);
    memcpy(model_fp + 28, &mask, 4);
    for (unsigned i = 160; i < 512; ++i)
        model_fp[i] = (uint8_t)i;
    process->is_user = true;
    process->magic = PROCESS_MAGIC;
    process->lifetime_state = PROCESS_LIFETIME_ALIVE;
    process->uid = 100;
    process->pid = 42;
    process->threads = first;
    g_process_list = process;
    first->process = process;
    first->is_user = true;
    first->tid = 100;
    first->process_next = second;
    second->process = process;
    second->is_user = true;
    second->tid = 101;
    model_current = first;
    first->signal_altstack.ss_flags = second->signal_altstack.ss_flags = ALIX_SS_DISABLE;
    model_fail_alloc = model_copy_fail = -1;
    model_prepare = true;
    model_address_mapped = false;
    model_flags = RFLAGS_DEFAULT;
    model_interrupt_wait = false;
    model_ticks = 0;
    model_exit_status = model_kill_status = 0;
}
static void install_action(int n, uint32_t flags)
{
    alix_sigaction_t *a = (void *)model_user;
    *a = (alix_sigaction_t){.handler = (uintptr_t)model_user + 512, .flags = flags};
    CHECK(process_signal_sigaction(n, (uintptr_t)a, 0, sizeof(*a)) == 0);
}
static exception_frame_t fault_frame(unsigned vector)
{
    exception_frame_t f = {0};
    uint64_t *g = (void *)&f;
    for (unsigned i = 0; i < 15; ++i)
        g[i] = 0x11110000u + i;
    f.vector = vector;
    f.error_code = vector == 14 ? 6 : 0;
    f.cpu = (interrupt_frame_t){.rip = (uintptr_t)model_user + 1024,
                                .rsp = (uintptr_t)model_user + 65536,
                                .cs = 0x2b,
                                .ss = 0x33,
                                .rflags = 0x603};
    return f;
}
static void return_current(void)
{
    syscall_frame_t output = {0};
    uintptr_t address = first->signal_frames->address;
    CHECK(process_signal_return(&output, address) == 0);
    CHECK(!(model_flags & 0x200));
    model_flags = RFLAGS_DEFAULT;
}
static void frame_contract(void)
{
    reset_state();
    install_action(ALIX_SIGSEGV, ALIX_SA_SIGINFO | ALIX_SA_ONSTACK);
    install_action(ALIX_SIGILL, ALIX_SA_SIGINFO | ALIX_SA_ONSTACK);
    alix_stack_t *alt = (void *)(model_user + 128);
    *alt = (alix_stack_t){model_user + 131072, 65536, 0, 0};
    CHECK(process_signal_sigaltstack((uintptr_t)alt, 0, sizeof(*alt), (uintptr_t)model_user + 65536) == 0);
    exception_frame_t original = fault_frame(14), f = original;
    uint8_t original_fp[512];
    memcpy(original_fp, model_fp, 512);
    CHECK(process_signal_fault(&f, 0xdead0000));
    CHECK(first->signal_depth == 1 && first->signal_onstack);
    process_signal_frame_t *record = first->signal_frames;
    alix_signal_frame_t *user = (void *)record->address;
    CHECK(f.cpu.rsp % 16 == 8 && f.cpu.rip == (uintptr_t)model_user + 512);
    CHECK(*(uintptr_t *)(uintptr_t)f.cpu.rsp == USER_STUB_CODE_BASE + ALIX_SIGNAL_RESTORER_OFFSET);
    CHECK(f.rdi == ALIX_SIGSEGV && f.rsi == (uintptr_t)&user->info && f.rdx == (uintptr_t)&user->context);
    CHECK(!(f.cpu.rflags & 0x400));
    CHECK(!memcmp(&user->context.uc_mcontext, &original, 120));
    CHECK(!memcmp(&user->context.uc_mcontext.rip, &original.cpu, sizeof(original.cpu)));
    CHECK(!memcmp(user->context.uc_mcontext.fpregs, original_fp, 512));
    CHECK(user->info.si_addr == (void *)0xdead0000 && user->info.si_code == ALIX_SEGV_MAPERR);
    CHECK(first->signal_mask == signal_bit(ALIX_SIGSEGV));
    CHECK(process_signal_sigaltstack((uintptr_t)alt, 0, sizeof(*alt), f.cpu.rsp) == -EPERM);
    uintptr_t outer = record->address;
    exception_frame_t nested = f;
    nested.vector = 6;
    nested.cpu.rip += 32;
    CHECK(process_signal_fault(&nested, 0));
    CHECK(first->signal_depth == 2 && first->signal_onstack);
    syscall_frame_t output = {0};
    CHECK(process_signal_return(&output, outer) == -EPERM);
    return_current();
    CHECK(first->signal_depth == 1 && first->signal_onstack);
    user = (void *)first->signal_frames->address;
    alix_signal_frame_t pristine = *user;
#define REJECT(change)                                                                                       \
    do                                                                                                       \
    {                                                                                                        \
        *user = pristine;                                                                                    \
        change;                                                                                              \
        CHECK(process_signal_return(&output, (uintptr_t)user) == -EINVAL);                                   \
        CHECK(first->signal_depth == 1);                                                                     \
    } while (0)
    REJECT(user->owner_tid = second->tid);
    REJECT(user->sequence++);
    REJECT(user->frame_address += 16);
    REJECT(user->magic = 0);
    REJECT(user->context.uc_size--);
    REJECT(user->context.uc_flags = 0);
    REJECT(user->context.uc_mcontext.cs = 0x8);
    REJECT(user->context.uc_mcontext.ss = 0x10);
    REJECT(user->context.uc_mcontext.rip = 0xffff800000001000ULL);
    REJECT(user->context.uc_mcontext.rsp = 0x800000000000ULL + 1);
    REJECT(user->context.uc_mcontext.rflags |= 0x3000);
    REJECT(user->context.uc_mcontext.rflags &= ~0x200ULL);
    REJECT(user->context.uc_mcontext.fpregs[27] = 0x80);
#undef REJECT
    *user = pristine;
    model_current = second;
    CHECK(process_signal_return(&output, (uintptr_t)user) == -EPERM);
    model_current = first;
    user->context.uc_mcontext.rip += 3;
    user->context.uc_mcontext.rax = 77;
    memset(model_fp, 0x55, 512);
    /* Hardware MXCSR mask stays CPU-owned even when the handler changes state. */
    uint32_t mask = 0xffff;
    memcpy(model_fp + 28, &mask, 4);
    CHECK(process_signal_return(&output, (uintptr_t)user) == 0);
    CHECK(output.rax == 77 && output.rip == original.cpu.rip + 3);
    CHECK(output.rflags == original.cpu.rflags && !memcmp(model_fp, original_fp, 512));
    CHECK(first->signal_depth == 0 && !first->signal_onstack && first->signal_mask == 0 && model_live == 0);
}
static void pending_contract(void)
{
    reset_state();
    install_action(ALIX_SIGUSR1, ALIX_SA_SIGINFO);
    uint64_t *mask = (void *)(model_user + 128);
    *mask = signal_bit(ALIX_SIGUSR1) | SIGNAL_UNBLOCKABLE;
    CHECK(process_signal_sigprocmask(ALIX_SIG_BLOCK, (uintptr_t)mask, 0) == 0);
    CHECK(first->signal_mask == signal_bit(ALIX_SIGUSR1));
    CHECK(process_signal_raise(ALIX_SIGUSR1, 0) == 0);
    CHECK(first->signal_pending == signal_bit(ALIX_SIGUSR1));
    CHECK(process_signal_sigprocmask(ALIX_SIG_PENDING, 0, (uintptr_t)(mask + 1)) == 0 &&
          mask[1] == signal_bit(ALIX_SIGUSR1));
    exception_frame_t f = fault_frame(14);
    syscall_frame_t sf;
    memcpy(&sf, &f, 120);
    memcpy(&sf.rip, &f.cpu, 40);
    process_signal_syscall_return(&sf, 0);
    CHECK(!first->signal_frames);
    *mask = signal_bit(ALIX_SIGUSR1);
    CHECK(process_signal_sigprocmask(ALIX_SIG_UNBLOCK, (uintptr_t)mask, 0) == 0);
    first->io_request = (void *)1;
    process_signal_syscall_return(&sf, 0);
    CHECK(!first->signal_frames && first->signal_pending);
    first->io_request = NULL;
    process_signal_syscall_return(&sf, 0);
    CHECK(first->signal_depth == 1 && !first->signal_pending);
    return_current();
    first->futex_waiting = true;
    CHECK(process_signal_raise(ALIX_SIGUSR1, first->tid) == 0);
    CHECK(first->futex_interrupted && first->futex_notified && first->futex_queue.wakeups == 1);
    first->futex_waiting = false;
    first->signal_pending = 0;
    CHECK(process_signal_raise(0, second->tid) == 0 && process_signal_raise(0, 999) == -ESRCH);
    CHECK(process_signal_sigaction(ALIX_SIGKILL, (uintptr_t)model_user, 0, 24) == -EINVAL);
    CHECK(process_signal_raise(ALIX_SIGSTOP, 0) == -ENOTSUP &&
          process_signal_kill(0, ALIX_SIGUSR1) == -ENOTSUP);
    first->signal_mask = second->signal_mask = signal_bit(ALIX_SIGUSR1);
    CHECK(process_signal_kill(42, ALIX_SIGUSR1) == 0 && process->signal_pending == signal_bit(ALIX_SIGUSR1));
    CHECK(process->join_waiters == 0);
    first->signal_mask = 0;
    sf.rip = f.cpu.rip;
    sf.rsp = f.cpu.rsp;
    process_signal_syscall_return(&sf, 0);
    CHECK(first->signal_depth == 1 && !process->signal_pending);
    return_current();
    CHECK(process_signal_kill(999, 0) == -ESRCH);
    reset_state();
    if (!setjmp(model_exit_jump))
    {
        process_signal_raise(ALIX_SIGTERM, 0);
        CHECK(false);
    }
    CHECK(model_exit_status == 128 + ALIX_SIGTERM);
}
static void preempt_contract(void)
{
    reset_state();
    install_action(ALIX_SIGUSR1, ALIX_SA_SIGINFO);
    uint64_t *saved = (void *)(model_user + 65536);
    saved[0] = 0x603;
    for (unsigned i = 1; i <= 15; ++i)
        saved[i] = 0xAAAA0000u + i;
    uint64_t expected[16];
    memcpy(expected, saved, sizeof(expected));
    syscall_frame_t f = {.rip = USER_PREEMPT_STUB_BASE + ALIX_PREEMPT_RETURN_OFFSET,
                         .rsp = (uintptr_t)saved,
                         .cs = 0x2b,
                         .ss = 0x33,
                         .rflags = 0x202};
    CHECK(process_signal_raise(ALIX_SIGUSR1, 0) == 0);
    process_signal_syscall_return(&f, (uintptr_t)model_user + 1024);
    alix_mcontext_t *m = &((alix_signal_frame_t *)first->signal_frames->address)->context.uc_mcontext;
    CHECK(m->rip == (uintptr_t)model_user + 1024 && m->rsp == (uintptr_t)saved + 264 && m->rflags == 0x603);
    CHECK(m->r15 == expected[1] && m->r8 == expected[8] && m->rdi == expected[9] && m->rsi == expected[10]);
    CHECK(m->rbp == expected[11] && m->rbx == expected[12] && m->rdx == expected[13] &&
          m->rcx == expected[14] && m->rax == expected[15]);
    return_current();
}
static void failure_contract(void)
{
    for (int fail = 0; fail < 2; ++fail)
    {
        reset_state();
        install_action(ALIX_SIGSEGV, 0);
        model_fail_alloc = fail;
        exception_frame_t f = fault_frame(14);
        CHECK(!process_signal_fault(&f, 123));
        CHECK(!first->signal_frames && model_live == 0 && first->signal_fault_status == 139);
    }
    reset_state();
    install_action(ALIX_SIGSEGV, 0);
    model_prepare = false;
    exception_frame_t f = fault_frame(14);
    CHECK(!process_signal_fault(&f, 123) && model_live == 0);
    model_prepare = true;
    for (int fail = 0; fail < 3; ++fail)
    {
        model_copy_fail = fail;
        f = fault_frame(14);
        CHECK(!process_signal_fault(&f, 123) && model_live == 0);
    }
    model_copy_fail = -1;
    f = fault_frame(14);
    CHECK(process_signal_fault(&f, 123));
    model_copy_fail = 0;
    syscall_frame_t out = {0};
    CHECK(process_signal_return(&out, first->signal_frames->address) == -EFAULT);
    model_copy_fail = -1;
    process_signal_thread_cleanup(first);
    CHECK(model_live == 0);
    reset_state();
    install_action(ALIX_SIGSEGV, 0);
    model_address_mapped = true;
    f = fault_frame(14);
    CHECK(process_signal_fault(&f, 123));
    CHECK(((alix_signal_frame_t *)first->signal_frames->address)->info.si_code == ALIX_SEGV_ACCERR);
    return_current();
    reset_state();
    install_action(ALIX_SIGUSR1, ALIX_SA_NODEFER | ALIX_SA_RESETHAND);
    f = fault_frame(14);
    memcpy(&out, &f, 120);
    memcpy(&out.rip, &f.cpu, 40);
    CHECK(process_signal_raise(ALIX_SIGUSR1, 0) == 0);
    process_signal_syscall_return(&out, 0);
    CHECK(!first->signal_mask && !process->signal_actions[ALIX_SIGUSR1].handler);
    return_current();
}
static void oneshot_selection_contract(void)
{
    reset_state();
    install_action(ALIX_SIGUSR1, ALIX_SA_RESETHAND);
    first->signal_pending = second->signal_pending = signal_bit(ALIX_SIGUSR1);
    first->signal_info[ALIX_SIGUSR1].si_signo = second->signal_info[ALIX_SIGUSR1].si_signo = ALIX_SIGUSR1;
    alix_sigaction_t selected, other;
    alix_siginfo_t info, other_info;
    uint64_t flags = scheduler_lock_acquire("test_select");
    CHECK(signal_select_locked(first, &selected, &info) == ALIX_SIGUSR1);
    CHECK(process->signal_actions[ALIX_SIGUSR1].handler == 0);
    CHECK(signal_select_locked(second, &other, &other_info) == ALIX_SIGUSR1 && other.handler == 0);
    scheduler_lock_release(flags);
    /* A second CPU publishes a new action before the first builds its frame. */
    install_action(ALIX_SIGUSR1, ALIX_SA_SIGINFO);
    process->signal_actions[ALIX_SIGUSR1].handler += 16;
    uintptr_t replacement = process->signal_actions[ALIX_SIGUSR1].handler;
    exception_frame_t frame = fault_frame(14);
    CHECK(signal_install(first, &frame, &frame.cpu, &selected, &info, 0, 0, 0, 0));
    CHECK(frame.cpu.rip == selected.handler && process->signal_actions[ALIX_SIGUSR1].handler == replacement);
    return_current();
    install_action(ALIX_SIGILL, ALIX_SA_RESETHAND);
    frame = fault_frame(6);
    CHECK(process_signal_fault(&frame, 0));
    CHECK(process->signal_actions[ALIX_SIGILL].handler == 0);
    return_current();
}

static void edited_stack_contract(void)
{
    reset_state();
    install_action(ALIX_SIGILL, ALIX_SA_SIGINFO | ALIX_SA_ONSTACK);
    alix_stack_t *alt = (void *)(model_user + 128);
    *alt = (alix_stack_t){model_user + 131072, 65536, 0, 0};
    uintptr_t outside = (uintptr_t)model_user + 65536;
    CHECK(process_signal_sigaltstack((uintptr_t)alt, 0, sizeof(*alt), outside) == 0);
    exception_frame_t frame = fault_frame(6);
    CHECK(process_signal_fault(&frame, 0));
    alix_signal_frame_t *user = (void *)first->signal_frames->address;
    uintptr_t edited_rsp = (uintptr_t)alt->ss_sp + 32768;
    user->context.uc_mcontext.rsp = edited_rsp;
    syscall_frame_t returned;
    CHECK(process_signal_return(&returned, (uintptr_t)user) == 0 && returned.rsp == edited_rsp);
    CHECK(first->signal_onstack && !first->signal_frames);
    first->signal_onstack = false; /* A cached value is never authoritative. */
    CHECK(process_signal_sigaltstack((uintptr_t)alt, 0, sizeof(*alt), edited_rsp) == -EPERM);
    frame = fault_frame(6);
    frame.cpu.rsp = edited_rsp;
    first->signal_onstack = false;
    CHECK(process_signal_fault(&frame, 0));
    CHECK(frame.cpu.rsp < edited_rsp - 128 && frame.cpu.rsp > (uintptr_t)alt->ss_sp);
    user = (void *)first->signal_frames->address;
    CHECK(user->context.uc_stack.ss_flags == ALIX_SS_ONSTACK);
    user->context.uc_mcontext.rsp = outside;
    return_current();
    CHECK(!first->signal_onstack);
    first->signal_onstack = true;
    CHECK(process_signal_sigaltstack(0, (uintptr_t)(alt + 1), sizeof(*alt), outside) == 0);
    CHECK(alt[1].ss_flags == 0 && !first->signal_onstack);
    CHECK(process_signal_sigaltstack(0, (uintptr_t)(alt + 1), sizeof(*alt),
                                     (uintptr_t)alt->ss_sp + alt->ss_size) == 0);
    CHECK(alt[1].ss_flags == ALIX_SS_ONSTACK);
    frame = fault_frame(6);
    frame.cpu.rsp = (uintptr_t)alt->ss_sp;
    CHECK(!process_signal_fault(&frame, 0) && !first->signal_frames);
}

static void pending_allocation_contract(void)
{
    for (int failure = 0; failure < 3; ++failure)
    {
        reset_state();
        install_action(ALIX_SIGUSR1, 0);
        exception_frame_t fault = fault_frame(14);
        syscall_frame_t frame;
        memcpy(&frame, &fault, 120);
        memcpy(&frame.rip, &fault.cpu, 40);
        CHECK(process_signal_raise(ALIX_SIGUSR1, 0) == 0);
        model_fail_alloc = failure;
        if (!setjmp(model_exit_jump))
        {
            process_signal_syscall_return(&frame, 0);
            CHECK(false);
        }
        CHECK(model_exit_status == 128 + (failure < 2 ? ALIX_SIGSEGV : ALIX_SIGUSR1));
        CHECK(model_live == 0 && !first->signal_frames);
    }
}
static void sleep_contract(void)
{
    reset_state();
    install_action(ALIX_SIGUSR1, 0);
    uint32_t *left = (void *)(model_user + 128);
    CHECK(process_signal_sleep(100, (uintptr_t)left) == 0 && *left == 0 && model_ticks == 100);
    model_interrupt_wait = true;
    CHECK(process_signal_sleep(100, (uintptr_t)left) == -EINTR && *left == 67);
    CHECK(!first->signal_sleeping && !first->signal_sleep_interrupted && first->signal_pending);
    CHECK(process_signal_sleep(10, (uintptr_t)left) == -EINTR && *left == 10);
}
int main(void)
{
    model_user_size = 262144;
    model_user = calloc(1, model_user_size);
    process = calloc(1, sizeof(*process));
    first = calloc(1, sizeof(*first));
    second = calloc(1, sizeof(*second));
    assert(model_user && process && first && second);
    frame_contract();
    pending_contract();
    preempt_contract();
    failure_contract();
    oneshot_selection_contract();
    edited_stack_contract();
    pending_allocation_contract();
    sleep_contract();
    reset_state();
    CHECK(!model_live && !model_lock && !model_guard);
    free(first);
    free(second);
    free(process);
    free(model_user);
    printf("Native signal production host contracts: PASS checks=%u frames masks nesting forgery FP preempt "
           "EINTR cleanup\n",
           checks);
    return 0;
}
