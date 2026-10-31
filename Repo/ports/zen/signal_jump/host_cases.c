static alix_sigjmp_state_t *jump_environment(unsigned slot, uintptr_t rsp)
{
    alix_sigjmp_state_t *saved = (void *)(model_user + 4096 + slot * sizeof(*saved));
    memset(saved, 0, sizeof(*saved));
    saved->rbx = 11;
    saved->rbp = 22;
    saved->r12 = 33;
    saved->r13 = 44;
    saved->r14 = 55;
    saved->r15 = 66;
    saved->rsp = rsp;
    saved->rip = (uintptr_t)model_user + 1024 + slot * 16;
    *(uint64_t *)(rsp - 8) = saved->rip;
    return saved;
}
static syscall_frame_t jump_call_frame(uintptr_t rsp)
{
    return (syscall_frame_t){
        .rsp = rsp - 8, .rip = (uintptr_t)model_user + 2048, .cs = 0x2b, .ss = 0x33, .rflags = 0x202};
}
static int jump_capture(alix_sigjmp_state_t *saved, int mask)
{
    syscall_frame_t frame = jump_call_frame(saved->rsp);
    return process_signal_jump(&frame, ALIX_SIGJUMP_CAPTURE, (uintptr_t)saved, sizeof(*saved), mask);
}
static int jump_restore(syscall_frame_t *frame, alix_sigjmp_state_t *saved, int value)
{
    return process_signal_jump(frame, ALIX_SIGJUMP_RESTORE, (uintptr_t)saved, sizeof(*saved),
                               (uint32_t)value);
}
static void jump_continuation_contract(void)
{
    reset_state();
    first->signal_mask = signal_bit(ALIX_SIGUSR2);
    alix_sigjmp_state_t *saved = jump_environment(0, (uintptr_t)model_user + 65536);
    CHECK(jump_capture(saved, 0) == 0 && saved->version == 1 && saved->size == 128 &&
          saved->owner_tid == first->tid);
    CHECK(saved->epoch && saved->epoch == first->signal_jump_epoch && !saved->saved_mask && !saved->flags);
    uint64_t epoch = saved->epoch;
    first->signal_mask = signal_bit(ALIX_SIGUSR1);
    uint8_t fp[512];
    memset(model_fp, 0x5a, sizeof(model_fp));
    memcpy(fp, model_fp, 512);
    syscall_frame_t result = jump_call_frame(saved->rsp);
    CHECK(jump_restore(&result, saved, 0) == 0 && result.rax == 1 && result.rip == saved->rip &&
          result.rsp == saved->rsp);
    CHECK(result.rbx == 11 && result.rbp == 22 && result.r12 == 33 && result.r13 == 44 && result.r14 == 55 &&
          result.r15 == 66);
    CHECK(first->signal_mask == signal_bit(ALIX_SIGUSR1) && !memcmp(fp, model_fp, 512) && model_live == 0);
    CHECK(!(model_flags & 0x200));
    model_flags = RFLAGS_DEFAULT;
    CHECK(jump_restore(&result, saved, -7) == 0 && (int64_t)result.rax == -7 &&
          first->signal_jump_epoch == epoch);
    model_flags = RFLAGS_DEFAULT;
    CHECK(jump_restore(&result, saved, -1) == 0 && (int64_t)result.rax == -1);
    model_flags = RFLAGS_DEFAULT;
    CHECK(jump_restore(&result, saved, INT_MIN) == 0 && (int64_t)result.rax == INT_MIN);
    model_flags = RFLAGS_DEFAULT;
    CHECK(jump_capture(saved, 1) == 0 && saved->epoch == epoch &&
          saved->saved_mask == signal_bit(ALIX_SIGUSR1));
    first->signal_mask = 0;
    CHECK(jump_restore(&result, saved, 19) == 0 && result.rax == 19 &&
          first->signal_mask == signal_bit(ALIX_SIGUSR1));
    CHECK(!memcmp(fp, model_fp, 512));
}
static void jump_frame_unwind_contract(void)
{
    reset_state();
    install_action(ALIX_SIGILL, ALIX_SA_SIGINFO);
    install_action(ALIX_SIGSEGV, ALIX_SA_SIGINFO);
    alix_sigjmp_state_t *base = jump_environment(0, (uintptr_t)model_user + 65536);
    CHECK(jump_capture(base, 1) == 0);
    exception_frame_t outer = fault_frame(6);
    CHECK(process_signal_fault(&outer, 0));
    uintptr_t outer_address = first->signal_frames->address;
    alix_sigjmp_state_t *inside = jump_environment(1, outer.cpu.rsp - 512);
    CHECK(jump_capture(inside, 1) == 0);
    uint64_t target = inside->frame_sequence;
    CHECK(target == first->signal_frames->sequence && target);
    exception_frame_t nested = fault_frame(14);
    nested.cpu.rsp = inside->rsp - 128;
    CHECK(process_signal_fault(&nested, 123));
    uintptr_t nested_address = first->signal_frames->address;
    CHECK(first->signal_depth == 2 && model_live == 2);
    syscall_frame_t frame = jump_call_frame(inside->rsp);
    CHECK(jump_restore(&frame, inside, 3) == 0 && first->signal_depth == 1 &&
          first->signal_frames->sequence == target && model_live == 1);
    CHECK(first->signal_mask == signal_bit(ALIX_SIGILL) && first->signal_frames->address == outer_address);
    CHECK(process_signal_return(&frame, nested_address) == -EPERM);
    model_flags = RFLAGS_DEFAULT;
    CHECK(jump_restore(&frame, inside, 4) == 0 && first->signal_depth == 1 && frame.rax == 4);
    model_flags = RFLAGS_DEFAULT;
    return_current();
    CHECK(!first->signal_frames && !first->signal_depth && model_live == 0);
    syscall_frame_t unchanged = frame;
    CHECK(jump_restore(&frame, inside, 1) == -EINVAL && !memcmp(&frame, &unchanged, sizeof(frame)));
    outer = fault_frame(6);
    CHECK(process_signal_fault(&outer, 0));
    nested = fault_frame(14);
    nested.cpu.rsp = outer.cpu.rsp - 256;
    CHECK(process_signal_fault(&nested, 123));
    CHECK(jump_restore(&frame, base, 5) == 0 && !first->signal_frames && !first->signal_depth &&
          model_live == 0 && first->signal_mask == 0);
    model_flags = RFLAGS_DEFAULT;
    CHECK(jump_capture(base, 0) == 0);
    outer = fault_frame(6);
    CHECK(process_signal_fault(&outer, 0));
    nested = fault_frame(14);
    nested.cpu.rsp = outer.cpu.rsp - 256;
    CHECK(process_signal_fault(&nested, 123));
    CHECK(jump_restore(&frame, base, 6) == 0 && !first->signal_frames && model_live == 0);
    CHECK(first->signal_mask == (signal_bit(ALIX_SIGILL) | signal_bit(ALIX_SIGSEGV)));
}
static void jump_validation_contract(void)
{
    reset_state();
    install_action(ALIX_SIGILL, 0);
    alix_sigjmp_state_t *saved = jump_environment(0, (uintptr_t)model_user + 65536);
    CHECK(jump_capture(saved, 1) == 0);
    exception_frame_t outer = fault_frame(6);
    CHECK(process_signal_fault(&outer, 0));
    struct process_signal_frame *head = first->signal_frames;
    uint64_t mask = first->signal_mask;
    alix_sigjmp_state_t good = *saved;
    syscall_frame_t frame = jump_call_frame(saved->rsp), original = frame;
#define JUMP_REJECT(edit, error)                                                                             \
    do                                                                                                       \
    {                                                                                                        \
        *saved = good;                                                                                       \
        edit;                                                                                                \
        CHECK(jump_restore(&frame, saved, 1) == error);                                                      \
        CHECK(first->signal_frames == head && first->signal_depth == 1 && first->signal_mask == mask &&      \
              model_live == 1 && !memcmp(&frame, &original, sizeof(frame)));                                 \
    } while (0)
    JUMP_REJECT(saved->version = 0, -EINVAL);
    JUMP_REJECT(saved->size = 0, -EINVAL);
    JUMP_REJECT(saved->flags = 2, -EINVAL);
    JUMP_REJECT(saved->reserved = 1, -EINVAL);
    JUMP_REJECT(saved->reserved_words[0] = 1, -EINVAL);
    JUMP_REJECT(saved->reserved_words[1] = 1, -EINVAL);
    JUMP_REJECT(saved->saved_mask = 1ULL << 63, -EINVAL);
    JUMP_REJECT(saved->saved_mask = signal_bit(ALIX_SIGKILL), -EINVAL);
    JUMP_REJECT(saved->flags = 0; saved->saved_mask = 1, -EINVAL);
    JUMP_REJECT(saved->owner_tid = second->tid, -EPERM);
    JUMP_REJECT(saved->epoch = 0, -EPERM);
    JUMP_REJECT(saved->epoch++, -EPERM);
    JUMP_REJECT(saved->frame_sequence = first->signal_sequence + 1, -EINVAL);
    JUMP_REJECT(saved->rip = 0xffff800000000000ULL, -EINVAL);
    JUMP_REJECT(saved->rsp = 0, -EINVAL);
#undef JUMP_REJECT
    *saved = good;
    model_current = second;
    CHECK(jump_restore(&frame, saved, 1) == -EPERM && second->signal_jump_epoch == 0 &&
          !second->signal_frames);
    model_current = first;
    first->io_request = (void *)1;
    CHECK(jump_restore(&frame, saved, 1) == -EBUSY && first->signal_frames == head);
    first->io_request = NULL;
    model_fail_alloc = 0;
    CHECK(jump_restore(&frame, saved, 1) == -ENOMEM && first->signal_frames == head && model_live == 1);
    model_fail_alloc = -1;
    model_copy_fail = 0;
    CHECK(jump_restore(&frame, saved, 1) == -EFAULT && first->signal_frames == head && model_live == 1);
    model_copy_fail = -1;
    CHECK(process_signal_jump(&frame, 7, (uintptr_t)saved, sizeof(*saved), 1) == -EINVAL);
    CHECK(process_signal_jump(&frame, ALIX_SIGJUMP_RESTORE, (uintptr_t)saved, 127, 1) == -EINVAL);
    CHECK(jump_restore(&frame, saved, 1) == 0 && !first->signal_frames && model_live == 0);
}
static void jump_capture_failure_contract(void)
{
    for (int point = 0; point < 3; ++point)
    {
        reset_state();
        install_action(ALIX_SIGILL, 0);
        exception_frame_t outer = fault_frame(6);
        CHECK(process_signal_fault(&outer, 0));
        alix_sigjmp_state_t *saved = jump_environment(0, outer.cpu.rsp - 512);
        struct process_signal_frame *head = first->signal_frames;
        uint64_t mask = first->signal_mask;
        model_copy_fail = point;
        CHECK(jump_capture(saved, 1) == -EFAULT);
        model_copy_fail = -1;
        CHECK(first->signal_frames == head && first->signal_mask == mask && first->signal_depth == 1 &&
              model_live == 1);
    }
    reset_state();
    alix_sigjmp_state_t *saved = jump_environment(0, (uintptr_t)model_user + 65536);
    model_fail_alloc = 0;
    CHECK(jump_capture(saved, 1) == -ENOMEM && model_live == 0);
    model_fail_alloc = -1;
    *(uint64_t *)(saved->rsp - 8) = saved->rip + 1;
    CHECK(jump_capture(saved, 1) == -EINVAL);
    *(uint64_t *)(saved->rsp - 8) = saved->rip;
    uint64_t next = g_signal_jump_next_epoch;
    g_signal_jump_next_epoch = UINT64_MAX;
    CHECK(jump_capture(saved, 1) == -EOVERFLOW && !first->signal_jump_epoch && model_live == 0);
    CHECK(g_signal_jump_next_epoch == UINT64_MAX);
    g_signal_jump_next_epoch = next;
    CHECK(jump_capture(saved, 1) == 0);
    uint64_t first_epoch = saved->epoch;
    model_current = second;
    saved = jump_environment(1, (uintptr_t)model_user + 69632);
    CHECK(jump_capture(saved, 1) == 0);
    CHECK(saved->epoch != first_epoch && saved->owner_tid == second->tid);
    model_current = first;
}
static void jump_pending_contract(void)
{
    reset_state();
    install_action(ALIX_SIGUSR1, ALIX_SA_SIGINFO);
    first->signal_mask = signal_bit(ALIX_SIGUSR2);
    alix_sigjmp_state_t *saved = jump_environment(0, (uintptr_t)model_user + 65536);
    CHECK(jump_capture(saved, 1) == 0);
    first->signal_mask |= signal_bit(ALIX_SIGUSR1);
    CHECK(process_signal_raise(ALIX_SIGUSR1, 0) == 0);
    syscall_frame_t frame = jump_call_frame(saved->rsp);
    CHECK(jump_restore(&frame, saved, 23) == 0);
    process_signal_syscall_return(&frame, 0);
    CHECK(first->signal_depth == 1 && first->signal_pending == 0);
    alix_signal_frame_t *delivered = (void *)first->signal_frames->address;
    CHECK(delivered->context.uc_mcontext.rip == saved->rip &&
          delivered->context.uc_mcontext.rsp == saved->rsp && delivered->context.uc_mcontext.rax == 23);
    return_current();
    CHECK(first->signal_mask == signal_bit(ALIX_SIGUSR2) && model_live == 0);
}
static void jump_contracts(void)
{
    jump_continuation_contract();
    jump_frame_unwind_contract();
    jump_validation_contract();
    jump_capture_failure_contract();
    jump_pending_contract();
    reset_state();
}
