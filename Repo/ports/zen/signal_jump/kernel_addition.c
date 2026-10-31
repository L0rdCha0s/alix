/* Signal-aware checkpoints contain values only. No user-buffer address or
 * per-checkpoint heap record is retained after CAPTURE returns. */
static uint64_t g_signal_jump_next_epoch = 1;

static uint64_t signal_jump_allocate_epoch(void)
{
    uint64_t next = __atomic_load_n(&g_signal_jump_next_epoch, __ATOMIC_RELAXED);
    for (;;)
    {
        if (!next || next == UINT64_MAX)
            return 0;
        if (__atomic_compare_exchange_n(&g_signal_jump_next_epoch, &next, next + 1, false, __ATOMIC_RELAXED,
                                        __ATOMIC_RELAXED))
            return next;
    }
}

static bool signal_jump_user_registers_valid(const alix_sigjmp_state_t *saved)
{
    return user_ptr_range_valid((const void *)(uintptr_t)saved->rip, 1) &&
           saved->rsp >= USER_ADDRESS_SPACE_BASE && saved->rsp <= USER_ADDRESS_SPACE_LIMIT + 1;
}

int process_signal_jump(syscall_frame_t *frame, uint32_t operation, uintptr_t buffer, size_t size,
                        uint64_t argument)
{
    thread_t *thread = current_thread_local();
    if (!frame || (frame->cs & 3u) != 3u || !signal_user_thread(thread))
        return -EPERM;
    if (size != sizeof(alix_sigjmp_state_t) || operation > ALIX_SIGJUMP_RESTORE)
        return -EINVAL;
    if (!user_ptr_range_valid((void *)buffer, size))
        return -EFAULT;
    uint64_t irq = cpu_save_flags();
    cpu_cli();
    alix_sigjmp_state_t *saved = calloc(1, sizeof(*saved));
    if (!saved)
    {
        cpu_restore_flags(irq);
        return -ENOMEM;
    }
    size_t input_size = operation == ALIX_SIGJUMP_CAPTURE ? ALIX_SIGJUMP_REGISTER_BYTES : sizeof(*saved);
    int result = user_copy_from_user(saved, (const void *)buffer, input_size) ? 0 : -EFAULT;
    if (!result && !signal_jump_user_registers_valid(saved))
        result = -EINVAL;
    if (!result && operation == ALIX_SIGJUMP_CAPTURE)
    {
        uint64_t return_pc = 0;
        if (frame->rsp > UINTPTR_MAX - 8 || saved->rsp != frame->rsp + 8)
            result = -EINVAL;
        else if (!user_copy_from_user(&return_pc, (const void *)(uintptr_t)frame->rsp, sizeof(return_pc)))
            result = -EFAULT;
        else if (saved->rip != return_pc)
            result = -EINVAL;
        if (!result && !thread->signal_jump_epoch)
        {
            thread->signal_jump_epoch = signal_jump_allocate_epoch();
            if (!thread->signal_jump_epoch)
                result = -EOVERFLOW;
        }
        if (!result)
        {
            uint64_t lock = scheduler_lock_acquire("signal_jump_capture");
            saved->version = ALIX_SIGJUMP_VERSION;
            saved->size = sizeof(*saved);
            saved->owner_tid = thread->tid;
            saved->epoch = thread->signal_jump_epoch;
            saved->frame_sequence = thread->signal_frames ? thread->signal_frames->sequence : 0;
            saved->flags = argument ? ALIX_SIGJUMP_SAVE_MASK : 0;
            saved->saved_mask = argument ? thread->signal_mask : 0;
            scheduler_lock_release(lock);
            if (!user_copy_to_user((void *)buffer, saved, sizeof(*saved)))
                result = -EFAULT;
        }
    }
    else if (!result)
    {
        if (saved->version != ALIX_SIGJUMP_VERSION || saved->size != sizeof(*saved) ||
            (saved->flags & ~ALIX_SIGJUMP_SAVE_MASK) || saved->reserved || saved->reserved_words[0] ||
            saved->reserved_words[1] || (saved->saved_mask & ~ALIX_SIGNAL_MASK) ||
            (saved->saved_mask & SIGNAL_UNBLOCKABLE) ||
            (!(saved->flags & ALIX_SIGJUMP_SAVE_MASK) && saved->saved_mask))
            result = -EINVAL;
        else if (saved->owner_tid != thread->tid || !saved->epoch ||
                 saved->epoch != thread->signal_jump_epoch)
            result = -EPERM;
        else if (thread->io_request)
            result = -EBUSY;
        if (!result)
        {
            uint64_t lock = scheduler_lock_acquire("signal_jump_restore");
            process_signal_frame_t *target = thread->signal_frames;
            unsigned drop = 0;
            while (target && target->sequence != saved->frame_sequence)
            {
                target = target->previous;
                ++drop;
            }
            if ((saved->frame_sequence && !target) || drop > thread->signal_depth)
                result = -EINVAL;
            if (!result)
            {
                process_signal_frame_t *retired = thread->signal_frames;
                thread->signal_frames = target;
                thread->signal_depth -= drop;
                if (saved->flags & ALIX_SIGJUMP_SAVE_MASK)
                    thread->signal_mask = saved->saved_mask;
                thread->signal_onstack = signal_stack_pointer_on_stack(&thread->signal_altstack, saved->rsp);
                scheduler_lock_release(lock);
                while (retired != target)
                {
                    process_signal_frame_t *previous = retired->previous;
                    free(retired);
                    retired = previous;
                }
                frame->rbx = saved->rbx;
                frame->rbp = saved->rbp;
                frame->r12 = saved->r12;
                frame->r13 = saved->r13;
                frame->r14 = saved->r14;
                frame->r15 = saved->r15;
                frame->rsp = saved->rsp;
                frame->rip = saved->rip;
                int value = (int32_t)argument;
                frame->rax = (uint64_t)(int64_t)(value ? value : 1);
                frame->cs = SIGNAL_USER_CS;
                frame->ss = SIGNAL_USER_SS;
                frame->rflags = (frame->rflags & SIGNAL_RFLAGS_ALLOWED & ~(1ULL << 10)) | RFLAGS_DEFAULT;
                free(saved);
                /* Preserve the current FP environment; abandoned handler
                 * snapshots are not ordinary sigreturn targets. Keep IRQs
                 * disabled through the direct continuation/pending delivery. */
                return 0;
            }
            scheduler_lock_release(lock);
        }
    }
    free(saved);
    cpu_restore_flags(irq);
    return result;
}
