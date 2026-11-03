#include "process_internal.h"
#include "user_copy.h"
#include "errno.h"

_Static_assert(sizeof(syscall_resource_usage_t) == 48, "native usage snapshot ABI");
_Static_assert(sizeof(syscall_resource_usage_v2_t) == 64, "extended native usage snapshot ABI");

static uint64_t usage_saturating_add(uint64_t value, uint64_t increment)
{
    return increment > UINT64_MAX - value ? UINT64_MAX : value + increment;
}

static uint64_t usage_lock(process_t *process)
{
    uint64_t flags = cpu_save_flags();
    cpu_cli();
    spinlock_lock(&process->usage_lock);
    return flags;
}

static void usage_unlock(process_t *process, uint64_t flags)
{
    spinlock_unlock(&process->usage_lock);
    cpu_restore_flags(flags);
}

void process_usage_add_cpu(process_t *process, uint64_t ticks, bool user_mode)
{
    if (!process || !ticks) return;
    uint64_t flags = usage_lock(process);
    uint64_t *counter = user_mode ? &process->usage_user_ticks : &process->usage_system_ticks;
    *counter = usage_saturating_add(*counter, ticks);
    usage_unlock(process, flags);
}

void process_usage_add_fault(process_t *process, bool major)
{
    if (!process) return;
    uint64_t flags = usage_lock(process);
    uint64_t *counter = major ? &process->usage_major_faults : &process->usage_minor_faults;
    *counter = usage_saturating_add(*counter, 1);
    usage_unlock(process, flags);
}

int process_user_resource_usage(int which, uintptr_t output, size_t bytes)
{
    if (which != SYSCALL_USAGE_SELF ||
        (bytes != sizeof(syscall_resource_usage_t) && bytes != sizeof(syscall_resource_usage_v2_t))) return -EINVAL;
    if (!user_ptr_range_valid((void *)output, bytes)) return -EFAULT;
    spinlock_preempt_disable();
    process_t *process = current_process_local();
    if (!process || !process->is_user) { spinlock_preempt_enable(); return -ESRCH; }
    syscall_resource_usage_v2_t *extended = calloc(1, sizeof(*extended));
    syscall_resource_usage_t *snapshot = extended ? &extended->usage : NULL;
    if (!snapshot) { spinlock_preempt_enable(); return -ENOMEM; }
    uint64_t flags = usage_lock(process);
    snapshot->version = bytes == sizeof(*snapshot) ? SYSCALL_USAGE_VERSION : SYSCALL_USAGE_VERSION_2;
    snapshot->size = (uint32_t)bytes;
    snapshot->tick_frequency = timer_frequency();
    snapshot->user_ticks = process->usage_user_ticks;
    snapshot->system_ticks = process->usage_system_ticks;
    snapshot->minor_faults = process->usage_minor_faults;
    snapshot->major_faults = process->usage_major_faults;
    usage_unlock(process, flags);
    if (bytes == sizeof(*extended))
        paging_user_residency(&process->address_space, &extended->resident_pages, &extended->peak_resident_pages);
    /* No usage lock spans safe user copying, which can acquire memory_lock.
     * Only this guarded, call-bounded heap snapshot survives that lock. */
    int result = !snapshot->tick_frequency ? -EAGAIN :
                 user_copy_to_user((void *)output, snapshot, bytes) ? 0 : -EFAULT;
    free(extended);
    spinlock_preempt_enable();
    return result;
}
