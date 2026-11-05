#include "process_internal.h"
#include "physmem.h"
#include "io_vfs.h"
#include "errno.h"
#include "swap.h"
#include "io_service.h"
#include "pmm.h"
#include "procfs.h"

/* Anonymous VM has its own address arena, leaving the existing ELF, sbrk,
 * main stack and descending thread/TLS pool unchanged. A PROT_NONE area has
 * no physical-page array until it is committed. Discarded pages are null
 * array entries, even when their VMA remains accessible. Metadata and in-flight
 * transactions belong to the process, never to a caller's stack. */
#define VM_PAGE_SIZE PAGE_SIZE_BYTES_LOCAL
#define VM_THREAD_POOL_BYTES USER_DEFAULT_THREAD_POOL_SIZE
#define VM_HEAP_GAP_BYTES USER_DEFAULT_VM_HEAP_GAP
#define VM_NEW_PAGE ((paddr_t)1)
#define VM_OWNED_PAGE ((paddr_t)2)
#define VM_PAGE_FLAGS (VM_NEW_PAGE | VM_OWNED_PAGE)
#define VM_PHYSICAL(page) ((page) & ~VM_PAGE_FLAGS)
#define VM_EINVAL (-22)
#define VM_ENOMEM (-12)
#define VM_EEXIST (-17)

typedef struct process_vm_area
{
    uintptr_t base;
    size_t length;
    uint32_t protection;
    paddr_t *pages;
    fd_description_t *file;
    bool private_file;
    size_t file_offset;
    struct process_vm_area *next;
} process_vm_area_t;

typedef struct process_vm_transaction
{
    process_vm_area_t *old_areas;
    process_vm_area_t *new_areas;
    process_vm_area_t *new_tail;
    paddr_t *retired;
    size_t retired_count;
    size_t retired_capacity;
    paging_tlb_ticket_t ticket;
    bool awaiting_tlb;
} process_vm_transaction_t;

typedef enum { VM_OPERATION_MAP, VM_OPERATION_PROTECT, VM_OPERATION_UNMAP,
               VM_OPERATION_REPLACE, VM_OPERATION_DISCARD } vm_operation_t;

/* Readable in the existing debugger profile without per-operation logging. */
uint64_t g_vm_fresh_maps;
uint64_t g_vm_no_present_changes;
uint64_t g_vm_tlb_transactions;
/* Retained for before/after debugger profiles: timer sleeps are now zero. */
uint64_t g_vm_tlb_wait_sleeps;
uint64_t g_vm_tlb_waits;
uint64_t g_vm_serial_waits;
uint64_t g_vm_tlb_completion_wakes;
uint64_t g_vm_serial_wakes;
uint64_t g_vm_empty_wakes_avoided;
static uint64_t g_vm_tlb_pending_transactions;
static bool g_vm_tlb_notify_pending;
/* Permanent queue storage: cancellation uses the ordinary thread wait-queue
 * cleanup, while predicates refer only to heap-owned process/journal state. */
static wait_queue_t g_vm_progress_queue;
static wait_queue_t g_vm_serial_queue;

static bool vm_wake_waiters(wait_queue_t *queue)
{
    /* Publication precedes this queue-locked check. A waiter either already
     * enqueued, or sees the published predicate when it acquires this lock.
     * Drop it before taking the scheduler lock to preserve lock ordering. */
    uint64_t flags = spinlock_lock_irqsave(&queue->lock);
    bool waiting = queue->head != NULL;
    spinlock_unlock_irqrestore(&queue->lock, flags);
    if (waiting) wait_queue_wake_all(queue);
    else __atomic_fetch_add(&g_vm_empty_wakes_avoided, 1u, __ATOMIC_RELAXED);
    return waiting;
}

void process_vm_poll_tlb_completion(void)
{
    if (!__atomic_load_n(&g_vm_tlb_notify_pending, __ATOMIC_ACQUIRE)) return;
    /* A TLB IPI may interrupt a subsidiary-lock owner. Do not invert the
     * scheduler -> subsidiary lock order; timer/schedule-IPIs retry safely. */
    if (spinlock_preempt_disabled()) return;
    if (__atomic_exchange_n(&g_vm_tlb_notify_pending, false, __ATOMIC_ACQ_REL))
    {
        if (vm_wake_waiters(&g_vm_progress_queue))
            __atomic_fetch_add(&g_vm_tlb_completion_wakes, 1u, __ATOMIC_RELAXED);
    }
}

void process_vm_notify_tlb_completion(void)
{
    if (!__atomic_load_n(&g_vm_tlb_pending_transactions, __ATOMIC_ACQUIRE)) return;
    __atomic_store_n(&g_vm_tlb_notify_pending, true, __ATOMIC_RELEASE);
    process_vm_poll_tlb_completion();
}

static uintptr_t vm_arena_start(void)
{
    return align_up_uintptr(USER_HEAP_BASE + USER_HEAP_SIZE + VM_HEAP_GAP_BYTES, VM_PAGE_SIZE);
}

static uintptr_t vm_arena_end(void)
{
    return align_down_uintptr(USER_STUB_CODE_BASE - VM_THREAD_POOL_BYTES, VM_PAGE_SIZE);
}

uintptr_t process_vm_auxiliary_base(void)
{
    return vm_arena_end();
}

bool process_vm_range_reserved(uintptr_t address, size_t length)
{
    if (!length || address > UINTPTR_MAX - length)
    {
        return false;
    }
    return address < vm_arena_end() && address + length > vm_arena_start();
}

static bool vm_length_valid(size_t requested, size_t *rounded)
{
    if (!requested || requested > SIZE_MAX - (VM_PAGE_SIZE - 1))
    {
        return false;
    }
    *rounded = align_up_size(requested, VM_PAGE_SIZE);
    return vm_arena_end() > vm_arena_start() && *rounded <= vm_arena_end() - vm_arena_start();
}

static bool vm_range_valid(uintptr_t address, size_t length)
{
    return !(address & (VM_PAGE_SIZE - 1)) && address >= vm_arena_start() &&
           address < vm_arena_end() && length <= vm_arena_end() - address;
}

static bool vm_protection_valid(uint32_t protection)
{
    const uint32_t allowed = SYSCALL_VM_PROT_READ | SYSCALL_VM_PROT_WRITE | SYSCALL_VM_PROT_EXEC;
    return !(protection & ~allowed);
}

static uint32_t vm_protection_normalize(uint32_t protection)
{
    /* x86-64 present user pages are readable. Keep software-copy permissions
     * consistent with the hardware for write-only and execute-only requests.
     * Upstream SpiderMonkey also uses RWX mappings on supported platforms. */
    if (protection & (SYSCALL_VM_PROT_WRITE | SYSCALL_VM_PROT_EXEC))
    {
        protection |= SYSCALL_VM_PROT_READ;
    }
    return protection;
}

static void vm_free_area_metadata(process_vm_area_t *area, bool free_new, bool free_all)
{
    while (area)
    {
        process_vm_area_t *next = area->next;
        if (area->pages)
        {
            size_t count = area->length / VM_PAGE_SIZE;
            for (size_t index = 0; index < count; ++index)
            {
                paddr_t page = area->pages[index];
                if ((!area->file || (page & VM_OWNED_PAGE)) && page && (free_all || (free_new && (page & VM_NEW_PAGE))))
                {
                    user_memory_free_page(VM_PHYSICAL(page));
                }
            }
        }
        fd_description_put(area->file);
        free(area->pages);
        free(area);
        area = next;
    }
}

static void vm_destroy_transaction(process_vm_transaction_t *transaction, bool completed)
{
    if (!transaction)
    {
        return;
    }
    if (transaction->awaiting_tlb)
        __atomic_fetch_sub(&g_vm_tlb_pending_transactions, 1u, __ATOMIC_RELEASE);
    vm_free_area_metadata(transaction->new_areas, true, false);
    vm_free_area_metadata(transaction->old_areas, false, false);
    if (completed)
    {
        for (size_t index = 0; index < transaction->retired_count; ++index)
        {
            user_memory_free_page(VM_PHYSICAL(transaction->retired[index]));
        }
    }
    free(transaction->retired);
    free(transaction);
}

void process_vm_destroy(process_t *process)
{
    if (!process)
    {
        return;
    }
    /* Process creation failure/final teardown has no address-space users. */
    vm_free_area_metadata(process->vm_areas, false, true);
    process->vm_areas = NULL;
    process_vm_transaction_t *pending = __atomic_load_n(&process->vm_pending, __ATOMIC_ACQUIRE);
    __atomic_store_n(&process->vm_pending, NULL, __ATOMIC_RELEASE);
    vm_destroy_transaction(pending, true);
}

static process_vm_area_t *vm_find_area(process_vm_area_t *head, uintptr_t address)
{
    for (process_vm_area_t *area = head; area && area->base <= address; area = area->next)
    {
        if (address - area->base < area->length)
        {
            return area;
        }
    }
    return NULL;
}

/* Called with memory_lock held, including from IRQ-disabled user page faults.
 * The page table was prepared when access was granted. A null leaf becomes
 * present without replacing any live backing; x86 does not cache nonpresent
 * translations. The prepared writer also invalidates this CPU's translation.
 * Other CPUs may still have a pre-discard page until the pending transaction's
 * acknowledgement, but that separate backing remains owned by its journal. */
static bool vm_commit_page_locked(process_t *process, process_vm_area_t *area,
                                  uintptr_t address, bool write_access)
{
    if (!area->pages || area->protection == SYSCALL_VM_PROT_NONE)
    {
        return false;
    }
    size_t index = (address - area->base) / VM_PAGE_SIZE;
    paddr_t page = area->pages[index];
    if (page & (USER_PAGE_SWAPPED | USER_PAGE_BUSY)) return false;
    bool allocated = false;
    if (!page)
    {
        if (area->file)
        {
            page = io_vfs_mapping_page(area->file, area->file_offset / VM_PAGE_SIZE + index);
            if (!page) return false;
        }
        else if (!user_memory_alloc_page(&page))
        {
            return false;
        }
        else
        {
            memset(phys_to_virt(page), 0, VM_PAGE_SIZE);
            allocated = true;
        }
    }
    if (page & VM_NEW_PAGE) return false;
    if (write_access && area->private_file && !(page & VM_OWNED_PAGE))
    {
        paddr_t copy = 0;
        if (!user_memory_alloc_page(&copy)) return false;
        memcpy(phys_to_virt(copy), phys_to_virt(page), VM_PAGE_SIZE);
        page = copy | VM_OWNED_PAGE;
        allocated = true;
    }
    if (!paging_write_prepared_user_page(&process->address_space,
                                         align_down_uintptr(address, VM_PAGE_SIZE), VM_PHYSICAL(page),
                                         true, (area->protection & SYSCALL_VM_PROT_WRITE) != 0 &&
                                         (!area->private_file || (page & VM_OWNED_PAGE)),
                                         (area->protection & SYSCALL_VM_PROT_EXEC) != 0))
    {
        if (allocated) user_memory_free_page(VM_PHYSICAL(page));
        return false;
    }
    area->pages[index] = page;
    if (allocated && area->private_file)
        process->vm_cow_ticket = paging_request_tlb_flush(&process->address_space);
    return true;
}

bool process_vm_contains_locked(process_t *process, uintptr_t address)
{
    return process && vm_find_area(process->vm_areas, address) != NULL;
}

bool process_vm_fault_locked(process_t *process, uintptr_t address,
                              bool write_access, bool execute_access)
{
    if (!process) return false;
    process_vm_area_t *area = vm_find_area(process->vm_areas, address);
    if (!area || !(area->protection & SYSCALL_VM_PROT_READ) ||
        (write_access && !(area->protection & SYSCALL_VM_PROT_WRITE)) ||
        (execute_access && !(area->protection & SYSCALL_VM_PROT_EXEC)))
    {
        return false;
    }
    /* A different CPU may already have filled this page since the fault. */
    return vm_commit_page_locked(process, area, address, write_access);
}

bool process_vm_resolve_locked(process_t *process, uintptr_t address, bool write_access,
                               uint8_t **host_out, size_t *available_out)
{
    if (!process || !host_out || !available_out)
    {
        return false;
    }
    process_vm_area_t *area = vm_find_area(process->vm_areas, address);
    if (!area || !(area->protection & SYSCALL_VM_PROT_READ) ||
        (write_access && !(area->protection & SYSCALL_VM_PROT_WRITE)) || !area->pages)
    {
        return false;
    }
    size_t offset = (size_t)(address - area->base);
    paddr_t page = area->pages[offset / VM_PAGE_SIZE];
    if (!page || (write_access && area->private_file && !(page & VM_OWNED_PAGE)))
    {
        if (!vm_commit_page_locked(process, area, address, write_access)) return false;
        page = area->pages[offset / VM_PAGE_SIZE];
    }
    if (page & (VM_NEW_PAGE | USER_PAGE_SWAPPED | USER_PAGE_BUSY)) return false;
    *host_out = (uint8_t *)phys_to_virt(VM_PHYSICAL(page)) + offset % VM_PAGE_SIZE;
    *available_out = VM_PAGE_SIZE - offset % VM_PAGE_SIZE;
    return true;
}

static bool vm_process_ready(void *context)
{
    process_t *process = context;
    /* Queue predicates run under scheduler serialization. Never wait for a
     * large VM allocation's memory_lock while holding the global scheduler. */
    return __atomic_load_n(&process->vm_pending, __ATOMIC_ACQUIRE) == NULL &&
           !__atomic_load_n(&process->vm_pager_busy, __ATOMIC_ACQUIRE);
}

static uint64_t vm_lock_ready(process_t *process)
{
    for (;;)
    {
        uint64_t flags = process_memory_lock(process);
        if (!__atomic_load_n(&process->vm_pending, __ATOMIC_ACQUIRE) && !process->vm_pager_busy)
        {
            return flags;
        }
        process_memory_unlock(process, flags);
        __atomic_fetch_add(&g_vm_serial_waits, 1u, __ATOMIC_RELAXED);
        wait_queue_wait(&g_vm_serial_queue, vm_process_ready, process);
    }
}

static bool vm_call_valid(process_t *process)
{
    return process && process->is_user && process == current_process_local() &&
           (cpu_save_flags() & RFLAGS_IF_BIT) && !spinlock_preempt_disabled();
}

bool process_vm_fault_access(process_t *process, uintptr_t address, bool write, bool execute)
{
    uint64_t flags = process_memory_lock(process);
    process_vm_area_t *area = vm_find_area(process->vm_areas, address);
    bool valid = area && (area->protection & SYSCALL_VM_PROT_READ) &&
        (!write || (area->protection & SYSCALL_VM_PROT_WRITE)) &&
        (!execute || (area->protection & SYSCALL_VM_PROT_EXEC));
    if (!area && !execute)
    {
        paddr_t *slot = process_legacy_page_slot_locked(process, address);
        valid = slot && *slot;
    }
    process_memory_unlock(process, flags);
    return valid;
}

bool process_vm_fault_page(process_t *process, uintptr_t address, bool write, bool execute)
{
    uint64_t flags = vm_lock_ready(process);
    process_vm_area_t *area = vm_find_area(process->vm_areas, address);
    paddr_t *slot = area && area->pages ? &area->pages[(address - area->base) / VM_PAGE_SIZE] :
        process_legacy_page_slot_locked(process, address);
    bool swapped = slot && (*slot & USER_PAGE_SWAPPED);
    process_memory_unlock(process, flags);
    if (swapped && !process_vm_page_in(process, address)) return false;
    flags = vm_lock_ready(process);
    area = vm_find_area(process->vm_areas, address);
    bool result = area ? process_vm_fault_locked(process, address, write, execute) :
        !execute && process_legacy_page_slot_locked(process, address) != NULL;
    paging_tlb_ticket_t ticket = result ? paging_request_tlb_flush(&process->address_space) : (paging_tlb_ticket_t){0};
    process_memory_unlock(process, flags);
    while (result && !paging_tlb_flush_complete(ticket)) process_yield();
    if (result && !swapped) process_usage_add_fault(process, false);
    return result;
}

static bool vm_area_append(process_vm_transaction_t *transaction, const process_vm_area_t *old,
                           uintptr_t base, size_t length, uint32_t protection, bool discard)
{
    if (!length)
    {
        return true;
    }
    process_vm_area_t *area = calloc(1, sizeof(*area));
    if (!area)
    {
        return false;
    }
    area->base = base;
    area->length = length;
    area->protection = protection;
    if (old && old->file) {
        if (!fd_description_get(old->file)) { free(area); return false; }
        area->file = old->file;
        area->private_file = old->private_file;
        area->file_offset = old->file_offset + base - old->base;
    }
    if (transaction->new_tail)
    {
        transaction->new_tail->next = area;
    }
    else
    {
        transaction->new_areas = area;
    }
    transaction->new_tail = area;
    if ((old && (old->pages || old->file)) || protection != SYSCALL_VM_PROT_NONE)
    {
        size_t count = length / VM_PAGE_SIZE;
        if (count > SIZE_MAX / sizeof(*area->pages))
        {
            return false;
        }
        area->pages = calloc(count, sizeof(*area->pages));
        if (!area->pages)
        {
            return false;
        }
        for (size_t index = 0; index < count; ++index)
        {
            if (discard)
            {
                /* The unchanged VMA will demand-zero this page on first use. */
                continue;
            }
            else if (old && old->file && !old->pages)
            {
                /* Shared read-only files retain the mapping, but fault their
                 * physical cache pages in only when used. Preserve the backing
                 * offset across mprotect/munmap splits. */
                if (!area->private_file && io_vfs_mapping_writable(old->file))
                {
                    area->pages[index] = io_vfs_mapping_page(old->file, area->file_offset/VM_PAGE_SIZE+index);
                    if (!area->pages[index]) return false;
                }
            }
            else if (old && old->pages)
            {
                area->pages[index] = old->pages[(base - old->base) / VM_PAGE_SIZE + index];
            }
            else
            {
                paddr_t page = 0;
                if (!user_memory_alloc_page(&page)) return false;
                memset(phys_to_virt(page), 0, VM_PAGE_SIZE);
                area->pages[index] = page | VM_NEW_PAGE;
            }
        }
    }
    return true;
}

static bool vm_covered(process_vm_area_t *head, uintptr_t start, uintptr_t end)
{
    uintptr_t cursor = start;
    for (process_vm_area_t *area = head; area && cursor < end; area = area->next)
    {
        if (area->base + area->length <= cursor)
        {
            continue;
        }
        if (area->base > cursor)
        {
            return false;
        }
        cursor = area->base + area->length;
    }
    return cursor >= end;
}

static uintptr_t vm_find_space(process_t *process, uintptr_t hint, size_t length)
{
    if (hint && vm_range_valid(hint, length))
    {
        bool overlap = false;
        for (process_vm_area_t *area = process->vm_areas; area; area = area->next)
        {
            if (area->base < hint + length && area->base + area->length > hint)
            {
                overlap = true;
                break;
            }
        }
        if (!overlap)
        {
            return hint;
        }
    }
    uintptr_t candidate = vm_arena_start();
    for (process_vm_area_t *area = process->vm_areas; area; area = area->next)
    {
        if (area->base >= candidate && length <= area->base - candidate)
        {
            return candidate;
        }
        if (area->base + area->length > candidate)
        {
            candidate = area->base + area->length;
        }
    }
    return vm_range_valid(candidate, length) ? candidate : 0;
}

static void vm_write_leaf(process_t *process, uintptr_t address, process_vm_area_t *area)
{
    paddr_t page = area && area->pages ? area->pages[(address - area->base) / VM_PAGE_SIZE] : 0;
    bool present = page && !(page & (USER_PAGE_SWAPPED | USER_PAGE_BUSY)) && area->protection != SYSCALL_VM_PROT_NONE;
    if (!present) page = 0;
    if (!paging_write_prepared_user_page(&process->address_space, address, VM_PHYSICAL(page), present,
                                         present && (area->protection & SYSCALL_VM_PROT_WRITE) &&
                                         (!area->private_file || (page & VM_OWNED_PAGE)),
                                         present && (area->protection & SYSCALL_VM_PROT_EXEC)))
    {
        fatal("prepared VM page-table transaction lost its leaf");
    }
}

static int vm_change_locked(process_t *process, uintptr_t start, size_t length,
                            uint32_t protection, vm_operation_t operation,
                            process_vm_transaction_t **transaction_out, const process_vm_area_t *backing)
{
    uintptr_t end = start + length;
    if ((operation == VM_OPERATION_PROTECT || operation == VM_OPERATION_DISCARD) &&
        !vm_covered(process->vm_areas, start, end))
    {
        return VM_ENOMEM;
    }
    process_vm_area_t *before = NULL;
    process_vm_area_t *first = process->vm_areas;
    while (first && first->base + first->length <= start)
    {
        before = first;
        first = first->next;
    }
    process_vm_area_t *after = first;
    process_vm_area_t *last = NULL;
    size_t retired_count = 0;
    bool had_present_leaf = false;
    while (after && after->base < end)
    {
        if (operation == VM_OPERATION_MAP)
        {
            return VM_EEXIST;
        }
        if (after->file && operation == VM_OPERATION_DISCARD) return -ENOTSUP;
        if (after->file && operation == VM_OPERATION_PROTECT &&
            (protection & SYSCALL_VM_PROT_WRITE) && !io_vfs_mapping_writable(after->file)) return -EACCES;
        uintptr_t low = after->base > start ? after->base : start;
        uintptr_t high = after->base + after->length < end ? after->base + after->length : end;
        /* vm_lock_ready completed every earlier removal/protection barrier.
         * Only a committed, accessible old page can now leave a cached present
         * translation. PROT_NONE backing and sparse page slots cannot. */
        if (!had_present_leaf && after->protection != SYSCALL_VM_PROT_NONE && after->pages)
        {
            for (size_t page = (low - after->base) / VM_PAGE_SIZE;
                 page < (high - after->base) / VM_PAGE_SIZE; ++page)
            {
                if (after->pages[page]) { had_present_leaf = true; break; }
            }
        }
        if ((operation == VM_OPERATION_UNMAP || operation == VM_OPERATION_REPLACE ||
             operation == VM_OPERATION_DISCARD) && after->pages)
        {
            for (size_t page = (low - after->base) / VM_PAGE_SIZE;
                 page < (high - after->base) / VM_PAGE_SIZE; ++page)
            {
                if ((!after->file || (after->pages[page] & VM_OWNED_PAGE)) && after->pages[page]) ++retired_count;
            }
        }
        last = after;
        after = after->next;
    }
    if (operation == VM_OPERATION_UNMAP && !last)
    {
        *transaction_out = NULL;
        return 0;
    }
    process_vm_transaction_t *transaction = calloc(1, sizeof(*transaction));
    if (!transaction)
    {
        return VM_ENOMEM;
    }
    if (retired_count)
    {
        transaction->retired = malloc(retired_count * sizeof(*transaction->retired));
        if (!transaction->retired)
        {
            free(transaction);
            return VM_ENOMEM;
        }
        transaction->retired_capacity = retired_count;
    }
    bool okay = true;
    if (operation == VM_OPERATION_MAP)
    {
        okay = vm_area_append(transaction, backing, start, length, protection, false);
    }
    else if (operation == VM_OPERATION_REPLACE)
    {
        if (last && first->base < start)
        {
            okay = vm_area_append(transaction, first, first->base, start - first->base,
                                  first->protection, false);
        }
        if (okay)
        {
            okay = vm_area_append(transaction, backing, start, length, protection, false);
        }
        if (okay && last && last->base + last->length > end)
        {
            okay = vm_area_append(transaction, last, end, last->base + last->length - end,
                                  last->protection, false);
        }
        for (process_vm_area_t *area = first; area != after; area = area->next)
        {
            if (!area->pages)
            {
                continue;
            }
            uintptr_t low = area->base > start ? area->base : start;
            uintptr_t high = area->base + area->length < end ? area->base + area->length : end;
            for (size_t page = (low - area->base) / VM_PAGE_SIZE;
                 page < (high - area->base) / VM_PAGE_SIZE; ++page)
            {
                if ((!area->file || (area->pages[page] & VM_OWNED_PAGE)) && area->pages[page])
                    transaction->retired[transaction->retired_count++] = area->pages[page];
            }
        }
    }
    else
    {
        for (process_vm_area_t *area = first; okay && area != after; area = area->next)
        {
            uintptr_t low = area->base > start ? area->base : start;
            uintptr_t high = area->base + area->length < end ? area->base + area->length : end;
            okay = vm_area_append(transaction, area, area->base, low - area->base, area->protection, false);
            if (okay && (operation == VM_OPERATION_PROTECT || operation == VM_OPERATION_DISCARD))
            {
                bool discard = operation == VM_OPERATION_DISCARD;
                okay = vm_area_append(transaction, area, low, high - low,
                                      discard ? area->protection : protection, discard);
            }
            if (okay)
            {
                okay = vm_area_append(transaction, area, high, area->base + area->length - high,
                                      area->protection, false);
            }
            if ((operation == VM_OPERATION_UNMAP || operation == VM_OPERATION_DISCARD) && area->pages)
            {
                for (size_t page = (low - area->base) / VM_PAGE_SIZE;
                     page < (high - area->base) / VM_PAGE_SIZE; ++page)
                {
                    if ((!area->file || (area->pages[page] & VM_OWNED_PAGE)) && area->pages[page])
                        transaction->retired[transaction->retired_count++] = area->pages[page];
                }
            }
        }
    }
    /* Table allocation can fail, but no leaf/visible VMA has changed yet.
     * Empty prepared page tables remain owned by the address space as cache. */
    for (process_vm_area_t *area = transaction->new_areas; okay && area; area = area->next)
    {
        uintptr_t low = area->base > start ? area->base : start;
        uintptr_t high = area->base + area->length < end ? area->base + area->length : end;
        if (low < high && area->protection != SYSCALL_VM_PROT_NONE)
        {
            okay = paging_prepare_user_range(&process->address_space, low, high - low);
        }
    }
    if (!okay)
    {
        vm_destroy_transaction(transaction, false);
        return VM_ENOMEM;
    }
    for (process_vm_area_t *area = transaction->new_areas; area; area = area->next)
    {
        for (size_t page = 0; area->pages && page < area->length / VM_PAGE_SIZE; ++page)
        {
            area->pages[page] &= ~VM_NEW_PAGE;
        }
    }
    /* Update formerly accessible leaves directly to their new permissions or
     * clear them. Do not transiently unmap readable pages on RW -> R/RX. */
    if (last)
    {
        for (process_vm_area_t *area = first; area != after; area = area->next)
        {
            if (area->protection == SYSCALL_VM_PROT_NONE)
            {
                continue;
            }
            uintptr_t low = area->base > start ? area->base : start;
            uintptr_t high = area->base + area->length < end ? area->base + area->length : end;
            for (uintptr_t address = low; address < high; address += VM_PAGE_SIZE)
            {
                vm_write_leaf(process, address, vm_find_area(transaction->new_areas, address));
            }
        }
    }
    for (process_vm_area_t *area = transaction->new_areas; area; area = area->next)
    {
        if (area->protection == SYSCALL_VM_PROT_NONE)
        {
            continue;
        }
        uintptr_t low = area->base > start ? area->base : start;
        uintptr_t high = area->base + area->length < end ? area->base + area->length : end;
        for (uintptr_t address = low; address < high; address += VM_PAGE_SIZE)
        {
            vm_write_leaf(process, address, area);
        }
    }
    if (last)
    {
        transaction->old_areas = first;
        last->next = NULL;
    }
    process_vm_area_t *replacement = transaction->new_areas ? transaction->new_areas : after;
    if (transaction->new_tail)
    {
        transaction->new_tail->next = after;
    }
    if (before)
    {
        before->next = replacement;
    }
    else
    {
        process->vm_areas = replacement;
    }
    transaction->new_areas = NULL; /* Published VMA list owns these now. */
    transaction->new_tail = NULL;
    if (!had_present_leaf)
    {
        /* x86 does not cache nonpresent translations. This also covers fixed
         * replacement/commit of PROT_NONE reservations and sparse ranges.
         * Inaccessible retained backing is safe to retire here: its previous
         * protection/removal barrier completed before this operation started. */
        if (operation == VM_OPERATION_MAP)
            __atomic_fetch_add(&g_vm_fresh_maps, 1u, __ATOMIC_RELAXED);
        else
            __atomic_fetch_add(&g_vm_no_present_changes, 1u, __ATOMIC_RELAXED);
        vm_destroy_transaction(transaction, true);
        *transaction_out = NULL;
        return 0;
    }
    __atomic_fetch_add(&g_vm_tlb_transactions, 1u, __ATOMIC_RELAXED);
    transaction->awaiting_tlb = true;
    __atomic_fetch_add(&g_vm_tlb_pending_transactions, 1u, __ATOMIC_RELEASE);
    transaction->ticket = paging_request_tlb_flush(&process->address_space);
    __atomic_store_n(&process->vm_pending, transaction, __ATOMIC_RELEASE);
    *transaction_out = transaction;
    return 0;
}

static bool vm_transaction_complete(void *context)
{
    process_vm_transaction_t *transaction = context;
    return paging_tlb_flush_complete(transaction->ticket);
}

static void vm_finish(process_t *process, process_vm_transaction_t *transaction)
{
    if (!transaction)
    {
        return;
    }
    /* All resources are process-owned while this caller sleeps. If the
     * process is killed here, quiescent process teardown cleans its journal. */
    if (!paging_tlb_flush_complete(transaction->ticket))
    {
        __atomic_fetch_add(&g_vm_tlb_waits, 1u, __ATOMIC_RELAXED);
        /* The wait helper checks this predicate with scheduler serialization
         * before enqueueing. An acknowledgement before or during registration
         * therefore cannot be lost. No timer quantization is required. */
        wait_queue_wait(&g_vm_progress_queue, vm_transaction_complete, transaction);
    }
    uint64_t flags = process_memory_lock(process);
    if (__atomic_load_n(&process->vm_pending, __ATOMIC_ACQUIRE) != transaction)
    {
        fatal("VM transaction ownership changed before completion");
    }
    __atomic_store_n(&process->vm_pending, NULL, __ATOMIC_RELEASE);
    vm_destroy_transaction(transaction, true);
    process_memory_unlock(process, flags);
    /* Every clear checks the serialization queue. A waiter can observe a new
     * journal before it resumes, so a flag attached to the old one is unsafe. */
    if (vm_wake_waiters(&g_vm_serial_queue))
        __atomic_fetch_add(&g_vm_serial_wakes, 1u, __ATOMIC_RELAXED);
}

static int64_t vm_map_backing(process_t *process, uintptr_t address, size_t length,
                       uint32_t protection, uint32_t flags, fd_description_t *file)
{
    uint32_t required = SYSCALL_VM_MAP_PRIVATE | SYSCALL_VM_MAP_ANONYMOUS;
    uint32_t fixed = SYSCALL_VM_MAP_FIXED | SYSCALL_VM_MAP_FIXED_NOREPLACE;
    uint32_t allowed = (file ? SYSCALL_VM_MAP_PRIVATE | SYSCALL_VM_MAP_SHARED | fixed : required | fixed) |
                       SYSCALL_VM_MAP_NORESERVE;
    size_t rounded;
    if (!vm_call_valid(process) || !vm_length_valid(length, &rounded) ||
        !vm_protection_valid(protection) ||
        (file ? ((flags & 3u) != SYSCALL_VM_MAP_PRIVATE && (flags & 3u) != SYSCALL_VM_MAP_SHARED) :
                (flags & required) != required) || (flags & ~allowed) ||
        ((flags & fixed) && !vm_range_valid(address, rounded)) ||
        ((flags & fixed) && !address) || (flags & fixed) == fixed)
    {
        return VM_EINVAL;
    }
    /* Nonfixed addresses are advisory. Ignore impossible hints and round
     * usable hints down to a page; fixed mappings remain exact and strict. */
    if (!(flags & fixed) && address)
    {
        address = align_down_uintptr(address, VM_PAGE_SIZE);
        if (!vm_range_valid(address, rounded)) address = 0;
    }
    protection = vm_protection_normalize(protection);
    uint64_t irq_flags = vm_lock_ready(process);
    uintptr_t selected = (flags & fixed)
                           ? address : vm_find_space(process, address, rounded);
    process_vm_area_t backing = {.base=selected,.length=rounded,.protection=protection,.file=file,
        .private_file=file && io_vfs_mapping_private(file)};
    process_vm_transaction_t *transaction = NULL;
    int result = selected ? vm_change_locked(process, selected, rounded, protection,
                                             (flags & SYSCALL_VM_MAP_FIXED) ? VM_OPERATION_REPLACE : VM_OPERATION_MAP,
                                             &transaction, file ? &backing : NULL) : VM_ENOMEM;
    process_memory_unlock(process, irq_flags);
    if (result != 0)
    {
        return result;
    }
    vm_finish(process, transaction);
    return (int64_t)selected;
}

int process_vm_protect(process_t *process, uintptr_t address, size_t length, uint32_t protection)
{
    size_t rounded;
    if (!vm_call_valid(process) || !vm_length_valid(length, &rounded) ||
        !vm_range_valid(address, rounded) || !vm_protection_valid(protection))
    {
        return VM_EINVAL;
    }
    protection = vm_protection_normalize(protection);
    uint64_t flags = vm_lock_ready(process);
    process_vm_transaction_t *transaction = NULL;
    int result = vm_change_locked(process, address, rounded, protection, VM_OPERATION_PROTECT, &transaction, NULL);
    process_memory_unlock(process, flags);
    if (result == 0)
    {
        vm_finish(process, transaction);
    }
    return result;
}

int process_vm_unmap(process_t *process, uintptr_t address, size_t length)
{
    size_t rounded;
    if (!vm_call_valid(process) || !vm_length_valid(length, &rounded) || !vm_range_valid(address, rounded))
    {
        return VM_EINVAL;
    }
    uint64_t flags = vm_lock_ready(process);
    process_vm_transaction_t *transaction = NULL;
    int result = vm_change_locked(process, address, rounded, 0, VM_OPERATION_UNMAP, &transaction, NULL);
    process_memory_unlock(process, flags);
    if (result == 0)
    {
        vm_finish(process, transaction);
    }
    return result;
}

int process_vm_advise(process_t *process, uintptr_t address, size_t length, uint32_t advice)
{
    bool posix_hint = (advice & SYSCALL_VM_ADVICE_POSIX) != 0;
    uint32_t policy = advice & ~SYSCALL_VM_ADVICE_POSIX;
    if (!vm_call_valid(process) || policy > SYSCALL_VM_ADVICE_DONTNEED ||
        (!posix_hint && policy != SYSCALL_VM_ADVICE_DONTNEED) ||
        (address & (VM_PAGE_SIZE - 1)))
    {
        return VM_EINVAL;
    }
    /* Permit the conventional zero-length advice-support query. */
    if (!length) return 0;
    size_t rounded;
    if (!vm_length_valid(length, &rounded) || !vm_range_valid(address, rounded))
    {
        return VM_EINVAL;
    }
    uint64_t flags = vm_lock_ready(process);
    if (posix_hint)
    {
        /* POSIX advice cannot change observable memory contents. Validate the
         * complete anonymous mapping; there is no replacement/prefetch policy
         * to tune yet, so these optional performance hints have no effect. */
        int result = vm_covered(process->vm_areas, address, address + rounded) ? 0 : VM_ENOMEM;
        process_memory_unlock(process, flags);
        return result;
    }
    process_vm_transaction_t *transaction = NULL;
    int result = vm_change_locked(process, address, rounded, 0, VM_OPERATION_DISCARD, &transaction, NULL);
    process_memory_unlock(process, flags);
    if (result == 0) vm_finish(process, transaction);
    return result;
}

int64_t process_vm_map(process_t *process, uintptr_t address, size_t length,
                       uint32_t protection, uint32_t flags)
{ return vm_map_backing(process,address,length,protection,flags,NULL); }
int64_t process_vm_map_file(process_t *process, uintptr_t address, size_t length,
                            uint32_t protection, uint32_t flags, fd_description_t *file)
{ return file ? vm_map_backing(process,address,length,protection,flags,file) : -EBADF; }
int process_vm_file_check(uintptr_t address, size_t length, uint32_t protection,
                          uint32_t flags, int64_t offset, size_t *rounded)
{
    uint32_t fixed=SYSCALL_VM_MAP_FIXED|SYSCALL_VM_MAP_FIXED_NOREPLACE;
    uint32_t sharing=flags & (SYSCALL_VM_MAP_PRIVATE|SYSCALL_VM_MAP_SHARED);
    if (!vm_length_valid(length,rounded) || !vm_protection_valid(protection) ||
        (sharing!=SYSCALL_VM_MAP_PRIVATE && sharing!=SYSCALL_VM_MAP_SHARED) ||
        (flags & ~(fixed|SYSCALL_VM_MAP_PRIVATE|SYSCALL_VM_MAP_SHARED|SYSCALL_VM_MAP_NORESERVE)) ||
        (flags&fixed)==fixed || ((flags&fixed) && !vm_range_valid(address,*rounded)) ||
        offset<0 || ((uint64_t)offset&(VM_PAGE_SIZE-1)) || *rounded>(uint64_t)INT64_MAX-offset) return -EINVAL;
    return 0;
}
int process_vm_sync_prepare(process_t *process, uintptr_t address, size_t length,
                            uint32_t options, fd_description_t **out)
{
    *out=NULL;
    uint32_t mode=options & (SYSCALL_MS_SYNC|SYSCALL_MS_ASYNC);
    size_t rounded=0;
    if ((options & ~(SYSCALL_MS_SYNC|SYSCALL_MS_ASYNC|SYSCALL_MS_INVALIDATE)) ||
        (mode!=SYSCALL_MS_SYNC && mode!=SYSCALL_MS_ASYNC) ||
        (address&(VM_PAGE_SIZE-1)) || (length && !vm_length_valid(length,&rounded)) ||
        !vm_range_valid(address,rounded)) return -EINVAL;
    uint64_t irq=process_memory_lock(process);
    int result=vm_covered(process->vm_areas,address,address+rounded)?0:-ENOMEM;
    size_t count=0;
    for (process_vm_area_t *a=process->vm_areas; !result && a; a=a->next)
        if (a->file && a->base<address+rounded && a->base+a->length>address) ++count;
    fd_description_t *bundle=result?NULL:io_vfs_sync_bundle_create(count);
    if (!result && !bundle) result=-ENOMEM;
    for (process_vm_area_t *a=process->vm_areas; !result && a; a=a->next)
        if (a->file && a->base<address+rounded && a->base+a->length>address &&
            !io_vfs_sync_bundle_add(bundle,a->file)) result=-ENOMEM;
    process_memory_unlock(process,irq);
    if (result) fd_description_put(bundle); else *out=bundle;
    return result;
}

bool process_vm_clone_locked(process_t *child, process_t *source)
{
    if (source->vm_pending || source->vm_pager_busy) return false;
    process_vm_area_t **tail = &child->vm_areas;
    for (process_vm_area_t *old = source->vm_areas; old; old = old->next)
    {
        process_vm_area_t *area = calloc(1, sizeof(*area));
        if (!area) return false;
        area->base = old->base; area->length = old->length;
        area->protection = old->protection; area->private_file = old->private_file;
        area->file_offset = old->file_offset;
        if (old->file && !fd_description_get(old->file)) { free(area); return false; }
        area->file = old->file;
        *tail = area; tail = &area->next;
        if (!old->pages) continue;
        size_t count = old->length / VM_PAGE_SIZE;
        area->pages = calloc(count, sizeof(*area->pages));
        if (!area->pages || !paging_prepare_user_range(&child->address_space, area->base, area->length)) return false;
        for (size_t i = 0; i < count; ++i)
        {
            paddr_t page = old->pages[i];
            if (!page) continue;
            if (page & USER_PAGE_SWAPPED)
            {
                if (!swap_retain(page)) return false;
                area->pages[i] = page;
                ++child->vm_swapped_pages;
                continue;
            }
            if (!old->file || (page & VM_OWNED_PAGE))
            {
                paddr_t copy;
                if (!user_memory_alloc_page(&copy)) return false;
                memcpy(phys_to_virt(copy), phys_to_virt(VM_PHYSICAL(page)), VM_PAGE_SIZE);
                page = copy | (old->file ? VM_OWNED_PAGE : 0);
            }
            area->pages[i] = page;
            vm_write_leaf(child, area->base + i * VM_PAGE_SIZE, area);
        }
    }
    return true;
}

/* Pager continuations run on protected workers, never on an IST, syscall
 * stack borrowed by another CPU, or while holding a VM/scheduler lock. */
static io_service_t *g_vm_pager_service;
static process_t *g_vm_pager_daemon;
static uint64_t g_vm_pager_target_mib;
extern uint64_t g_swap_reads, g_swap_writes, g_swap_errors;

static paddr_t *vm_page_slot_locked(process_t *process, uintptr_t address, uint32_t *protection)
{
    process_vm_area_t *area = vm_find_area(process->vm_areas, address);
    if (area && area->pages)
    {
        *protection = area->protection;
        return &area->pages[(address - area->base) / VM_PAGE_SIZE];
    }
    paddr_t *slot = process_legacy_page_slot_locked(process, address);
    if (slot) *protection = SYSCALL_VM_PROT_READ | SYSCALL_VM_PROT_WRITE;
    return slot;
}

static paddr_t *vm_swap_candidate_locked(process_t *process, uintptr_t *address, bool swapped)
{
    for (process_vm_area_t *area = process->vm_areas; area; area = area->next)
    {
        if (!area->pages) continue;
        for (size_t i = 0; i < area->length / VM_PAGE_SIZE; ++i)
        {
            paddr_t page = area->pages[i];
            if (!page || (page & (VM_NEW_PAGE | USER_PAGE_BUSY)) ||
                ((page & USER_PAGE_SWAPPED) != 0) != swapped ||
                (area->file && !(page & VM_OWNED_PAGE))) continue;
            *address = area->base + i * VM_PAGE_SIZE;
            return &area->pages[i];
        }
    }
    return process_legacy_swap_candidate_locked(process, address, swapped);
}

static void vm_pager_finish_locked(process_t *process)
{
    __atomic_store_n(&process->vm_pager_busy, false, __ATOMIC_RELEASE);
}

static int vm_page_in_direct(process_t *process, uintptr_t address)
{
    uint64_t flags = vm_lock_ready(process);
    uint32_t protection = 0;
    paddr_t *slot = vm_page_slot_locked(process, address, &protection);
    paddr_t token = slot ? *slot : 0;
    if (!(token & USER_PAGE_SWAPPED)) { process_memory_unlock(process, flags); return 0; }
    __atomic_store_n(&process->vm_pager_busy, true, __ATOMIC_RELEASE);
    process_memory_unlock(process, flags);
    paddr_t physical = 0;
    int result = !user_memory_alloc_page(&physical) ? -ENOMEM :
        !swap_load(token, physical) ? -EIO : 0;
    flags = process_memory_lock(process);
    slot = vm_page_slot_locked(process, address, &protection);
    if (!slot || *slot != token) fatal("pager lost an owned swap slot");
    if (!result)
    {
        bool accessible = protection != SYSCALL_VM_PROT_NONE;
        if (!paging_write_prepared_user_page(&process->address_space, address, physical, accessible,
                (protection & SYSCALL_VM_PROT_WRITE) != 0, (protection & SYSCALL_VM_PROT_EXEC) != 0))
            result = -ENOMEM;
        else
        {
            *slot = physical | (token & VM_OWNED_PAGE);
            __atomic_sub_fetch(&process->vm_swapped_pages, 1u, __ATOMIC_RELEASE);
            swap_release(token);
            physical = 0;
            process_usage_add_fault(process, true);
        }
    }
    vm_pager_finish_locked(process);
    process_memory_unlock(process, flags);
    if (physical) user_memory_free_page(physical);
    vm_wake_waiters(&g_vm_serial_queue);
    return result;
}

static int vm_pager_owner_close(void *context)
{ process_release_reference(context); return 0; }
static const fd_ops_t vm_pager_owner_ops = { .close = vm_pager_owner_close };
static void vm_pager_handler(io_request_t *request, io_service_result_t *result)
{
    result->description_owned = NULL; result->result = -EINVAL;
    fd_description_t *owner = io_request_description(request);
    if (!owner || fd_description_ops(owner)->close != vm_pager_owner_close ||
        io_request_buffer_size(request) != sizeof(uintptr_t)) return;
    uintptr_t address = *(uintptr_t *)io_request_buffer(request);
    result->result = vm_page_in_direct(fd_description_context(owner), address);
}

bool process_vm_page_in(process_t *process, uintptr_t address)
{
    if (!g_vm_pager_service || spinlock_preempt_disabled()) return false;
    spinlock_preempt_disable();
    uint64_t flags = spinlock_lock_irqsave(&g_process_lock);
    bool valid = process->lifetime_state == PROCESS_LIFETIME_ALIVE && process->join_waiters != UINT32_MAX;
    if (valid) ++process->join_waiters;
    spinlock_unlock_irqrestore(&g_process_lock, flags);
    fd_description_t *owner = valid ? fd_description_create_deferred(&vm_pager_owner_ops, process,
        process_fd_retirement_queue()) : NULL;
    if (valid && !owner) process_release_reference(process);
    io_request_t *request = NULL;
    int error = owner ? io_service_request_create(g_vm_pager_service, sizeof(uintptr_t), 0, 0, &request) : -ENOMEM;
    if (!error) error = io_request_bind(request, owner, NULL, NULL);
    if (!error) { owner = NULL; *(uintptr_t *)io_request_buffer(request) = align_down_uintptr(address, VM_PAGE_SIZE); }
    if (!error) error = process_io_register_current(request);
    bool registered = !error;
    if (!error) error = io_service_submit(g_vm_pager_service, request);
    if (error)
    {
        fd_description_put(owner);
        if (registered) (void)process_io_finish_current(true);
        else if (request) io_request_waiter_abandon(request);
    }
    spinlock_preempt_enable();
    if (error) return false;
    io_request_status_t status;
    error = process_io_wait_current(&status);
    spinlock_preempt_disable();
    if (!error) error = (int)status.result;
    (void)process_io_finish_current(error != 0);
    spinlock_preempt_enable();
    return !error;
}

static bool vm_reclaim_page(process_t *process)
{
    uint64_t flags = process_memory_lock(process);
    if (process->vm_pending || process->vm_pager_busy || process->exec_owner_tid ||
        __atomic_load_n(&process->vm_syscall_users, __ATOMIC_ACQUIRE) || process->state == PROCESS_STATE_ZOMBIE)
    { process_memory_unlock(process, flags); return false; }
    uintptr_t address = 0;
    paddr_t *slot = vm_swap_candidate_locked(process, &address, false);
    if (!slot) { process_memory_unlock(process, flags); return false; }
    paddr_t old = *slot;
    uint32_t protection = 0;
    (void)vm_page_slot_locked(process, address, &protection);
    if (!paging_write_prepared_user_page(&process->address_space, address, 0, false, false, false))
    { process_memory_unlock(process, flags); return false; }
    *slot = old | USER_PAGE_BUSY;
    __atomic_store_n(&process->vm_pager_busy, true, __ATOMIC_RELEASE);
    paging_tlb_ticket_t ticket = paging_request_tlb_flush(&process->address_space);
    process_memory_unlock(process, flags);
    while (!paging_tlb_flush_complete(ticket)) process_yield();
    paddr_t token = swap_store(VM_PHYSICAL(old));
    flags = process_memory_lock(process);
    slot = vm_page_slot_locked(process, address, &protection);
    if (!slot || *slot != (old | USER_PAGE_BUSY)) fatal("pager lost an eviction continuation");
    if (token)
    {
        *slot = token | (old & VM_OWNED_PAGE);
        __atomic_add_fetch(&process->vm_swapped_pages, 1u, __ATOMIC_RELEASE);
    }
    else
    {
        *slot = old;
        (void)paging_write_prepared_user_page(&process->address_space, address, VM_PHYSICAL(old),
            protection != SYSCALL_VM_PROT_NONE, (protection & SYSCALL_VM_PROT_WRITE) != 0,
            (protection & SYSCALL_VM_PROT_EXEC) != 0);
    }
    vm_pager_finish_locked(process);
    process_memory_unlock(process, flags);
    if (token) user_memory_free_page(VM_PHYSICAL(old));
    vm_wake_waiters(&g_vm_serial_queue);
    return token != 0;
}

static void vm_pager_daemon(void *unused)
{
    (void)unused;
    uint64_t cursor = 0;
    for (;;)
    {
        if (!swap_available() && !swap_discover()) { process_sleep_ms(1000); continue; }
        size_t target = pmm_total_bytes() / 16;
        if (target > 64u * 1024u * 1024u) target = 64u * 1024u * 1024u;
        if (target < 8u * 1024u * 1024u) target = 8u * 1024u * 1024u;
        uint64_t configured = __atomic_load_n(&g_vm_pager_target_mib, __ATOMIC_ACQUIRE);
        if (configured) target = configured * 1024u * 1024u;
        if (pmm_available_bytes() >= target) { process_sleep_ms(10); continue; }
        uint64_t flags = spinlock_lock_irqsave(&g_process_lock);
        process_t *selected = NULL;
        for (process_t *p = g_process_list; p; p = p->next)
            if (p->is_user && p->state != PROCESS_STATE_ZOMBIE && p->pid > cursor &&
                p->lifetime_state == PROCESS_LIFETIME_ALIVE && p->join_waiters != UINT32_MAX &&
                (!selected || p->pid < selected->pid)) selected = p;
        if (selected) { ++selected->join_waiters; cursor = selected->pid; }
        else cursor = 0;
        spinlock_unlock_irqrestore(&g_process_lock, flags);
        bool progress = false;
        if (selected)
        {
            for (unsigned i = 0; i < 64 && pmm_available_bytes() < target; ++i)
            { if (!vm_reclaim_page(selected)) break; progress = true; }
            process_release_reference(selected);
        }
        if (!progress) process_sleep_ms(1);
    }
}

static ssize_t vm_swap_status(vfs_node_t *node, size_t offset, void *buffer, size_t count, void *context)
{
    (void)node; (void)context;
    char *text = malloc(256);
    if (!text) return -ENOMEM;
    int length = snprintf(text, 256, "enabled=%u used_pages=%llu read_pages=%llu written_pages=%llu errors=%llu\n",
        swap_available() ? 1u : 0u, (unsigned long long)swap_used_pages(),
        (unsigned long long)__atomic_load_n(&g_swap_reads, __ATOMIC_RELAXED),
        (unsigned long long)__atomic_load_n(&g_swap_writes, __ATOMIC_RELAXED),
        (unsigned long long)__atomic_load_n(&g_swap_errors, __ATOMIC_RELAXED));
    size_t available = length > 0 && offset < (size_t)length ? (size_t)length - offset : 0;
    if (count > available) count = available;
    if (count) memcpy(buffer, text + offset, count);
    free(text); return (ssize_t)count;
}

static ssize_t vm_swap_target_write(vfs_node_t *node, size_t offset, const void *buffer, size_t count, void *context)
{
    (void)node; (void)context;
    if (offset || !count || count > 20) return -EINVAL;
    const char *text = buffer;
    uint64_t value = 0;
    size_t digits = 0;
    while (digits < count && text[digits] >= '0' && text[digits] <= '9')
    {
        value = value * 10 + (unsigned)(text[digits++] - '0');
        if (value > 1048576) return -EINVAL;
    }
    if (!digits) return -EINVAL;
    for (size_t i = digits; i < count; ++i)
        if (text[i] != '\n' && text[i] != '\r' && text[i] != ' ') return -EINVAL;
    __atomic_store_n(&g_vm_pager_target_mib, value, __ATOMIC_RELEASE);
    serial_printf("[swap] free-memory target MiB=%llu", (unsigned long long)value);
    return (ssize_t)count;
}

bool process_vm_pager_start(void)
{
    if (g_vm_pager_service) return true;
    io_service_t *service = io_service_create(32, 2, vm_pager_handler);
    if (!service) return false;
    process_t *daemon = process_create_kernel_service("pager", vm_pager_daemon, NULL, 0);
    if (!daemon)
    {
        if (io_service_shutdown(service) || io_service_destroy(service)) fatal("pager startup rollback failed");
        return false;
    }
    g_vm_pager_daemon = daemon;
    g_vm_pager_service = service;
    (void)procfs_create_file_at("memory/swap", vm_swap_status, NULL, NULL);
    (void)procfs_create_file_at("memory/swap_target_mib", NULL, vm_swap_target_write, NULL);
    return true;
}

static bool vm_syscall_pager_ready(void *context)
{
    process_t *process = context;
    return !__atomic_load_n(&process->vm_pager_busy, __ATOMIC_ACQUIRE);
}

int process_vm_syscall_enter(void)
{
    thread_t *thread = current_thread_local();
    if (!thread || !thread->is_user) return 0;
    process_t *process = thread->process;
    uint64_t flags;
    for (;;)
    {
        flags = process_memory_lock(process);
        if (!process->vm_pager_busy) break;
        process_memory_unlock(process, flags);
        __atomic_fetch_add(&g_vm_serial_waits, 1u, __ATOMIC_RELAXED);
        wait_queue_wait(&g_vm_serial_queue, vm_syscall_pager_ready, process);
    }
    /* Entry pins against eviction, not against unrelated VM transactions.
     * Publication is atomic under memory_lock, and each user copy validates
     * the published mapping while holding that same lock. Its old backing
     * stays journal-owned until TLB completion. VM mutation/fault operations
     * still use vm_lock_ready; ordinary clocks/UI calls need not park behind
     * a stream of another thread's discard/protection transactions. */
    thread->vm_syscall_active = true;
    __atomic_add_fetch(&process->vm_syscall_users, 1u, __ATOMIC_ACQ_REL);
    process_memory_unlock(process, flags);
    /* Conservative initial pinning policy: no usercopy or futex path may wait
     * for disk under a scheduler/VM lock. Restore evicted process pages before
     * entering the syscall, then exclude this process from reclamation until
     * every concurrent syscall has left. */
    while (__atomic_load_n(&process->vm_swapped_pages, __ATOMIC_ACQUIRE))
    {
        flags = vm_lock_ready(process);
        uintptr_t address = 0;
        paddr_t *slot = vm_swap_candidate_locked(process, &address, true);
        process_memory_unlock(process, flags);
        if (!slot) return -EIO;
        if (!process_vm_page_in(process, address)) return -ENOMEM;
    }
    return 0;
}

void process_vm_syscall_leave(void)
{
    thread_t *thread = current_thread_local();
    if (thread && thread->vm_syscall_active)
    {
        /* Safe-copy COW may publish under a lock and cannot wait there. Finish
         * its remote visibility barrier before returning from the syscall. */
        uint64_t flags = process_memory_lock(thread->process);
        paging_tlb_ticket_t ticket = thread->process->vm_cow_ticket;
        process_memory_unlock(thread->process, flags);
        if (ticket.generation && !paging_tlb_flush_complete(ticket))
        {
            if (!(flags & RFLAGS_IF_BIT)) __asm__ volatile ("sti" ::: "memory");
            while (!paging_tlb_flush_complete(ticket)) process_yield();
            cpu_restore_flags(flags);
        }
        thread->vm_syscall_active = false;
        __atomic_sub_fetch(&thread->process->vm_syscall_users, 1u, __ATOMIC_ACQ_REL);
    }
}
