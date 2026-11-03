#include "process_internal.h"
#include "physmem.h"
#include "io_vfs.h"
#include "errno.h"

/* Anonymous VM has its own address arena, leaving the existing ELF, sbrk,
 * main stack and descending thread/TLS pool unchanged. A PROT_NONE area has
 * no physical-page array until it is committed. Discarded pages are null
 * array entries, even when their VMA remains accessible. Metadata and in-flight
 * transactions belong to the process, never to a caller's stack. */
#define VM_PAGE_SIZE PAGE_SIZE_BYTES_LOCAL
#define VM_THREAD_POOL_BYTES USER_DEFAULT_THREAD_POOL_SIZE
#define VM_HEAP_GAP_BYTES USER_DEFAULT_VM_HEAP_GAP
#define VM_NEW_PAGE ((paddr_t)1)
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
} process_vm_transaction_t;

typedef enum { VM_OPERATION_MAP, VM_OPERATION_PROTECT, VM_OPERATION_UNMAP,
               VM_OPERATION_REPLACE, VM_OPERATION_DISCARD } vm_operation_t;

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
                if (!area->file && page && (free_all || (free_new && (page & VM_NEW_PAGE))))
                {
                    user_memory_free_page(page & ~VM_NEW_PAGE);
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
    vm_free_area_metadata(transaction->new_areas, true, false);
    vm_free_area_metadata(transaction->old_areas, false, false);
    if (completed)
    {
        for (size_t index = 0; index < transaction->retired_count; ++index)
        {
            user_memory_free_page(transaction->retired[index]);
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
    vm_destroy_transaction(process->vm_pending, true);
    process->vm_pending = NULL;
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
                                  uintptr_t address)
{
    if (!area->pages || area->protection == SYSCALL_VM_PROT_NONE)
    {
        return false;
    }
    size_t index = (address - area->base) / VM_PAGE_SIZE;
    paddr_t page = area->pages[index];
    bool allocated = false;
    if (!page)
    {
        if (!user_memory_alloc_page(&page))
        {
            return false;
        }
        memset(phys_to_virt(page), 0, VM_PAGE_SIZE);
        allocated = true;
    }
    if (page & VM_NEW_PAGE)
    {
        return false;
    }
    if (!paging_write_prepared_user_page(&process->address_space,
                                         align_down_uintptr(address, VM_PAGE_SIZE), page,
                                         true, (area->protection & SYSCALL_VM_PROT_WRITE) != 0,
                                         (area->protection & SYSCALL_VM_PROT_EXEC) != 0))
    {
        if (allocated) user_memory_free_page(page);
        return false;
    }
    area->pages[index] = page;
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
    return vm_commit_page_locked(process, area, address);
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
    if (!page)
    {
        if (!vm_commit_page_locked(process, area, address)) return false;
        page = area->pages[offset / VM_PAGE_SIZE];
    }
    if (page & VM_NEW_PAGE)
    {
        return false;
    }
    *host_out = (uint8_t *)phys_to_virt(page) + offset % VM_PAGE_SIZE;
    *available_out = VM_PAGE_SIZE - offset % VM_PAGE_SIZE;
    return true;
}

static uint64_t vm_lock_ready(process_t *process)
{
    for (;;)
    {
        uint64_t flags = process_memory_lock(process);
        if (!process->vm_pending)
        {
            return flags;
        }
        process_memory_unlock(process, flags);
        process_sleep_ms(1);
    }
}

static bool vm_call_valid(process_t *process)
{
    return process && process->is_user && process == current_process_local() &&
           (cpu_save_flags() & RFLAGS_IF_BIT) && !spinlock_preempt_disabled();
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
                area->pages[index] = io_vfs_mapping_page(old->file, (base-old->base)/VM_PAGE_SIZE+index);
                if (!area->pages[index]) return false;
            }
            else if (old && old->pages)
            {
                area->pages[index] = old->pages[(base - old->base) / VM_PAGE_SIZE + index];
            }
            else
            {
                paddr_t page = 0;
                if (!user_memory_alloc_page(&page))
                {
                    return false;
                }
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
    bool present = page && area->protection != SYSCALL_VM_PROT_NONE;
    if (!present) page = 0;
    if (!paging_write_prepared_user_page(&process->address_space, address, page, present,
                                         present && (area->protection & SYSCALL_VM_PROT_WRITE),
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
        if ((operation == VM_OPERATION_UNMAP || operation == VM_OPERATION_REPLACE ||
             operation == VM_OPERATION_DISCARD) && after->pages)
        {
            for (size_t page = (low - after->base) / VM_PAGE_SIZE;
                 page < (high - after->base) / VM_PAGE_SIZE; ++page)
            {
                if (!after->file && after->pages[page]) ++retired_count;
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
                if (!area->file && area->pages[page])
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
                    if (!area->file && area->pages[page])
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
    transaction->ticket = paging_request_tlb_flush(&process->address_space);
    process->vm_pending = transaction;
    *transaction_out = transaction;
    return 0;
}

static void vm_finish(process_t *process, process_vm_transaction_t *transaction)
{
    if (!transaction)
    {
        return;
    }
    /* All resources are process-owned while this caller sleeps. If the
     * process is killed here, quiescent process teardown cleans its journal. */
    while (!paging_tlb_flush_complete(transaction->ticket))
    {
        process_sleep_ms(1);
    }
    uint64_t flags = process_memory_lock(process);
    if (process->vm_pending != transaction)
    {
        fatal("VM transaction ownership changed before completion");
    }
    process->vm_pending = NULL;
    vm_destroy_transaction(transaction, true);
    process_memory_unlock(process, flags);
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
    process_vm_area_t backing = {.base=selected,.length=rounded,.protection=protection,.file=file};
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
