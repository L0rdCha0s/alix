#include "process_internal.h"

bool process_set_elf_metadata(process_t *process, const void *headers, size_t count, uintptr_t entry)
{
    if (!process || !headers || !count || count > UINT16_MAX || process->user_elf_metadata) return false;
    size_t size = sizeof(syscall_elf_info_t) + count * SYSCALL_ELF_PHENT;
    syscall_elf_info_t *info = calloc(1, size);
    if (!info) return false;
    info->version = SYSCALL_ELF_INFO_VERSION; info->size = (uint32_t)size;
    info->phent = SYSCALL_ELF_PHENT; info->phnum = (uint32_t)count; info->entry = entry;
    info->uid = process->uid; info->gid = process->gid;
    memcpy(info + 1, headers, count * SYSCALL_ELF_PHENT);
    process->user_elf_metadata = info;
    process->user_elf_metadata_size = size;
    return true;
}
#include "physmem.h"
#include "swap.h"

/*
 * src/kernel/process/process_memory.c
 *
 * Process address space management:
 * - allocates and initialises `process_t` and its paging space (`paging_space_t`)
 * - maps user virtual regions (ELF segments, user stack, user heap growth)
 * - tracks user mappings for cleanup on exit
 *
 * This layer bridges:
 * - `user_memory_*` (physical backing allocator) and
 * - `paging_*` (virtual→physical page table mappings).
 *
 * See docs/kernel/memory.md.
 */

static uintptr_t process_stack_bottom(const process_t *process);

typedef struct
{
    paddr_t physical;
    size_t bytes;
    uintptr_t virtual_address; /* Used only while preparing a rollback. */
} process_retired_range_t;

typedef struct process_retired_memory
{
    struct process_retired_memory *next;
    paging_tlb_ticket_t ticket;
    size_t count;
    process_retired_range_t ranges[];
} process_retired_memory_t;

static spinlock_t g_retired_memory_lock;
static process_retired_memory_t *g_retired_memory;

/* Allocate before changing PTEs: allocation failure must leave ownership and
 * mappings intact. Every record is heap-owned and outlives its source process. */
static process_retired_memory_t *process_retirement_allocate(size_t capacity)
{
    if (capacity == 0 || capacity > (SIZE_MAX - sizeof(process_retired_memory_t)) /
                                     sizeof(process_retired_range_t))
    {
        return NULL;
    }
    process_retired_memory_t *retired = malloc(sizeof(*retired) + capacity * sizeof(retired->ranges[0]));
    if (retired)
    {
        retired->next = NULL;
        retired->count = 0;
    }
    return retired;
}

static void process_retirement_enqueue(process_retired_memory_t *retired, paging_space_t *space)
{
    if (!retired)
    {
        return;
    }
    if (retired->count == 0)
    {
        free(retired);
        return;
    }
    retired->ticket = paging_request_tlb_flush(space);
    uint64_t flags = spinlock_lock_irqsave(&g_retired_memory_lock);
    retired->next = g_retired_memory;
    g_retired_memory = retired;
    spinlock_unlock_irqrestore(&g_retired_memory_lock, flags);
}

/* Called only from ordinary scheduler/idle context, never the IPI handler.
 * No acknowledgement wait, process pointer, or stack-owned asynchronous state. */
void process_reap_retired_memory(void)
{
    if ((cpu_save_flags() & (1ULL << 9)) == 0 || spinlock_preempt_disabled())
    {
        return;
    }
    /* A killed/preempted user thread must not strand a detached global list
     * on its discarded kernel stack. Keep ownership on-CPU until every batch
     * is either freed or republished; IRQs remain enabled for TLB responses. */
    spinlock_preempt_disable();
    uint64_t flags = spinlock_lock_irqsave(&g_retired_memory_lock);
    process_retired_memory_t *retired = g_retired_memory;
    g_retired_memory = NULL;
    spinlock_unlock_irqrestore(&g_retired_memory_lock, flags);

    process_retired_memory_t *pending = NULL;
    process_retired_memory_t *tail = NULL;
    while (retired)
    {
        process_retired_memory_t *next = retired->next;
        if (paging_tlb_flush_complete(retired->ticket))
        {
            for (size_t i = 0; i < retired->count; ++i)
            {
                user_memory_free(retired->ranges[i].physical, retired->ranges[i].bytes);
            }
            free(retired);
        }
        else
        {
            retired->next = pending;
            pending = retired;
            if (!tail)
            {
                tail = retired;
            }
        }
        retired = next;
    }
    if (pending)
    {
        flags = spinlock_lock_irqsave(&g_retired_memory_lock);
        tail->next = g_retired_memory;
        g_retired_memory = pending;
        spinlock_unlock_irqrestore(&g_retired_memory_lock, flags);
    }
    spinlock_preempt_enable();
}

uint64_t process_memory_lock(process_t *process)
{
    uint64_t flags = cpu_save_flags();
    cpu_cli();
    if (process)
    {
        spinlock_lock(&process->memory_lock);
    }
    return flags;
}

void process_memory_unlock(process_t *process, uint64_t flags)
{
    if (process)
    {
        spinlock_unlock(&process->memory_lock);
    }
    cpu_restore_flags(flags);
}

/* User-visible pid_t is signed 32-bit. Never truncate, recycle a live PID or
 * wrap the counter: the value after INT32_MAX is a permanent exhaustion
 * sentinel. Allocation failures may leave gaps, which do not affect identity. */
static uint64_t process_allocate_pid(void)
{
    uint64_t candidate = __atomic_load_n(&g_next_pid, __ATOMIC_RELAXED);
    for (;;)
    {
        if (candidate == 0 || candidate > 0x7fffffffULL)
        {
            return 0;
        }
        if (__atomic_compare_exchange_n(&g_next_pid, &candidate, candidate + 1,
                                        false, __ATOMIC_RELAXED, __ATOMIC_RELAXED))
        {
            return candidate;
        }
    }
}

process_t *allocate_process(const char *name, bool is_user)
{
    bool needs_clone = is_user;
    bool trace_clone = needs_clone && string_name_equals(name, "shell");
    bool trace_usb = string_name_equals(name, "usb_initd");
    if (trace_clone)
    {
        heap_debug_verify("shell_pre_alloc_verify");
        heap_debug_dump("shell_pre_alloc_dump");
        serial_printf("%s", "[process] paging trace enabled\r\n");
        paging_set_clone_trace(true);
    }
    if (trace_usb)
    {
        serial_printf("[proc usb_initd] alloc begin clone=%s\r\n", needs_clone ? "true" : "false");
    }
    process_t *proc = (process_t *)malloc(sizeof(process_t));
    if (!proc)
    {
        if (trace_clone)
        {
            serial_printf("%s", "[process] shell malloc failed\r\n");
            paging_set_clone_trace(false);
        }
        if (trace_usb)
        {
            serial_printf("%s", "[proc usb_initd] malloc failed\r\n");
        }
        return NULL;
    }
    memset(proc, 0, sizeof(*proc));
    serial_printf("[process] allocate name=%s\r\n",
                  (name && name[0]) ? name : "<unnamed>");
    proc->pid = process_allocate_pid();
    if (proc->pid == 0)
    {
        free(proc);
        if (trace_clone)
        {
            paging_set_clone_trace(false);
        }
        process_create_log(name, "pid_exhausted");
        return NULL;
    }
    proc->started_monotonic_ticks = timer_ticks();
    proc->state = PROCESS_STATE_READY;
    proc->lifetime_state = PROCESS_LIFETIME_ALIVE;
    bool space_ready = false;
    if (needs_clone)
    {
        process_create_log(name, "clone_start");
        space_ready = paging_clone_kernel_space(&proc->address_space);
    }
    else
    {
        process_create_log(name, "share_kernel");
        space_ready = paging_share_kernel_space(&proc->address_space);
    }
    if (trace_usb)
    {
        serial_printf("[proc usb_initd] share_kernel_space=%s\r\n", space_ready ? "ok" : "fail");
    }
    if (trace_clone)
    {
        heap_debug_verify("shell_post_clone_verify");
        serial_printf("%s", "[process] paging trace disabled\r\n");
        paging_set_clone_trace(false);
    }
    if (!space_ready)
    {
        free(proc);
        process_create_log(name, "space_fail");
        if (trace_usb)
        {
            serial_printf("%s", "[proc usb_initd] space setup failed\r\n");
        }
        return NULL;
    }
    process_create_log(name, needs_clone ? "clone_done" : "share_done");
    proc->cr3 = proc->address_space.cr3;
    serial_printf("[process] alloc detail ptr=0x%016llX name=%s pid=0x%016llX cr3=0x%016llX as_cr3=0x%016llX\r\n",
                  (unsigned long long)(uintptr_t)proc,
                  (name && name[0]) ? name : "<unnamed>",
                  (unsigned long long)proc->pid,
                  (unsigned long long)proc->cr3,
                  (unsigned long long)proc->address_space.cr3);
    if (name)
    {
        size_t len = strlen(name);
        if (len >= PROCESS_NAME_MAX)
        {
            len = PROCESS_NAME_MAX - 1;
        }
        memcpy(proc->name, name, len);
        proc->name[len] = '\0';
    }
    else
    {
        proc->name[0] = '\0';
    }
    proc->exit_status = 0;
    proc->wait_status = 0;
    proc->main_thread = NULL;
    proc->current_thread = NULL;
    spinlock_init(&proc->threads_lock);
    spinlock_init(&proc->memory_lock);
    spinlock_init(&proc->context_lock);
    spinlock_init(&proc->usage_lock);
    proc->threads = NULL;
    proc->thread_count = 0;
    proc->running_thread_count = 0;
    proc->join_waiters = 0;
    proc->next = NULL;
    proc->stdout_fd = g_console_stdout_fd;
    proc->uid = VFS_UID_ROOT;
    proc->gid = VFS_GID_ROOT;
    proc->is_user = is_user;
    proc->parent = NULL;
    proc->first_child = NULL;
    proc->sibling_prev = NULL;
    proc->sibling_next = NULL;
    proc->cwd = NULL;
    proc->cwd_owner = NULL;
    proc->user_regions = NULL;
    proc->user_entry_point = 0;
    proc->user_stack_top = 0;
    proc->user_stack_size = 0;
    proc->user_stack_committed = 0;
    proc->user_stack_pages = NULL;
    proc->user_stack_page_count = 0;
    /* Keep user-mode stubs at the top of user space; thread stacks start below. */
    proc->user_thread_stack_next = is_user
                                   ? align_down_uintptr(USER_STUB_CODE_BASE, PAGE_SIZE_BYTES_LOCAL)
                                   : 0;
    proc->user_heap_base = 0;
    proc->user_heap_brk = 0;
    proc->user_heap_limit = 0;
    proc->user_heap_committed = 0;
    proc->heap_page_dirs = NULL;
    proc->heap_dir_count = 0;
    proc->default_priority = THREAD_PRIORITY_NORMAL;
    proc->default_priority_override = THREAD_PRIORITY_NORMAL;
    proc->default_priority_override_active = false;
    proc->default_affinity_enabled = false;
    proc->default_affinity_cpu = RUN_QUEUE_CPU_INVALID;
    proc->magic = PROCESS_MAGIC;
    wait_queue_init(&proc->wait_queue);
    return proc;
}

void process_free_user_regions(process_t *process)
{
    process_clear_args(process);
    process_clear_environment(process);
    if (process)
    {
        process_clear_user_tls_template(process);
    }
    if (!process)
    {
        return;
    }
    process_vm_destroy(process);
    free(process->user_elf_metadata);
    process->user_elf_metadata = NULL;
    process->user_elf_metadata_size = 0;

    if (process->user_stack_pages && process->user_stack_page_count > 0 &&
        process->user_stack_top != 0 && process->user_stack_size != 0)
    {
        for (size_t i = 0; i < process->user_stack_page_count; ++i)
        {
            paddr_t phys = process->user_stack_pages[i];
            if (phys == 0)
            {
                continue;
            }
            process->user_stack_pages[i] = 0;
            user_memory_free(phys, PAGE_SIZE_BYTES_LOCAL);
        }
    }
    if (process->user_stack_pages)
    {
        free(process->user_stack_pages);
        process->user_stack_pages = NULL;
    }
    process->user_stack_page_count = 0;
    process->user_stack_committed = 0;
    process->user_stack_top = 0;
    process->user_stack_size = 0;
    process->user_initial_stack = 0;

    process_user_region_t *region = process->user_regions;
    while (region)
    {
        process_user_region_t *next = region->next;
        if (region->phys_base != 0 && region->mapped_size > 0)
        {
            user_memory_free(region->phys_base, region->mapped_size);
        }
        free(region->retirement);
        free(region);
        region = next;
    }
    process->user_regions = NULL;
    process_free_heap_pages(process);
    process->user_heap_base = 0;
    process->user_heap_brk = 0;
    process->user_heap_limit = 0;
    process->user_heap_committed = 0;
}

static void process_unlink_user_region(process_t *process, process_user_region_t *region)
{
    if (!process || !region)
    {
        return;
    }
    process_user_region_t **cursor = &process->user_regions;
    while (*cursor)
    {
        if (*cursor == region)
        {
            *cursor = region->next;
            break;
        }
        cursor = &(*cursor)->next;
    }
    /* The caller transfers backing ownership to a retirement batch first. */
    free(region);
}

static bool process_map_user_region(process_t *process, const process_user_region_t *region)
{
    if (!process || !region || region->mapped_size == 0)
    {
        return false;
    }
    return paging_map_user_range(&process->address_space,
                                 region->user_base,
                                 (uintptr_t)region->phys_base,
                                 region->mapped_size,
                                 region->writable,
                                 region->executable);
}

static size_t process_heap_dir_capacity(const process_t *process)
{
    return process ? process->heap_dir_count : 0;
}

static process_heap_l2_t *process_heap_table(process_t *process, size_t dir_index, bool create)
{
    if (!process || !process->heap_page_dirs || dir_index >= process->heap_dir_count)
    {
        return NULL;
    }
    process_heap_l2_t *table = process->heap_page_dirs[dir_index];
    if (!table && create)
    {
        table = (process_heap_l2_t *)malloc(sizeof(process_heap_l2_t));
        if (!table)
        {
            return NULL;
        }
        memset(table, 0, sizeof(*table));
        process->heap_page_dirs[dir_index] = table;
    }
    return table;
}

static inline bool process_heap_entry_present(const process_heap_l2_t *table, size_t index)
{
    if (!table || index >= PROCESS_HEAP_L2_ENTRIES)
    {
        return false;
    }
    return (table->present[index / 64] >> (index % 64)) & 1ULL;
}

static inline void process_heap_entry_set(process_heap_l2_t *table, size_t index, uintptr_t phys)
{
    if (!table || index >= PROCESS_HEAP_L2_ENTRIES)
    {
        return;
    }
    table->phys[index] = (paddr_t)phys;
    table->present[index / 64] |= (1ULL << (index % 64));
}

static inline void process_heap_entry_clear(process_heap_l2_t *table, size_t index)
{
    if (!table || index >= PROCESS_HEAP_L2_ENTRIES)
    {
        return;
    }
    table->phys[index] = 0;
    table->present[index / 64] &= ~(1ULL << (index % 64));
}

static bool process_heap_table_empty(const process_heap_l2_t *table)
{
    if (!table)
    {
        return true;
    }
    for (size_t i = 0; i < PROCESS_HEAP_PRESENT_WORDS; ++i)
    {
        if (table->present[i])
        {
            return false;
        }
    }
    return true;
}

static bool process_heap_lookup(const process_t *process, uintptr_t virt_page, paddr_t *phys_out)
{
    if (!process || virt_page < process->user_heap_base || virt_page >= process->user_heap_limit)
    {
        return false;
    }
    uintptr_t offset = (virt_page - process->user_heap_base) / PAGE_SIZE_BYTES_LOCAL;
    size_t dir_index = (size_t)(offset >> PROCESS_HEAP_L2_SHIFT);
    size_t entry_index = (size_t)(offset & PROCESS_HEAP_L2_MASK);
    if (!process->heap_page_dirs || dir_index >= process->heap_dir_count)
    {
        return false;
    }
    process_heap_l2_t *table = process->heap_page_dirs[dir_index];
    if (!process_heap_entry_present(table, entry_index))
    {
        return false;
    }
    if (table->phys[entry_index] & (USER_PAGE_SWAPPED | USER_PAGE_BUSY)) return false;
    if (phys_out)
    {
        *phys_out = table->phys[entry_index];
    }
    return true;
}

static void process_heap_free_map(process_t *process)
{
    if (!process)
    {
        return;
    }
    if (process->heap_page_dirs)
    {
        for (size_t i = 0; i < process->heap_dir_count; ++i)
        {
            if (process->heap_page_dirs[i])
            {
                free(process->heap_page_dirs[i]);
                process->heap_page_dirs[i] = NULL;
            }
        }
        free(process->heap_page_dirs);
    }
    process->heap_page_dirs = NULL;
    process->heap_dir_count = 0;
}

bool process_heap_zero_range(process_t *process, uintptr_t start, size_t bytes)
{
    if (!process || bytes == 0)
    {
        return true;
    }
    uintptr_t addr = start;
    size_t remaining = bytes;
    while (remaining > 0)
    {
        uintptr_t page_base = align_down_uintptr(addr, PAGE_SIZE_BYTES_LOCAL);
        paddr_t phys = 0;
        if (!process_heap_lookup(process, page_base, &phys))
        {
            return false;
        }
        size_t page_offset = (size_t)(addr - page_base);
        size_t chunk = PAGE_SIZE_BYTES_LOCAL - page_offset;
        if (chunk > remaining)
        {
            chunk = remaining;
        }
        memset((uint8_t *)phys_to_virt(phys) + page_offset, 0, chunk);
        addr += chunk;
        remaining -= chunk;
    }
    return true;
}

bool process_heap_release_from(process_t *process, uintptr_t virt_start)
{
    if (!process || !process->heap_page_dirs)
    {
        return true;
    }

    if (virt_start < process->user_heap_base)
    {
        virt_start = process->user_heap_base;
    }

    uintptr_t aligned_start = align_down_uintptr(virt_start, PAGE_SIZE_BYTES_LOCAL);
    size_t start_page = (size_t)((aligned_start - process->user_heap_base) / PAGE_SIZE_BYTES_LOCAL);
    size_t max_pages = process_heap_dir_capacity(process) * PROCESS_HEAP_L2_ENTRIES;

    size_t count = 0;
    for (size_t page = start_page; page < max_pages; ++page)
    {
        uintptr_t virt = process->user_heap_base + page * PAGE_SIZE_BYTES_LOCAL;
        if (virt >= process->user_heap_limit)
        {
            break;
        }
        process_heap_l2_t *table = process_heap_table(process, page >> PROCESS_HEAP_L2_SHIFT, false);
        if (process_heap_entry_present(table, page & PROCESS_HEAP_L2_MASK))
        {
            ++count;
        }
    }
    if (count == 0)
    {
        return true;
    }
    process_retired_memory_t *retired = process_retirement_allocate(count);
    if (!retired)
    {
        return false;
    }

    for (size_t page = start_page; page < max_pages; ++page)
    {
        uintptr_t virt = process->user_heap_base + page * PAGE_SIZE_BYTES_LOCAL;
        if (virt >= process->user_heap_limit)
        {
            break;
        }

        size_t dir_index = page >> PROCESS_HEAP_L2_SHIFT;
        size_t entry_index = page & PROCESS_HEAP_L2_MASK;
        process_heap_l2_t *table = process_heap_table(process, dir_index, false);
        if (!table || !process_heap_entry_present(table, entry_index))
        {
            continue;
        }

        paddr_t phys = table->phys[entry_index];
        if (!paging_unmap_user_page(&process->address_space, virt))
        {
            fatal("owned heap page could not be unmapped");
        }
        process_heap_entry_clear(table, entry_index);
        retired->ranges[retired->count++] = (process_retired_range_t){
            .physical = phys, .bytes = PAGE_SIZE_BYTES_LOCAL, .virtual_address = virt
        };

        if (process_heap_table_empty(table))
        {
            free(table);
            process->heap_page_dirs[dir_index] = NULL;
        }
    }
    process_retirement_enqueue(retired, &process->address_space);
    return true;
}

void process_free_heap_pages(process_t *process)
{
    if (!process)
    {
        return;
    }
    /* Only process creation failure and final quiescent teardown call this.
     * No CPU can retain this process's non-global user translations then. */
    for (size_t dir = 0; dir < process->heap_dir_count; ++dir)
    {
        process_heap_l2_t *table = process_heap_table(process, dir, false);
        for (size_t index = 0; table && index < PROCESS_HEAP_L2_ENTRIES; ++index)
        {
            if (process_heap_entry_present(table, index))
            {
                user_memory_free_page(table->phys[index]);
            }
        }
    }
    process->user_heap_committed = process->user_heap_base;
    process_heap_free_map(process);
}

static void process_heap_rollback(process_t *process, process_retired_memory_t *retired)
{
    for (size_t i = 0; i < retired->count; ++i)
    {
        uintptr_t virt = retired->ranges[i].virtual_address;
        size_t page = (size_t)((virt - process->user_heap_base) / PAGE_SIZE_BYTES_LOCAL);
        size_t dir = page >> PROCESS_HEAP_L2_SHIFT;
        process_heap_l2_t *table = process_heap_table(process, dir, false);
        if (!paging_unmap_user_page(&process->address_space, virt))
        {
            fatal("heap rollback could not remove owned mapping");
        }
        process_heap_entry_clear(table, page & PROCESS_HEAP_L2_MASK);
        if (process_heap_table_empty(table))
        {
            free(table);
            process->heap_page_dirs[dir] = NULL;
        }
    }
    process_retirement_enqueue(retired, &process->address_space);
}

bool process_heap_commit_range(process_t *process, uintptr_t start, uintptr_t end)
{
    if (!process || start >= end)
    {
        return true;
    }
    if (((start | end) & (PAGE_SIZE_BYTES_LOCAL - 1)) != 0 ||
        start < process->user_heap_base || end > process->user_heap_limit)
    {
        return false;
    }
    process_retired_memory_t *rollback = process_retirement_allocate((end - start) / PAGE_SIZE_BYTES_LOCAL);
    if (!rollback)
    {
        return false;
    }
    uintptr_t page_addr = start;
    while (page_addr < end)
    {
        paddr_t phys = 0;
        uintptr_t offset = (page_addr - process->user_heap_base) / PAGE_SIZE_BYTES_LOCAL;
        size_t dir_index = (size_t)(offset >> PROCESS_HEAP_L2_SHIFT);
        size_t entry_index = (size_t)(offset & PROCESS_HEAP_L2_MASK);

        if (dir_index >= process->heap_dir_count)
        {
            process_heap_rollback(process, rollback);
            process->user_heap_committed = start;
            return false;
        }

        process_heap_l2_t *table = process_heap_table(process, dir_index, true);
        if (!table)
        {
            process_heap_rollback(process, rollback);
            process->user_heap_committed = start;
            return false;
        }

        if (process_heap_entry_present(table, entry_index))
        {
            page_addr += PAGE_SIZE_BYTES_LOCAL;
            continue;
        }

        if (!user_memory_alloc_page(&phys))
        {
            serial_printf("[heap] alloc_page failed pid=0x%016llX virt=0x%016llX avail=0x%016llX\n",
                          (unsigned long long)process->pid,
                          (unsigned long long)page_addr,
                          (unsigned long long)user_memory_available());
            process_heap_rollback(process, rollback);
            process->user_heap_committed = start;
            return false;
        }
        memset(phys_to_virt(phys), 0, PAGE_SIZE_BYTES_LOCAL);
        if (!paging_map_user_page(&process->address_space,
                                  page_addr,
                                  (uintptr_t)phys,
                                  true,
                                  false))
        {
            serial_printf("[heap] map failed pid=0x%016llX virt=0x%016llX phys=0x%016llX\n",
                          (unsigned long long)process->pid,
                          (unsigned long long)page_addr,
                          (unsigned long long)phys);
            user_memory_free_page(phys);
            process_heap_rollback(process, rollback);
            process->user_heap_committed = start;
            return false;
        }
        process_heap_entry_set(table, entry_index, phys);
        rollback->ranges[rollback->count++] = (process_retired_range_t){
            .physical = phys, .bytes = PAGE_SIZE_BYTES_LOCAL, .virtual_address = page_addr
        };
        page_addr += PAGE_SIZE_BYTES_LOCAL;
    }
    free(rollback);
    process->user_heap_committed = end;
    return true;
}

static bool process_user_region_allocate(process_t *process,
                                         uintptr_t user_base,
                                         size_t bytes,
                                         bool writable,
                                         bool executable,
                                         process_user_region_t **region_out)
{
    if (!process || bytes == 0)
    {
        return false;
    }

    size_t aligned_bytes = align_up_size(bytes, PAGE_SIZE_BYTES_LOCAL);
    paddr_t phys = user_memory_alloc(aligned_bytes);
    if (phys == 0)
    {
        return false;
    }
    void *host = phys_to_virt(phys);
    memset(host, 0, aligned_bytes);

    process_user_region_t *region = (process_user_region_t *)malloc(sizeof(process_user_region_t));
    if (!region)
    {
        user_memory_free(phys, aligned_bytes);
        return false;
    }

    process_retired_memory_t *retirement = process_retirement_allocate(1);
    if (!retirement)
    {
        user_memory_free(phys, aligned_bytes);
        free(region);
        return false;
    }

    region->phys_base = phys;
    region->mapped_size = aligned_bytes;
    region->user_base = user_base;
    region->writable = writable;
    region->executable = executable;
    region->retirement = retirement;
    region->next = process->user_regions;
    process->user_regions = region;

    if (region_out)
    {
        *region_out = region;
    }
    return true;
}

static bool __attribute__((unused)) process_heap_commit(process_t *process, uintptr_t commit_start, uintptr_t commit_end)
{
    if (!process || commit_end <= commit_start)
    {
        return true;
    }
    uintptr_t addr = commit_start;
    while (addr < commit_end)
    {
        size_t chunk = commit_end - addr;
        void *host = NULL;
        if (!process_map_user_segment(process, addr, chunk, true, false, &host))
        {
            return false;
        }
        memset(host, 0, chunk);
        addr += chunk;
    }
    return true;
}

/*
 * Map a user virtual range into a process address space.
 *
 * - Allocates physical backing pages from `user_memory_alloc`.
 * - Records the mapping in `process->user_regions` for later teardown.
 * - Maps the pages into `process->address_space` as user-accessible pages.
 *
 * On success, `host_ptr_out` receives a kernel-mapped pointer to the same
 * physical pages, which is useful for initialising contents (ELF copy, zeroing).
 */
static bool process_ranges_overlap(uintptr_t lhs_base,
                                   uintptr_t lhs_end,
                                   uintptr_t rhs_base,
                                   uintptr_t rhs_end)
{
    return lhs_base < rhs_end && rhs_base < lhs_end;
}

bool process_map_user_segment_locked(process_t *process,
                                     uintptr_t user_base,
                                     size_t bytes,
                                     bool writable,
                                     bool executable,
                                     bool allow_reserved,
                                     void **host_ptr_out)
{
    if (!process || bytes == 0)
    {
        return false;
    }

    uintptr_t aligned_base = align_down_uintptr(user_base, PAGE_SIZE_BYTES_LOCAL);
    size_t offset = (size_t)(user_base - aligned_base);
    if (bytes > SIZE_MAX - offset)
    {
        return false;
    }
    if (bytes + offset > SIZE_MAX - (PAGE_SIZE_BYTES_LOCAL - 1))
    {
        return false;
    }
    size_t total = align_up_size(bytes + offset, PAGE_SIZE_BYTES_LOCAL);
    if (total == 0 || total < bytes || aligned_base < USER_ADDRESS_SPACE_BASE ||
        aligned_base > UINTPTR_MAX - total)
    {
        return false;
    }
    uintptr_t aligned_end = aligned_base + total;
    if (aligned_end == 0 || aligned_end - 1 > USER_ADDRESS_SPACE_LIMIT)
    {
        return false;
    }
    /* Native VM owns a separate arena, including uncommitted reservations.
     * Legacy ELF/thread/TLS allocation must never collide with that arena. */
    if (process_vm_range_reserved(aligned_base, total))
    {
        return false;
    }

    if (!allow_reserved)
    {
        uintptr_t stack_bottom = process_stack_bottom(process);
        uintptr_t guarded_stack_bottom = stack_bottom >= USER_DEFAULT_STACK_GUARD_SIZE
                                           ? stack_bottom - USER_DEFAULT_STACK_GUARD_SIZE : stack_bottom;
        if ((process->user_heap_limit > process->user_heap_base &&
             process_ranges_overlap(aligned_base, aligned_end,
                                    process->user_heap_base, process->user_heap_limit)) ||
            (stack_bottom != 0 && process->user_stack_top > stack_bottom &&
             process_ranges_overlap(aligned_base, aligned_end,
                                    guarded_stack_bottom, process->user_stack_top)) ||
            process_ranges_overlap(aligned_base, aligned_end,
                                   USER_STUB_CODE_BASE,
                                   USER_PREEMPT_STUB_BASE + PAGE_SIZE_BYTES_LOCAL))
        {
            return false;
        }
    }

    for (process_user_region_t *existing = process->user_regions;
         existing;
         existing = existing->next)
    {
        uintptr_t existing_end = existing->user_base + existing->mapped_size;
        if (existing_end < existing->user_base ||
            process_ranges_overlap(aligned_base, aligned_end,
                                   existing->user_base, existing_end))
        {
            return false;
        }
    }

    process_user_region_t *region = NULL;
    if (!process_user_region_allocate(process,
                                      aligned_base,
                                      total,
                                      writable,
                                      executable,
                                      &region))
    {
        return false;
    }

    if (!process_map_user_region(process, region))
    {
        process_retired_memory_t *rollback = region->retirement;
        rollback->ranges[rollback->count++] = (process_retired_range_t){
            .physical = region->phys_base, .bytes = region->mapped_size, .virtual_address = region->user_base
        };
        process_unlink_user_region(process, region);
        /* paging_map_user_range removed any partially installed PTEs. Keep
         * all backing until its remote translations have been invalidated. */
        process_retirement_enqueue(rollback, &process->address_space);
        return false;
    }

    if (host_ptr_out)
    {
        uint8_t *base_ptr = (uint8_t *)phys_to_virt(region->phys_base);
        *host_ptr_out = base_ptr + offset;
    }
    return true;
}

bool process_allocate_aux_user_segment_locked(process_t *process, size_t bytes,
                                              uintptr_t *base_out, void **host_out)
{
    if (!process || !base_out || !host_out || !bytes ||
        (bytes & (PAGE_SIZE_BYTES_LOCAL - 1)))
    {
        return false;
    }
    *base_out = 0;
    *host_out = NULL;
    uintptr_t floor = process_vm_auxiliary_base();
    uintptr_t top = align_down_uintptr(USER_STUB_CODE_BASE, PAGE_SIZE_BYTES_LOCAL);
    const uintptr_t guard = PAGE_SIZE_BYTES_LOCAL;
    if (floor >= top || top - floor <= guard || bytes > top - floor - guard)
    {
        return false;
    }

    /* Scan the current region set rather than permanently consuming a cursor.
     * Existing regions include both stacks and TLS. Reserving one page below
     * every region also preserves stack guards when holes are reused. */
    uintptr_t candidate_top = top;
    while (candidate_top > floor && candidate_top - floor >= bytes + guard)
    {
        uintptr_t base = candidate_top - bytes;
        uintptr_t guarded_base = base - guard;
        uintptr_t conflict_top = candidate_top;
        bool conflict = false;
        for (process_user_region_t *region = process->user_regions; region; region = region->next)
        {
            if (region->mapped_size == 0)
            {
                continue;
            }
            if (region->user_base > UINTPTR_MAX - region->mapped_size)
            {
                return false;
            }
            uintptr_t occupied_end = region->user_base + region->mapped_size;
            uintptr_t occupied_start = region->user_base >= guard ? region->user_base - guard : 0;
            if (occupied_end <= floor || occupied_start >= candidate_top)
            {
                continue;
            }
            if (guarded_base < occupied_end && candidate_top > occupied_start)
            {
                conflict = true;
                if (occupied_start < conflict_top)
                {
                    conflict_top = occupied_start;
                }
            }
        }
        if (conflict)
        {
            if (conflict_top <= floor)
            {
                return false;
            }
            candidate_top = conflict_top;
            continue;
        }
        if (!process_map_user_segment_locked(process, base, bytes, true, false, false, host_out))
        {
            return false;
        }
        *base_out = base;
        process->user_thread_stack_next = guarded_base;
        return true;
    }
    return false;
}

bool process_complete_user_mapping(process_t *process)
{
    if (!process)
    {
        return false;
    }
    paging_tlb_ticket_t ticket = paging_request_tlb_flush(&process->address_space);
    if (!paging_tlb_flush_complete(ticket) &&
        (((cpu_save_flags() & RFLAGS_IF_BIT) == 0) || spinlock_preempt_disabled()))
    {
        return false;
    }
    /* Reused stack/TLS addresses must not reach a new thread while another
     * CPU can still translate that VA to retired backing. No lock is held. */
    while (!paging_tlb_flush_complete(ticket))
    {
        process_sleep_ms(1);
    }
    return true;
}

bool process_map_user_segment(process_t *process,
                              uintptr_t user_base,
                              size_t bytes,
                              bool writable,
                              bool executable,
                              void **host_ptr_out)
{
    uint64_t flags = process_memory_lock(process);
    bool ok = process_map_user_segment_locked(process,
                                              user_base,
                                              bytes,
                                              writable,
                                              executable,
                                              false,
                                              host_ptr_out);
    process_memory_unlock(process, flags);
    return ok;
}

bool process_unmap_user_segment(process_t *process, uintptr_t user_base, size_t bytes)
{
    if (!process || bytes == 0)
    {
        return false;
    }
    uintptr_t aligned_base = align_down_uintptr(user_base, PAGE_SIZE_BYTES_LOCAL);
    size_t offset = (size_t)(user_base - aligned_base);
    if (bytes > SIZE_MAX - offset)
    {
        return false;
    }
    if (bytes + offset > SIZE_MAX - (PAGE_SIZE_BYTES_LOCAL - 1))
    {
        return false;
    }
    size_t total = align_up_size(bytes + offset, PAGE_SIZE_BYTES_LOCAL);
    uint64_t flags = process_memory_lock(process);
    process_user_region_t *region = process->user_regions;
    while (region && (region->user_base != aligned_base || region->mapped_size != total))
    {
        region = region->next;
    }
    if (!region)
    {
        process_memory_unlock(process, flags);
        return false;
    }
    /* Reserved at map time, so thread-stack teardown cannot fail for lack of
     * retirement metadata while holding the scheduler lock. */
    process_retired_memory_t *retired = region->retirement;
    retired->ranges[retired->count++] = (process_retired_range_t){
        .physical = region->phys_base, .bytes = region->mapped_size, .virtual_address = region->user_base
    };
    for (uintptr_t addr = aligned_base; addr < aligned_base + total; addr += PAGE_SIZE_BYTES_LOCAL)
    {
        if (!paging_unmap_user_page(&process->address_space, addr))
        {
            fatal("owned user segment could not be unmapped");
        }
    }
    process_unlink_user_region(process, region);
    process_retirement_enqueue(retired, &process->address_space);
    process_memory_unlock(process, flags);
    return true;
}

static bool process_setup_user_stack(process_t *process)
{
    process->user_stack_top = USER_STACK_TOP;
    process->user_stack_size = USER_STACK_SIZE;
    process->user_stack_committed = USER_STACK_TOP;

    size_t page_count = align_up_size(USER_STACK_SIZE, PAGE_SIZE_BYTES_LOCAL) / PAGE_SIZE_BYTES_LOCAL;
    if (page_count == 0)
    {
        return false;
    }
    process->user_stack_pages = (paddr_t *)malloc(sizeof(paddr_t) * page_count);
    if (!process->user_stack_pages)
    {
        return false;
    }
    memset(process->user_stack_pages, 0, sizeof(paddr_t) * page_count);
    process->user_stack_page_count = page_count;
    return true;
}

static bool process_setup_user_heap(process_t *process)
{
    if (!process)
    {
        return false;
    }
    process->user_heap_base = USER_HEAP_BASE;
    process->user_heap_brk = USER_HEAP_BASE;
    process->user_heap_limit = USER_HEAP_BASE + USER_HEAP_SIZE;
    process->user_heap_committed = USER_HEAP_BASE;
    size_t dir_count = (USER_HEAP_SIZE + PROCESS_HEAP_L2_SPAN - 1) / PROCESS_HEAP_L2_SPAN;
    if (dir_count == 0)
    {
        dir_count = 1;
    }
    process->heap_dir_count = dir_count;
    process->heap_page_dirs = (process_heap_l2_t **)malloc(sizeof(process_heap_l2_t *) * dir_count);
    if (!process->heap_page_dirs)
    {
        process->heap_dir_count = 0;
        return false;
    }
    memset(process->heap_page_dirs, 0, sizeof(process_heap_l2_t *) * dir_count);
    return true;
}

void process_clear_args(process_t *process)
{
    if (!process)
    {
        return;
    }
    if (process->arg_values)
    {
        free(process->arg_values);
        process->arg_values = NULL;
    }
    if (process->arg_storage)
    {
        free(process->arg_storage);
        process->arg_storage = NULL;
    }
    process->arg_storage_size = 0;
    process->arg_count = 0;
}

void process_clear_environment(process_t *process)
{
    if (!process) return;
    free(process->env_values); free(process->env_storage);
    process->env_values = NULL; process->env_storage = NULL; process->env_count = 0;
}

bool process_store_environment(process_t *process, const char *const *environment, size_t count)
{
    if (!process || (count && !environment) || count > SIZE_MAX / sizeof(char *)) return false;
    process_clear_environment(process);
    if (!count) return true;
    size_t bytes = 0;
    for (size_t index = 0; index < count; ++index)
    {
        if (!environment[index]) return false;
        size_t length = strlen(environment[index]) + 1;
        if (length > SIZE_MAX - bytes) return false;
        bytes += length;
    }
    char **values = malloc(count * sizeof(*values));
    char *storage = values ? malloc(bytes) : NULL;
    if (!storage) { free(values); return false; }
    size_t position = 0;
    for (size_t index = 0; index < count; ++index)
    {
        size_t length = strlen(environment[index]) + 1;
        values[index] = storage + position;
        memcpy(values[index], environment[index], length); position += length;
    }
    process->env_values = values; process->env_storage = storage; process->env_count = count;
    return true;
}

bool process_store_args(process_t *process,
                        const char *const *argv,
                        size_t argc)
{
    if (!process)
    {
        return false;
    }

    process_clear_args(process);

    if (!argv || argc == 0)
    {
        return true;
    }

    char **values = (char **)malloc(sizeof(char *) * argc);
    if (!values)
    {
        return false;
    }

    size_t total_bytes = 0;
    for (size_t i = 0; i < argc; ++i)
    {
        const char *arg = argv[i] ? argv[i] : "";
        total_bytes += strlen(arg) + 1;
    }
    if (total_bytes == 0)
    {
        total_bytes = 1;
    }

    char *storage = (char *)malloc(total_bytes);
    if (!storage)
    {
        free(values);
        return false;
    }

    size_t offset = 0;
    for (size_t i = 0; i < argc; ++i)
    {
        const char *arg = argv[i] ? argv[i] : "";
        size_t len = strlen(arg);
        memcpy(storage + offset, arg, len);
        storage[offset + len] = '\0';
        values[i] = storage + offset;
        offset += len + 1;
    }

    process->arg_values = values;
    process->arg_storage = storage;
    process->arg_storage_size = offset;
    process->arg_count = argc;
    return true;
}

static void process_dump_stack_entry(uintptr_t addr, uintptr_t value, bool mark_rsp)
{
    serial_printf("    [%016llX] = 0x%016llX%s\r\n",
                  (unsigned long long)addr,
                  (unsigned long long)value,
                  mark_rsp ? " <-- rsp" : "");
}

#define USER_STACK_GROW_PREFETCH_BYTES (32UL * 1024UL)

static void process_dump_stack_entry_unmapped(uintptr_t addr, bool mark_rsp)
{
    serial_printf("    [%016llX] = <unmapped>%s\r\n",
                  (unsigned long long)addr,
                  mark_rsp ? " <-- rsp" : "");
}

static uintptr_t process_stack_bottom(const process_t *process)
{
    if (!process || process->user_stack_top == 0 || process->user_stack_size == 0)
    {
        return 0;
    }
    return process->user_stack_top - process->user_stack_size;
}

static bool process_stack_translate(process_t *process,
                                    uintptr_t addr,
                                    uint8_t **host_out,
                                    size_t *chunk_out)
{
    if (!process || !host_out || process->user_stack_top == 0 || process->user_stack_size == 0 ||
        !process->user_stack_pages || process->user_stack_page_count == 0)
    {
        return false;
    }

    uintptr_t stack_top = process->user_stack_top;
    uintptr_t stack_bottom = process_stack_bottom(process);
    if (stack_bottom == 0 || addr < stack_bottom || addr >= stack_top)
    {
        return false;
    }

    uintptr_t page_base = align_down_uintptr(addr, PAGE_SIZE_BYTES_LOCAL);
    size_t page_index = (size_t)((page_base - stack_bottom) / PAGE_SIZE_BYTES_LOCAL);
    if (page_index >= process->user_stack_page_count)
    {
        return false;
    }

    paddr_t phys = process->user_stack_pages[page_index];
    if (phys == 0 || (phys & (USER_PAGE_SWAPPED | USER_PAGE_BUSY))) return false;

    size_t offset = (size_t)(addr - page_base);
    *host_out = (uint8_t *)phys_to_virt(phys) + offset;

    if (chunk_out)
    {
        size_t chunk = PAGE_SIZE_BYTES_LOCAL - offset;
        uintptr_t max_end = page_base + PAGE_SIZE_BYTES_LOCAL;
        if (max_end > stack_top)
        {
            chunk = (size_t)(stack_top - addr);
        }
        *chunk_out = chunk;
    }
    return true;
}

bool process_memory_resolve_user_locked(process_t *process, uintptr_t address,
                                        bool write_access, uint8_t **host_out,
                                        size_t *available_out)
{
    if (!process || !host_out || !available_out ||
        address < USER_ADDRESS_SPACE_BASE || address > USER_ADDRESS_SPACE_LIMIT)
    {
        return false;
    }
    *host_out = NULL;
    *available_out = 0;
    uint8_t *host = NULL;
    paddr_t physical = 0;
    uintptr_t page = align_down_uintptr(address, PAGE_SIZE_BYTES_LOCAL);
    size_t available = PAGE_SIZE_BYTES_LOCAL - (size_t)(address - page);
    if (process_heap_lookup(process, page, &physical))
    {
        host = (uint8_t *)phys_to_virt(physical) + (address - page);
    }
    else if (!process_stack_translate(process, address, &host, &available))
    {
        for (process_user_region_t *region = process->user_regions; region; region = region->next)
        {
            if (address >= region->user_base && address - region->user_base < region->mapped_size)
            {
                if (write_access && !region->writable)
                {
                    return false;
                }
                host = (uint8_t *)phys_to_virt(region->phys_base) + (address - region->user_base);
                size_t remaining = region->mapped_size - (size_t)(address - region->user_base);
                if (available > remaining)
                {
                    available = remaining;
                }
                break;
            }
        }
    }
    if (!host)
    {
        /* Anonymous VM ranges never overlap the legacy heap/stack/ELF ranges.
         * Its resolver also rejects PROT_NONE and disallowed writes. */
        return process_vm_resolve_locked(process, address, write_access,
                                          host_out, available_out);
    }
    *host_out = host;
    *available_out = available;
    return true;
}

static bool process_memory_read_user_u32_locked(process_t *process, uintptr_t address, uint32_t *value_out)
{
    uint8_t *host = NULL;
    size_t available = 0;
    bool valid = process_memory_resolve_user_locked(process, address, false, &host, &available) &&
                 available >= sizeof(uint32_t);
    if (valid)
    {
        /* memory_lock pins the physical backing and permission snapshot. */
        *value_out = __atomic_load_n((const uint32_t *)host, __ATOMIC_ACQUIRE);
    }
    return valid;
}

bool process_memory_read_user_u32(process_t *process, uintptr_t address, uint32_t *value_out)
{
    if (!process || !value_out || (address & (sizeof(uint32_t) - 1)) != 0 ||
        address < USER_ADDRESS_SPACE_BASE || address > USER_ADDRESS_SPACE_LIMIT - (sizeof(uint32_t) - 1))
        return false;
    uint64_t flags = process_memory_lock(process);
    bool valid = process_memory_read_user_u32_locked(process, address, value_out);
    process_memory_unlock(process, flags);
    return valid;
}

bool process_memory_try_read_user_u32(process_t *process, uintptr_t address,
                                      uint32_t *value_out, bool *busy_out)
{
    if (!busy_out) return false;
    *busy_out = false;
    if (!process || !value_out || (address & (sizeof(uint32_t) - 1)) != 0 ||
        address < USER_ADDRESS_SPACE_BASE || address > USER_ADDRESS_SPACE_LIMIT - (sizeof(uint32_t) - 1))
        return false;
    uint64_t flags = cpu_save_flags();
    cpu_cli();
    spinlock_preempt_disable();
    uint32_t unlocked = 0;
    if (!__atomic_compare_exchange_n(&process->memory_lock.value, &unlocked, 1u, false,
                                     __ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
    {
        *busy_out = true;
        spinlock_preempt_enable();
        cpu_restore_flags(flags);
        return false;
    }
    bool valid = process_memory_read_user_u32_locked(process, address, value_out);
    process_memory_unlock(process, flags);
    return valid;
}

static bool process_stack_copy_to(process_t *process,
                                 uintptr_t addr,
                                 const void *src,
                                 size_t bytes)
{
    if (!process || !src || bytes == 0)
    {
        return bytes == 0;
    }

    const uint8_t *in = (const uint8_t *)src;
    size_t remaining = bytes;
    uintptr_t cursor = addr;
    while (remaining > 0)
    {
        uint8_t *host = NULL;
        size_t chunk = 0;
        if (!process_stack_translate(process, cursor, &host, &chunk) || chunk == 0)
        {
            return false;
        }
        if (chunk > remaining)
        {
            chunk = remaining;
        }
        memcpy(host, in, chunk);
        in += chunk;
        cursor += chunk;
        remaining -= chunk;
    }
    return true;
}

static bool process_stack_copy_from(process_t *process,
                                   uintptr_t addr,
                                   void *dst,
                                   size_t bytes)
{
    if (!process || !dst || bytes == 0)
    {
        return bytes == 0;
    }

    uint8_t *out = (uint8_t *)dst;
    size_t remaining = bytes;
    uintptr_t cursor = addr;
    while (remaining > 0)
    {
        uint8_t *host = NULL;
        size_t chunk = 0;
        if (!process_stack_translate(process, cursor, &host, &chunk) || chunk == 0)
        {
            return false;
        }
        if (chunk > remaining)
        {
            chunk = remaining;
        }
        memcpy(out, host, chunk);
        out += chunk;
        cursor += chunk;
        remaining -= chunk;
    }
    return true;
}

static bool process_stack_commit_range(process_t *process, uintptr_t start, uintptr_t end)
{
    if (!process || start >= end)
    {
        return true;
    }
    if (!process->user_stack_pages || process->user_stack_page_count == 0 ||
        process->user_stack_top == 0 || process->user_stack_size == 0)
    {
        return false;
    }

    uintptr_t stack_top = process->user_stack_top;
    uintptr_t stack_bottom = process_stack_bottom(process);
    if (stack_bottom == 0 || end <= stack_bottom || start >= stack_top)
    {
        return false;
    }

    uintptr_t aligned_start = align_down_uintptr(start, PAGE_SIZE_BYTES_LOCAL);
    uintptr_t aligned_end = align_up_uintptr(end, PAGE_SIZE_BYTES_LOCAL);
    if (aligned_start < stack_bottom)
    {
        aligned_start = stack_bottom;
    }
    if (aligned_end > stack_top)
    {
        aligned_end = stack_top;
    }
    if (aligned_start >= aligned_end)
    {
        return true;
    }

    uintptr_t old_committed = process->user_stack_committed ? process->user_stack_committed : stack_top;
    if (aligned_end > old_committed)
    {
        aligned_end = old_committed;
    }
    if (aligned_start >= aligned_end)
    {
        return true;
    }

    process_retired_memory_t *retired = process_retirement_allocate((aligned_end - aligned_start) / PAGE_SIZE_BYTES_LOCAL);
    if (!retired)
    {
        return false;
    }
    uintptr_t page_addr = aligned_start;
    for (; page_addr < aligned_end; page_addr += PAGE_SIZE_BYTES_LOCAL)
    {
        size_t page_index = (size_t)((page_addr - stack_bottom) / PAGE_SIZE_BYTES_LOCAL);
        if (page_index >= process->user_stack_page_count)
        {
            break;
        }
        if (process->user_stack_pages[page_index] != 0)
        {
            break;
        }

        paddr_t phys = 0;
        if (!user_memory_alloc_page(&phys))
        {
            serial_printf("[stack] alloc_page failed pid=0x%016llX virt=0x%016llX avail=0x%016llX\r\n",
                          (unsigned long long)process->pid,
                          (unsigned long long)page_addr,
                          (unsigned long long)user_memory_available());
            break;
        }
        memset(phys_to_virt(phys), 0, PAGE_SIZE_BYTES_LOCAL);
        if (!paging_map_user_page(&process->address_space, page_addr, (uintptr_t)phys, true, false))
        {
            serial_printf("[stack] map failed pid=0x%016llX virt=0x%016llX phys=0x%016llX\r\n",
                          (unsigned long long)process->pid,
                          (unsigned long long)page_addr,
                          (unsigned long long)phys);
            user_memory_free_page(phys);
            break;
        }
        process->user_stack_pages[page_index] = phys;
        retired->ranges[retired->count++] = (process_retired_range_t){
            .physical = phys, .bytes = PAGE_SIZE_BYTES_LOCAL, .virtual_address = page_addr
        };
    }

    if (page_addr == aligned_end)
    {
        free(retired);
        process->user_stack_committed = aligned_start;
        return true;
    }

    /* Roll back any pages we allocated for this range. */
    for (size_t i = 0; i < retired->count; ++i)
    {
        uintptr_t rollback = retired->ranges[i].virtual_address;
        size_t page_index = (size_t)((rollback - stack_bottom) / PAGE_SIZE_BYTES_LOCAL);
        if (!paging_unmap_user_page(&process->address_space, rollback))
        {
            fatal("stack rollback could not remove owned mapping");
        }
        process->user_stack_pages[page_index] = 0;
    }
    process_retirement_enqueue(retired, &process->address_space);
    process->user_stack_committed = old_committed;
    return false;
}

static bool process_stack_ensure_range(process_t *process, uintptr_t addr, size_t bytes)
{
    if (!process || bytes == 0)
    {
        return true;
    }
    if (!process->user_stack_pages || process->user_stack_page_count == 0 ||
        process->user_stack_top == 0 || process->user_stack_size == 0)
    {
        return false;
    }

    uintptr_t stack_top = process->user_stack_top;
    uintptr_t stack_bottom = process_stack_bottom(process);
    if (stack_bottom == 0)
    {
        return false;
    }

    uintptr_t end_addr = addr + bytes;
    if (end_addr < addr || addr < stack_bottom || end_addr > stack_top)
    {
        return false;
    }

    uintptr_t required = align_down_uintptr(addr, PAGE_SIZE_BYTES_LOCAL);
    uintptr_t desired = required;
    if (desired > stack_bottom)
    {
        uintptr_t candidate = desired;
        if (candidate >= stack_bottom + USER_STACK_GROW_PREFETCH_BYTES)
        {
            candidate -= USER_STACK_GROW_PREFETCH_BYTES;
        }
        else
        {
            candidate = stack_bottom;
        }
        desired = align_down_uintptr(candidate, PAGE_SIZE_BYTES_LOCAL);
        if (desired < stack_bottom)
        {
            desired = stack_bottom;
        }
    }

    uintptr_t committed = process->user_stack_committed ? process->user_stack_committed : stack_top;
    if (desired >= committed)
    {
        return true;
    }

    return process_stack_commit_range(process, desired, committed);
}

/* Bounded preparation for a signal frame. New main-stack pages use the
 * same no-wait commit/retirement path as page-fault recovery. Other owned
 * stack/heap/VM ranges are validated by the subsequent safe copy itself. */
bool process_signal_prepare_user_frame(process_t *process, uintptr_t address, size_t bytes)
{
    if (!process || !bytes || address > UINTPTR_MAX - bytes) return false;
    uintptr_t end = address + bytes;
    uintptr_t bottom = process_stack_bottom(process);
    uint64_t flags = process_memory_lock(process);
    bool okay = true;
    if (address < process->user_stack_top && end > bottom)
        okay = address >= bottom && end <= process->user_stack_top &&
               process_stack_ensure_range(process, address, bytes);
    process_memory_unlock(process, flags);
    return okay;
}

/* Permission faults can have a nonpresent PTE after MADV_DONTNEED.
 * Classify by logical ownership, without populating or waiting on a mapping. */
bool process_signal_address_mapped(process_t *process, uintptr_t address)
{
    if (!process) return false;
    uint64_t flags = process_memory_lock(process);
    uintptr_t stack_bottom = process_stack_bottom(process);
    bool mapped = (address >= process->user_heap_base && address < process->user_heap_brk) ||
                  (stack_bottom && address >= stack_bottom && address < process->user_stack_top) ||
                  process_vm_contains_locked(process, address);
    for (process_user_region_t *region = process->user_regions; !mapped && region; region = region->next)
        mapped = address >= region->user_base && address - region->user_base < region->mapped_size;
    process_memory_unlock(process, flags);
    return mapped;
}

bool process_stack_handle_page_fault(process_t *process, uintptr_t fault_addr, uintptr_t rsp)
{
    (void)rsp;

    if (!process || !process->is_user)
    {
        return false;
    }
    if (!process->user_stack_pages || process->user_stack_page_count == 0 ||
        process->user_stack_top == 0 || process->user_stack_size == 0)
    {
        return false;
    }

    uintptr_t stack_top = process->user_stack_top;
    uintptr_t stack_bottom = process_stack_bottom(process);
    if (stack_bottom == 0 || fault_addr < stack_bottom || fault_addr >= stack_top)
    {
        return false;
    }

    uint64_t flags = process_memory_lock(process);
    bool ok = process_stack_ensure_range(process, fault_addr, sizeof(uintptr_t));
    process_memory_unlock(process, flags);
    return ok;
}

static bool process_setup_preempt_stub(process_t *process)
{
    if (!process)
    {
        return false;
    }

    void *stub_ptr = NULL;
    uint64_t flags = process_memory_lock(process);
    bool mapped = process_map_user_segment_locked(process,
                                                  USER_PREEMPT_STUB_BASE,
                                                  PAGE_SIZE_BYTES_LOCAL,
                                                  false,
                                                  true,
                                                  true,
                                                  &stub_ptr);
    process_memory_unlock(process, flags);
    if (!mapped)
    {
        return false;
    }

    memset(stub_ptr, 0x90, PAGE_SIZE_BYTES_LOCAL);
    memcpy(stub_ptr, g_user_preempt_stub, sizeof(g_user_preempt_stub));
    return true;
}

void process_dump_user_stack(process_t *process,
                             uintptr_t rsp,
                             size_t max_entries_above,
                             size_t max_entries_below)
{
    if (!process || !process->is_user || (max_entries_above == 0 && max_entries_below == 0))
    {
        return;
    }
    if (!process->user_stack_pages || process->user_stack_page_count == 0 ||
        process->user_stack_top == 0 || process->user_stack_size == 0 || rsp == 0)
    {
        serial_printf("%s", "  user stack: unavailable\r\n");
        return;
    }

    uintptr_t stack_top = process->user_stack_top;
    uintptr_t stack_bottom = stack_top - process->user_stack_size;

    serial_printf("  user stack: range=[%016llX, %016llX) rsp=%016llX\r\n",
                  (unsigned long long)stack_bottom,
                  (unsigned long long)stack_top,
                  (unsigned long long)rsp);

    if (rsp < stack_bottom || rsp >= stack_top)
    {
        serial_printf("%s", "  user stack: rsp outside stack bounds\r\n");
        return;
    }

    /* Print entries below rsp (older stack values) */
    if (max_entries_below > 0)
    {
        uintptr_t addr = rsp;
        size_t ready = 0;
        while (addr > stack_bottom && ready < max_entries_below)
        {
            addr -= sizeof(uintptr_t);
            ready++;
            if (addr < stack_bottom)
            {
                break;
            }
        }

        while (ready > 0 && addr >= stack_bottom)
        {
            uintptr_t value = 0;
            if (process_stack_copy_from(process, addr, &value, sizeof(value)))
            {
                process_dump_stack_entry(addr, value, false);
            }
            else
            {
                process_dump_stack_entry_unmapped(addr, false);
            }
            addr += sizeof(uintptr_t);
            ready--;
        }
    }

    /* Print entries starting at rsp and moving upward */
    if (max_entries_above > 0)
    {
        uintptr_t addr = rsp;
        size_t remaining = max_entries_above;
        while (remaining > 0 && addr + sizeof(uintptr_t) <= stack_top)
        {
            uintptr_t value = 0;
            if (process_stack_copy_from(process, addr, &value, sizeof(value)))
            {
                process_dump_stack_entry(addr, value, addr == rsp);
            }
            else
            {
                process_dump_stack_entry_unmapped(addr, addr == rsp);
            }
            addr += sizeof(uintptr_t);
            remaining--;
        }
    }
}

static bool process_prepare_environment_stack(process_t *process, uintptr_t *stack)
{
    process->user_envp_ptr = 0;
    size_t count = process->env_count;
    if (!count) return true;
    if (count >= SIZE_MAX / sizeof(uintptr_t)) return false;
    uintptr_t *pointers = calloc(count + 1, sizeof(*pointers));
    if (!pointers) return false;
    uintptr_t bottom = process->user_stack_top - process->user_stack_size;
    bool ok = true;
    for (size_t index = 0; index < count; ++index)
    {
        size_t length = strlen(process->env_values[index]) + 1;
        if (*stack < bottom || length > *stack - bottom) { ok = false; break; }
        *stack -= length; pointers[index] = *stack;
        if (!process_stack_ensure_range(process, *stack, length) ||
            !process_stack_copy_to(process, *stack, process->env_values[index], length)) { ok = false; break; }
    }
    size_t bytes = (count + 1) * sizeof(*pointers);
    *stack = align_down_uintptr(*stack, 16ULL);
    if (*stack < bottom || bytes > *stack - bottom) ok = false;
    if (ok)
    {
        *stack -= bytes;
        ok = process_stack_ensure_range(process, *stack, bytes) && process_stack_copy_to(process, *stack, pointers, bytes);
        if (ok) process->user_envp_ptr = *stack;
    }
    free(pointers);
    return ok;
}

bool process_prepare_stack_with_args(process_t *process)
{
    if (!process || !process->user_stack_pages || process->user_stack_page_count == 0 ||
        process->user_stack_top == 0 || process->user_stack_size == 0)
    {
        return false;
    }

    uintptr_t stack_top = process->user_stack_top;
    uintptr_t stack_bottom = stack_top - process->user_stack_size;

    size_t argc = process->arg_count;
    char **argv = process->arg_values;

    uintptr_t sp = stack_top;
    if (!process_prepare_environment_stack(process, &sp)) return false;
    uintptr_t *arg_ptrs = NULL;

    if (argc > 0)
    {
        arg_ptrs = (uintptr_t *)malloc(sizeof(uintptr_t) * argc);
        if (!arg_ptrs)
        {
            return false;
        }
    }

    for (size_t i = 0; i < argc; ++i)
    {
        const char *arg = argv[i] ? argv[i] : "";
        size_t len = strlen(arg) + 1;
        if (sp < stack_bottom + len)
        {
            free(arg_ptrs);
            return false;
        }
        sp -= len;
        uintptr_t dst = sp;
        if (!process_stack_ensure_range(process, dst, len) ||
            !process_stack_copy_to(process, dst, arg, len))
        {
            free(arg_ptrs);
            return false;
        }
        arg_ptrs[i] = dst;
    }

    sp = align_down_uintptr(sp, 16ULL);
    if (sp < stack_bottom + sizeof(uintptr_t))
    {
        free(arg_ptrs);
        return false;
    }
    sp -= sizeof(uintptr_t);
    uintptr_t null_sentinel = 0;
    if (!process_stack_ensure_range(process, sp, sizeof(null_sentinel)) ||
        !process_stack_copy_to(process, sp, &null_sentinel, sizeof(null_sentinel)))
    {
        free(arg_ptrs);
        return false;
    }

    for (size_t i = argc; i > 0; --i)
    {
        if (sp < stack_bottom + sizeof(uintptr_t))
        {
            free(arg_ptrs);
            return false;
        }
        sp -= sizeof(uintptr_t);
        uintptr_t arg_ptr = arg_ptrs[i - 1];
        if (!process_stack_ensure_range(process, sp, sizeof(arg_ptr)) ||
            !process_stack_copy_to(process, sp, &arg_ptr, sizeof(arg_ptr)))
        {
            free(arg_ptrs);
            return false;
        }
    }

    uintptr_t argv_ptr = sp;

    if (sp < stack_bottom + sizeof(uintptr_t))
    {
        free(arg_ptrs);
        return false;
    }
    sp -= sizeof(uintptr_t);
    uintptr_t argc_value = (uintptr_t)argc;
    if (!process_stack_ensure_range(process, sp, sizeof(argc_value)) ||
        !process_stack_copy_to(process, sp, &argc_value, sizeof(argc_value)))
    {
        free(arg_ptrs);
        return false;
    }

    process->user_initial_stack = sp;
    process->user_argc = argc;
    process->user_argv_ptr = argv_ptr;

    if (arg_ptrs)
    {
        free(arg_ptrs);
    }
    process_clear_args(process);
    process_clear_environment(process);
    return true;
}

bool process_setup_basic_user_memory(process_t *process)
{
    if (!process_setup_user_stack(process))
    {
        return false;
    }
    if (!process_setup_user_heap(process))
    {
        return false;
    }
    void *stub_ptr = NULL;
    uint64_t flags = process_memory_lock(process);
    bool mapped = process_map_user_segment_locked(process,
                                                  USER_STUB_CODE_BASE,
                                                  PAGE_SIZE_BYTES_LOCAL,
                                                  false,
                                                  true,
                                                  true,
                                                  &stub_ptr);
    process_memory_unlock(process, flags);
    if (!mapped)
    {
        return false;
    }
    memset(stub_ptr, 0x90, PAGE_SIZE_BYTES_LOCAL);
    memcpy(stub_ptr, g_user_exit_stub, sizeof(g_user_exit_stub));
    memcpy((uint8_t *)stub_ptr + ALIX_SIGNAL_RESTORER_OFFSET, g_user_signal_restorer, sizeof(g_user_signal_restorer));
    memcpy((uint8_t *)stub_ptr + USER_THREAD_EXIT_STUB_OFFSET,
           g_user_thread_exit_stub,
           sizeof(g_user_thread_exit_stub));
    return process_setup_preempt_stub(process);
}

bool process_setup_dummy_user_space(process_t *process)
{
    if (!process)
    {
        return false;
    }

    if (!process_setup_basic_user_memory(process))
    {
        return false;
    }

    process->user_entry_point = USER_STUB_CODE_BASE;
    return true;
}

/* Unpublished child only. The caller holds the source memory lock and owns
 * both processes. Kernel stacks and scheduler records are never cloned. */
bool process_clone_user_memory_locked(process_t *child, process_t *source)
{
    child->user_entry_point = source->user_entry_point;
    child->user_stack_top = source->user_stack_top;
    child->user_stack_size = source->user_stack_size;
    child->user_stack_committed = source->user_stack_committed;
    child->user_stack_page_count = source->user_stack_page_count;
    child->user_thread_stack_next = source->user_thread_stack_next;
    child->user_heap_base = source->user_heap_base;
    child->user_heap_brk = source->user_heap_brk;
    child->user_heap_limit = source->user_heap_limit;
    child->user_heap_committed = source->user_heap_committed;
    child->user_initial_stack = source->user_initial_stack;
    child->user_argc = source->user_argc;
    child->user_argv_ptr = source->user_argv_ptr;
    child->user_envp_ptr = source->user_envp_ptr;
    child->user_tls_filesz = source->user_tls_filesz;
    child->user_tls_memsz = source->user_tls_memsz;
    child->user_tls_align = source->user_tls_align;
    child->user_tls_offset = source->user_tls_offset;
    if (source->user_tls_filesz)
    {
        child->user_tls_image = malloc(source->user_tls_filesz);
        if (!child->user_tls_image) return false;
        memcpy(child->user_tls_image, source->user_tls_image, source->user_tls_filesz);
    }
    if (source->user_elf_metadata_size)
    {
        child->user_elf_metadata = malloc(source->user_elf_metadata_size);
        if (!child->user_elf_metadata) return false;
        child->user_elf_metadata_size = source->user_elf_metadata_size;
        memcpy(child->user_elf_metadata, source->user_elf_metadata, source->user_elf_metadata_size);
    }
    if (!process_store_args(child, (const char *const *)source->arg_values, source->arg_count) ||
        !process_store_environment(child, (const char *const *)source->env_values, source->env_count)) return false;
    for (process_user_region_t *region = source->user_regions; region; region = region->next)
    {
        void *host = NULL;
        if (!process_map_user_segment_locked(child, region->user_base, region->mapped_size,
                region->writable, region->executable, true, &host)) return false;
        memcpy(host, phys_to_virt(region->phys_base), region->mapped_size);
    }
    child->user_stack_pages = calloc(source->user_stack_page_count, sizeof(paddr_t));
    if (source->user_stack_page_count && !child->user_stack_pages) return false;
    uintptr_t bottom = source->user_stack_top - source->user_stack_size;
    for (size_t i = 0; i < source->user_stack_page_count; ++i)
    {
        if (!source->user_stack_pages[i]) continue;
        paddr_t page;
        if (source->user_stack_pages[i] & USER_PAGE_SWAPPED)
        {
            if (!swap_retain(source->user_stack_pages[i])) return false;
            child->user_stack_pages[i] = source->user_stack_pages[i];
            ++child->vm_swapped_pages;
            continue;
        }
        if (!user_memory_alloc_page(&page)) return false;
        child->user_stack_pages[i] = page;
        memcpy(phys_to_virt(page), phys_to_virt(source->user_stack_pages[i]), PAGE_SIZE_BYTES_LOCAL);
        if (!paging_map_user_page(&child->address_space, bottom + i * PAGE_SIZE_BYTES_LOCAL, page, true, false)) return false;
    }
    child->heap_dir_count = source->heap_dir_count;
    child->heap_page_dirs = calloc(source->heap_dir_count, sizeof(*child->heap_page_dirs));
    if (source->heap_dir_count && !child->heap_page_dirs) return false;
    for (size_t d = 0; d < source->heap_dir_count; ++d)
    {
        if (!source->heap_page_dirs[d]) continue;
        process_heap_l2_t *table = process_heap_table(child, d, true);
        if (!table) return false;
        for (size_t i = 0; i < PROCESS_HEAP_L2_ENTRIES; ++i)
        {
            if (!process_heap_entry_present(source->heap_page_dirs[d], i)) continue;
            paddr_t page;
            if (source->heap_page_dirs[d]->phys[i] & USER_PAGE_SWAPPED)
            {
                page = source->heap_page_dirs[d]->phys[i];
                if (!swap_retain(page)) return false;
                process_heap_entry_set(table, i, page);
                ++child->vm_swapped_pages;
                continue;
            }
            if (!user_memory_alloc_page(&page)) return false;
            process_heap_entry_set(table, i, page);
            memcpy(phys_to_virt(page), phys_to_virt(source->heap_page_dirs[d]->phys[i]), PAGE_SIZE_BYTES_LOCAL);
            uintptr_t address = child->user_heap_base + (d * PROCESS_HEAP_L2_ENTRIES + i) * PAGE_SIZE_BYTES_LOCAL;
            if (!paging_map_user_page(&child->address_space, address, page, true, false)) return false;
        }
    }
    return process_vm_clone_locked(child, source);
}

paddr_t *process_legacy_page_slot_locked(process_t *process, uintptr_t address)
{
    if (address >= process->user_heap_base && address < process->user_heap_brk)
    {
        size_t index = (address - process->user_heap_base) / PAGE_SIZE_BYTES_LOCAL;
        size_t directory = index / PROCESS_HEAP_L2_ENTRIES;
        if (directory < process->heap_dir_count && process->heap_page_dirs[directory])
        {
            process_heap_l2_t *table = process->heap_page_dirs[directory];
            if (process_heap_entry_present(table, index % PROCESS_HEAP_L2_ENTRIES))
                return &table->phys[index % PROCESS_HEAP_L2_ENTRIES];
        }
    }
    uintptr_t bottom = process->user_stack_top - process->user_stack_size;
    if (process->user_stack_pages && address >= bottom && address < process->user_stack_top)
        return &process->user_stack_pages[(address - bottom) / PAGE_SIZE_BYTES_LOCAL];
    return NULL;
}

paddr_t *process_legacy_swap_candidate_locked(process_t *process, uintptr_t *address, bool swapped)
{
    for (size_t d = 0; d < process->heap_dir_count; ++d)
    {
        process_heap_l2_t *table = process->heap_page_dirs[d];
        if (!table) continue;
        for (size_t i = 0; i < PROCESS_HEAP_L2_ENTRIES; ++i)
            if (table->phys[i] && ((table->phys[i] & USER_PAGE_SWAPPED) != 0) == swapped)
            {
                *address = process->user_heap_base + (d * PROCESS_HEAP_L2_ENTRIES + i) * PAGE_SIZE_BYTES_LOCAL;
                return &table->phys[i];
            }
    }
    for (size_t i = 0; i < process->user_stack_page_count; ++i)
        if (process->user_stack_pages[i] && ((process->user_stack_pages[i] & USER_PAGE_SWAPPED) != 0) == swapped)
        {
            *address = process->user_stack_top - process->user_stack_size + i * PAGE_SIZE_BYTES_LOCAL;
            return &process->user_stack_pages[i];
        }
    return NULL;
}
