#include "process_internal.h"
#include "physmem.h"

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
    proc->pid = __sync_fetch_and_add(&g_next_pid, 1);
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
    proc->main_thread = NULL;
    proc->current_thread = NULL;
    spinlock_init(&proc->threads_lock);
    spinlock_init(&proc->memory_lock);
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
    if (!process)
    {
        return;
    }

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
    if (region->phys_base != 0 && region->mapped_size > 0)
    {
        user_memory_free(region->phys_base, region->mapped_size);
    }
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

void process_heap_release_from(process_t *process, uintptr_t virt_start)
{
    if (!process || !process->heap_page_dirs)
    {
        return;
    }

    if (virt_start < process->user_heap_base)
    {
        virt_start = process->user_heap_base;
    }

    uintptr_t aligned_start = align_down_uintptr(virt_start, PAGE_SIZE_BYTES_LOCAL);
    size_t start_page = (size_t)((aligned_start - process->user_heap_base) / PAGE_SIZE_BYTES_LOCAL);
    size_t max_pages = process_heap_dir_capacity(process) * PROCESS_HEAP_L2_ENTRIES;

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
        process_heap_entry_clear(table, entry_index);
        paging_unmap_user_page(&process->address_space, virt);
        user_memory_free_page(phys);

        if (process_heap_table_empty(table))
        {
            free(table);
            process->heap_page_dirs[dir_index] = NULL;
        }
    }
}

void process_free_heap_pages(process_t *process)
{
    if (!process)
    {
        return;
    }
    process_heap_release_from(process, process->user_heap_base);
    process->user_heap_committed = process->user_heap_base;
    process_heap_free_map(process);
}

bool process_heap_commit_range(process_t *process, uintptr_t start, uintptr_t end)
{
    if (!process || start >= end)
    {
        return true;
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
            process_heap_release_from(process, start);
            process->user_heap_committed = start;
            return false;
        }

        process_heap_l2_t *table = process_heap_table(process, dir_index, true);
        if (!table)
        {
            process_heap_release_from(process, start);
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
            process_heap_release_from(process, start);
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
            process_heap_release_from(process, start);
             process->user_heap_committed = start;
            return false;
        }
        process_heap_entry_set(table, entry_index, phys);
        page_addr += PAGE_SIZE_BYTES_LOCAL;
    }
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

    region->phys_base = phys;
    region->mapped_size = aligned_bytes;
    region->user_base = user_base;
    region->writable = writable;
    region->executable = executable;
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

    if (!allow_reserved)
    {
        uintptr_t stack_bottom = process_stack_bottom(process);
        if ((process->user_heap_limit > process->user_heap_base &&
             process_ranges_overlap(aligned_base, aligned_end,
                                    process->user_heap_base, process->user_heap_limit)) ||
            (stack_bottom != 0 && process->user_stack_top > stack_bottom &&
             process_ranges_overlap(aligned_base, aligned_end,
                                    stack_bottom, process->user_stack_top)) ||
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
        process_unlink_user_region(process, region);
        return false;
    }

    if (host_ptr_out)
    {
        uint8_t *base_ptr = (uint8_t *)phys_to_virt(region->phys_base);
        *host_ptr_out = base_ptr + offset;
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
    for (uintptr_t addr = aligned_base; addr < aligned_base + total; addr += PAGE_SIZE_BYTES_LOCAL)
    {
        (void)paging_unmap_user_page(&process->address_space, addr);
    }
    process_unlink_user_region(process, region);
    paging_flush_space_tlb(&process->address_space);
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
    if (phys == 0)
    {
        return false;
    }

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
    }

    if (page_addr == aligned_end)
    {
        process->user_stack_committed = aligned_start;
        return true;
    }

    /* Roll back any pages we allocated for this range. */
    for (uintptr_t rollback = aligned_start; rollback < page_addr; rollback += PAGE_SIZE_BYTES_LOCAL)
    {
        size_t page_index = (size_t)((rollback - stack_bottom) / PAGE_SIZE_BYTES_LOCAL);
        if (page_index >= process->user_stack_page_count)
        {
            continue;
        }
        paddr_t phys = process->user_stack_pages[page_index];
        if (phys == 0)
        {
            continue;
        }
        process->user_stack_pages[page_index] = 0;
        paging_unmap_user_page(&process->address_space, rollback);
        user_memory_free_page(phys);
    }
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
