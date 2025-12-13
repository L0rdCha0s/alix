#include "process_internal.h"

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
    proc->pid = g_next_pid++;
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
    proc->threads = NULL;
    proc->thread_count = 0;
    proc->next = NULL;
    proc->stdout_fd = g_console_stdout_fd;
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
    proc->user_thread_stack_next = is_user
                                   ? align_down_uintptr(g_mem_layout.user_pointer_limit + 1, PAGE_SIZE_BYTES_LOCAL)
                                   : 0;
    proc->user_heap_base = 0;
    proc->user_heap_brk = 0;
    proc->user_heap_limit = 0;
    proc->user_heap_committed = 0;
    proc->heap_page_dirs = NULL;
    proc->heap_dir_count = 0;
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

    process_user_region_t *region = process->user_regions;
    while (region)
    {
        process_user_region_t *next = region->next;
        if (region->aligned_allocation && region->mapped_size > 0)
        {
            user_memory_free(region->aligned_allocation, region->mapped_size);
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
    if (region->aligned_allocation && region->mapped_size > 0)
    {
        user_memory_free(region->aligned_allocation, region->mapped_size);
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
                                 (uintptr_t)region->aligned_allocation,
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
    table->phys[index] = phys;
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

static bool process_heap_lookup(const process_t *process, uintptr_t virt_page, uintptr_t *phys_out)
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
        uintptr_t phys = 0;
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
        memset((uint8_t *)(uintptr_t)phys + page_offset, 0, chunk);
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

        uintptr_t phys = table->phys[entry_index];
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
        uintptr_t phys = 0;
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
            process_heap_release_from(process, start);
            process->user_heap_committed = start;
            return false;
        }
        memset((void *)(uintptr_t)phys, 0, PAGE_SIZE_BYTES_LOCAL);
        if (!paging_map_user_page(&process->address_space,
                                  page_addr,
                                  phys,
                                  true,
                                  false))
        {
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
    void *host = user_memory_alloc(aligned_bytes);
    if (!host)
    {
        return false;
    }
    memset(host, 0, aligned_bytes);

    process_user_region_t *region = (process_user_region_t *)malloc(sizeof(process_user_region_t));
    if (!region)
    {
        user_memory_free(host, aligned_bytes);
        return false;
    }

    region->raw_allocation = host;
    region->aligned_allocation = host;
    region->mapped_size = aligned_bytes;
    region->user_base = user_base;
    region->writable = writable;
    region->executable = executable;
    region->next = process->user_regions;
    process->user_regions = region;
    process_log("region host=", (uintptr_t)host);
    process_log("region size=", aligned_bytes);

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

bool process_map_user_segment(process_t *process,
                              uintptr_t user_base,
                              size_t bytes,
                              bool writable,
                              bool executable,
                              void **host_ptr_out)
{
    if (!process || bytes == 0)
    {
        return false;
    }

    uintptr_t aligned_base = align_down_uintptr(user_base, PAGE_SIZE_BYTES_LOCAL);
    size_t offset = (size_t)(user_base - aligned_base);
    size_t total = align_up_size(bytes + offset, PAGE_SIZE_BYTES_LOCAL);
    process_log("map base=", aligned_base);
    process_log("map bytes=", total);

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
        process_log("map fail base=", aligned_base);
        return false;
    }

    if (host_ptr_out)
    {
        uint8_t *base_ptr = (uint8_t *)region->aligned_allocation;
        *host_ptr_out = base_ptr + offset;
        process_log("map host ptr=", (uintptr_t)*host_ptr_out);
    }
    return true;
}

static bool process_setup_user_stack(process_t *process)
{
    void *host = NULL;
    if (!process_map_user_segment(process,
                                  USER_STACK_TOP - USER_STACK_SIZE,
                                  USER_STACK_SIZE,
                                  true,
                                  false,
                                  &host))
    {
        return false;
    }
    process->user_stack_top = USER_STACK_TOP;
    process->user_stack_size = USER_STACK_SIZE;
    process->user_stack_host = (uint8_t *)host;
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
    serial_printf("%s", "    [");
    serial_printf("%016llX", (unsigned long long)(addr));
    serial_printf("%s", "] = 0x");
    serial_printf("%016llX", (unsigned long long)(value));
    if (mark_rsp)
    {
        serial_printf("%s", " <-- rsp");
    }
    serial_printf("%s", "\r\n");
}

static inline bool process_write_stack_uintptr(uint8_t *host_base,
                                               uintptr_t stack_bottom,
                                               uintptr_t stack_top,
                                               uintptr_t addr,
                                               uintptr_t value)
{
    if (!host_base || addr < stack_bottom || addr + sizeof(uintptr_t) > stack_top)
    {
        return false;
    }
    size_t offset = (size_t)(addr - stack_bottom);
    memcpy(host_base + offset, &value, sizeof(uintptr_t));
    return true;
}

static bool process_setup_preempt_stub(process_t *process)
{
    if (!process)
    {
        return false;
    }

    void *stub_ptr = NULL;
    if (!process_map_user_segment(process,
                                  USER_PREEMPT_STUB_BASE,
                                  PAGE_SIZE_BYTES_LOCAL,
                                  false,
                                  true,
                                  &stub_ptr))
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
    if (!process->user_stack_host || process->user_stack_size == 0 || rsp == 0)
    {
        serial_printf("%s", "  user stack: unavailable\r\n");
        return;
    }

    uintptr_t stack_top = process->user_stack_top;
    uintptr_t stack_bottom = stack_top - process->user_stack_size;

    serial_printf("%s", "  user stack: range=[");
    serial_printf("%016llX", (unsigned long long)(stack_bottom));
    serial_printf("%s", ", ");
    serial_printf("%016llX", (unsigned long long)(stack_top));
    serial_printf("%s", ") rsp=");
    serial_printf("%016llX", (unsigned long long)(rsp));
    serial_printf("%s", "\r\n");

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
            size_t offset = (size_t)(addr - stack_bottom);
            uintptr_t value = 0;
            memcpy(&value, process->user_stack_host + offset, sizeof(uintptr_t));
            process_dump_stack_entry(addr, value, false);
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
            size_t offset = (size_t)(addr - stack_bottom);
            uintptr_t value = 0;
            memcpy(&value, process->user_stack_host + offset, sizeof(uintptr_t));
            process_dump_stack_entry(addr, value, addr == rsp);
            addr += sizeof(uintptr_t);
            remaining--;
        }
    }
}

bool process_prepare_stack_with_args(process_t *process)
{
    if (!process || !process->user_stack_host || process->user_stack_size == 0)
    {
        return false;
    }

    uintptr_t stack_top = process->user_stack_top;
    uintptr_t stack_bottom = stack_top - process->user_stack_size;
    uint8_t *host = process->user_stack_host;

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
        size_t offset = (size_t)(dst - stack_bottom);
        memcpy(host + offset, arg, len);
        arg_ptrs[i] = dst;
    }

    sp = align_down_uintptr(sp, 16ULL);

    if (sp < stack_bottom + sizeof(uintptr_t))
    {
        free(arg_ptrs);
        return false;
    }

    if (sp < stack_bottom + sizeof(uintptr_t))
    {
        if (arg_ptrs) free(arg_ptrs);
        return false;
    }
    sp -= sizeof(uintptr_t);
    if (!process_write_stack_uintptr(host, stack_bottom, stack_top, sp, 0))
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
        if (!process_write_stack_uintptr(host, stack_bottom, stack_top, sp, arg_ptrs[i - 1]))
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
    if (!process_write_stack_uintptr(host, stack_bottom, stack_top, sp, (uintptr_t)argc))
    {
        free(arg_ptrs);
        return false;
    }

    process->user_stack_top = sp;
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
    if (!process_map_user_segment(process,
                                  USER_STUB_CODE_BASE,
                                  PAGE_SIZE_BYTES_LOCAL,
                                  false,
                                  true,
                                  &stub_ptr))
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
