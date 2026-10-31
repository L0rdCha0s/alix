#!/usr/bin/env python3
"""Execute shared-kernel permission updates with stale local TLB permissions."""
import sys

sys.dont_write_bytecode = True
from audio_stream_contract_test import ROOT, compile_and_run, function_definition


def main():
    source = (ROOT / "src/arch/x86/paging.c").read_text()
    program = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#define PAGE_SIZE_BYTES 4096UL
#define PAGE_PRESENT 1UL
#define PAGE_WRITABLE 2UL
#define START 0x10000UL
typedef struct { uint64_t cr3; uint64_t *tables_base; } paging_space_t;
typedef struct { uintptr_t base, top; } thread_t;
static uint64_t entries[512];
static bool cached_writable[512];
static paging_space_t g_kernel_space;
static bool g_paging_ready, held, heap_held, table_available;
static uint64_t irq_flags, current_cr3, request_generation, remote_acknowledged;
static unsigned local_invalidations, broadcasts;
static thread_t current;
static uintptr_t align_down(uintptr_t value, uintptr_t alignment) { return value & ~(alignment-1); }
static uintptr_t align_up(uintptr_t value, uintptr_t alignment) { return (value+alignment-1) & ~(alignment-1); }
static size_t index_pt(uintptr_t address) { return (address >> 12) & 511; }
static uint64_t __attribute__((unused)) read_cr3(void) { return current_cr3; }
static bool paging_check_lock_order(const char *where) { (void)where; return !heap_held; }
static uint64_t paging_space_lock(paging_space_t *space, bool *used_global)
{
    assert(space == &g_kernel_space && !held); held = true; *used_global = true;
    uint64_t saved = irq_flags; irq_flags &= ~512UL; return saved;
}
static void paging_space_unlock(paging_space_t *space, bool used_global, uint64_t flags)
{
    assert(space == &g_kernel_space && held && used_global); held = false; irq_flags = flags;
}
static thread_t *thread_current(void) { return &current; }
static bool process_thread_stack_bounds(const thread_t *thread, uintptr_t *base, uintptr_t *top)
{ assert(thread == &current); *base = current.base; *top = current.top; return current.top > current.base; }
static bool ensure_page_table(paging_space_t *space, uintptr_t address, bool create, uint64_t **out)
{
    assert(space == &g_kernel_space && held && !create);
    assert(address == START || address == START + PAGE_SIZE_BYTES);
    if (!table_available) return false;
    *out = entries; return true;
}
static void invalidate_page(uintptr_t address)
{
    assert(held && !(irq_flags & 512));
    ++local_invalidations;
    cached_writable[index_pt(address)] = (entries[index_pt(address)] & PAGE_WRITABLE) != 0;
}
static void paging_flush_space_tlb(paging_space_t *space)
{
    assert(space == &g_kernel_space && held && !(irq_flags & 512));
    ++broadcasts; ++request_generation;
    /* Existing global flush invalidates local permissions and queues remote
     * IPIs. It does not wait for their acknowledgements while locks are held. */
    for (size_t index=0; index<512; ++index)
        cached_writable[index] = (entries[index] & PAGE_WRITABLE) != 0;
}
'''
    for signature in ("static bool paging_set_kernel_range_writable_internal(",
                      "bool paging_set_kernel_range_writable(",
                      "bool paging_set_kernel_range_writable_force("):
        program += function_definition(source, signature) + "\n"
    program += r'''
static void reset(bool writable, bool stale_writable, bool kernel_cr3)
{
    memset(entries, 0, sizeof(entries)); memset(cached_writable, 0, sizeof(cached_writable));
    g_kernel_space = (paging_space_t){ .cr3 = 0x1000, .tables_base = entries };
    current_cr3 = kernel_cr3 ? 0x1000 : 0x2000;
    g_paging_ready = table_available = true; held = heap_held = false;
    irq_flags = 514; local_invalidations = broadcasts = 0;
    request_generation = 9; remote_acknowledged = 8;
    current = (thread_t){0};
    for (uintptr_t address=START; address<START+2*PAGE_SIZE_BYTES; address+=PAGE_SIZE_BYTES)
    {
        entries[index_pt(address)] = PAGE_PRESENT | (writable ? PAGE_WRITABLE : 0);
        cached_writable[index_pt(address)] = stale_writable;
    }
}
int main(void)
{
    for (unsigned kernel_cr3=0; kernel_cr3<2; ++kernel_cr3)
    {
        for (unsigned writable=0; writable<2; ++writable)
        {
            /* Another CPU has already changed both PTEs. Its flush IPI is
             * pending, so this CPU still caches the old global permissions. */
            reset(writable, !writable, kernel_cr3);
            assert(paging_set_kernel_range_writable(START, 2*PAGE_SIZE_BYTES, writable));
            assert(local_invalidations == 2 && broadcasts == 0 && request_generation == 9);
            assert(cached_writable[index_pt(START)] == (bool)writable);
            assert(cached_writable[index_pt(START+PAGE_SIZE_BYTES)] == (bool)writable);
            assert(remote_acknowledged == 8 && !held && irq_flags == 514);

            reset(!writable, !writable, kernel_cr3);
            assert(paging_set_kernel_range_writable(START, 2*PAGE_SIZE_BYTES, writable));
            assert(local_invalidations == 2 && broadcasts == 1 && request_generation == 10);
            assert(cached_writable[index_pt(START)] == (bool)writable);
            assert(cached_writable[index_pt(START+PAGE_SIZE_BYTES)] == (bool)writable);
            assert(remote_acknowledged == 8 && !held && irq_flags == 514);
        }
    }
    reset(true, true, false);
    current = (thread_t){START, START+PAGE_SIZE_BYTES};
    assert(!paging_set_kernel_range_writable(START, 2*PAGE_SIZE_BYTES, false));
    assert(local_invalidations == 0 && broadcasts == 0 && !held && irq_flags == 514);
    reset(true, false, false); heap_held = true;
    assert(!paging_set_kernel_range_writable(START, PAGE_SIZE_BYTES, true));
    assert(local_invalidations == 0 && !held);
    assert(paging_set_kernel_range_writable_force(START, PAGE_SIZE_BYTES, true));
    assert(local_invalidations == 1 && broadcasts == 0 && !held && irq_flags == 514);
    reset(true, false, false); table_available = false;
    assert(!paging_set_kernel_range_writable(START, PAGE_SIZE_BYTES, true));
    assert(local_invalidations == 0 && !held && irq_flags == 514);
    reset(true, false, false); g_paging_ready = false;
    assert(!paging_set_kernel_range_writable(START, PAGE_SIZE_BYTES, true));
    assert(local_invalidations == 0 && !held && irq_flags == 514);
    puts("shared kernel permissions invalidate stale local entries under every CR3 without waiting");
    return 0;
}
'''
    compile_and_run("kernel-permission-tlb", program)
    print("shared kernel permission local TLB contracts passed")


if __name__ == "__main__":
    main()
