#!/usr/bin/env python3
"""Run production TLB-ticket and backing-retirement code with delayed CPUs."""

import sys
sys.dont_write_bytecode = True
from audio_stream_contract_test import ROOT, compile_and_run, function_definition


def main():
    paging = (ROOT / "src/arch/x86/paging.c").read_text()
    memory = (ROOT / "src/kernel/process/process_memory.c").read_text()
    layout_defines = chr(10).join(line for line in (ROOT / "include/memory_layout.h").read_text().splitlines()
                                if line.startswith("#define USER_DEFAULT_"))
    program = layout_defines + r'''
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#define CHECK(c) do { if (!(c)) { fprintf(stderr, "VM check failed line %d: %s\n", __LINE__, #c); exit(1); } } while (0)
#define SMP_MAX_CPUS 4
#define USER_PAGE_SWAPPED 4u
#define USER_PAGE_BUSY 8u
#define PAGE_SIZE_BYTES_LOCAL 4096UL
#define USER_ADDRESS_SPACE_BASE USER_DEFAULT_POINTER_BASE
#define USER_ADDRESS_SPACE_LIMIT USER_DEFAULT_POINTER_LIMIT
#define PROCESS_HEAP_L2_SHIFT 9UL
#define PROCESS_HEAP_L2_ENTRIES 512UL
#define PROCESS_HEAP_L2_MASK 511UL
#define PROCESS_HEAP_PRESENT_WORDS 8UL
typedef uintptr_t paddr_t;
typedef struct { uint32_t active_cpu_mask; } paging_space_t;
typedef struct { uint64_t generation; uint32_t cpu_mask; } paging_tlb_ticket_t;
static paging_space_t g_kernel_space;
static uint64_t g_tlb_request_generation, g_tlb_acknowledged[SMP_MAX_CPUS];
static unsigned current_cpu, flushes, sent_mask;
static bool online_cpu[SMP_MAX_CPUS]={true,true,false,false};
static uint64_t flags = 512;
static bool inject_request_during_flush;
static uint64_t paging_disable_interrupts(void) { uint64_t old=flags; flags=0; return old; }
static void paging_restore_interrupts(uint64_t old) { flags=old; }
static uint32_t smp_current_cpu_index(void) { CHECK(online_cpu[current_cpu]); return current_cpu; }
static uint32_t smp_online_cpu_mask(void) { return 3; }
static void smp_tlb_flush_mask(uint32_t mask) { CHECK(flags==0); sent_mask=mask; }
static void process_vm_notify_tlb_completion(void) {}
static void flush_local_tlb(void) {
    ++flushes;
    if (inject_request_during_flush) { ++g_tlb_request_generation; inject_request_during_flush=false; }
}
'''
    for signature in (
        "static void paging_acknowledge_tlb", "void paging_initialize_cpu_tlb",
        "void paging_handle_remote_tlb_flush",
        "paging_tlb_ticket_t paging_request_tlb_flush", "bool paging_tlb_flush_complete",
    ):
        program += function_definition(paging, signature) + "\n"
    program += r'''
typedef struct { bool locked; uint32_t value; } spinlock_t;
static unsigned held_locks;
static bool require_reaper_guard;
static uint64_t cpu_save_flags(void) { return flags; }
static void cpu_cli(void) { flags=0; }
static void cpu_restore_flags(uint64_t saved) { flags=saved; }
static bool spinlock_preempt_disabled(void) { return held_locks != 0; }
static void spinlock_preempt_disable(void) { ++held_locks; }
static void spinlock_preempt_enable(void) { CHECK(held_locks); --held_locks; }
static uint64_t spinlock_lock_irqsave(spinlock_t *lock) {
    if (require_reaper_guard) CHECK(held_locks==1);
    CHECK(!lock->locked); uint64_t old=flags; flags=0; lock->locked=true; ++held_locks; return old;
}
static void spinlock_unlock_irqrestore(spinlock_t *lock,uint64_t old) {
    CHECK(lock->locked); lock->locked=false; --held_locks; flags=old;
}
static bool fail_malloc;
static void *test_malloc(size_t n) { if (fail_malloc) { fail_malloc=false; return NULL; } return malloc(n); }
#define malloc test_malloc
static unsigned allocated_pages, freed_pages, map_calls, unmap_calls, fail_map_at;
static void *phys_to_virt(paddr_t p) { return (void *)p; }
static bool user_memory_alloc_page(paddr_t *out) { *out=(paddr_t)malloc(4096); if (*out) ++allocated_pages; return *out!=0; }
static void user_memory_free_page(paddr_t p) {
    CHECK(p); if (require_reaper_guard) CHECK(held_locks==1 && flags==512);
    ++freed_pages; free((void *)p);
}
static void user_memory_free(paddr_t p,size_t bytes) { CHECK(bytes==4096); user_memory_free_page(p); }
static size_t user_memory_available(void) { return 4096*1024; }
static bool paging_map_user_page(paging_space_t *s,uintptr_t v,uintptr_t p,bool w,bool x) {
    (void)s;(void)v;(void)p;(void)w;(void)x; ++map_calls; return !fail_map_at || map_calls!=fail_map_at;
}
static bool paging_unmap_user_page(paging_space_t *s,uintptr_t v) { (void)s;(void)v; ++unmap_calls; return true; }
static void fatal(const char *message) { fprintf(stderr,"fatal: %s\n",message); abort(); }
static void serial_printf(const char *format,...) { (void)format; }
static uintptr_t align_down_uintptr(uintptr_t x,uintptr_t n) { return x&~(n-1); }
static uintptr_t align_up_uintptr(uintptr_t x,uintptr_t n) { return (x+n-1)&~(n-1); }
static size_t align_up_size(size_t x,size_t n) { return (x+n-1)&~(n-1); }
typedef struct { paddr_t phys[512]; uint64_t present[8]; } process_heap_l2_t;
struct process_retired_memory;
typedef struct process_user_region {
    paddr_t phys_base; size_t mapped_size; uintptr_t user_base; bool writable,executable;
    struct process_retired_memory *retirement; struct process_user_region *next;
} process_user_region_t;
typedef struct {
    uint64_t pid; paging_space_t address_space; spinlock_t memory_lock;
    process_heap_l2_t **heap_page_dirs; size_t heap_dir_count;
    uintptr_t user_heap_base,user_heap_limit,user_heap_committed;
    uintptr_t user_stack_top,user_stack_committed; size_t user_stack_size,user_stack_page_count;
    paddr_t *user_stack_pages; process_user_region_t *user_regions;
} process_t;
static bool process_vm_resolve_locked(process_t *p,uintptr_t a,bool write,uint8_t **host,size_t *available) {
    (void)p;(void)a;(void)write;(void)host;(void)available; return false;
}
static uint64_t process_memory_lock(process_t *p) {
    CHECK(!p->memory_lock.value);p->memory_lock.value=1;++held_locks;
    uint64_t saved=flags;flags=0;return saved;
}
static void process_memory_unlock(process_t *p,uint64_t f) {
    CHECK(p->memory_lock.value && held_locks);p->memory_lock.value=0;--held_locks;flags=f;
}
'''
    start = memory.index("typedef struct\n{\n    paddr_t physical;")
    end = memory.index("uint64_t process_memory_lock", start)
    program += memory[start:end] + "\n"
    for signature in (
        "static void process_unlink_user_region", "bool process_unmap_user_segment",
        "static size_t process_heap_dir_capacity", "static process_heap_l2_t *process_heap_table",
        "static inline bool process_heap_entry_present", "static inline void process_heap_entry_set",
        "static inline void process_heap_entry_clear", "static bool process_heap_table_empty",
        "static bool process_heap_lookup", "static void process_heap_free_map",
        "bool process_heap_release_from", "void process_free_heap_pages",
        "static void process_heap_rollback", "bool process_heap_commit_range",
        "static uintptr_t process_stack_bottom", "static bool process_stack_translate",
        "bool process_memory_resolve_user_locked", "static bool process_memory_read_user_u32_locked",
        "bool process_memory_read_user_u32(", "bool process_memory_try_read_user_u32(", "static bool process_stack_commit_range",
    ):
        program += function_definition(memory, signature) + "\n"
    program += r'''
static void acknowledge_remote(void) {
    unsigned prior=current_cpu; current_cpu=1; paging_handle_remote_tlb_flush(); current_cpu=prior;
}
static void reap(void) {
    unsigned previous=held_locks;
    require_reaper_guard=true; process_reap_retired_memory(); require_reaper_guard=false;
    CHECK(previous==held_locks);
}
static process_t make_process(void) {
    process_t p={0}; p.pid=1; p.address_space.active_cpu_mask=3;
    p.user_heap_base=USER_ADDRESS_SPACE_BASE; p.user_heap_limit=p.user_heap_base+8*4096;
    p.user_heap_committed=p.user_heap_base; p.heap_dir_count=1;
    p.heap_page_dirs=calloc(1,sizeof(*p.heap_page_dirs)); CHECK(p.heap_page_dirs); return p;
}
int main(void) {
    current_cpu=2; paging_initialize_cpu_tlb(2); current_cpu=0;
    CHECK(!online_cpu[2]); /* AP flush must not use the online-only accessor. */
    paging_space_t space={.active_cpu_mask=3};
    paging_tlb_ticket_t first=paging_request_tlb_flush(&space);
    CHECK(first.generation==1 && first.cpu_mask==2 && sent_mask==2 && flags==512);
    CHECK(g_tlb_acknowledged[0]==1 && !paging_tlb_flush_complete(first));
    acknowledge_remote(); CHECK(paging_tlb_flush_complete(first));
    paging_tlb_ticket_t second=paging_request_tlb_flush(&space);
    inject_request_during_flush=true; acknowledge_remote();
    CHECK(g_tlb_acknowledged[1]==second.generation);
    paging_tlb_ticket_t during={g_tlb_request_generation,2};
    CHECK(!paging_tlb_flush_complete(during));
    acknowledge_remote(); CHECK(paging_tlb_flush_complete(during));
    paging_acknowledge_tlb(1,1); CHECK(g_tlb_acknowledged[1]==during.generation);
    paging_tlb_ticket_t global=paging_request_tlb_flush(&g_kernel_space);
    CHECK(global.cpu_mask==2 && !paging_tlb_flush_complete(global));
    acknowledge_remote(); CHECK(paging_tlb_flush_complete(global));

    process_t p=make_process();
    fail_malloc=true;
    CHECK(!process_heap_commit_range(&p,p.user_heap_base,p.user_heap_base+2*4096));
    CHECK(allocated_pages==0 && map_calls==0 && !g_retired_memory);
    CHECK(process_heap_commit_range(&p,p.user_heap_base,p.user_heap_base+2*4096));
    CHECK(allocated_pages==2 && !g_retired_memory && freed_pages==0);
    uint32_t value=0;
    *(uint32_t *)((uint8_t *)phys_to_virt(p.heap_page_dirs[0]->phys[0])+128)=0x12345678;
    CHECK(process_memory_read_user_u32(&p,p.user_heap_base+128,&value) && value==0x12345678);
    CHECK(!process_memory_read_user_u32(&p,p.user_heap_base+129,&value));
    CHECK(!process_memory_read_user_u32(&p,p.user_heap_base+7*4096,&value));
    CHECK(!process_memory_read_user_u32(&p,0,&value));
    for(unsigned enabled=0;enabled<2;++enabled) {
        flags=enabled?512:0;held_locks=2;p.memory_lock.value=1;
        bool busy=false;value=0xfeed1234;
        CHECK(!process_memory_try_read_user_u32(&p,p.user_heap_base+128,&value,&busy) && busy);
        CHECK(value==0xfeed1234 && held_locks==2 && flags==(enabled?512u:0u) && p.memory_lock.value==1);
        p.memory_lock.value=0;busy=true;
        CHECK(process_memory_try_read_user_u32(&p,p.user_heap_base+128,&value,&busy) && !busy);
        CHECK(value==0x12345678 && held_locks==2 && flags==(enabled?512u:0u) && !p.memory_lock.value);
        value=0xfeed1234;
        CHECK(!process_memory_try_read_user_u32(&p,p.user_heap_base+7*4096,&value,&busy) && !busy);
        CHECK(value==0xfeed1234 && held_locks==2 && flags==(enabled?512u:0u) && !p.memory_lock.value);
    }
    held_locks=0;flags=512;
    fail_malloc=true;
    CHECK(!process_heap_release_from(&p,p.user_heap_base+4096));
    CHECK(unmap_calls==0 && process_heap_entry_present(p.heap_page_dirs[0],1));
    CHECK(process_heap_release_from(&p,p.user_heap_base+4096));
    CHECK(unmap_calls==1 && freed_pages==0 && g_retired_memory);
    reap(); CHECK(freed_pages==0 && g_retired_memory);
    acknowledge_remote(); flags=0; reap(); CHECK(freed_pages==0);
    flags=512; held_locks=1; reap(); CHECK(freed_pages==0); held_locks=0;
    reap(); CHECK(freed_pages==1 && !g_retired_memory);
    CHECK(process_heap_release_from(&p,p.user_heap_base));
    CHECK(!p.heap_page_dirs[0] && freed_pages==1);
    acknowledge_remote(); reap(); CHECK(freed_pages==2 && !g_retired_memory);
    process_free_heap_pages(&p);

    p=make_process(); unsigned before=freed_pages;
    fail_map_at=map_calls+2;
    CHECK(!process_heap_commit_range(&p,p.user_heap_base,p.user_heap_base+2*4096));
    CHECK(freed_pages==before+1 && !p.heap_page_dirs[0] && g_retired_memory);
    CHECK(p.user_heap_committed==p.user_heap_base);
    reap(); CHECK(freed_pages==before+1);
    acknowledge_remote(); reap(); CHECK(freed_pages==before+2 && !g_retired_memory);
    fail_map_at=0;
    CHECK(process_heap_commit_range(&p,p.user_heap_base,p.user_heap_base+4096));
    process_free_heap_pages(&p); CHECK(freed_pages==before+3);

    process_t stack={0}; stack.pid=2; stack.address_space.active_cpu_mask=3;
    stack.user_stack_top=USER_ADDRESS_SPACE_BASE+0x100000;
    stack.user_stack_committed=stack.user_stack_top;
    stack.user_stack_size=8192; stack.user_stack_page_count=2;
    stack.user_stack_pages=calloc(2,sizeof(paddr_t)); CHECK(stack.user_stack_pages);
    before=freed_pages; fail_map_at=map_calls+2;
    CHECK(!process_stack_commit_range(&stack,stack.user_stack_top-8192,stack.user_stack_top));
    CHECK(freed_pages==before+1 && !stack.user_stack_pages[0] && !stack.user_stack_pages[1]);
    CHECK(stack.user_stack_committed==stack.user_stack_top && g_retired_memory);
    reap(); CHECK(freed_pages==before+1);
    acknowledge_remote(); reap(); CHECK(freed_pages==before+2 && !g_retired_memory);
    fail_map_at=0;
    CHECK(process_stack_commit_range(&stack,stack.user_stack_top-8192,stack.user_stack_top));
    *(uint32_t *)phys_to_virt(stack.user_stack_pages[0])=42;
    CHECK(process_memory_read_user_u32(&stack,stack.user_stack_top-8192,&value) && value==42);
    user_memory_free_page(stack.user_stack_pages[0]); user_memory_free_page(stack.user_stack_pages[1]);
    free(stack.user_stack_pages);

    process_t owner={0}; owner.address_space.active_cpu_mask=3;
    process_user_region_t *region=malloc(sizeof(*region)); CHECK(region);
    memset(region,0,sizeof(*region)); CHECK(user_memory_alloc_page(&region->phys_base));
    region->mapped_size=4096; region->user_base=USER_ADDRESS_SPACE_BASE+0x200000;
    region->retirement=process_retirement_allocate(1); CHECK(region->retirement);
    owner.user_regions=region;
    *(uint32_t *)phys_to_virt(region->phys_base)=99;
    CHECK(process_memory_read_user_u32(&owner,region->user_base,&value) && value==99);
    before=freed_pages;
    CHECK(!process_unmap_user_segment(&owner,region->user_base+4096,4096));
    CHECK(owner.user_regions==region && freed_pages==before);
    fail_malloc=true;
    CHECK(process_unmap_user_segment(&owner,region->user_base,4096));
    CHECK(fail_malloc && !owner.user_regions && freed_pages==before); fail_malloc=false;
    memset(&owner,0,sizeof(owner)); /* Retirement must not retain a process pointer. */
    reap(); CHECK(freed_pages==before);
    acknowledge_remote(); reap(); CHECK(freed_pages==before+1 && !g_retired_memory);
    CHECK(allocated_pages==freed_pages && flags==512 && held_locks==0);
    CHECK(flushes>0);
    puts("VM generation, delayed-ack, OOM, heap/stack rollback, safe-read and reclamation tests passed");
    return 0;
}
'''
    compile_and_run("vm-reclamation", program)
    print("VM generation, delayed-ack, OOM, heap/stack rollback, safe-read and reclamation tests passed")


if __name__ == "__main__":
    main()
