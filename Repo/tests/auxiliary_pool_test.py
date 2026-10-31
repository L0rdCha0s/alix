#!/usr/bin/env python3
"""Exercise production stack/TLS hole reuse and its cross-CPU map barrier."""
import sys
sys.dont_write_bytecode = True
from audio_stream_contract_test import ROOT, compile_and_run, function_definition


def main():
    source = (ROOT / "src/kernel/process/process_memory.c").read_text()
    layout_defines = chr(10).join(line for line in (ROOT / "include/memory_layout.h").read_text().splitlines()
                                if line.startswith("#define USER_DEFAULT_"))
    program = layout_defines + r'''
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(c) do { if(!(c)) { fprintf(stderr,"auxiliary pool check failed line %d: %s\n",__LINE__,#c); exit(1); } } while(0)
#define PAGE_SIZE_BYTES_LOCAL 4096UL
#define POOL_BASE (USER_DEFAULT_POINTER_LIMIT+1ULL-8192ULL-USER_DEFAULT_THREAD_POOL_SIZE)
#define USER_STUB_CODE_BASE (POOL_BASE+16*4096UL)
#define RFLAGS_IF_BIT 512UL
typedef struct { unsigned unused; } paging_space_t;
typedef struct { uint64_t generation; uint32_t cpu_mask; } paging_tlb_ticket_t;
typedef struct process_user_region {
    uintptr_t user_base; size_t mapped_size; void *host; struct process_user_region *next;
} process_user_region_t;
typedef struct { uintptr_t user_thread_stack_next; process_user_region_t *user_regions; paging_space_t address_space; } process_t;
static process_t process;
static bool mapping_failure, remote_complete;
static unsigned locks=1,sleeps;
static uint64_t flags=512,generation;
static uintptr_t align_down_uintptr(uintptr_t value,uintptr_t alignment) { return value&~(alignment-1); }
static uintptr_t process_vm_auxiliary_base(void) { return POOL_BASE; }
static bool process_map_user_segment_locked(process_t *p,uintptr_t base,size_t bytes,bool writable,bool executable,bool allow_reserved,void **host_out) {
    CHECK(p==&process && locks==1 && writable && !executable && !allow_reserved);
    if(mapping_failure)return false;
    CHECK(base>=POOL_BASE+4096 && base+bytes<=USER_STUB_CODE_BASE);
    for(process_user_region_t *r=p->user_regions;r;r=r->next)
        CHECK(base+bytes<=r->user_base || base>=r->user_base+r->mapped_size);
    process_user_region_t *r=calloc(1,sizeof(*r));CHECK(r);
    r->host=calloc(1,bytes);CHECK(r->host);r->user_base=base;r->mapped_size=bytes;r->next=p->user_regions;
    p->user_regions=r;*host_out=r->host;return true;
}
static paging_tlb_ticket_t paging_request_tlb_flush(paging_space_t *space) { CHECK(space==&process.address_space);return(paging_tlb_ticket_t){++generation,2}; }
static bool paging_tlb_flush_complete(paging_tlb_ticket_t ticket) { CHECK(ticket.generation==generation);return remote_complete; }
static uint64_t cpu_save_flags(void) { return flags; }
static bool spinlock_preempt_disabled(void) { return locks!=0; }
static void process_sleep_ms(uint32_t ms) { CHECK(ms==1 && flags==512 && locks==0);++sleeps;remote_complete=true; }
'''
    program += function_definition(source, "bool process_allocate_aux_user_segment_locked") + "\n"
    program += function_definition(source, "bool process_complete_user_mapping") + "\n"
    program += r'''
static void remove_region(uintptr_t base) {
    process_user_region_t **cursor=&process.user_regions;
    while(*cursor && (*cursor)->user_base!=base)cursor=&(*cursor)->next;
    CHECK(*cursor);process_user_region_t *r=*cursor;*cursor=r->next;free(r->host);free(r);
}
static void guards_do_not_overlap(void) {
    for(process_user_region_t *a=process.user_regions;a;a=a->next)
        for(process_user_region_t *b=a->next;b;b=b->next)
            CHECK(a->user_base+a->mapped_size<=b->user_base-4096 ||
                  b->user_base+b->mapped_size<=a->user_base-4096);
}
int main(void) {
    process_user_region_t *stub=calloc(1,sizeof(*stub));CHECK(stub);
    stub->user_base=USER_STUB_CODE_BASE;stub->mapped_size=8192;process.user_regions=stub;
    uintptr_t *bases=calloc(5,sizeof(*bases));CHECK(bases);void *host=NULL;
    for(unsigned i=0;i<5;i++) {
        CHECK(process_allocate_aux_user_segment_locked(&process,8192,&bases[i],&host));
        CHECK(bases[i]==USER_STUB_CODE_BASE-(3*i+3)*4096UL);
        memset(host,(int)(i+1),8192);guards_do_not_overlap();
    }
    uintptr_t cursor=process.user_thread_stack_next,base=42;
    CHECK(!process_allocate_aux_user_segment_locked(&process,4096,&base,&host));
    CHECK(base==0 && host==NULL && process.user_thread_stack_next==cursor);
    remove_region(bases[2]);
    mapping_failure=true;
    CHECK(!process_allocate_aux_user_segment_locked(&process,8192,&base,&host));
    CHECK(process.user_thread_stack_next==cursor);
    mapping_failure=false;
    CHECK(process_allocate_aux_user_segment_locked(&process,4096,&base,&host));
    CHECK(base==bases[2]+4096);guards_do_not_overlap();
    remove_region(base);
    CHECK(process_allocate_aux_user_segment_locked(&process,8192,&base,&host));CHECK(base==bases[2]);
    remove_region(base);
    /* Repeated allocations do not consume the monotonic cursor permanently. */
    for(unsigned i=0;i<4096;i++) {
        CHECK(process_allocate_aux_user_segment_locked(&process,8192,&base,&host));CHECK(base==bases[2]);
        memset(host,0x7A,8192);remove_region(base);
    }
    CHECK(!process_allocate_aux_user_segment_locked(&process,0,&base,&host));
    CHECK(!process_allocate_aux_user_segment_locked(&process,8193,&base,&host));
    CHECK(!process_allocate_aux_user_segment_locked(&process,SIZE_MAX-4095,&base,&host));
    for(unsigned i=0;i<5;i++)if(i!=2)remove_region(bases[i]);
    guards_do_not_overlap();
    free(bases);free(stub);process.user_regions=NULL;

    locks=0;flags=512;remote_complete=false;
    CHECK(process_complete_user_mapping(&process) && sleeps==1);
    remote_complete=false;flags=0;
    CHECK(!process_complete_user_mapping(&process) && sleeps==1);
    remote_complete=true;CHECK(process_complete_user_mapping(&process));
    remote_complete=false;flags=512;locks=1;
    CHECK(!process_complete_user_mapping(&process) && sleeps==1);
    CHECK(!process_complete_user_mapping(NULL));
    puts("auxiliary stack/TLS pool exhaustion, reuse, guards and barrier tests passed");
}
'''
    compile_and_run("auxiliary-pool", program)
    print("auxiliary pool reuse contracts passed")


if __name__ == "__main__":
    main()
