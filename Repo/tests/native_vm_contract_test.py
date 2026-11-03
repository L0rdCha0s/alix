#!/usr/bin/env python3
"""Exercise production native VM transactions with OOM and delayed CPUs."""
import sys
sys.dont_write_bytecode = True
from audio_stream_contract_test import ROOT, compile_and_run, function_definition


def main():
    production = (ROOT / "src/kernel/process/process_vm.c").read_text()
    production = "\n".join(line for line in production.splitlines() if not line.startswith("#include"))
    layout_defines = chr(10).join(line for line in (ROOT / "include/memory_layout.h").read_text().splitlines()
                                if line.startswith("#define USER_DEFAULT_"))
    program = layout_defines + r'''
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>
#include <errno.h>
#define CHECK(c) do { if (!(c)) { fprintf(stderr,"native VM check failed line %d: %s\n",__LINE__,#c); exit(1); } } while (0)
#define PAGE_SIZE_BYTES_LOCAL 4096UL
#define USER_HEAP_BASE (USER_DEFAULT_POINTER_BASE+USER_DEFAULT_HEAP_BASE_OFFSET)
#define USER_HEAP_SIZE USER_DEFAULT_HEAP_SIZE
#define USER_STUB_CODE_BASE (USER_DEFAULT_POINTER_LIMIT+1ULL-8192ULL)
#define RFLAGS_IF_BIT 512UL
#define SYSCALL_VM_PROT_NONE 0u
#define SYSCALL_VM_PROT_READ 1u
#define SYSCALL_VM_PROT_WRITE 2u
#define SYSCALL_VM_PROT_EXEC 4u
#define SYSCALL_VM_MAP_SHARED 1u
#define SYSCALL_MS_ASYNC 1u
#define SYSCALL_MS_INVALIDATE 2u
#define SYSCALL_MS_SYNC 4u
#define SYSCALL_VM_MAP_PRIVATE 2u
#define SYSCALL_VM_MAP_ANONYMOUS 32u
#define SYSCALL_VM_MAP_NORESERVE 0x4000u
#define SYSCALL_VM_MAP_FIXED 16u
#define SYSCALL_VM_MAP_FIXED_NOREPLACE 0x100000u
#define SYSCALL_VM_ADVICE_DONTNEED 4u
#define SYSCALL_VM_ADVICE_POSIX 0x100u
typedef uintptr_t paddr_t;
typedef struct fd_description {unsigned refs;bool writable,bundle;size_t count;paddr_t pages[3];struct fd_description *children[3];} fd_description_t;
typedef struct { unsigned unused; } paging_space_t;
typedef struct { uint64_t generation; uint32_t cpu_mask; } paging_tlb_ticket_t;
struct process_vm_area;
struct process_vm_transaction;
typedef struct {
    bool is_user; paging_space_t address_space;
    struct process_vm_area *vm_areas;
    struct process_vm_transaction *vm_pending;
} process_t;
static process_t process = {.is_user=true};
static uint64_t irq_flags=512, generation, acknowledged;
static unsigned memory_locks, sleeps, physical_live, metadata_live;
static int fail_metadata=-1, fail_physical=-1;
static bool fail_prepare, destroy_during_wait, quiescent;
static void (*during_wait)(void);
static jmp_buf canceled;
typedef struct { uintptr_t address; paddr_t physical; unsigned protection; } fake_leaf_t;
static fake_leaf_t leaves[8192];
static size_t leaf_count;
typedef struct { paddr_t physical; bool mapped; } physical_record_t;
static physical_record_t physical_records[8192];
static size_t physical_count;
static uintptr_t align_up_uintptr(uintptr_t x,uintptr_t n) { return (x+n-1)&~(n-1); }
static uintptr_t align_down_uintptr(uintptr_t x,uintptr_t n) { return x&~(n-1); }
static size_t align_up_size(size_t x,size_t n) { return (x+n-1)&~(n-1); }
static uint64_t cpu_save_flags(void) { return irq_flags; }
static bool spinlock_preempt_disabled(void) { return memory_locks!=0; }
static process_t *current_process_local(void) { return &process; }
static uint64_t process_memory_lock(process_t *p) { CHECK(p==&process && !memory_locks); uint64_t old=irq_flags; irq_flags=0; ++memory_locks; return old; }
static void process_memory_unlock(process_t *p,uint64_t old) { CHECK(p==&process && memory_locks==1); --memory_locks; irq_flags=old; }
static void *phys_to_virt(paddr_t p) { return (void *)p; }
static void fatal(const char *message) { fprintf(stderr,"fatal: %s\n",message); abort(); }
static void *checked_malloc(size_t n) {
    if (fail_metadata==0) return NULL;
    if (fail_metadata>0) --fail_metadata;
    void *p=malloc(n); if(p) ++metadata_live; return p;
}
static void *checked_calloc(size_t n,size_t s) { CHECK(!s || n<=SIZE_MAX/s); void *p=checked_malloc(n*s); if(p) memset(p,0,n*s); return p; }
static void checked_free(void *p) { if(p) { CHECK(metadata_live); --metadata_live; free(p); } }
static bool user_memory_alloc_page(paddr_t *out) {
    if(fail_physical==0) return false;
    if(fail_physical>0) --fail_physical;
    void *p=malloc(4096); if(!p)return false;
    CHECK(physical_count<8192); physical_records[physical_count++]=(physical_record_t){(paddr_t)p,false};
    ++physical_live; *out=(paddr_t)p; memset(p,0xCC,4096); return true;
}
static physical_record_t *physical_record(paddr_t p) {
    for(size_t i=0;i<physical_count;i++) if(physical_records[i].physical==p)return &physical_records[i];
    CHECK(false); return NULL;
}
static void user_memory_free_page(paddr_t p) {
    physical_record_t *record=physical_record(p);
    CHECK(quiescent || !record->mapped || acknowledged>=generation);
    CHECK(physical_live); --physical_live; record->physical=0; free((void *)p);
}
static fake_leaf_t *leaf(uintptr_t address) {
    for(size_t i=0;i<leaf_count;i++)if(leaves[i].address==address)return &leaves[i];
    CHECK(leaf_count<8192); leaves[leaf_count].address=address; return &leaves[leaf_count++];
}
static bool paging_prepare_user_range(paging_space_t *space,uintptr_t address,size_t length) {
    (void)space; CHECK(memory_locks==1 && irq_flags==0 && !(address&4095) && !(length&4095)); return !fail_prepare;
}
static bool paging_write_prepared_user_page(paging_space_t *space,uintptr_t address,paddr_t physical,bool present,bool writable,bool executable) {
    (void)space; CHECK(memory_locks==1 && irq_flags==0 && !(address&4095));
    fake_leaf_t *pte=leaf(address); pte->physical=physical;
    pte->protection=present ? 1u|(writable?2u:0u)|(executable?4u:0u) : 0;
    if(present)physical_record(physical)->mapped=true;
    return true;
}
static paging_tlb_ticket_t paging_request_tlb_flush(paging_space_t *space) {
    (void)space; CHECK(memory_locks==1 && irq_flags==0); return (paging_tlb_ticket_t){++generation,2};
}
static bool paging_tlb_flush_complete(paging_tlb_ticket_t ticket) { return acknowledged>=ticket.generation; }
void process_vm_destroy(process_t *p);
static void process_sleep_ms(uint32_t ms) {
    CHECK(ms==1 && memory_locks==0 && irq_flags==512 && process.vm_pending); ++sleeps;
    if(during_wait) { void (*callback)(void)=during_wait; during_wait=NULL; callback(); }
    if(destroy_during_wait) {
        destroy_during_wait=false; quiescent=true; process_vm_destroy(&process); quiescent=false;
        longjmp(canceled,1);
    }
    acknowledged=generation;
}
static fd_description_t *model_file_create(void) {return calloc(1,sizeof(fd_description_t));}
static bool fd_description_get(fd_description_t *f) {CHECK(f && f->refs);++f->refs;return true;}
static void fd_description_put(fd_description_t *f) {
    if(!f || --f->refs)return;
    if(f->bundle)for(size_t i=0;i<f->count;++i)fd_description_put(f->children[i]);
    else for(size_t i=0;i<f->count;++i)user_memory_free_page(f->pages[i]);
    free(f);
}
static bool io_vfs_mapping_writable(const fd_description_t *f) {return f->writable;}
static paddr_t io_vfs_mapping_page(const fd_description_t *f,size_t index) {return index<f->count?f->pages[index]:0;}
static fd_description_t *io_vfs_sync_bundle_create(size_t capacity) {
    CHECK(capacity<=3);fd_description_t *f=calloc(1,sizeof(*f));CHECK(f);f->refs=1;f->bundle=true;return f;
}
static bool io_vfs_sync_bundle_add(fd_description_t *b,fd_description_t *f) {
    CHECK(b->count<3);fd_description_get(f);b->children[b->count++]=f;return true;
}
#define malloc checked_malloc
#define calloc checked_calloc
#define free checked_free
'''
    program += production + r'''
static const uint32_t anonymous_flags=SYSCALL_VM_MAP_PRIVATE|SYSCALL_VM_MAP_ANONYMOUS|SYSCALL_VM_MAP_NORESERVE;
static void clear_process(void) {
    quiescent=true; process_vm_destroy(&process); quiescent=false;
    CHECK(!metadata_live && !physical_live && !memory_locks && irq_flags==512);
    memset(leaves,0,sizeof(leaves)); leaf_count=0; physical_count=0;
    fail_metadata=fail_physical=-1; fail_prepare=false;
}
static uint8_t *resolve(uintptr_t address,bool write) {
    uint64_t flags=process_memory_lock(&process); uint8_t *host=NULL;size_t bytes=0;
    bool okay=process_vm_resolve_locked(&process,address,write,&host,&bytes);
    CHECK(!okay || (host && bytes>0 && bytes<=4096-(address&4095)));
    process_memory_unlock(&process,flags); return okay?host:NULL;
}
static bool fault(uintptr_t address,bool write,bool execute) {
    uint64_t saved=irq_flags; irq_flags=0;
    uint64_t flags=process_memory_lock(&process);
    bool result=process_vm_fault_locked(&process,address,write,execute);
    process_memory_unlock(&process,flags); CHECK(irq_flags==0); irq_flags=saved;
    return result;
}
static uintptr_t racing_address;
static paddr_t racing_old_page;
static void touch_during_discard(void) {
    CHECK(process.vm_pending && acknowledged<generation && physical_live==1);
    CHECK(physical_record(racing_old_page)->physical==racing_old_page);
    CHECK(fault(racing_address,true,false) && physical_live==2);
    paddr_t fresh=leaf(racing_address)->physical;
    CHECK(fresh && fresh!=racing_old_page && *resolve(racing_address,false)==0);
    CHECK(fault(racing_address,true,false) && physical_live==2 && leaf(racing_address)->physical==fresh);
    *resolve(racing_address,true)=0x72;
}
int main(void) {
    CHECK(process_vm_map(&process,0,0,3,anonymous_flags)==-22);
    CHECK(process_vm_map(&process,0,4096,0x80,anonymous_flags)==-22);
    CHECK(process_vm_map(&process,0,4096,3,2)==-22);
    CHECK(process_vm_map(&process,0,4096,3,anonymous_flags|0x80000000u)==-22);
    CHECK(process_vm_map(&process,0,4096,3,anonymous_flags|0x100000)==-22);
    CHECK(process_vm_map(&process,0x100000000,4096,3,anonymous_flags|16)==-22);
    CHECK(process_vm_map(&process,0,SIZE_MAX,0,anonymous_flags)==-22);
    CHECK(metadata_live==0 && physical_live==0);
    CHECK(process_vm_map(&process,0,4096,3,anonymous_flags & ~SYSCALL_VM_MAP_NORESERVE)>0);
    CHECK(physical_live==1);
    clear_process();
    /* Advisory hints must never make a legal nonfixed reservation fail. */
    const uintptr_t hints[]={1,USER_HEAP_BASE,USER_STUB_CODE_BASE,UINTPTR_MAX};
    for(unsigned i=0;i<sizeof(hints)/sizeof(hints[0]);++i) {
        CHECK(process_vm_map(&process,hints[i],4096,0,anonymous_flags)==(int64_t)vm_arena_start());
        clear_process();
    }
    uintptr_t hint=vm_arena_start()+17*4096;
    CHECK(process_vm_map(&process,hint+123,4096,0,anonymous_flags)==(int64_t)hint);
    CHECK(process_vm_map(&process,hint,4096,0,anonymous_flags)==(int64_t)vm_arena_start());
    CHECK(process_vm_map(&process,hint+1,4096,0,anonymous_flags|16)==-22);
    CHECK(process_vm_map(&process,hint+1,4096,0,anonymous_flags|0x100000)==-22);
    clear_process();
    /* Real address scale, no 12GiB backing or leaf preparation. */
    uintptr_t high=(32ULL<<40)-(6ULL<<30);
    size_t huge=12ULL<<30;
    CHECK(process_vm_map(&process,high,huge,0,anonymous_flags)==(int64_t)high);
    CHECK(!process.vm_areas->pages && physical_live==0 && leaf_count==0);
    CHECK(process_vm_protect(&process,high,4096,3)==0);
    CHECK(process_vm_protect(&process,high+huge-4096,4096,3)==0);
    CHECK(physical_live==2 && resolve(high,true) && resolve(high+huge-4096,true));
    CHECK(process_vm_unmap(&process,high,huge)==0 && physical_live==0 && metadata_live==0);
    clear_process();

    /* Large reservation stays sparse. Partial commitment and PROT_NONE cycles
     * preserve existing bytes rather than silently allocating replacement data. */
    uintptr_t base=(uintptr_t)process_vm_map(&process,0,512u*1024u*1024u,0,anonymous_flags);
    CHECK(base==vm_arena_start() && physical_live==0 && !resolve(base,false));
    CHECK(process_vm_protect(&process,base+4096,8192,3)==0 && physical_live==2);
    CHECK(resolve(base+4096,true) && *resolve(base+4096,false)==0);
    *resolve(base+4096,true)=0xA7; *resolve(base+8192,true)=0xB8;
    paddr_t original=leaf(base+4096)->physical;
    CHECK(process_vm_protect(&process,base+4096,4096,0)==0);
    CHECK(!resolve(base+4096,false) && leaf(base+4096)->protection==0 && physical_live==2);
    CHECK(process_vm_protect(&process,base+4096,4096,5)==0);
    CHECK(*resolve(base+4096,false)==0xA7 && !resolve(base+4096,true));
    CHECK(leaf(base+4096)->physical==original && leaf(base+4096)->protection==5);
    CHECK(process_vm_protect(&process,base+4096,4096,0x80)==-22 && leaf(base+4096)->protection==5);
    CHECK(process_vm_unmap(&process,base+4096,4096)==0 && physical_live==1);
    CHECK(!resolve(base+4096,false) && *resolve(base+8192,false)==0xB8);
    CHECK(process_vm_protect(&process,base,12288,3)==-12);
    CHECK(!resolve(base,false) && leaf(base+8192)->protection==3);
    CHECK(process_vm_map(&process,base+8192,4096,3,anonymous_flags|0x100000)==-17);
    CHECK(process_vm_map(&process,base+4096,4096,3,anonymous_flags|0x100000)==(int64_t)(base+4096));
    CHECK(*resolve(base+4096,false)==0 && physical_live==2);
    CHECK(process_vm_unmap(&process,base,512u*1024u*1024u)==0);
    CHECK(!process.vm_areas && physical_live==0 && metadata_live==0);
    CHECK(process_vm_unmap(&process,base,8192)==0);
    CHECK(sleeps>0 && acknowledged==generation);
    clear_process();

    /* Every supported bit combination follows the x86 hardware contract. */
    for(unsigned protection=0;protection<8;protection++) {
        unsigned normalized=protection?protection|1u:0;
        base=(uintptr_t)process_vm_map(&process,0,4096,protection,anonymous_flags);
        CHECK(base==vm_arena_start());
        CHECK(process.vm_areas->protection==normalized);
        CHECK((resolve(base,false)!=NULL)==(protection!=0));
        CHECK((resolve(base,true)!=NULL)==((protection&2u)!=0));
        if(protection)CHECK(leaf(base)->protection==normalized);
        CHECK(process_vm_protect(&process,base,4096,7)==0 && leaf(base)->protection==7 && resolve(base,true));
        CHECK(process_vm_protect(&process,base,4096,4)==0 && leaf(base)->protection==5 && !resolve(base,true));
        CHECK(process_vm_protect(&process,base,4096,2)==0 && leaf(base)->protection==3 && resolve(base,true));
        clear_process();
    }

    /* Atomic fixed replacement spans multiple areas and holes, preserving
     * both outside fragments and publishing only zeroed fresh backing. */
    base=(uintptr_t)process_vm_map(&process,0,6*4096,3,anonymous_flags);
    for(unsigned i=0;i<6;i++)*resolve(base+i*4096,true)=(uint8_t)(0x50+i);
    CHECK(process_vm_unmap(&process,base+2*4096,4096)==0);
    CHECK(process_vm_protect(&process,base+3*4096,4096,0)==0);
    CHECK(process_vm_map(&process,base+4096,4*4096,3,anonymous_flags|16)==(int64_t)(base+4096));
    CHECK(physical_live==6 && *resolve(base,false)==0x50 && *resolve(base+5*4096,false)==0x55);
    for(unsigned i=1;i<5;i++)CHECK(*resolve(base+i*4096,false)==0);
    CHECK(process_vm_map(&process,base+4096,4*4096,0,anonymous_flags|16)==(int64_t)(base+4096));
    CHECK(physical_live==2 && !resolve(base+4096,false));
    CHECK(process_vm_map(&process,base,4096,3,anonymous_flags|16|0x100000)==-22);
    clear_process();

    /* Every metadata and physical allocation failure precedes publication. */
    unsigned failures=0, successes=0;
    for(int point=0;point<14;point++) {
        base=(uintptr_t)process_vm_map(&process,0,16384,0,anonymous_flags);
        process_vm_area_t *old=process.vm_areas;unsigned old_meta=metadata_live;
        fail_metadata=point;
        int result=process_vm_protect(&process,base+4096,8192,3);
        fail_metadata=-1;
        if(result==-12) {
            ++failures;CHECK(process.vm_areas==old && old->length==16384 && old->protection==0 && !old->pages);
            CHECK(metadata_live==old_meta && physical_live==0 && !resolve(base+4096,false));
        } else { ++successes;CHECK(result==0 && physical_live==2); }
        clear_process();
    }
    CHECK(failures>=5 && successes>0);
    failures=successes=0;
    for(int point=0;point<12;point++) {
        base=(uintptr_t)process_vm_map(&process,0,16384,3,anonymous_flags);
        *resolve(base+4096,true)=0xE5;
        process_vm_area_t *old=process.vm_areas;unsigned old_meta=metadata_live;
        paddr_t old_page=leaf(base+4096)->physical;
        fail_metadata=point;
        int64_t result=process_vm_map(&process,base+4096,8192,3,anonymous_flags|16);
        fail_metadata=-1;
        if(result==-12) {
            ++failures;CHECK(process.vm_areas==old && metadata_live==old_meta && physical_live==4);
            CHECK(leaf(base+4096)->physical==old_page && *resolve(base+4096,true)==0xE5);
        } else { ++successes;CHECK(result==(int64_t)(base+4096) && physical_live==4 && *resolve(base+4096,true)==0); }
        clear_process();
    }
    CHECK(failures>=5 && successes>0);
    for(int point=0;point<3;point++) {
        base=(uintptr_t)process_vm_map(&process,0,16384,0,anonymous_flags);
        process_vm_area_t *old=process.vm_areas;
        fail_physical=point;
        int result=process_vm_protect(&process,base,12288,3);
        fail_physical=-1;
        CHECK(result==-12 && process.vm_areas==old && physical_live==0);
        clear_process();
    }
    for(int point=0;point<2;point++) {
        base=(uintptr_t)process_vm_map(&process,0,16384,3,anonymous_flags);
        process_vm_area_t *old=process.vm_areas;*resolve(base+4096,true)=0x6B;
        fail_physical=point;
        int64_t result=process_vm_map(&process,base+4096,8192,3,anonymous_flags|16);
        fail_physical=-1;
        CHECK(result==-12 && process.vm_areas==old && physical_live==4 && *resolve(base+4096,true)==0x6B);
        clear_process();
    }
    base=(uintptr_t)process_vm_map(&process,0,8192,3,anonymous_flags);
    *resolve(base,true)=0x55;unsigned physical_before=physical_live;
    fail_prepare=true;
    CHECK(process_vm_protect(&process,base,4096,1)==-12);
    CHECK(physical_live==physical_before && *resolve(base,true)==0x55 && leaf(base)->protection==3);
    fail_prepare=false;clear_process();

    /* Discard changes backing, not address ownership or access permissions.
     * Unaligned lengths round up; unaffected fragments keep their contents. */
    CHECK(process_vm_advise(&process,0,0,4)==0);
    CHECK(process_vm_advise(&process,0,0,99)==-22);
    base=(uintptr_t)process_vm_map(&process,0,4*4096,3,anonymous_flags);
    for(unsigned i=0;i<4;i++)*resolve(base+i*4096,true)=(uint8_t)(0x40+i);
    for(unsigned advice=0;advice<=4;advice++) {
        process_vm_area_t *original_area=process.vm_areas;
        paddr_t original_page=leaf(base)->physical;
        CHECK(process_vm_advise(&process,base,4*4096,0x100|advice)==0);
        CHECK(process.vm_areas==original_area && physical_live==4 && leaf(base)->physical==original_page);
        for(unsigned i=0;i<4;i++)CHECK(*resolve(base+i*4096,false)==0x40+i);
    }
    CHECK(process_vm_advise(&process,base,4096,0x105)==-22);
    CHECK(process_vm_advise(&process,base+1,4096,0x104)==-22);
    CHECK(process_vm_advise(&process,base+1,4096,4)==-22 && physical_live==4);
    CHECK(process_vm_advise(&process,base,SIZE_MAX,4)==-22 && physical_live==4);
    CHECK(process_vm_advise(&process,base+4096,4097,4)==0 && physical_live==2);
    CHECK(!leaf(base+4096)->physical && !leaf(base+8192)->physical);
    CHECK(*resolve(base,false)==0x40 && *resolve(base+12288,false)==0x43);
    CHECK(process_vm_advise(&process,base+4096,8192,4)==0 && physical_live==2);
    CHECK(*resolve(base+4096,false)==0 && physical_live==3);
    CHECK(fault(base+8192,true,false) && *resolve(base+8192,false)==0 && physical_live==4);
    CHECK(process_vm_unmap(&process,base+8192,4096)==0);
    CHECK(process_vm_advise(&process,base+4096,8192,4)==-12 && physical_live==3);
    CHECK(process_vm_advise(&process,base+4096,8192,0x104)==-12 && physical_live==3);
    CHECK(resolve(base+4096,true)!=NULL);
    clear_process();

    /* Read-only/execute/PROT_NONE mappings never gain extra permissions when
     * filled by a fault or a safe kernel copy. Hidden discarded data stays gone. */
    base=(uintptr_t)process_vm_map(&process,0,4096,3,anonymous_flags);
    *resolve(base,true)=0xA3;
    CHECK(process_vm_protect(&process,base,4096,1)==0);
    CHECK(process_vm_advise(&process,base,4096,4)==0 && physical_live==0);
    CHECK(!resolve(base,true) && !fault(base,true,false) && !fault(base,false,true) && !physical_live);
    CHECK(fault(base,false,false) && physical_live==1 && leaf(base)->protection==1);
    CHECK(*resolve(base,false)==0 && !resolve(base,true));
    CHECK(process_vm_protect(&process,base,4096,0)==0 && physical_live==1);
    CHECK(process_vm_advise(&process,base,4096,4)==0 && physical_live==0);
    CHECK(!resolve(base,false) && !fault(base,false,false) && !physical_live);
    CHECK(process_vm_protect(&process,base,4096,5)==0 && physical_live==0);
    CHECK(fault(base,false,true) && leaf(base)->protection==5 && *resolve(base,false)==0);
    clear_process();

    /* Every consumer of page arrays must tolerate null entries: splitting,
     * protection changes, fixed replacement, unmap and process teardown. */
    base=(uintptr_t)process_vm_map(&process,0,3*4096,3,anonymous_flags);
    CHECK(process_vm_advise(&process,base,3*4096,4)==0 && !physical_live);
    CHECK(process_vm_protect(&process,base+4096,4096,1)==0 && !physical_live);
    CHECK(process_vm_map(&process,base,8192,3,anonymous_flags|16)==(int64_t)base && physical_live==2);
    CHECK(process_vm_unmap(&process,base,3*4096)==0 && !physical_live);
    clear_process();

    failures=successes=0;
    for(int point=0;point<12;point++) {
        base=(uintptr_t)process_vm_map(&process,0,3*4096,3,anonymous_flags);
        process_vm_area_t *old=process.vm_areas;unsigned old_meta=metadata_live;
        *resolve(base+4096,true)=0x67;
        fail_metadata=point;
        int result=process_vm_advise(&process,base+4096,4096,4);
        fail_metadata=-1;
        if(result==-12) {
            ++failures;CHECK(process.vm_areas==old && metadata_live==old_meta && physical_live==3);
            CHECK(*resolve(base+4096,false)==0x67);
        } else { ++successes;CHECK(result==0 && physical_live==2); }
        clear_process();
    }
    CHECK(failures>=5 && successes>0);
    base=(uintptr_t)process_vm_map(&process,0,4096,3,anonymous_flags);
    *resolve(base,true)=0x88;
    fail_prepare=true;
    CHECK(process_vm_advise(&process,base,4096,4)==-12 && physical_live==1 && *resolve(base,false)==0x88);
    fail_prepare=false;
    CHECK(process_vm_advise(&process,base,4096,4)==0 && !physical_live);
    fail_physical=0;
    CHECK(!resolve(base,true) && !fault(base,false,false) && !physical_live && !leaf(base)->physical);
    fail_physical=-1;
    CHECK(fault(base,true,false) && *resolve(base,false)==0 && physical_live==1);
    clear_process();

    /* A first touch while the transaction owner sleeps cannot free backing
     * still cached by the delayed CPU, nor lose the freshly published page. */
    base=(uintptr_t)process_vm_map(&process,0,4096,3,anonymous_flags);
    racing_address=base;racing_old_page=leaf(base)->physical;
    during_wait=touch_during_discard;
    CHECK(process_vm_advise(&process,base,4096,4)==0 && physical_live==1);
    CHECK(*resolve(base,false)==0x72 && acknowledged==generation);
    clear_process();
    base=(uintptr_t)process_vm_map(&process,0,4096,3,anonymous_flags);
    racing_address=base;racing_old_page=leaf(base)->physical;
    during_wait=touch_during_discard;destroy_during_wait=true;
    if(setjmp(canceled)==0) { (void)process_vm_advise(&process,base,4096,4); CHECK(false); }
    CHECK(!process.vm_areas && !process.vm_pending && !physical_live && !metadata_live);
    clear_process();

    /* Kill the transaction owner while acknowledgements are pending. The
     * journal is reachable from the process and quiescent teardown owns it. */
    base=(uintptr_t)process_vm_map(&process,0,12288,3,anonymous_flags);
    destroy_during_wait=true;
    if(setjmp(canceled)==0) {
        (void)process_vm_unmap(&process,base+4096,4096);
        CHECK(false);
    }
    CHECK(!process.vm_areas && !process.vm_pending && !physical_live && !metadata_live);
    clear_process();
    /* File descriptor references, rather than the VMA, own shared physical pages.
     * Splits, replacement, rollback and delayed acknowledgement retain them. */
    fd_description_t *file=model_file_create();CHECK(file);file->refs=1;file->count=3;
    for(size_t i=0;i<3;++i)CHECK(user_memory_alloc_page(&file->pages[i]));
    base=(uintptr_t)process_vm_map_file(&process,0,12288,1,1,file);
    CHECK(base==vm_arena_start() && file->refs==2 && physical_live==3);
    CHECK(process_vm_protect(&process,base,4096,3)==-EACCES && file->refs==2);
    CHECK(process_vm_advise(&process,base,4096,4)==-ENOTSUP);
    CHECK(process_vm_protect(&process,base+4096,4096,0)==0 && file->refs==4);
    CHECK(process_vm_protect(&process,base+4096,4096,1)==0 && file->refs==4);
    fd_description_t *bundle=NULL;
    CHECK(process_vm_sync_prepare(&process,base,12288,4,&bundle)==0 && bundle);
    fd_description_put(bundle);
    CHECK(process_vm_unmap(&process,base+4096,4096)==0 && physical_live==3);
    CHECK(process_vm_sync_prepare(&process,base,12288,4,&bundle)==-ENOMEM && !bundle);
    CHECK(process_vm_map(&process,base,4096,3,anonymous_flags|16)==(int64_t)base);
    CHECK(physical_live==4 && file->refs==2);
    CHECK(process_vm_unmap(&process,base,12288)==0 && file->refs==1 && physical_live==3);
    fd_description_put(file);clear_process();
    for(int point=0;point<5;++point) {
        file=model_file_create();CHECK(file);file->refs=1;file->count=1;
        CHECK(user_memory_alloc_page(&file->pages[0]));
        fail_metadata=point;
        int64_t mapped=process_vm_map_file(&process,0,4096,1,1,file);
        fail_metadata=-1;
        CHECK(mapped==-ENOMEM || mapped==(int64_t)vm_arena_start());
        CHECK(physical_live==1);
        if(mapped>0)CHECK(process_vm_unmap(&process,(uintptr_t)mapped,4096)==0);
        CHECK(file->refs==1);fd_description_put(file);clear_process();
    }
    puts("native VM anonymous/file ownership/split/OOM/delayed-ack/cancellation tests passed");
    return 0;
}
'''
    compile_and_run("native-vm-contract", program)
    wrappers = (ROOT / "user/lib/mman.c").read_text()
    layout_defines = chr(10).join(line for line in (ROOT / "include/memory_layout.h").read_text().splitlines()
                                if line.startswith("#define USER_DEFAULT_"))
    program = layout_defines + r'''
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <errno.h>
#include <assert.h>
#define SYSCALL_VM_ADVICE_POSIX 0x100u
#define POSIX_MADV_NORMAL 0
#define POSIX_MADV_DONTNEED 4
#define MADV_NORMAL 0
#define MADV_WILLNEED 3
#define MADV_DONTNEED 4
static int result;
static unsigned calls;
static uintptr_t seen_address;
static size_t seen_length;
static uint32_t seen_advice;
static int sys_vm_advise(uintptr_t address,size_t length,uint32_t advice) {
    ++calls;seen_address=address;seen_length=length;seen_advice=advice;return result;
}
'''
    program += function_definition(wrappers, "int madvise(") + "\n"
    program += function_definition(wrappers, "int posix_madvise(") + r'''
int main(void) {
    for(int advice=0;advice<=4;advice++) {
        errno=EDOM;result=0;
        assert(posix_madvise((void *)0x1234000,8192,advice)==0 && errno==EDOM);
        assert(seen_address==0x1234000 && seen_length==8192 && seen_advice==(0x100u|(uint32_t)advice));
        result=-ENOMEM;
        assert(posix_madvise((void *)0x1234000,8192,advice)==ENOMEM && errno==EDOM);
    }
    unsigned before=calls;
    assert(posix_madvise((void *)0x1234000,8192,99)==EINVAL && errno==EDOM && calls==before);
    assert(madvise((void *)0x1234000,8192,0x104)==-1 && errno==EINVAL && calls==before);
    for(int advice=0;advice<=3;advice+=3) {
        result=0;errno=EDOM;
        assert(madvise((void *)0x1234000,8192,advice)==0 && errno==EDOM);
        assert(seen_address==0x1234000 && seen_length==8192 && seen_advice==(0x100u|(uint32_t)advice));
        result=-ENOMEM;
        assert(madvise((void *)0x1234000,8192,advice)==-1 && errno==ENOMEM);
    }
    result=-EINVAL;
    assert(madvise((void *)0x1234000,8192,4)==-1 && errno==EINVAL && seen_advice==4);
    result=0;errno=EDOM;
    assert(madvise((void *)0x1234000,8192,4)==0 && errno==EDOM);
    return 0;
}
'''
    compile_and_run("native-vm-advice-wrappers", program)
    print("native VM transaction contracts passed")


if __name__ == "__main__":
    main()
