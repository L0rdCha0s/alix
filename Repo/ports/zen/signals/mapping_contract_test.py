#!/usr/bin/env python3
"""Classify logical mappings, independently of present/PTE permission bits."""
from pathlib import Path
import argparse,subprocess,sys
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2]
parser=argparse.ArgumentParser();parser.add_argument('--active',action='store_true');args=parser.parse_args()
tree=ROOT if args.active else HERE/'pending'
sys.path.insert(0,str(ROOT/'tests'))
from audio_stream_contract_test import function_definition
memory=(tree/'src/kernel/process/process_memory.c').read_text();vm=(tree/'src/kernel/process/process_vm.c').read_text()
source=r'''
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <assert.h>
#include <stdio.h>
typedef struct process_vm_area { uintptr_t base;size_t length;struct process_vm_area *next; } process_vm_area_t;
typedef struct process_user_region { uintptr_t user_base;size_t mapped_size;struct process_user_region *next; } process_user_region_t;
typedef struct {uintptr_t user_heap_base,user_heap_brk,user_stack_top,user_stack_size;process_vm_area_t *vm_areas;process_user_region_t *user_regions;} process_t;
static unsigned held;
static uint64_t process_memory_lock(process_t *p){(void)p;assert(!held);held=1;return 99;}
static void process_memory_unlock(process_t *p,uint64_t f){(void)p;assert(held&&f==99);held=0;}
static uintptr_t process_stack_bottom(process_t *p){assert(held);return p->user_stack_top-p->user_stack_size;}
'''
for text,signature in [(vm,'static process_vm_area_t *vm_find_area('),(vm,'bool process_vm_contains_locked('),(memory,'bool process_signal_address_mapped(')]:source+=function_definition(text,signature)+'\n'
source+=r'''
int main(void){
 process_vm_area_t v={.base=0x580000000,.length=4096};
 process_user_region_t r={.user_base=0x100001000,.mapped_size=8192};
 process_t p={.user_heap_base=0x180000000,.user_heap_brk=0x180001013,.user_stack_top=0x140000000,.user_stack_size=8*1024*1024,.vm_areas=&v,.user_regions=&r};
 assert(!process_signal_address_mapped(NULL,v.base));
 assert(process_signal_address_mapped(&p,v.base)&&process_signal_address_mapped(&p,v.base+4095));
 assert(!process_signal_address_mapped(&p,v.base-1)&&!process_signal_address_mapped(&p,v.base+4096));
 assert(process_signal_address_mapped(&p,p.user_heap_brk-1)&&!process_signal_address_mapped(&p,p.user_heap_brk));
 assert(!process_signal_address_mapped(&p,p.user_heap_base-1));
 assert(process_signal_address_mapped(&p,p.user_stack_top-p.user_stack_size)&&!process_signal_address_mapped(&p,p.user_stack_top-p.user_stack_size-1));
 assert(process_signal_address_mapped(&p,p.user_stack_top-1)&&!process_signal_address_mapped(&p,p.user_stack_top));
 assert(process_signal_address_mapped(&p,r.user_base)&&process_signal_address_mapped(&p,r.user_base+8191)&&!process_signal_address_mapped(&p,r.user_base+8192));
 assert(!held);puts("Signal mapping classification: PASS reservation/discard boundaries heap brk image main guard");
}
'''
out=HERE/'out';out.mkdir(exist_ok=True);path=out/'mapping_test.c';path.write_text(source)
exe=out/'mapping_test';subprocess.run(['cc','-std=c11','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',str(path),'-o',str(exe)],check=True);subprocess.run([str(exe)],check=True)
