#!/usr/bin/env python3
"""Run native environment copying/stack encoding with mapping and OOM failures."""
import sys
sys.dont_write_bytecode = True
from audio_stream_contract_test import ROOT, compile_and_run, function_definition


def main():
    source=(ROOT/"src/kernel/process/process_memory.c").read_text()
    code=r'''
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x) do{if(!(x)){fprintf(stderr,"environment stack line %d: %s\n",__LINE__,#x);abort();}}while(0)
#define BASE UINT64_C(0x100000000)
typedef struct{char **env_values;char *env_storage;size_t env_count;uintptr_t user_envp_ptr,user_stack_top;size_t user_stack_size;unsigned char *backing;}process_t;
static unsigned allocations,attempts,fail_at;
static bool fail_mapping,fail_copy;
static void *owned_malloc(size_t bytes){if(++attempts==fail_at)return NULL;void*p=malloc(bytes);if(p)++allocations;return p;}
static void *owned_calloc(size_t count,size_t bytes){if(++attempts==fail_at)return NULL;void*p=calloc(count,bytes);if(p)++allocations;return p;}
static void owned_free(void*p){if(p){CHECK(allocations);--allocations;free(p);}}
static uintptr_t align_down_uintptr(uintptr_t value,uintptr_t alignment){return value&~(alignment-1);}
static bool process_stack_ensure_range(process_t *process,uintptr_t address,size_t bytes){
    return !fail_mapping&&address>=BASE&&bytes<=process->user_stack_size&&address-BASE<=process->user_stack_size-bytes;
}
static bool process_stack_copy_to(process_t *process,uintptr_t address,const void *data,size_t bytes){
    if(fail_copy)return false;CHECK(process_stack_ensure_range(process,address,bytes));memcpy(process->backing+address-BASE,data,bytes);return true;
}
#define malloc owned_malloc
#define calloc owned_calloc
#define free owned_free
'''
    for signature in ("void process_clear_environment(","bool process_store_environment(","static bool process_prepare_environment_stack("):
        code+=function_definition(source,signature)+"\n"
    code+=r'''
int main(void){
    process_t *process=calloc(1,sizeof(*process));CHECK(process);
    process->user_stack_top=BASE+16384;process->user_stack_size=16384;process->backing=calloc(1,16384);CHECK(process->backing);
    static const char *input[]={"ONE=with spaces","EMPTY=","UTF8=\xc3\xa9"};
    for(unsigned failure=1;failure<=2;++failure){
        attempts=0;fail_at=failure;CHECK(!process_store_environment(process,input,3));fail_at=0;
        CHECK(!process->env_values&&!process->env_storage&&!process->env_count&&allocations==2);
    }
    CHECK(process_store_environment(process,input,3)&&allocations==4);
    CHECK(process->env_values[0]!=input[0]&&!strcmp(process->env_values[2],input[2]));
    uintptr_t stack=process->user_stack_top;
    attempts=0;fail_at=1;CHECK(!process_prepare_environment_stack(process,&stack)&&!process->user_envp_ptr&&allocations==4);fail_at=0;
    fail_mapping=true;stack=process->user_stack_top;CHECK(!process_prepare_environment_stack(process,&stack)&&!process->user_envp_ptr&&allocations==4);fail_mapping=false;
    fail_copy=true;stack=process->user_stack_top;CHECK(!process_prepare_environment_stack(process,&stack)&&!process->user_envp_ptr&&allocations==4);fail_copy=false;
    stack=process->user_stack_top;CHECK(process_prepare_environment_stack(process,&stack)&&process->user_envp_ptr==stack&&stack>=BASE);
    uintptr_t *vector=(uintptr_t*)(process->backing+stack-BASE);
    for(unsigned index=0;index<3;++index)CHECK(vector[index]>=BASE&&!strcmp((char*)process->backing+vector[index]-BASE,input[index]));
    CHECK(!vector[3]&&allocations==4);
    process_clear_environment(process);CHECK(allocations==2);
    stack=process->user_stack_top;CHECK(process_prepare_environment_stack(process,&stack)&&stack==process->user_stack_top&&!process->user_envp_ptr);
    char *large=malloc(17000);CHECK(large);memset(large,'x',16999);large[16999]=0;
    const char **oversized=calloc(1,sizeof(*oversized));CHECK(oversized);oversized[0]=large;
    CHECK(process_store_environment(process,oversized,1));stack=process->user_stack_top;
    CHECK(!process_prepare_environment_stack(process,&stack)&&!process->user_envp_ptr);
    process_clear_environment(process);free(oversized);free(large);
    CHECK(!process_store_environment(process,input,SIZE_MAX/sizeof(char*)+1));
    free(process->backing);free(process);CHECK(!allocations);
    puts("Environment stack contracts PASS");return 0;
}
'''
    compile_and_run("process-environment-stack",code)
    print("Environment stack PASS: owned copies, empty startup, user pointer encoding, size/OOM and mapping/copy rollback")
    return 0

if __name__=="__main__":sys.exit(main())
