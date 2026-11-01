#!/usr/bin/env python3
"""Native environment initialization/snapshot ownership and concurrent mutation."""
import re
import sys
sys.dont_write_bytecode = True
from audio_stream_contract_test import ROOT, compile_and_run, function_definition


def main():
    source=(ROOT/"user/lib/libc.c").read_text()
    code=r'''
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#define CHECK(x) do{if(!(x)){fprintf(stderr,"environment line %d: %s\n",__LINE__,#x);abort();}}while(0)
typedef unsigned alix_mutex_t;
static pthread_mutex_t host_mutex=PTHREAD_MUTEX_INITIALIZER;
static _Thread_local unsigned held,alloc_calls,fail_at;
static uint64_t live;
static void alix_mutex_lock(alix_mutex_t *unused){(void)unused;CHECK(!held&&!pthread_mutex_lock(&host_mutex));held=1;}
static void alix_mutex_unlock(alix_mutex_t *unused){(void)unused;CHECK(held);held=0;CHECK(!pthread_mutex_unlock(&host_mutex));}
static void *managed_malloc(size_t bytes){if(++alloc_calls==fail_at)return NULL;void*p=malloc(bytes);if(p)__atomic_add_fetch(&live,1,__ATOMIC_RELAXED);return p;}
static void *managed_calloc(size_t count,size_t bytes){if(++alloc_calls==fail_at)return NULL;void*p=calloc(count,bytes);if(p)__atomic_add_fetch(&live,1,__ATOMIC_RELAXED);return p;}
static void *managed_realloc(void *old,size_t bytes){if(++alloc_calls==fail_at)return NULL;void*p=realloc(old,bytes);if(p&&!old)__atomic_add_fetch(&live,1,__ATOMIC_RELAXED);return p;}
static void managed_free(void *pointer){if(pointer){CHECK(__atomic_fetch_sub(&live,1,__ATOMIC_RELAXED));free(pointer);}}
#define malloc managed_malloc
#define calloc managed_calloc
#define realloc managed_realloc
#define free managed_free
typedef struct {char *name,*value;} libc_env_entry_t;
static libc_env_entry_t *g_env_entries;
static size_t g_env_count,g_env_capacity;
static alix_mutex_t g_env_mutex;
'''
    signatures=("static int libc_env_find(", "static bool libc_env_reserve(",
                "static char *libc_getenv_unlocked(", "char *getenv(",
                "static int libc_setenv_unlocked(", "int setenv(",
                "static int libc_unsetenv_unlocked(", "int unsetenv(",
                "void alix_environment_free(", "char **alix_environment_copy(",
                "int __alix_environment_initialize(")
    for signature in signatures:
        body=function_definition(source,signature)
        for name in ("getenv","setenv","unsetenv"):
            body=re.sub(r"\b"+name+r"\b","native_"+name,body)
        code+=body+"\n"
    code+=r'''
static void reset(void){
    for(size_t i=0;i<g_env_count;++i){free(g_env_entries[i].name);free(g_env_entries[i].value);}
    free(g_env_entries);g_env_entries=NULL;g_env_count=g_env_capacity=0;CHECK(!live);
}
static void contracts(void){
    char *initial[]={"A=first","A=second","EMPTY=","VALUE=space = and \xc3\xa9","invalid","=invalid",NULL};
    CHECK(!__alix_environment_initialize(initial)&&!strcmp(native_getenv("A"),"first")&&
          native_getenv("EMPTY")&&!native_getenv("EMPTY")[0]&&!strcmp(native_getenv("VALUE"),"space = and \xc3\xa9"));
    uint64_t baseline=live;char *old=native_getenv("A");
    for(unsigned failure=1;failure<7;++failure){
        alloc_calls=0;fail_at=failure;char **copy=alix_environment_copy();fail_at=0;
        if(copy){CHECK(copy[0]&&copy[1]&&copy[2]&&!copy[3]);alix_environment_free(copy);}
        else CHECK(errno==ENOMEM);
        CHECK(live==baseline&&native_getenv("A")==old&&!held);
    }
    for(unsigned failure=1;failure<=2;++failure){
        alloc_calls=0;fail_at=failure;CHECK(native_setenv("NEW","value",1)==-1&&errno==ENOMEM);fail_at=0;
        CHECK(!native_getenv("NEW")&&live==baseline&&!strcmp(native_getenv("A"),"first"));
    }
    char **copy=alix_environment_copy();CHECK(copy&&copy[0]);
    CHECK(!native_setenv("A","replacement",1)&&!strcmp(copy[0],"A=first"));alix_environment_free(copy);
    CHECK(!native_unsetenv("EMPTY")&&!native_getenv("EMPTY"));reset();
}
typedef struct {bool writer;} worker_t;
static void *worker(void *argument){
    worker_t *record=argument;
    for(unsigned i=0;i<1000;++i){
        if(record->writer)CHECK(!native_setenv("RACE",i&1?"one complete value":"another complete value",1));
        else{
            char **copy=alix_environment_copy();CHECK(copy);bool found=false;
            for(unsigned j=0;copy[j];++j)if(!strncmp(copy[j],"RACE=",5)){
                CHECK(!strcmp(copy[j]+5,"one complete value")||!strcmp(copy[j]+5,"another complete value"));found=true;
            }
            CHECK(found);alix_environment_free(copy);
        }
    }
    CHECK(!held);return NULL;
}
int main(void){
    contracts();CHECK(!native_setenv("RACE","one complete value",1));
    worker_t *workers=calloc(5,sizeof(*workers));pthread_t *threads=calloc(5,sizeof(*threads));CHECK(workers&&threads);
    for(unsigned i=0;i<5;++i){workers[i].writer=!i;CHECK(!pthread_create(&threads[i],NULL,worker,&workers[i]));}
    for(unsigned i=0;i<5;++i)CHECK(!pthread_join(threads[i],NULL));free(threads);free(workers);reset();
    puts("Environment initialization/snapshot contracts PASS");return 0;
}
'''
    compile_and_run("spawn-environment",code)
    print("Environment contracts PASS: constructor import, duplicates/empty/UTF-8, OOM rollback, owned copies and 4000 concurrent snapshots")
    return 0

if __name__=="__main__":sys.exit(main())
