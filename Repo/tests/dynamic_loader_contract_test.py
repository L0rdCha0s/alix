#!/usr/bin/env python3
"""Fault production ELF loading and fuzz its metadata without executing target code."""
import re
import sys
sys.dont_write_bytecode=True
from audio_stream_contract_test import ROOT,compile_and_run,function_definition

source=(ROOT/'user/lib/dlfcn.c').read_text()
source=re.sub(r'^#include[^\n]*\n','',source,flags=re.M)
for signature in ('static bool dl_startup_range(', 'static void dl_main_startup('):
    source=source.replace(function_definition(source,signature),'',1)
source=re.sub(r'__attribute__\(\(section\("\.preinit_array\.alix_runtime"\),\s*used\)\)\s*static void \(\*const dl_startup_entry\)\(void\)\s*=\s*dl_main_startup;','',source)
assert 'dl_startup_entry' not in source
body=function_definition(source,'static bool dl_main_initialize(')
source=source.replace(body,'static bool dl_main_initialize(void) { return dl_modules != NULL; }',1)
body=function_definition(source,'static bool dl_call(')
source=source.replace(body,'static bool dl_call(uintptr_t address) { if (!dl_callable(address)) return false; if (address && address != UINTPTR_MAX) ++callbacks; return true; }',1)
source=source.replace('static bool dl_startup_done;','')
source=source.replace('__asm__ volatile("movq %%fs:8,%0" : "=r"(base));','base=(uintptr_t)model_static_tls;')
source=source.replace('__asm__ volatile("movq %%fs:0,%0\\n\\tmovq %%fs:8,%1" : "=r"(tp), "=r"(block));', 'tp=(uintptr_t)model_static_tls; block=(uintptr_t)model_static_tls;')
assert '__asm__' not in source
for name in ('dlopen','dlclose','dlsym','dlvsym','dlerror','dladdr','__tls_get_addr','dl_iterate_phdr'):
    source=re.sub(r'\b'+name+r'\b','model_'+name,source)

code=r'''
#define _XOPEN_SOURCE 700
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdatomic.h>
#include <sched.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#define CHECK(c) do {if(!(c)){fprintf(stderr,"loader contract %d: %s\n",__LINE__,#c);abort();}}while(0)
'''
code+='#include "'+str(ROOT/'include/dlfcn.h')+'"\n#include "'+str(ROOT/'user/lib/dynamic_elf.h')+'"\n'
code+='#define TTF_HOST_BUILD 1\n#include "'+str(ROOT/'include/link.h')+'"\n'
code+=r'''
typedef struct {atomic_uint state;} alix_mutex_t;
static void alix_mutex_lock(alix_mutex_t *m){while(atomic_exchange_explicit(&m->state,1,memory_order_acquire))sched_yield();}
static void alix_mutex_unlock(alix_mutex_t *m){atomic_store_explicit(&m->state,0,memory_order_release);}
static unsigned allocations,calls,fail_at,callbacks;
static unsigned live_files;
static void sys_serial_write(const char *data,size_t bytes){(void)data;(void)bytes;}
static bool injected;
static unsigned char model_static_tls[16384];
static bool step(void){++calls;if(calls==fail_at){injected=true;errno=ENOMEM;return true;}return false;}
static void *owned_malloc(size_t n){if(step())return NULL;void*p=malloc(n);if(p)++allocations;return p;}
static void *owned_calloc(size_t n,size_t s){if(step())return NULL;void*p=calloc(n,s);if(p)++allocations;return p;}
static void *owned_realloc(void*p,size_t n){if(step())return NULL;bool existed=p!=NULL;void*q=realloc(p,n);if(q&&!existed)++allocations;return q;}
static void owned_free(void*p){if(p){CHECK(allocations);--allocations;free(p);}}
static char *owned_strdup(const char*s){size_t n=strlen(s)+1;char*p=owned_malloc(n);if(p)memcpy(p,s,n);return p;}
static char *owned_realpath(const char *path,char *out){CHECK(!out);char *resolved=realpath(path,NULL);if(!resolved)return NULL;char *copy=owned_strdup(resolved);free(resolved);return copy;}
static int checked_open(const char *path,int flags){CHECK(flags&O_CLOEXEC);if(step())return -1;int fd=open(path,flags);if(fd>=0)++live_files;return fd;}
static int checked_fstat(int fd,struct stat *value){if(step())return -1;return fstat(fd,value);}
static ssize_t checked_pread(int fd,void *data,size_t bytes,off_t offset){if(step())return -1;return pread(fd,data,bytes,offset);}
static int checked_close(int fd){CHECK(live_files);--live_files;return close(fd);}
typedef struct {void *data;size_t bytes;} mapping;
static mapping mappings[1024];static unsigned live_maps;static bool fail_unmap;
#define MAP_FAILED ((void*)-1)
#define MAP_SHARED 1
#define MAP_PRIVATE 2
#define MAP_FIXED 16
#define MAP_ANONYMOUS 32
#define PROT_NONE 0
#define PROT_READ 1
#define PROT_WRITE 2
#define PROT_EXEC 4
static void *model_mmap(void *where,size_t n,int prot,int flags,int fd,int64_t offset){
    if(where){
        CHECK((flags== (MAP_SHARED|MAP_FIXED) || flags==(MAP_PRIVATE|MAP_FIXED)) && fd>=0 && offset>=0);
        bool owned=false;
        for(unsigned i=0;i<1024;++i)if(mappings[i].data && (uintptr_t)where>=(uintptr_t)mappings[i].data &&
            (uintptr_t)where-(uintptr_t)mappings[i].data<=mappings[i].bytes && n<=mappings[i].bytes-((uintptr_t)where-(uintptr_t)mappings[i].data))owned=true;
        CHECK(owned); if(step())return MAP_FAILED;
        size_t done=0;
        while(done<n){ssize_t got=checked_pread(fd,(char*)where+done,n-done,offset+done);if(got<0)return MAP_FAILED;if(!got)break;done+=(size_t)got;}
        memset((char*)where+done,0,n-done);return where;
    }
    CHECK(!where&&prot==0&&flags==(MAP_PRIVATE|MAP_ANONYMOUS)&&fd==-1&&!offset);
    void *data=owned_calloc(1,n);if(!data)return MAP_FAILED;
    for(unsigned i=0;i<1024;++i)if(!mappings[i].data){mappings[i]=(mapping){data,n};++live_maps;return data;}abort();
}
static int model_mprotect(void *where,size_t n,int prot){
    CHECK(((uintptr_t)where%4096)==0&&n%4096==0&&!(prot&PROT_WRITE&&prot&PROT_EXEC));
    for(unsigned i=0;i<1024;++i)if(mappings[i].data && (uintptr_t)where>=(uintptr_t)mappings[i].data &&
        (uintptr_t)where-(uintptr_t)mappings[i].data<=mappings[i].bytes && n<=mappings[i].bytes-((uintptr_t)where-(uintptr_t)mappings[i].data))return step()?-1:0;
    abort();
}
static int model_munmap(void *where,size_t n){if(fail_unmap){fail_unmap=false;errno=ENOMEM;return -1;}for(unsigned i=0;i<1024;++i)if(mappings[i].data==where){CHECK(mappings[i].bytes==n);owned_free(where);mappings[i].data=NULL;--live_maps;return 0;}abort();}
static char **alix_environment_copy(void){return owned_calloc(1,sizeof(char*));}
static void alix_environment_free(char **environment){owned_free(environment);}
#define malloc owned_malloc
#define calloc owned_calloc
#define realloc owned_realloc
#define free owned_free
#define realpath owned_realpath
#define mmap model_mmap
#define mprotect model_mprotect
#define munmap model_munmap
#define open checked_open
#define fstat checked_fstat
#define pread checked_pread
#define close checked_close
'''
code+=source
code+=r'''
static dl_sym exports[16];static char export_names[512];
static void initialize_model(void){
    static const char *names[]={"malloc","free","strcpy","strcmp","loader_event","__cxa_finalize","__tls_get_addr"};
    size_t used=1;for(unsigned i=0;i<7;++i){strcpy(export_names+used,names[i]);exports[i+1]=(dl_sym){.name=(uint32_t)used,.info=0x12,.section=0xfff1,.value=0x1000+i*16};used+=strlen(names[i])+1;}
    dl_main=(dl_module){.main=true,.global=true,.nodelete=true,.initialized=true,.relocated=true,.id=1,.symbols=exports,.strings=export_names,.string_bytes=used,.symbol_count=8,.path="<model>"};dl_modules=&dl_main;
}
static unsigned open_and_close(const char *path,unsigned failure){
    calls=0;fail_at=failure;injected=false;callbacks=0;void *handle=model_dlopen(path,RTLD_NOW);unsigned observed=calls;fail_at=0;
    if(failure){CHECK(injected&&!handle&&model_dlerror()&&callbacks==0);}else {CHECK(handle&&callbacks>=2);CHECK(model_dlsym(handle,"loader_plugin_value"));CHECK(!model_dlclose(handle));}
    CHECK(!live_maps&&!live_files&&!allocations&&dl_modules==&dl_main&&!dl_main.next);return observed;
}
static void metadata_mutations(const char *path){
    dl_module *m=calloc(1,sizeof(*m));CHECK(m);m->path=(char*)path;CHECK(dl_map_file(m));
    unsigned char *image=malloc(m->reservation_bytes);CHECK(image);memcpy(image,(void*)m->reservation,m->reservation_bytes);
    dl_module baseline=*m;uint32_t random=0x12345678;
    for(unsigned iteration=0;iteration<3000;++iteration){
        memcpy((void*)m->reservation,image,m->reservation_bytes);*m=baseline;
        random=random*1664525u+1013904223u;size_t entry=random%m->dynamic_count;random=random*1664525u+1013904223u;
        ((unsigned char*)&m->dynamic[entry])[random%16]^=(unsigned char)(1u<<((random>>8)%8));dl_pending=false;
        if(dl_meta(m))(void)dl_own_symbol_version(m,"loader_plugin_value",NULL);
    }
    memcpy((void*)baseline.reservation,image,baseline.reservation_bytes);*m=baseline;dl_pending=false;CHECK(dl_meta(m));
    for(size_t i=0;i<m->dynamic_count;++i)if(m->dynamic[i].tag==DL_SYMTAB){m->dynamic[i].value++;dl_pending=false;CHECK(!dl_meta(m));break;}
    free(image);model_munmap((void*)baseline.reservation,baseline.reservation_bytes);free(baseline.segments);free((void*)baseline.program_headers);free(m);CHECK(!allocations&&!live_maps);
}
int main(void){initialize_model();
'''
fixture=ROOT/'build/ports/zen/dynamic-loader/libalix-loader-plugin.so'
code+='const char *fixture="'+str(fixture)+'";\n'
code+=r'''
    unsigned points=open_and_close(fixture,0);for(unsigned point=1;point<=points;++point)open_and_close(fixture,point);
    metadata_mutations(fixture);CHECK(!allocations&&!live_maps);
    void *handle=model_dlopen(fixture,RTLD_NOW);CHECK(handle);fail_unmap=true;CHECK(!model_dlclose(handle)&&live_maps==1&&dl_main.next&&dl_main.next->retiring);
    unsigned completed=callbacks;dl_collect();CHECK(callbacks==completed&&!allocations&&!live_maps&&!dl_main.next);
    printf("DYNAMIC_LOADER_CONTRACT: PASS fault_points=%u metadata_mutations=3000 rollback=1 dependencies=1 no_leaks=1\n",points);return 0;
}
'''
compile_and_run('dynamic-loader-contract',code)
print('Production dynamic loader: PASS every allocation/VM preparation fault, complete dependency rollback, 3000 metadata mutations and cleanup')
