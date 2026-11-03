#!/usr/bin/env python3
"""Production account-cache ownership, growth and real pthread TSD cleanup."""
import sys
sys.dont_write_bytecode = True
from audio_stream_contract_test import ROOT, compile_and_run

source = (ROOT / "user/lib/pwd.c").read_text()
start = source.index("typedef struct\n{\n    struct passwd entry;")
code = r'''
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pwd.h>
#include <pthread.h>
#define CHECK(c) do {if(!(c)){fprintf(stderr,"cached pwd line %d: %s\n",__LINE__,#c);abort();}}while(0)
#define PWD_DATABASE_LIMIT (64u*1024u)
static unsigned live;
static _Thread_local bool fail_next;
static bool large_record;
static void *tracked_malloc(size_t size){if(fail_next){fail_next=false;return NULL;}void*p=malloc(size);if(p)__atomic_add_fetch(&live,1,__ATOMIC_RELAXED);return p;}
static void *tracked_calloc(size_t n,size_t size){if(fail_next){fail_next=false;return NULL;}void*p=calloc(n,size);if(p)__atomic_add_fetch(&live,1,__ATOMIC_RELAXED);return p;}
static void *tracked_realloc(void *old,size_t size){if(fail_next){fail_next=false;return NULL;}void*p=realloc(old,size);if(p&&!old)__atomic_add_fetch(&live,1,__ATOMIC_RELAXED);return p;}
static void tracked_free(void*p){if(p){CHECK(__atomic_fetch_sub(&live,1,__ATOMIC_RELAXED));free(p);}}
static char *tracked_strdup(const char*s){size_t n=strlen(s)+1;char*p=tracked_malloc(n);if(p)memcpy(p,s,n);return p;}
static int model_lookup(bool matches,struct passwd*entry,char*buffer,size_t size,struct passwd**result){
    *result=NULL;if(!matches)return 0;if(size<(large_record?8192u:64u))return ERANGE;
    memcpy(buffer,"native\0/home/native\0",20);entry->pw_name=buffer;entry->pw_dir=buffer+7;entry->pw_uid=123;entry->pw_gid=456;
    *result=entry;return 0;
}
static int model_getpwuid_r(uid_t uid,struct passwd*entry,char*buffer,size_t size,struct passwd**result){return model_lookup(uid==123,entry,buffer,size,result);}
static int model_getpwnam_r(const char*name,struct passwd*entry,char*buffer,size_t size,struct passwd**result){return model_lookup(!strcmp(name,"native"),entry,buffer,size,result);}
#define malloc tracked_malloc
#define calloc tracked_calloc
#define realloc tracked_realloc
#define free tracked_free
#define strdup tracked_strdup
#define getpwuid_r model_getpwuid_r
#define getpwnam_r model_getpwnam_r
#define getpwuid native_getpwuid
#define getpwnam native_getpwnam
'''
code += source[start:]
code += r'''
static void *worker(void*unused){
    (void)unused;
    for(unsigned i=0;i<32;++i){errno=EDOM;struct passwd*p=native_getpwuid(123);CHECK(p&&p->pw_uid==123&&errno==EDOM);
        p=native_getpwnam(p->pw_name);CHECK(p&&!strcmp(p->pw_dir,"/home/native")&&errno==EDOM);}
    return NULL;
}
int main(void){
    fail_next=true;CHECK(!native_getpwuid(123)&&errno==ENOMEM&&!live);
    errno=EDOM;struct passwd*p=native_getpwuid(123);CHECK(p&&p->pw_uid==123&&errno==EDOM&&live==2);
    large_record=true;p=native_getpwnam(p->pw_name);CHECK(p&&!strcmp(p->pw_name,"native")&&errno==EDOM);
    CHECK(!native_getpwnam("absent")&&errno==EDOM&&!native_getpwuid(999)&&errno==EDOM);
    CHECK(!native_getpwnam(NULL)&&errno==EINVAL);
    unsigned baseline=live;pthread_t*threads=calloc(8,sizeof(*threads));CHECK(threads);
    for(unsigned i=0;i<8;++i)CHECK(!pthread_create(&threads[i],NULL,worker,NULL));
    for(unsigned i=0;i<8;++i)CHECK(!pthread_join(threads[i],NULL));
    free(threads);CHECK(live==baseline);
    pwd_cached_destroy(pthread_getspecific(pwd_key));CHECK(!pthread_setspecific(pwd_key,NULL)&&!pthread_key_delete(pwd_key)&&!live);
    puts("Cached account contracts PASS");return 0;
}
'''
compile_and_run("cached-pwd", code)
print("Cached account contracts PASS: OOM, aliased name during growth, missing entries, errno and eight-thread destructor cleanup")
