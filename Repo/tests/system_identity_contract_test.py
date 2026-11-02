#!/usr/bin/env python3
"""Production identity/hostname parser, owned VFS snapshots and credential getters."""
import sys
sys.dont_write_bytecode = True
from audio_stream_contract_test import ROOT, compile_and_run, function_definition

program = r'''
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#define CHECK(c) do {if(!(c)){fprintf(stderr,"identity contract line %d: %s\n",__LINE__,#c);abort();}}while(0)
typedef struct {char sysname[65],nodename[65],release[65],version[65],machine[65];} syscall_utsname_t;
typedef struct {unsigned type;size_t size;unsigned char *data;void *read_cb,*write_cb;pthread_mutex_t lock;} vfs_node_t;
#define VFS_NODE_FILE 1u
static _Thread_local bool data_locked,fail_copy_allocation;
static void vfs_lock_node_data(vfs_node_t *node){CHECK(!data_locked);CHECK(!pthread_mutex_lock(&node->lock));data_locked=true;}
static void vfs_unlock_node_data(vfs_node_t *node){CHECK(data_locked);data_locked=false;CHECK(!pthread_mutex_unlock(&node->lock));}
static void *copy_malloc(size_t bytes){CHECK(data_locked);return fail_copy_allocation?NULL:malloc(bytes);}
#define malloc copy_malloc
'''
program += function_definition((ROOT/'src/kernel/vfs.c').read_text(), 'int vfs_file_snapshot_owned(')
program += r'''
#undef malloc
static unsigned char note[36]={4,0,0,0,20,0,0,0,3,0,0,0,'G','N','U',0};
#define __kernel_build_id_start note
#define __kernel_build_id_end (note+sizeof(note))
/* Model the native kernel's compile-time architecture after host headers. */
#ifndef __x86_64__
#define __x86_64__ 1
#endif
static vfs_node_t hostname;
static atomic_uint references=1;
static int open_error;
static int vfs_open_data_flags_owned(vfs_node_t *cwd,const char *path,bool create,bool truncate,bool exclusive,uint32_t uid,uint32_t gid,vfs_node_t **out){
    CHECK(cwd && !strcmp(path,"/etc/hostname") && !create && !truncate && !exclusive && uid==37 && gid==41);*out=NULL;
    if(open_error)return open_error;atomic_fetch_add(&references,1);*out=&hostname;return 0;
}
static void vfs_node_release_owned(vfs_node_t *node){CHECK(node==&hostname);CHECK(atomic_fetch_sub(&references,1)>1);}
'''
source=(ROOT/'src/kernel/system_identity.c').read_text()
for signature in ('static int identity_build_version(', 'static bool identity_space(',
                  'static int identity_hostname(', 'int system_identity_snapshot('):
    program += function_definition(source, signature) + '\n'
program += r'''
typedef struct {uint32_t uid,gid;pthread_mutex_t context_lock;} process_t;
#define VFS_UID_ROOT 0u
#define VFS_GID_ROOT 0u
static void spinlock_lock(pthread_mutex_t *lock){CHECK(!pthread_mutex_lock(lock));}
static void spinlock_unlock(pthread_mutex_t *lock){CHECK(!pthread_mutex_unlock(lock));}
'''
source=(ROOT/'src/kernel/process/process_resources.c').read_text()
for signature in ('uint32_t process_get_uid(', 'uint32_t process_get_gid(', 'void process_set_identity('):
    program += function_definition(source, signature) + '\n'
program += r'''
static void parsing(void){
    syscall_utsname_t *reply=calloc(1,sizeof(*reply));CHECK(reply);
    for(unsigned i=0;i<20;++i)note[16+i]=(unsigned char)i;
    CHECK(!identity_build_version(reply->version,note,sizeof(note)) && !strcmp(reply->version,"build:000102030405060708090a0b0c0d0e0f10111213"));
    CHECK(identity_build_version(reply->version,note,35)==-EIO);note[0]=3;CHECK(identity_build_version(reply->version,note,36)==-EIO);note[0]=4;
    CHECK(!identity_hostname(reply,(const unsigned char *)" \tzen-alix\n ",12) && !strcmp(reply->nodename,"zen-alix"));
    CHECK(!identity_hostname(reply,(const unsigned char *)"",0) && !strcmp(reply->nodename,"alix"));
    CHECK(identity_hostname(reply,(const unsigned char *)"a\0b",3)==-EINVAL);
    unsigned char *long_name=malloc(66);CHECK(long_name);memset(long_name,'x',66);
    CHECK(!identity_hostname(reply,long_name,64) && strlen(reply->nodename)==64);
    CHECK(identity_hostname(reply,long_name,65)==-ENAMETOOLONG);free(long_name);
    free(reply);
}
static void snapshot(void){
    syscall_utsname_t *reply=calloc(1,sizeof(*reply));CHECK(reply);
    hostname.type=VFS_NODE_FILE;hostname.size=13;hostname.data=calloc(1,4097);CHECK(hostname.data);memcpy(hostname.data,"native-host-A",13);
    CHECK(!pthread_mutex_init(&hostname.lock,NULL));
    CHECK(!system_identity_snapshot(&hostname,37,41,reply) && !strcmp(reply->sysname,"Alix") && !strcmp(reply->machine,"x86_64") && !strcmp(reply->nodename,"native-host-A"));
    CHECK(atomic_load(&references)==1);
    unsigned char *copy=NULL;size_t size=0;
    CHECK(!vfs_file_snapshot_owned(&hostname,4096,&copy,&size) && size==13 && !memcmp(copy,"native-host-A\0",14));
    hostname.data[0]='N';CHECK(copy[0]=='n');free(copy);hostname.data[0]='n';
    fail_copy_allocation=true;CHECK(system_identity_snapshot(&hostname,37,41,reply)==-ENOMEM && atomic_load(&references)==1);fail_copy_allocation=false;
    hostname.size=4097;CHECK(system_identity_snapshot(&hostname,37,41,reply)==-EFBIG && atomic_load(&references)==1);hostname.size=13;
    hostname.read_cb=(void *)1;CHECK(system_identity_snapshot(&hostname,37,41,reply)==-ENOTSUP && atomic_load(&references)==1);hostname.read_cb=NULL;
    open_error=-ENOENT;CHECK(!system_identity_snapshot(&hostname,37,41,reply) && !strcmp(reply->nodename,"alix"));
    open_error=-EIO;CHECK(system_identity_snapshot(&hostname,37,41,reply)==-EIO && atomic_load(&references)==1);open_error=0;
    free(reply);
}
static void *writer(void *unused){(void)unused;for(unsigned i=0;i<4000;++i){vfs_lock_node_data(&hostname);memset(hostname.data,i%2?'A':'B',64);hostname.size=64;vfs_unlock_node_data(&hostname);}return NULL;}
static void *reader(void *unused){(void)unused;for(unsigned i=0;i<4000;++i){unsigned char *copy=NULL;size_t size=0;CHECK(!vfs_file_snapshot_owned(&hostname,4096,&copy,&size) && size==64 && !copy[64]);CHECK(copy[0]=='A' || copy[0]=='B');for(unsigned n=1;n<64;++n)CHECK(copy[n]==copy[0]);free(copy);}return NULL;}
int main(void){
    parsing();snapshot();memset(hostname.data,'A',64);hostname.size=64;
    pthread_t threads[8];CHECK(!pthread_create(&threads[0],NULL,writer,NULL));for(unsigned i=1;i<8;++i)CHECK(!pthread_create(&threads[i],NULL,reader,NULL));for(unsigned i=0;i<8;++i)CHECK(!pthread_join(threads[i],NULL));
    process_t *process=calloc(1,sizeof(*process));CHECK(process);CHECK(!pthread_mutex_init(&process->context_lock,NULL));
    process_set_identity(process,0x87654321u,0xfedcba98u);CHECK(process_get_uid(process)==0x87654321u && process_get_gid(process)==0xfedcba98u);
    CHECK(!pthread_mutex_destroy(&process->context_lock));free(process);
    CHECK(!pthread_mutex_destroy(&hostname.lock));free(hostname.data);CHECK(atomic_load(&references)==1 && !data_locked);
    puts("SYSTEM_IDENTITY_CONTRACT: PASS build_note=1 hostname=1 bounds=1 callbacks=1 oom=1 node_ownership=1 credentials=1 snapshots=28000");return 0;
}
'''
compile_and_run('system-identity',program)
print('Production system identity contracts: PASS note parsing, hostname bounds, owned snapshots, credentials and 28000 concurrent snapshots')
