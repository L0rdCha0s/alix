#!/usr/bin/env python3
"""Exercise the production named-memory registry with ownership and OOM."""
from audio_stream_contract_test import ROOT, compile_and_run, function_definition

source = (ROOT / "src/kernel/vfs.c").read_text()
program = r'''
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef struct vfs_node {
    char *name;
    uint32_t uid, gid, permissions;
    size_t refcount, size;
    pthread_mutex_t lock;
} vfs_node_t;
enum { VFS_NODE_FILE=1 };
static pthread_mutex_t tree=PTHREAD_MUTEX_INITIALIZER;
static unsigned allocations, calls, fail_at;
static void *tracked_malloc(size_t size) {
    if(fail_at && ++calls==fail_at)return NULL;
    void *p=malloc(size);if(p)__atomic_add_fetch(&allocations,1,__ATOMIC_RELAXED);return p;
}
static void *tracked_calloc(size_t n,size_t size) {
    void *p=tracked_malloc(n*size);if(p)memset(p,0,n*size);return p;
}
static void tracked_free(void *p) {
    if(p){assert(__atomic_load_n(&allocations,__ATOMIC_RELAXED));__atomic_sub_fetch(&allocations,1,__ATOMIC_RELAXED);free(p);}
}
static void vfs_tree_lock_acquire(void){assert(!pthread_mutex_lock(&tree));}
static void vfs_tree_lock_release(void){assert(!pthread_mutex_unlock(&tree));}
static void vfs_lock_node_data(vfs_node_t *n){assert(!pthread_mutex_lock(&n->lock));}
static void vfs_unlock_node_data(vfs_node_t *n){assert(!pthread_mutex_unlock(&n->lock));}
static vfs_node_t *vfs_alloc_node(int type) {
    assert(type==VFS_NODE_FILE);vfs_node_t*n=tracked_calloc(1,sizeof(*n));
    if(n){n->refcount=1;assert(!pthread_mutex_init(&n->lock,NULL));}return n;
}
static void vfs_node_release(vfs_node_t*n) {
    vfs_lock_node_data(n);assert(n->refcount);bool last=!--n->refcount;vfs_unlock_node_data(n);
    if(last){assert(!pthread_mutex_destroy(&n->lock));tracked_free(n->name);tracked_free(n);}
}
static void vfs_node_release_owned(vfs_node_t*n){vfs_tree_lock_acquire();vfs_node_release(n);vfs_tree_lock_release();}
static int vfs_resize_data(vfs_node_t*n,uint64_t size){vfs_lock_node_data(n);n->size=size;vfs_unlock_node_data(n);return 0;}
#define malloc tracked_malloc
#define calloc tracked_calloc
#define free tracked_free
'''
program += function_definition(source, "static int vfs_node_access_locked(") + "\n"
start = source.index("typedef struct vfs_shm_entry\n")
end = source.index("static vfs_node_t *vfs_open_file_internal(", start)
program += source[start:end]
program += r'''
typedef struct{unsigned won;vfs_node_t*node;}job_t;
static void *contend(void*pointer){
    job_t*j=pointer;int r=vfs_shm_open_owned("/race",true,false,true,42,77,0600,6,&j->node);
    assert(!r || r==-EEXIST);j->won=!r;return NULL;
}
int main(void){
    vfs_node_t *node=NULL,*other=NULL;
    for(unsigned failure=1;failure<=3;++failure){
        fail_at=failure;calls=0;
        assert(vfs_shm_open_owned("/oom",true,false,true,42,77,0600,6,&node)==-ENOMEM);
        assert(!node&&!g_vfs_shm_count&&!allocations);
    }
    fail_at=0;
    assert(vfs_shm_open_owned("missing-slash",true,false,true,42,77,0600,6,&node)==-EINVAL);
    assert(vfs_shm_open_owned("/nested/name",true,false,true,42,77,0600,6,&node)==-EINVAL);
    assert(vfs_shm_open_owned("/private",true,false,true,42,77,0400,6,&node)==0);
    assert(node->uid==42&&node->gid==77&&node->permissions==0400&&node->refcount==2);
    assert(vfs_shm_open_owned("/private",false,false,false,42,77,0,6,&other)==-EACCES&&!other);
    assert(vfs_shm_open_owned("/private",false,false,false,43,78,0,4,&other)==-EACCES&&!other);
    assert(vfs_shm_open_owned("/private",false,false,false,0,0,0,6,&other)==0&&other==node);
    vfs_node_release_owned(other);
    assert(vfs_shm_unlink_owned("/private",43)==-EACCES);
    assert(vfs_shm_unlink_owned("/private",42)==0&&node->refcount==1);
    assert(vfs_shm_open_owned("/private",false,false,false,42,77,0,4,&other)==-ENOENT);
    assert(vfs_shm_open_owned("/private",true,false,true,42,77,0000,6,&other)==0&&other!=node);
    assert(vfs_shm_unlink_owned("/private",0)==0);vfs_node_release_owned(other);vfs_node_release_owned(node);
    assert(!g_vfs_shm_count&&!allocations);
    job_t*jobs=tracked_calloc(8,sizeof(*jobs));pthread_t*threads=tracked_calloc(8,sizeof(*threads));assert(jobs&&threads);
    for(unsigned i=0;i<8;++i)assert(!pthread_create(&threads[i],NULL,contend,&jobs[i]));
    unsigned wins=0;
    for(unsigned i=0;i<8;++i){assert(!pthread_join(threads[i],NULL));wins+=jobs[i].won;if(jobs[i].node)vfs_node_release_owned(jobs[i].node);}
    assert(wins==1&&g_vfs_shm_count==1&&vfs_shm_unlink_owned("/race",42)==0);
    tracked_free(threads);tracked_free(jobs);assert(!allocations&&!g_vfs_shm_count);
    puts("SHM_REGISTRY: PASS ownership=1 oom=3 exclusive_threads=8 unlink_refs=1 replacement=1 no_leaks=1");
    return 0;
}
'''
compile_and_run("shared-memory-registry", program)
print("Production shared-memory registry: PASS ownership, OOM, concurrent create and retained unlink")
