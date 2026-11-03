#!/usr/bin/env python3
"""Production ownership policy and coherent metadata snapshots under contention."""
import os
from audio_stream_contract_test import ROOT, compile_and_run, function_definition

os.environ["HOST_CC"] = os.environ.get("HOST_CC", "cc") + " -pthread"

def declaration(name):
    source = (ROOT / "include/vfs.h").read_text()
    end = source.index("} " + name + ";") + len("} " + name + ";")
    return source[source.rfind("typedef struct", 0, end):end] + "\n"

code = r'''
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <stdatomic.h>
#include <pthread.h>
#define CHECK(c) do {if(!(c)){fprintf(stderr,"identity contract line %d: %s\n",__LINE__,#c);abort();}} while(0)
#define VFS_UID_ROOT 0u
typedef enum {VFS_NODE_DIR,VFS_NODE_FILE,VFS_NODE_BLOCK,VFS_NODE_SYMLINK} vfs_node_type_t;
typedef struct vfs_node vfs_node_t;
typedef struct {vfs_node_t *mount_point;bool *backend;bool supports_times;} vfs_mount_t;
struct vfs_node {
    vfs_node_type_t type;
    vfs_node_t *parent,*first_child,*next_sibling;
    vfs_mount_t *mount;
    bool allow_mutation,dirty,disk_meta_dirty;
    void *read_cb,*write_cb;
    uint32_t uid,gid,permissions;
    uint64_t atime,mtime,ctime,object_id,dirty_seq;
    size_t size;
    pthread_mutex_t data_lock;
};
static pthread_mutex_t tree_lock=PTHREAD_MUTEX_INITIALIZER;
static _Thread_local unsigned tree_owned,data_owned;
static vfs_node_t *root;
static uint64_t g_vfs_next_object_id=1;
static atomic_uint dirty_marks;
static void vfs_tree_lock_acquire(void){CHECK(!tree_owned&&!data_owned);CHECK(!pthread_mutex_lock(&tree_lock));tree_owned=1;}
static void vfs_tree_lock_release(void){CHECK(tree_owned&&!data_owned);tree_owned=0;CHECK(!pthread_mutex_unlock(&tree_lock));}
static void vfs_lock_node_data(vfs_node_t*n){CHECK(tree_owned&&!data_owned);CHECK(!pthread_mutex_lock(&n->data_lock));data_owned=1;}
static void vfs_unlock_node_data(vfs_node_t*n){CHECK(data_owned);data_owned=0;CHECK(!pthread_mutex_unlock(&n->data_lock));}
static bool vfs_node_allows_mutation(vfs_node_t*n){CHECK(tree_owned&&data_owned);return n->allow_mutation;}
static bool alixfs_mount_supports_ownership(bool*backend){CHECK(tree_owned&&data_owned);return backend&&*backend;}
static uint64_t vfs_now_seconds(void){CHECK(tree_owned&&data_owned);return 100;}
static void vfs_mark_mount_dirty(vfs_mount_t*m){(void)m;CHECK(tree_owned&&!data_owned);atomic_fetch_add(&dirty_marks,1);}
'''
code += declaration("vfs_stat_snapshot_t") + declaration("vfs_stat_info_t")
source = (ROOT / "src/kernel/vfs.c").read_text()
for signature in ("static uint64_t vfs_directory_object_id_locked(", "static int vfs_stat_info_locked(",
                  "int vfs_node_stat_info(", "int vfs_chown_owned(", "int vfs_chmod_owned(", "static int vfs_node_access_locked(", "int vfs_set_times_owned("):
    code += function_definition(source, signature)
code += r'''
typedef struct {vfs_node_t*node;unsigned number;vfs_stat_info_t info;} job_t;
static void *worker(void *context){
    job_t*j=context;
    for(unsigned i=0;i<1000;++i){
        if(j->number&1){uint32_t uid=1000+j->number;CHECK(!vfs_chown_owned(j->node,0,0,uid,uid^0x3456));
            CHECK(!vfs_chmod_owned(j->node,0,(i&1)?0640:0600));}
        else {CHECK(!vfs_node_stat_info(j->node,&j->info));CHECK(j->info.gid==(j->info.uid^0x3456));
            CHECK(j->info.inode==1&&j->info.device==1&&j->info.links==1&&(j->info.permissions==0640||j->info.permissions==0600));}
    }
    return NULL;
}
int main(void){
    vfs_node_t*n=calloc(1,sizeof(*n));root=calloc(1,sizeof(*root));CHECK(n&&root);
    CHECK(!pthread_mutex_init(&n->data_lock,NULL));n->parent=root;n->type=VFS_NODE_FILE;n->allow_mutation=true;n->uid=10;n->gid=20;
    CHECK(vfs_chown_owned(n,11,20,UINT32_MAX,UINT32_MAX)==-EPERM&&!n->dirty_seq);
    CHECK(vfs_chown_owned(n,10,30,11,UINT32_MAX)==-EPERM&&!n->dirty_seq);
    CHECK(vfs_chown_owned(n,10,30,UINT32_MAX,31)==-EPERM&&!n->dirty_seq);
    CHECK(!vfs_chown_owned(n,10,30,10,30)&&n->uid==10&&n->gid==30&&n->dirty_seq==1&&n->ctime==100);
    CHECK(!vfs_chown_owned(n,10,30,UINT32_MAX,UINT32_MAX)&&n->uid==10&&n->gid==30);
    CHECK(vfs_chmod_owned(n,11,0600)==-EPERM);
    CHECK(!vfs_chmod_owned(n,10,0100640)&&n->permissions==0640);
    CHECK(vfs_chmod_owned(n,0,04000)==-EOPNOTSUPP&&n->permissions==0640);
    CHECK(vfs_chmod_owned(n,0,0x80000000)==-EINVAL&&n->permissions==0640);
    vfs_tree_lock_acquire();vfs_lock_node_data(n);
    CHECK(!vfs_node_access_locked(n,10,999,6)&&!vfs_node_access_locked(n,20,30,4));
    CHECK(vfs_node_access_locked(n,20,30,2)==-EACCES&&vfs_node_access_locked(n,20,40,4)==-EACCES);
    CHECK(!vfs_node_access_locked(n,0,40,6));vfs_unlock_node_data(n);vfs_tree_lock_release();
    CHECK(vfs_set_times_owned(n,11,30,true,1,2)==-EPERM&&vfs_set_times_owned(n,11,30,false,0,0)==-EACCES);
    CHECK(!vfs_chmod_owned(n,10,0660)&&!vfs_set_times_owned(n,11,30,false,0,0)&&n->atime==100&&n->mtime==100);
    CHECK(!vfs_set_times_owned(n,10,30,true,1,2)&&n->atime==1&&n->mtime==2);
    CHECK(!vfs_chmod_owned(n,10,0640));
    n->allow_mutation=false;CHECK(vfs_chown_owned(n,0,0,1,2)==-EROFS);n->allow_mutation=true;
    n->read_cb=(void*)1;CHECK(vfs_chown_owned(n,0,0,1,2)==-ENOTSUP);n->read_cb=NULL;
    bool ownership=false;vfs_mount_t*mount=calloc(1,sizeof(*mount));CHECK(mount);mount->backend=&ownership;n->mount=mount;
    CHECK(vfs_chown_owned(n,0,0,1,2)==-ENOTSUP);
    CHECK(vfs_set_times_owned(n,0,0,true,1,2)==-ENOTSUP);n->mount=NULL;
    CHECK(!vfs_chown_owned(n,0,0,1000,1000^0x3456));
    uint64_t initial_changes=n->dirty_seq;
    job_t*jobs=calloc(8,sizeof(*jobs));pthread_t*threads=calloc(8,sizeof(*threads));CHECK(jobs&&threads);
    for(unsigned i=0;i<8;++i){jobs[i].node=n;jobs[i].number=i;CHECK(!pthread_create(&threads[i],NULL,worker,&jobs[i]));}
    for(unsigned i=0;i<8;++i)CHECK(!pthread_join(threads[i],NULL));
    CHECK(n->dirty_seq==initial_changes+8000&&atomic_load(&dirty_marks)==initial_changes+8000);
    n->parent=NULL;CHECK(!vfs_node_stat_info(n,&jobs[0].info)&&!jobs[0].info.links&&jobs[0].info.inode==1);
    CHECK(!pthread_mutex_destroy(&n->data_lock));free(threads);free(jobs);free(mount);free(n);free(root);
    puts("FILE_IDENTITY_CONTRACT: PASS snapshots=4000 owner_updates=4000 mode_updates=4000 permission_checks=1 legacy_mount_error=1 no_torn_identity=1 orphan=1");
}
'''
compile_and_run("file-identity", code)
print("Production file identity/ownership contract: PASS")
