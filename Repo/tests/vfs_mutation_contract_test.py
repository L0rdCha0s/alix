#!/usr/bin/env python3
"""Exercise production rename/removal transactions and retained-node ownership."""
import sys
sys.dont_write_bytecode = True
from audio_stream_contract_test import ROOT, compile_and_run, function_definition

source=(ROOT/'src/kernel/vfs.c').read_text()
code=r'''
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#define CHECK(c) do { if(!(c)){fprintf(stderr,"vfs mutation line %d: %s\n",__LINE__,#c);abort();} }while(0)
#define serial_printf(...) ((void)0)
#define vfs_log(...) ((void)0)
typedef enum { VFS_NODE_DIR,VFS_NODE_FILE,VFS_NODE_BLOCK,VFS_NODE_SYMLINK,VFS_NODE_FIFO,VFS_NODE_CHARACTER } vfs_node_type_t;
typedef unsigned spinlock_t;
typedef struct vfs_node vfs_node_t;
typedef struct {vfs_node_t *mount_point;spinlock_t dirty_lock;bool needs_full_sync;} vfs_mount_t;
struct vfs_node {vfs_node_type_t type;char *name,*data;size_t size,capacity;pthread_mutex_t data_lock;vfs_node_t *parent,*first_child,*next_sibling;vfs_mount_t *mount;bool allow_mutation,disk_name_dirty,data_unloaded;uint64_t dirty_seq,data_seq,disk_data_offset;uint32_t uid,gid,refcount,permissions,character_kind;void *read_cb;ssize_t (*write_cb)(vfs_node_t *,size_t,const void *,size_t,void *);void *callback_context;};
static vfs_node_t *root;
static void vfs_lock_node_data(vfs_node_t *n);
static void vfs_unlock_node_data(vfs_node_t *n);
static pthread_mutex_t tree_mutex=PTHREAD_MUTEX_INITIALIZER;
static _Thread_local bool tree_owned;
static void vfs_tree_lock_acquire(void){CHECK(!tree_owned);CHECK(!pthread_mutex_lock(&tree_mutex));tree_owned=true;}
static void vfs_tree_lock_release(void){CHECK(tree_owned);tree_owned=false;CHECK(!pthread_mutex_unlock(&tree_mutex));}
static bool vfs_node_allows_mutation(const vfs_node_t *n){return n->allow_mutation;}
static void vfs_inherit_mutability(vfs_node_t *p,vfs_node_t *n){n->allow_mutation=p->allow_mutation;}
static void vfs_inherit_ownership(vfs_node_t *p,vfs_node_t *n){n->uid=p->uid;n->gid=p->gid;}
static void vfs_mark_meta_dirty(vfs_node_t *n){CHECK(tree_owned && n);}
static void vfs_node_release(vfs_node_t *n){CHECK(n->refcount);if(--n->refcount)return;CHECK(!n->first_child);CHECK(!pthread_mutex_destroy(&n->data_lock));free(n->name);free(n->data);free(n);}
'''
for signature in ['static void vfs_attach_child(', 'static void vfs_detach_child(', 'static vfs_node_t *vfs_find_child(']:
    code+=function_definition(source,signature)+'\n'
code+=r'''
static vfs_node_t *resolve(vfs_node_t *cwd,char *path){
    vfs_node_t *n=*path=='/'?root:cwd;char *save=NULL;
    for(char *part=strtok_r(path,"/",&save);part;part=strtok_r(NULL,"/",&save)){
        if(!strcmp(part,"."))continue;
        if(!strcmp(part,"..")){if(n->parent)n=n->parent;continue;}
        n=vfs_find_child(n,part);if(!n)return NULL;
    }return n;
}
static char *vfs_strdup(const char *s){return strdup(s);}
static bool is_dot(const char *s){return !strcmp(s,".");}
static bool is_dot_dot(const char *s){return !strcmp(s,"..");}
static vfs_node_t *vfs_readlink_resolve_locked(vfs_node_t *cwd,const char *path,bool follow,int *error){
    (void)follow;CHECK(tree_owned);char *copy=strdup(path);CHECK(copy);vfs_node_t *n=resolve(cwd,copy);free(copy);*error=n?0:-ENOENT;return n;
}
static bool fail_node_allocate;
static vfs_node_t *vfs_alloc_node(vfs_node_type_t type){
    CHECK(tree_owned);if(fail_node_allocate)return NULL;
    vfs_node_t *n=calloc(1,sizeof(*n));CHECK(n);n->type=type;n->refcount=1;n->allow_mutation=true;
    CHECK(!pthread_mutex_init(&n->data_lock,NULL));return n;
}
'''
for signature in ['static bool split_parent_and_name_checked(', 'static bool split_parent_and_name(',
                  'static int vfs_node_access_locked(', 'static int vfs_mkdir_internal(',
                  'int vfs_mkdir_exclusive(', 'int vfs_mkdir_mode_exclusive(',
                  'static int vfs_remove_path_mode(', 'int vfs_remove_path(', 'int vfs_remove_directory_path(', 'int vfs_rename_path(']:
    code+=function_definition(source,signature)+'\n'
code+=r'''
static void vfs_lock_node_data(vfs_node_t *n){CHECK(!pthread_mutex_lock(&n->data_lock));}
static void vfs_unlock_node_data(vfs_node_t *n){CHECK(!pthread_mutex_unlock(&n->data_lock));}
static bool vfs_backpressure_wait(vfs_mount_t *m,size_t count){(void)m;(void)count;return true;}
static int vfs_prepare_data(vfs_node_t *n){CHECK(!n->data_unloaded);return 0;}
#define VFS_CHARACTER_ENTROPY 1u
static vfs_node_type_t vfs_node_type(const vfs_node_t *n){return n->type;}
static void vfs_note_file_dirty(vfs_node_t *n,size_t offset,size_t count,bool changed){(void)n;(void)offset;(void)count;(void)changed;}
/* These rename/resize fixtures have no installed mappings. The page-cache
 * boundary is exercised with production code by filesystem_writeback_test. */
static bool vfs_mapping_busy_locked(vfs_node_t *n){(void)n;return false;}
static void vfs_mapping_push_locked(vfs_node_t *n,size_t offset,size_t count){(void)n;(void)offset;(void)count;}
static bool fail_capacity;
static bool ensure_capacity_locked(vfs_node_t *n,size_t needed){
    if(fail_capacity)return false;
    if(needed>=SIZE_MAX)return false;
    if(n->capacity>needed)return true;
    size_t capacity=needed+1024;char *data=realloc(n->data,capacity);if(!data)return false;
    n->data=data;n->capacity=capacity;return true;
}
static void ensure_terminator_locked(vfs_node_t *n){CHECK(ensure_capacity_locked(n,n->size));n->data[n->size]=0;}
#define VFS_PATH_MAX 4096u
'''
for signature in ['static bool vfs_truncate_data_locked(', 'int vfs_resize_data(', 'static ssize_t vfs_write_at_internal(', 'ssize_t vfs_write_append(', 'ssize_t vfs_write_data_at(']:
    code+=function_definition(source,signature)+'\n'
code+=r'''
typedef struct {uint32_t flags;} fd_description_t;
#define FD_STATUS_APPEND (1u << 16)
#define FD_STATUS_SYNC (1u << 19)
static bool vfs_flush_node(vfs_node_t *n){(void)n;CHECK(false);return false;}
static uint32_t fd_description_status_flags(fd_description_t *d){return d?d->flags:0;}
typedef struct {vfs_node_t *node;size_t offset;bool writable;fd_description_t *description;pthread_mutex_t gate;} io_vfs_file_t;
static void io_vfs_offset_lock(io_vfs_file_t *f){CHECK(!pthread_mutex_lock(&f->gate));}
static void io_vfs_offset_unlock(io_vfs_file_t *f){CHECK(!pthread_mutex_unlock(&f->gate));}
'''
code+=function_definition((ROOT/'src/kernel/io/vfs.c').read_text(),'static ssize_t io_vfs_file_write(')+'\n'
code+=r'''
static vfs_node_t *make_node(vfs_node_t *parent,const char *name,vfs_node_type_t type){
    vfs_node_t *n=calloc(1,sizeof(*n));CHECK(n);n->name=strdup(name);CHECK(n->name);n->type=type;n->refcount=1;n->allow_mutation=true;CHECK(!pthread_mutex_init(&n->data_lock,NULL));
    if(parent)vfs_attach_child(parent,n);return n;
}
static void free_tree(vfs_node_t *n){while(n->first_child){vfs_node_t *c=n->first_child;vfs_detach_child(c);free_tree(c);}vfs_node_release(n);}
static void retained_files(void){
    vfs_tree_lock_acquire();vfs_node_t *old=make_node(root,"old",VFS_NODE_FILE),*target=make_node(root,"target",VFS_NODE_FILE);
    ++old->refcount;++target->refcount;old->uid=37;old->gid=41;old->data=strdup("old bytes");target->data=strdup("target bytes");vfs_tree_lock_release();
    CHECK(!vfs_rename_path(root,"old","target"));CHECK(old->uid==37 && old->gid==41 && old->parent==root);
    CHECK(!target->parent && target->refcount==1 && !strcmp(target->data,"target bytes"));vfs_node_release(target);
    CHECK(!vfs_remove_path(root,"target",false));CHECK(!old->parent && old->refcount==1 && !strcmp(old->data,"old bytes"));vfs_node_release(old);
}
static void error_atomicity(void){
    vfs_tree_lock_acquire();vfs_node_t *a=make_node(root,"a",VFS_NODE_DIR),*b=make_node(root,"b",VFS_NODE_DIR);
    vfs_node_t *child=make_node(a,"child",VFS_NODE_FILE),*mount=make_node(root,"mount",VFS_NODE_DIR);
    vfs_mount_t mounted={.mount_point=mount};mount->mount=&mounted;vfs_tree_lock_release();
    CHECK(vfs_remove_path(root,"a",true)==-ENOTEMPTY && child->parent==a);
    CHECK(vfs_remove_path(root,"a",false)==-EISDIR);
    CHECK(vfs_remove_directory_path(root,"a/child")==-ENOTDIR && child->parent==a);
    CHECK(vfs_remove_directory_path(root,"a")==-ENOTEMPTY && child->parent==a);
    CHECK(vfs_remove_directory_path(root,"/")==-EBUSY);
    CHECK(vfs_remove_directory_path(root,"a/.")==-EINVAL);
    CHECK(vfs_remove_directory_path(root,"a/..")==-ENOTEMPTY);
    CHECK(vfs_rename_path(root,"a","a/sub")==-EINVAL && a->parent==root);
    CHECK(vfs_rename_path(root,"a/child","b")==-EISDIR && child->parent==a);
    CHECK(vfs_rename_path(root,"a","a")==0);
    CHECK(vfs_remove_path(root,"mount",true)==-EBUSY);
    CHECK(vfs_rename_path(root,"mount","other")==-EBUSY);
    b->allow_mutation=false;CHECK(vfs_rename_path(root,"a/child","b/new")==-EROFS && child->parent==a);b->allow_mutation=true;
    vfs_mount_t other={0};b->mount=&other;CHECK(vfs_rename_path(root,"a/child","b/new")==-EXDEV && child->parent==a);b->mount=NULL;
    CHECK(!vfs_remove_path(root,"a/child",false));CHECK(!vfs_remove_path(root,"a",true));CHECK(!vfs_remove_path(root,"b",true));
    mount->mount=NULL;CHECK(!vfs_remove_path(root,"mount",true));
    CHECK(vfs_rename_path(root,"absent","new")==-ENOENT);
}
static void *writer(void *unused){(void)unused;for(unsigned i=0;i<4000;i++)CHECK(!vfs_rename_path(root,i%2?"right":"left",i%2?"left":"right"));return NULL;}
static void *reader(void *unused){(void)unused;for(unsigned i=0;i<4000;i++){
    vfs_tree_lock_acquire();vfs_node_t *a=vfs_find_child(root,"left"),*b=vfs_find_child(root,"right");
    CHECK((a!=NULL)!=(b!=NULL));vfs_node_t *n=a?a:b;CHECK(n->uid==37 && n->gid==41 && n->parent==root);vfs_tree_lock_release();
}return NULL;}
typedef struct {io_vfs_file_t file;fd_description_t description;unsigned identity;} append_arg_t;
static void *append_writer(void *opaque){
    append_arg_t *arg=opaque;char record[2]={(char)('0'+arg->identity),'\n'};
    for(unsigned i=0;i<1000;++i)CHECK(io_vfs_file_write(&arg->file,record,2)==2);
    return NULL;
}
static void append_contract(void){
    vfs_tree_lock_acquire();vfs_node_t *n=make_node(root,"append",VFS_NODE_FILE);vfs_tree_lock_release();
    append_arg_t *args=calloc(8,sizeof(*args));CHECK(args);pthread_t threads[8];
    for(unsigned i=0;i<8;++i){args[i]=(append_arg_t){.file={.node=n,.writable=true,.description=&args[i].description},.description={.flags=FD_STATUS_APPEND},.identity=i};CHECK(!pthread_mutex_init(&args[i].file.gate,NULL));CHECK(!pthread_create(&threads[i],NULL,append_writer,&args[i]));}
    for(unsigned i=0;i<8;++i)CHECK(!pthread_join(threads[i],NULL));
    CHECK(n->size==16000);unsigned counts[8]={0};
    for(unsigned i=0;i<n->size;i+=2){CHECK(n->data[i]>='0' && n->data[i]<='7' && n->data[i+1]=='\n');++counts[n->data[i]-'0'];}
    for(unsigned i=0;i<8;++i){CHECK(counts[i]==1000);CHECK(!pthread_mutex_destroy(&args[i].file.gate));}
    free(args);CHECK(!vfs_remove_path(root,"append",false));
}
static void resize_contract(void){
    vfs_tree_lock_acquire();vfs_node_t *n=make_node(root,"resize",VFS_NODE_FILE);vfs_tree_lock_release();
    n->data=strdup("abcdef");n->size=6;n->capacity=7;
    CHECK(!vfs_resize_data(n,3) && n->size==3 && !memcmp(n->data,"abc\0",4));
    CHECK(!vfs_resize_data(n,8192) && n->size==8192 && !memcmp(n->data,"abc",3));
    for(unsigned i=3;i<8192;i++)CHECK(n->data[i]==0);
    fail_capacity=true;CHECK(vfs_resize_data(n,16384)==-ENOMEM && n->size==8192 && !memcmp(n->data,"abc",3));fail_capacity=false;
    CHECK(!vfs_resize_data(n,0) && n->size==0 && !n->data[0]);
    n->allow_mutation=false;CHECK(vfs_resize_data(n,7)==-EROFS && n->size==0);n->allow_mutation=true;
    CHECK(!vfs_remove_path(root,"resize",false));
}
static atomic_uint mkdir_successes;
static void *mkdir_writer(void *unused){
    (void)unused;char *path=malloc(64);CHECK(path);
    for(unsigned i=0;i<128;++i){snprintf(path,64,"mkdir-%u",i);int result=vfs_mkdir_mode_exclusive(root,path,37,41,0750);
        CHECK(result==0 || result==-EEXIST);if(!result)atomic_fetch_add(&mkdir_successes,1);}
    free(path);return NULL;
}
static void mkdir_contract(void){
    CHECK(vfs_mkdir_exclusive(root,"",37,41)==-ENOENT);
    CHECK(vfs_mkdir_exclusive(root,NULL,37,41)==-ENOENT);
    CHECK(vfs_mkdir_exclusive(root,"/",37,41)==-EEXIST);
    CHECK(vfs_mkdir_exclusive(root,".",37,41)==-EEXIST);
    CHECK(vfs_mkdir_exclusive(root,"absent/child",37,41)==-ENOENT);
    fail_node_allocate=true;CHECK(vfs_mkdir_exclusive(root,"no-memory",37,41)==-ENOMEM);fail_node_allocate=false;
    vfs_tree_lock_acquire();CHECK(!vfs_find_child(root,"no-memory"));root->allow_mutation=false;vfs_tree_lock_release();
    CHECK(vfs_mkdir_exclusive(root,"read-only",37,41)==-EROFS);
    vfs_tree_lock_acquire();root->allow_mutation=true;vfs_node_t *file=make_node(root,"file",VFS_NODE_FILE);vfs_tree_lock_release();
    CHECK(vfs_mkdir_exclusive(root,"file",37,41)==-EEXIST && file->parent==root);
    root->permissions=0500;
    CHECK(vfs_mkdir_mode_exclusive(root,"denied",37,41,0700)==-EACCES);
    CHECK(!vfs_find_child(root,"denied"));
    root->permissions=0777;
    CHECK(vfs_mkdir_mode_exclusive(root,"special",37,41,04700)==-EOPNOTSUPP);
    pthread_t threads[8];for(unsigned i=0;i<8;++i)CHECK(!pthread_create(&threads[i],NULL,mkdir_writer,NULL));
    for(unsigned i=0;i<8;++i)CHECK(!pthread_join(threads[i],NULL));
    CHECK(atomic_load(&mkdir_successes)==128);char path[64];
    for(unsigned i=0;i<128;++i){snprintf(path,sizeof(path),"mkdir-%u",i);
        vfs_tree_lock_acquire();vfs_node_t *n=vfs_find_child(root,path);CHECK(n && n->type==VFS_NODE_DIR && n->uid==37 && n->gid==41&&n->permissions==0750);vfs_tree_lock_release();
        CHECK(!vfs_remove_directory_path(root,path));}
    CHECK(!vfs_remove_path(root,"file",false));
}
int main(void){
    root=make_node(NULL,"/",VFS_NODE_DIR);retained_files();error_atomicity();append_contract();resize_contract();mkdir_contract();
    vfs_tree_lock_acquire();vfs_node_t *n=make_node(root,"left",VFS_NODE_FILE);n->uid=37;n->gid=41;vfs_tree_lock_release();
    pthread_t threads[8];CHECK(!pthread_create(&threads[0],NULL,writer,NULL));
    for(unsigned i=1;i<8;i++)CHECK(!pthread_create(&threads[i],NULL,reader,NULL));
    for(unsigned i=0;i<8;i++)CHECK(!pthread_join(threads[i],NULL));
    free_tree(root);puts("VFS_MUTATION_TEST: PASS retained=1 replace=1 errors=1 concurrent=32000 mkdir=1024");return 0;
}
'''
compile_and_run('vfs_mutation',code)
print('VFS mutation production contracts: PASS retained files, atomic replacement, errors, 32000 concurrent rename/read operations, 8000 atomic append writes and 1024 exclusive mkdir calls')
