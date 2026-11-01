#!/usr/bin/env python3
"""Execute production readlink traversal/snapshot with OOM and replacement races."""
import os
import shlex
import sys

sys.dont_write_bytecode = True
from audio_stream_contract_test import ROOT, compile_and_run, function_definition, uint_macro


def main():
    source = (ROOT / "src/kernel/vfs.c").read_text()
    code = r'''
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <sys/types.h>
#define CHECK(x) do { if(!(x)) { fprintf(stderr,"readlink line %d: %s\n",__LINE__,#x); abort(); } } while(0)
#define VFS_MAX_SYMLINK_DEPTH 16
#define VFS_PATH_MAX 4096u
typedef enum { VFS_NODE_DIR,VFS_NODE_FILE,VFS_NODE_BLOCK,VFS_NODE_SYMLINK } vfs_node_type_t;
typedef struct vfs_node {
    struct vfs_node *parent,*child,*next; char *name,*data; size_t size,capacity;
    vfs_node_type_t type; unsigned data_lock; uint32_t refcount;uint64_t atime,mtime,ctime;
} vfs_node_t;
typedef struct {uint64_t size_bytes;vfs_node_type_t type;uint64_t atime,mtime,ctime;} vfs_stat_snapshot_t;
static vfs_node_t *root;
static pthread_mutex_t tree_mutex=PTHREAD_MUTEX_INITIALIZER;
static _Thread_local bool tree_locked;
static _Thread_local unsigned node_locks,alloc_calls,fail_at;
static uint64_t live;
static vfs_node_t *owned_at_unlock;
static void *tracked_malloc(size_t n) {
    if(++alloc_calls==fail_at) return NULL;
    void *p=malloc(n); if(p) __atomic_fetch_add(&live,1,__ATOMIC_RELAXED); return p;
}
static void *tracked_calloc(size_t n,size_t s) { void *p=tracked_malloc(n*s); if(p) memset(p,0,n*s); return p; }
static void tracked_free(void *p) { if(p) { CHECK(__atomic_fetch_sub(&live,1,__ATOMIC_RELAXED)); free(p); } }
#define malloc tracked_malloc
#define calloc tracked_calloc
#define free tracked_free
static void vfs_tree_lock_acquire(void) { CHECK(!tree_locked); CHECK(!pthread_mutex_lock(&tree_mutex)); tree_locked=true; }
static void vfs_tree_lock_release(void) { CHECK(tree_locked && !node_locks); if(owned_at_unlock) CHECK(owned_at_unlock->refcount==2); tree_locked=false; CHECK(!pthread_mutex_unlock(&tree_mutex)); }
static void vfs_lock_node_data(vfs_node_t *n) { while(__atomic_exchange_n(&n->data_lock,1,__ATOMIC_ACQUIRE)) sched_yield(); ++node_locks; }
static void vfs_unlock_node_data(vfs_node_t *n) { CHECK(node_locks); --node_locks; __atomic_store_n(&n->data_lock,0,__ATOMIC_RELEASE); }
static bool vfs_is_dir(const vfs_node_t *n) { return n && n->type==VFS_NODE_DIR; }
static vfs_node_t *vfs_find_child(vfs_node_t *n,const char *name) {
    CHECK(tree_locked); for(vfs_node_t *c=n->child;c;c=c->next) if(!strcmp(c->name,name)) return c; return NULL;
}
static void vfs_mark_data_dirty(vfs_node_t *n,size_t bytes) { (void)n;(void)bytes; }
static void vfs_mark_meta_dirty(vfs_node_t *n) { (void)n; }
'''
    for signature in ("static inline const char *skip_separators(", "static bool is_dot(",
                      "static bool is_dot_dot(", "static char *vfs_strdup(", "static bool next_component(",
                      "static const char *vfs_node_symlink_target(", "static bool vfs_assign_symlink_target(",
                      "static vfs_node_t *vfs_readlink_resolve_locked(", "ssize_t vfs_readlink_snapshot(",
                      "bool vfs_stat(", "ssize_t vfs_path_snapshot(", "int vfs_path_stat_snapshot(",
                      "bool vfs_node_try_retain(", "int vfs_resolve_owned("):
        code += function_definition(source, signature) + "\n"
    code += r'''
static vfs_node_t *add(vfs_node_t *parent,const char *name,vfs_node_type_t type,const char *target) {
    vfs_node_t *n=calloc(1,sizeof(*n)); CHECK(n); n->name=vfs_strdup(name); CHECK(n->name); n->type=type; n->parent=parent; n->refcount=1;
    if(parent) { n->next=parent->child; parent->child=n; }
    if(target) CHECK(vfs_assign_symlink_target(n,target)); return n;
}
static void free_tree(vfs_node_t *n) { while(n->child) { vfs_node_t *c=n->child; n->child=c->next; free_tree(c); } free(n->name); free(n->data); free(n); }
static void expect(vfs_node_t *cwd,const char *path,const char *target) {
    char *output=malloc(4096); CHECK(output); memset(output,0x5a,4096);
    size_t len=strlen(target); CHECK(vfs_readlink_snapshot(cwd,path,output,4095,37,41)==(ssize_t)len);
    CHECK(!memcmp(output,target,len) && output[len]==0x5a); free(output);
}
typedef struct { vfs_node_t *node; unsigned loops; char *output; } race_arg_t;
static void *replace_links(void *opaque) {
    race_arg_t *a=opaque;
    for(unsigned i=0;i<a->loops;++i) { vfs_tree_lock_acquire(); CHECK(vfs_assign_symlink_target(a->node,i&1?"first/target":"second/longer/target")); vfs_tree_lock_release(); }
    return NULL;
}
static void *read_links(void *opaque) {
    race_arg_t *a=opaque;
    for(unsigned i=0;i<a->loops;++i) {
        memset(a->output,0x55,64); ssize_t n=vfs_readlink_snapshot(root,"race",a->output,63,37,41);
        CHECK((n==12 && !memcmp(a->output,"first/target",12)) || (n==20 && !memcmp(a->output,"second/longer/target",20)));
        CHECK(a->output[n]==0x55);
    } return NULL;
}
static void *read_stats(void *opaque) {
    race_arg_t *a=opaque;vfs_stat_snapshot_t metadata;
    for(unsigned i=0;i<a->loops;++i) {
        CHECK(!vfs_path_stat_snapshot(root,"race",false,37,41,&metadata));
        CHECK(metadata.type==VFS_NODE_SYMLINK&&(metadata.size_bytes==12||metadata.size_bytes==20));
    } return NULL;
}
int main(void) {
    root=add(NULL,"",VFS_NODE_DIR,NULL); vfs_node_t *etc=add(root,"etc",VFS_NODE_DIR,NULL);
    vfs_node_t *zones=add(root,"zones",VFS_NODE_DIR,NULL), *area=add(zones,"Area",VFS_NODE_DIR,NULL);
    add(area,"City",VFS_NODE_FILE,NULL); add(etc,"localtime",VFS_NODE_SYMLINK,"../zones/Area/City");
    add(etc,"link2",VFS_NODE_SYMLINK,"localtime"); add(etc,"file",VFS_NODE_FILE,NULL);
    add(root,"conf",VFS_NODE_SYMLINK,"etc"); add(root,"absolute",VFS_NODE_SYMLINK,"/etc");
    add(root,"chain",VFS_NODE_SYMLINK,"conf"); add(root,"loop",VFS_NODE_SYMLINK,"loop");
    expect(root,"etc/localtime","../zones/Area/City"); expect(etc,"localtime","../zones/Area/City");
    expect(root,"chain/localtime","../zones/Area/City"); expect(zones,"/absolute/localtime","../zones/Area/City");
    expect(root,"etc/link2","localtime"); expect(root,"conf","etc"); expect(root,"etc/../etc//localtime","../zones/Area/City");
    vfs_stat_snapshot_t metadata;
    CHECK(!vfs_path_stat_snapshot(root,"chain/localtime",true,37,41,&metadata)&&metadata.type==VFS_NODE_FILE);
    CHECK(!vfs_path_stat_snapshot(root,"chain/localtime",false,37,41,&metadata)&&metadata.type==VFS_NODE_SYMLINK&&metadata.size_bytes==18);
    CHECK(!vfs_path_stat_snapshot(root,"conf/",false,37,41,&metadata)&&metadata.type==VFS_NODE_DIR);
    CHECK(!vfs_path_stat_snapshot(root,"loop",false,37,41,&metadata)&&metadata.type==VFS_NODE_SYMLINK);
    CHECK(vfs_path_stat_snapshot(root,"loop",true,37,41,&metadata)==-ELOOP);
    CHECK(vfs_path_stat_snapshot(root,"etc/file/",true,37,41,&metadata)==-ENOTDIR);
    memset(&metadata,0xa5,sizeof(metadata));vfs_stat_snapshot_t unchanged=metadata;
    CHECK(vfs_path_stat_snapshot(root,"missing",true,37,41,&metadata)==-ENOENT&&!memcmp(&metadata,&unchanged,sizeof(metadata)));
    char *cwd_path=malloc(4096);CHECK(cwd_path);
    CHECK(vfs_path_snapshot(root,cwd_path,2)==1&&!strcmp(cwd_path,"/"));
    CHECK(vfs_path_snapshot(root,cwd_path,1)==-ERANGE);
    CHECK(vfs_path_snapshot(etc,cwd_path,5)==4&&!strcmp(cwd_path,"/etc"));
    CHECK(vfs_path_snapshot(etc,cwd_path,4)==-ERANGE);
    vfs_node_t *deep=root;
    for(unsigned i=0;i<100;++i)deep=add(deep,"d",VFS_NODE_DIR,NULL);
    CHECK(vfs_path_snapshot(deep,cwd_path,201)==200&&strlen(cwd_path)==200);
    for(unsigned i=0;i<200;++i)CHECK(cwd_path[i]==(i&1?'d':'/'));
    CHECK(vfs_path_snapshot(deep,cwd_path,200)==-ERANGE);
    vfs_node_t *detached=add(NULL,"detached",VFS_NODE_DIR,NULL);
    CHECK(vfs_path_snapshot(detached,cwd_path,4096)==-ENOENT);free_tree(detached);free(cwd_path);
    vfs_node_t *resolved=NULL; owned_at_unlock=etc;
    CHECK(!vfs_resolve_owned(root,"conf",&resolved) && resolved==etc && etc->refcount==2); owned_at_unlock=NULL; --etc->refcount;
    CHECK(!vfs_resolve_owned(root,"chain/localtime",&resolved) && resolved->type==VFS_NODE_FILE && resolved->refcount==2); --resolved->refcount;
    CHECK(vfs_resolve_owned(root,"loop",&resolved)==-ELOOP && !resolved);
    etc->refcount=UINT32_MAX; CHECK(vfs_resolve_owned(root,"etc",&resolved)==-EOVERFLOW && !resolved); etc->refcount=1;
    char *out=malloc(8192); CHECK(out); memset(out,0x5a,8192);
    CHECK(vfs_readlink_snapshot(root,"etc/localtime",out,3,37,41)==3 && !memcmp(out,"../",3) && out[3]==0x5a);
    CHECK(vfs_readlink_snapshot(root,"etc/localtime",out,0,37,41)==-EINVAL);
    CHECK(vfs_readlink_snapshot(root,"",out,8,37,41)==-ENOENT);
    CHECK(vfs_readlink_snapshot(root,"absent",out,8,37,41)==-ENOENT);
    CHECK(vfs_readlink_snapshot(root,"etc/file",out,8,37,41)==-EINVAL);
    CHECK(vfs_readlink_snapshot(root,"etc/file/",out,8,37,41)==-ENOTDIR);
    CHECK(vfs_readlink_snapshot(root,"etc/localtime/",out,8,37,41)==-ENOTDIR);
    CHECK(vfs_readlink_snapshot(root,"conf/",out,8,37,41)==-EINVAL);
    CHECK(vfs_readlink_snapshot(root,"loop/localtime",out,8,37,41)==-ELOOP);
    CHECK(vfs_readlink_snapshot(root,"/",out,8,37,41)==-EINVAL);
    CHECK(vfs_readlink_snapshot(root,".",out,8,37,41)==-EINVAL);
    strcpy(out,"chain/localtime"); CHECK(vfs_readlink_snapshot(root,out,out,4096,37,41)==18 && !memcmp(out,"../zones/Area/City",18));
    memset(out,'x',4096); out[4096]=0; CHECK(vfs_readlink_snapshot(root,out,out+4097,8,37,41)==-ENAMETOOLONG);
    vfs_node_t *large=add(root,"large",VFS_NODE_SYMLINK,"old");
    memset(out,'x',4095); out[4095]=0; CHECK(vfs_assign_symlink_target(large,out) && large->size==4095);
    memset(out+4096,0x44,4096); CHECK(vfs_readlink_snapshot(root,"large",out+4096,4096,37,41)==4095 && out[8191]==0x44);
    out[4095]='x'; out[4096]=0; CHECK(!vfs_assign_symlink_target(large,out) && large->size==4095 && large->data[4095]==0);
    /* Simulate an existing oversized loaded target; leave its bytes intact. */
    free(large->data); large->data=malloc(4097); CHECK(large->data); memset(large->data,'z',4096); large->data[4096]=0; large->size=4096; large->capacity=4097;
    CHECK(vfs_readlink_snapshot(root,"large",out,8192,37,41)==-ENAMETOOLONG && large->size==4096 && large->data[0]=='z');
    CHECK(vfs_resolve_owned(root,"large",&resolved)==-ENAMETOOLONG && !resolved && large->size==4096);
    uint64_t baseline=live;
    for(unsigned i=1;i<30;++i) {
        alloc_calls=0; fail_at=i; ssize_t result=vfs_readlink_snapshot(root,"chain/localtime",out,4096,37,41); fail_at=0;
        CHECK(live==baseline && !tree_locked && !node_locks);
        if(result>=0) { CHECK(result==18 && alloc_calls<i); break; }
        CHECK(result==-ENOMEM);
    }
    for(unsigned i=1;i<30;++i) {
        memset(&metadata,0xa5,sizeof(metadata));unchanged=metadata;
        alloc_calls=0;fail_at=i;int result=vfs_path_stat_snapshot(root,"chain/localtime",true,37,41,&metadata);fail_at=0;
        CHECK(live==baseline&&!tree_locked&&!node_locks);
        if(!result) {CHECK(metadata.type==VFS_NODE_FILE&&alloc_calls<i);break;}
        CHECK(result==-ENOMEM&&!memcmp(&metadata,&unchanged,sizeof(metadata)));
    }
    vfs_node_t *race=add(root,"race",VFS_NODE_SYMLINK,"first/target");
    enum { N=9, LOOPS=4000 }; pthread_t *threads=calloc(N,sizeof(*threads)); race_arg_t *args=calloc(N,sizeof(*args)); CHECK(threads && args);
    for(unsigned i=0;i<N;++i) { args[i].node=race; args[i].loops=LOOPS; args[i].output=malloc(64); CHECK(args[i].output); CHECK(!pthread_create(&threads[i],NULL,i?(i<5?read_links:read_stats):replace_links,&args[i])); }
    for(unsigned i=0;i<N;++i) { CHECK(!pthread_join(threads[i],NULL)); free(args[i].output); }
    free(threads); free(args); free(out); free_tree(root); CHECK(!live);
    puts("readlink/stat snapshot: PASS final nofollow, intermediate chains, metadata, bounds/OOM, 32000 concurrent snapshots"); return 0;
}
'''
    code = code.replace("#define VFS_MAX_SYMLINK_DEPTH 16", f"#define VFS_MAX_SYMLINK_DEPTH {uint_macro(source, 'VFS_MAX_SYMLINK_DEPTH')}")
    previous = os.environ.get("HOST_CC")
    os.environ["HOST_CC"] = shlex.join(shlex.split(previous or "cc") + ["-pthread"])
    try:
        compile_and_run("vfs-readlink", code)
    finally:
        if previous is None:
            os.environ.pop("HOST_CC", None)
        else:
            os.environ["HOST_CC"] = previous
    print("readlink production snapshot contracts: PASS")


if __name__ == "__main__":
    main()
