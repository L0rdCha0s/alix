#!/usr/bin/env python3
"""Exercise production immutable directory snapshots and object identities."""
import os,shlex,sys
sys.dont_write_bytecode=True
from audio_stream_contract_test import ROOT,compile_and_run,function_definition
source=(ROOT/'src/kernel/vfs.c').read_text();header=(ROOT/'include/vfs.h').read_text()
end=header.index('} vfs_directory_snapshot_t;')+len('} vfs_directory_snapshot_t;')
start=header.rfind('typedef struct',0,header.index('} vfs_directory_record_t;'))
code=r'''
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#define CHECK(x) do{if(!(x)){fprintf(stderr,"directory snapshot line %d: %s\n",__LINE__,#x);abort();}}while(0)
#define VFS_PATH_MAX 4096u
enum {VFS_NODE_DIR,VFS_NODE_FILE,VFS_NODE_BLOCK,VFS_NODE_SYMLINK};
typedef struct vfs_node {unsigned type;char *name;struct vfs_node *parent,*first_child,*next_sibling;uint64_t object_id;} vfs_node_t;
static pthread_mutex_t tree_mutex=PTHREAD_MUTEX_INITIALIZER;
static _Thread_local bool tree_held,fail_allocation;
static uint64_t allocations;
static void vfs_tree_lock_acquire(void){CHECK(!tree_held&&!pthread_mutex_lock(&tree_mutex));tree_held=true;}
static void vfs_tree_lock_release(void){CHECK(tree_held);tree_held=false;CHECK(!pthread_mutex_unlock(&tree_mutex));}
static void *snapshot_calloc(size_t n,size_t size){CHECK(tree_held&&n==1);if(fail_allocation){fail_allocation=false;return NULL;}void*p=calloc(n,size);CHECK(p);__atomic_add_fetch(&allocations,1,__ATOMIC_RELAXED);return p;}
static void snapshot_free(void*p){CHECK(!tree_held);if(p){CHECK(__atomic_fetch_sub(&allocations,1,__ATOMIC_RELAXED));free(p);}}
'''+header[start:end]+'\nstatic uint64_t g_vfs_next_object_id=1;\n'
for signature in ['static uint64_t vfs_directory_object_id_locked(', 'static int vfs_directory_name_length(',
                  'static size_t vfs_directory_record_bytes(', 'static int vfs_directory_emit_locked(',
                  'int vfs_directory_snapshot(', 'void vfs_directory_snapshot_release(']:
    text=function_definition(source,signature)
    import re
    text=re.sub(r'\bcalloc\b','snapshot_calloc',text);text=re.sub(r'\bfree\b','snapshot_free',text)
    code+=text+'\n'
code+=r'''
static vfs_node_t *node(vfs_node_t *parent,const char *name,unsigned type){
    vfs_node_t*n=calloc(1,sizeof(*n));CHECK(n);n->name=strdup(name);CHECK(n->name);n->parent=parent;n->type=type;
    if(parent){n->next_sibling=parent->first_child;parent->first_child=n;}return n;
}
static void free_tree(vfs_node_t*n){while(n->first_child){vfs_node_t*c=n->first_child;n->first_child=c->next_sibling;free_tree(c);}free(n->name);free(n);}
static vfs_directory_record_t *entry(vfs_directory_snapshot_t*s,size_t index){
    size_t offset=0;
    for(size_t i=0;i<s->count;++i){
        CHECK(offset<=s->bytes&&s->bytes-offset>=sizeof(vfs_directory_record_t));
        vfs_directory_record_t*r=(void*)(s->data+offset);CHECK(r->inode&&r->name_length<VFS_PATH_MAX&&r->name[r->name_length]==0);
        size_t bytes=vfs_directory_record_bytes(r->name_length);CHECK(bytes<=s->bytes-offset&&strlen((char*)r->name)==r->name_length);
        for(size_t p=sizeof(*r)+r->name_length+1;p<bytes;++p)CHECK(s->data[offset+p]==0);
        if(i==index)return r;offset+=bytes;
    }
    CHECK(false);return NULL;
}
static vfs_directory_record_t *find(vfs_directory_snapshot_t*s,const char*name){for(size_t i=0;i<s->count;++i){vfs_directory_record_t*r=entry(s,i);if(!strcmp((char*)r->name,name))return r;}CHECK(false);return NULL;}
static void basic_and_failures(void){
    vfs_node_t*root=node(NULL,"",VFS_NODE_DIR);vfs_node_t*dir=node(root,"dir",VFS_NODE_DIR);
    vfs_node_t*file=node(dir,"file",VFS_NODE_FILE);node(dir,"link",VFS_NODE_SYMLINK);node(dir,"block",VFS_NODE_BLOCK);node(dir,"caf\xc3\xa9",VFS_NODE_DIR);
    vfs_directory_snapshot_t snap={0};CHECK(!vfs_directory_snapshot(dir,&snap)&&snap.count==6);
    CHECK(!strcmp((char*)entry(&snap,0)->name,".")&&!strcmp((char*)entry(&snap,1)->name,".."));
    CHECK(entry(&snap,0)->inode==dir->object_id&&entry(&snap,1)->inode==root->object_id);
    CHECK(find(&snap,"file")->inode==file->object_id&&find(&snap,"link")->type==VFS_NODE_SYMLINK&&find(&snap,"block")->type==VFS_NODE_BLOCK&&find(&snap,"caf\xc3\xa9")->name_length==5);
    uint64_t id=find(&snap,"file")->inode;CHECK(id<16);
    CHECK(vfs_directory_snapshot(dir,&snap)==-EINVAL); /* Existing owner must not be overwritten. */
    vfs_directory_snapshot_t other={0};CHECK(!vfs_directory_snapshot(dir,&other)&&find(&other,"file")->inode==id);vfs_directory_snapshot_release(&other);
    /* Snapshot names/identities remain usable after the entire source tree dies. */
    free_tree(root);CHECK(find(&snap,"file")->inode==id);vfs_directory_snapshot_release(&snap);CHECK(!snap.data&&!snap.bytes&&!snap.count);
    root=node(NULL,"",VFS_NODE_DIR);file=node(root,"new",VFS_NODE_FILE);CHECK(!vfs_directory_snapshot(root,&snap)&&find(&snap,"new")->inode!=id);vfs_directory_snapshot_release(&snap);
    CHECK(vfs_directory_snapshot(file,&snap)==-ENOTDIR&&!snap.data);
    fail_allocation=true;CHECK(vfs_directory_snapshot(root,&snap)==-ENOMEM&&!snap.data&&!tree_held);
    char*long_name=malloc(VFS_PATH_MAX+1);CHECK(long_name);memset(long_name,'x',VFS_PATH_MAX);long_name[VFS_PATH_MAX-1]=0;
    vfs_node_t*long_node=node(root,long_name,VFS_NODE_FILE);CHECK(!vfs_directory_snapshot(root,&snap)&&find(&snap,long_name)->name_length==4095);vfs_directory_snapshot_release(&snap);
    free(long_node->name);long_name[VFS_PATH_MAX-1]='x';long_name[VFS_PATH_MAX]=0;long_node->name=strdup(long_name);CHECK(long_node->name);
    CHECK(vfs_directory_snapshot(root,&snap)==-ENAMETOOLONG&&!snap.data);
    free(long_node->name);long_node->name=strdup("short");CHECK(long_node->name);
    g_vfs_next_object_id=UINT64_MAX;node(root,"exhausted",VFS_NODE_FILE);
    CHECK(vfs_directory_snapshot(root,&snap)==-EOVERFLOW&&!snap.data&&!allocations);
    free(long_name);free_tree(root);
}
typedef struct {vfs_node_t *root,*leaf;bool writer;} race_arg_t;
static void *race(void*argument){race_arg_t*a=argument;for(unsigned i=0;i<2000;++i){
    if(a->writer){vfs_tree_lock_acquire();char*n=strdup(i&1?"first":"second-longer");CHECK(n);free(a->leaf->name);a->leaf->name=n;vfs_tree_lock_release();}
    else{vfs_directory_snapshot_t s={0};CHECK(!vfs_directory_snapshot(a->root,&s)&&s.count==3);vfs_directory_record_t*r=entry(&s,2);CHECK(!strcmp((char*)r->name,"first")||!strcmp((char*)r->name,"second-longer"));vfs_directory_snapshot_release(&s);}
}return NULL;}
static void concurrent_snapshots(void){
    /* A fresh test identity space is safe after every old node/snapshot died. */
    g_vfs_next_object_id=1;vfs_node_t*root=node(NULL,"",VFS_NODE_DIR),*leaf=node(root,"first",VFS_NODE_FILE);
    race_arg_t*args=calloc(8,sizeof(*args));pthread_t*threads=calloc(8,sizeof(*threads));CHECK(args&&threads);
    for(unsigned i=0;i<8;++i){args[i]=(race_arg_t){root,leaf,i==0};CHECK(!pthread_create(&threads[i],NULL,race,&args[i]));}
    for(unsigned i=0;i<8;++i)CHECK(!pthread_join(threads[i],NULL));free(threads);free(args);free_tree(root);
}
int main(void){basic_and_failures();concurrent_snapshots();CHECK(!allocations&&!tree_held);puts("DIRECTORY_SNAPSHOT: PASS stable_ids=1 owned_names=1 names4095=1 no_truncation=1 padding=zero concurrent=14000");return 0;}
'''
previous=os.environ.get('HOST_CC')
try:
    os.environ['HOST_CC']=shlex.join(shlex.split(previous or 'cc')+['-pthread'])
    compile_and_run('directory-snapshot',code)
finally:
    if previous is None:os.environ.pop('HOST_CC',None)
    else:os.environ['HOST_CC']=previous
print('Production directory snapshot contracts passed')
