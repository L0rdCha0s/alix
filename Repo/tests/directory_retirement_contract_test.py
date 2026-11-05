#!/usr/bin/env python3
"""Exercise actual orphan subtree retirement against retained child snapshots."""
import os
import re
import shlex
import sys
from pathlib import Path
sys.dont_write_bytecode = True
from audio_stream_contract_test import ROOT, compile_and_run, function_definition

source = Path(os.environ.get('ALIX_VFS_SOURCE', ROOT / 'src/kernel/vfs.c')).read_text()
header = (ROOT / 'include/vfs.h').read_text()
end = header.index('} vfs_directory_snapshot_t;') + len('} vfs_directory_snapshot_t;')
start = header.rfind('typedef struct', 0, header.index('} vfs_directory_record_t;'))
code = r'''
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#define CHECK(x) do { if(!(x)) { fprintf(stderr,"directory retirement line %d: %s\n",__LINE__,#x); abort(); } } while(0)
#define VFS_PATH_MAX 4096u
enum { VFS_NODE_DIR, VFS_NODE_FILE, VFS_NODE_BLOCK, VFS_NODE_SYMLINK };
typedef struct vfs_node vfs_node_t;
typedef struct { void *backend; vfs_node_t *mount_point; } vfs_mount_t;
struct vfs_node {
    unsigned type; char *name; vfs_node_t *parent,*first_child,*next_sibling;
    uint64_t object_id; size_t refcount; uint32_t lock; vfs_mount_t *mount;
    char *data; size_t size,capacity;
    void *fifo;
};
static pthread_mutex_t tree=PTHREAD_MUTEX_INITIALIZER;
static _Thread_local bool tree_held;
static _Thread_local unsigned data_locks;
static unsigned nodes_freed;
static void vfs_tree_lock_acquire(void) { CHECK(!tree_held); CHECK(!pthread_mutex_lock(&tree)); tree_held=true; }
static void vfs_tree_lock_release(void) { CHECK(tree_held&&!data_locks); tree_held=false; CHECK(!pthread_mutex_unlock(&tree)); }
static void vfs_lock_node_data(vfs_node_t *node) { while(__atomic_exchange_n(&node->lock,1,__ATOMIC_ACQUIRE)) sched_yield(); ++data_locks; }
static void vfs_unlock_node_data(vfs_node_t *node) { CHECK(data_locks); --data_locks; __atomic_store_n(&node->lock,0,__ATOMIC_RELEASE); }
static void free_tree_storage(void *pointer) { CHECK(tree_held&&!data_locks); free(pointer); }
static void vfs_free_subtree(vfs_node_t *node);
static bool vfs_retire_disk_node(vfs_node_t *node) { CHECK(!node->mount); return false; }
static void vfs_mapping_destroy_locked(vfs_node_t *node) { (void)node; }
static void io_pipe_named_destroy(void *fifo) { (void)fifo; CHECK(false); }
'''+header[start:end]+'\nstatic uint64_t g_vfs_next_object_id=1;\n'
for signature in ('void vfs_node_release(', 'static void vfs_free_subtree(',
                  'void vfs_node_release_owned(', 'static uint64_t vfs_directory_object_id_locked(',
                  'static int vfs_directory_name_length(', 'static size_t vfs_directory_record_bytes(',
                  'static int vfs_directory_emit_locked(', 'int vfs_directory_snapshot(',
                  'void vfs_directory_snapshot_release('):
    text = function_definition(source, signature)
    if signature.startswith('static void vfs_free_subtree'):
        text = re.sub(r'\bfree\(', 'free_tree_storage(', text)
        text = text.replace('free_tree_storage(node);', '__atomic_add_fetch(&nodes_freed,1,__ATOMIC_RELAXED); free_tree_storage(node);')
    code += text+'\n'
code += r'''
#define FAMILIES 256u
typedef struct { vfs_node_t **parents,**children; unsigned index; } worker_t;
static unsigned ready,start_workers;
static vfs_node_t *new_node(const char *name) { vfs_node_t *node=calloc(1,sizeof(*node)); CHECK(node); node->type=VFS_NODE_DIR; node->name=strdup(name); CHECK(node->name); node->refcount=1; return node; }
static void *run(void *argument) {
    worker_t *worker=argument; __atomic_add_fetch(&ready,1,__ATOMIC_RELEASE);
    while(!__atomic_load_n(&start_workers,__ATOMIC_ACQUIRE)) sched_yield();
    if(!worker->index) {
        for(unsigned i=0;i<FAMILIES;++i) { vfs_node_release_owned(worker->parents[i]); worker->parents[i]=NULL; sched_yield(); }
    } else for(unsigned i=0;i<3000;++i) {
        vfs_node_t *child=worker->children[(i*17+worker->index)%FAMILIES];
        vfs_directory_snapshot_t snapshot={0}; CHECK(!vfs_directory_snapshot(child,&snapshot)&&snapshot.count==2);
        vfs_directory_record_t *dot=(void *)snapshot.data;
        vfs_directory_record_t *parent=(void *)(snapshot.data+vfs_directory_record_bytes(1));
        CHECK(dot->inode&&parent->inode&&dot->type==VFS_NODE_DIR&&parent->type==VFS_NODE_DIR);
        CHECK(!strcmp((char *)dot->name,".")&&!strcmp((char *)parent->name,".."));
        vfs_directory_snapshot_release(&snapshot);
    }
    return NULL;
}
int main(void) {
    vfs_node_t **parents=calloc(FAMILIES,sizeof(*parents)), **children=calloc(FAMILIES,sizeof(*children));
    pthread_t *threads=calloc(8,sizeof(*threads)); worker_t *workers=calloc(8,sizeof(*workers)); CHECK(parents&&children&&threads&&workers);
    for(unsigned i=0;i<FAMILIES;++i) {
        parents[i]=new_node("orphan"); children[i]=new_node("retained-child");
        children[i]->refcount=2; children[i]->parent=parents[i]; parents[i]->first_child=children[i];
    }
    for(unsigned i=0;i<8;++i) { workers[i]=(worker_t){parents,children,i}; CHECK(!pthread_create(&threads[i],NULL,run,&workers[i])); }
    while(__atomic_load_n(&ready,__ATOMIC_ACQUIRE)!=8) sched_yield(); __atomic_store_n(&start_workers,1,__ATOMIC_RELEASE);
    for(unsigned i=0;i<8;++i) CHECK(!pthread_join(threads[i],NULL));
    CHECK(nodes_freed==FAMILIES);
    for(unsigned i=0;i<FAMILIES;++i) { CHECK(!children[i]->parent&&children[i]->refcount==1); vfs_node_release_owned(children[i]); }
    CHECK(nodes_freed==2*FAMILIES&&!tree_held&&!data_locks);
    free(workers); free(threads); free(children); free(parents);
    puts("DIRECTORY_RETIREMENT: PASS orphan_parents=256 retained_children=256 snapshots=21000 tree_serialized=1"); return 0;
}
'''
previous = os.environ.get('HOST_CC')
try:
    os.environ['HOST_CC'] = shlex.join(shlex.split(previous or 'cc') + ['-pthread'])
    compile_and_run('directory-retirement', code)
finally:
    if previous is None: os.environ.pop('HOST_CC', None)
    else: os.environ['HOST_CC'] = previous
print('Production directory retirement contracts passed')
