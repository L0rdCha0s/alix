#!/usr/bin/env python3
"""Execute staged owned VFS and protected storage adapter with real host threads."""
import os
from pathlib import Path
import shlex
import sys

sys.dont_write_bytecode = True
from audio_stream_contract_test import ROOT, compile_and_run, function_definition


def main():
    tree = ROOT / "build/ports/zen/vfs-owned-io"
    fd_tree = ROOT / "build/ports/zen/fd-retirement"
    def stripped(path):
        return "\n".join(line for line in path.read_text().splitlines() if not line.startswith("#include "))
    code = r'''
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <sys/types.h>
#define TIMEKEEPING_TZ_NAME_MAX 32
#define CHECK(x) do { if(!(x)) { fprintf(stderr,"owned VFS line %d: %s\n",__LINE__,#x); abort(); } } while(0)
typedef struct { uint32_t value; } spinlock_t;
static _Thread_local unsigned locks,preempt;
static _Thread_local bool protected_worker,tree_owned;
static void spinlock_init(spinlock_t *l) { l->value=0; }
static void spinlock_preempt_disable(void) { ++preempt; }
static void spinlock_preempt_enable(void) { CHECK(preempt); --preempt; }
static bool __attribute__((unused)) spinlock_preempt_disabled(void) { return preempt!=0; }
static void spinlock_lock(spinlock_t *l) { while(__atomic_exchange_n(&l->value,1,__ATOMIC_ACQUIRE)) sched_yield(); ++locks; }
static void spinlock_unlock(spinlock_t *l) { CHECK(locks); --locks; __atomic_store_n(&l->value,0,__ATOMIC_RELEASE); }
typedef struct { unsigned unused; } wait_queue_t;
static pthread_mutex_t wait_mutex=PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t wait_condition=PTHREAD_COND_INITIALIZER;
static void wait_queue_init(wait_queue_t *q) { q->unused=0; }
static void wait_queue_wait(wait_queue_t *q,bool (*ready)(void *),void *context) {
    (void)q; CHECK(protected_worker && !locks && !preempt); CHECK(!pthread_mutex_lock(&wait_mutex));
    while(!ready(context)) CHECK(!pthread_cond_wait(&wait_condition,&wait_mutex));
    CHECK(!pthread_mutex_unlock(&wait_mutex));
}
static void wait_queue_wake_all(wait_queue_t *q) { (void)q; CHECK(!pthread_mutex_lock(&wait_mutex)); CHECK(!pthread_cond_broadcast(&wait_condition)); CHECK(!pthread_mutex_unlock(&wait_mutex)); }
typedef struct block_device block_device_t;
'''
    code += stripped(ROOT / "include/syscall_defs.h") + "\n"
    for path in (ROOT / "include/fd.h", fd_tree / "include/fd_table.h", ROOT / "include/io_request.h",
                 ROOT / "include/io_service.h", tree / "include/vfs.h", tree / "include/io_vfs.h"):
        code += stripped(path) + "\n"
    code += r'''
struct io_request { void *buffer; size_t bytes; fd_description_t *description; void *cwd; uint32_t uid,gid; };
void *io_request_buffer(io_request_t *r) { return r->buffer; }
size_t io_request_buffer_size(const io_request_t *r) { return r->bytes; }
fd_description_t *io_request_description(const io_request_t *r) { return r->description; }
void *io_request_cwd(const io_request_t *r) { return r->cwd; }
uint32_t io_request_uid(const io_request_t *r) { return r->uid; }
uint32_t io_request_gid(const io_request_t *r) { return r->gid; }
typedef struct { bool block,entered,resume; unsigned calls; } mock_mount_t;
struct vfs_node {
    vfs_node_type_t type; char *name,*data; size_t size,capacity;
    uint32_t uid,gid,refcount,permissions; bool mutable;
    vfs_read_cb_t read_cb; vfs_write_cb_t write_cb; void *callback_context;
    spinlock_t data_lock; mock_mount_t *mount;
};
static vfs_node_t *root,*existing;
static pthread_mutex_t tree_mutex=PTHREAD_MUTEX_INITIALIZER;
static bool fail_node,fail_capacity,unlink_at_unlock,install_callback_after_ref;
static uint64_t callback_calls;
static unsigned retained_at_unlock;
static void vfs_tree_lock_acquire(void) { CHECK(!tree_owned); CHECK(!pthread_mutex_lock(&tree_mutex)); tree_owned=true; }
static void vfs_tree_lock_release(void) {
    CHECK(tree_owned);
    if(unlink_at_unlock && existing) { unlink_at_unlock=false; retained_at_unlock=existing->refcount;
        CHECK(existing->refcount>1); --existing->refcount; existing=NULL; }
    tree_owned=false; CHECK(!pthread_mutex_unlock(&tree_mutex));
}
static void vfs_lock_node_data(vfs_node_t *n) { spinlock_lock(&n->data_lock); }
static ssize_t forbidden_read(vfs_node_t *n,size_t off,void *b,size_t count,void *c) {
    (void)n;(void)off;(void)b;(void)count;(void)c; ++callback_calls; return 0;
}
static void vfs_unlock_node_data(vfs_node_t *n) {
    if(install_callback_after_ref && n->refcount==2) { install_callback_after_ref=false; n->read_cb=forbidden_read; }
    spinlock_unlock(&n->data_lock);
}
/* Data-path fixtures contain no file mappings. */
static void vfs_mapping_push_locked(vfs_node_t*n,size_t start,size_t length) { (void)start;(void)length;CHECK(n&&protected_worker&&locks); }
static bool vfs_mapping_busy_locked(vfs_node_t*n) { CHECK(n&&protected_worker&&locks);return false; }
void vfs_node_retain(vfs_node_t *n) { vfs_lock_node_data(n); CHECK(n->refcount && n->refcount<UINT32_MAX); ++n->refcount; vfs_unlock_node_data(n); }
void vfs_node_release(vfs_node_t *n) { vfs_lock_node_data(n); CHECK(n->refcount); bool last=--n->refcount==0; vfs_unlock_node_data(n); if(last) { free(n->name); free(n->data); free(n); } }
bool vfs_is_dir(const vfs_node_t *n) { return n && n->type==VFS_NODE_DIR; }
static bool split_parent_and_name(vfs_node_t *cwd,const char *path,vfs_node_t **parent,char **name) {
    CHECK(tree_owned); if(!strcmp(path,"missing-parent")) return false;
    *parent=cwd; *name=malloc(strlen(path)+1); CHECK(*name); strcpy(*name,path); return true;
}
static vfs_node_t *vfs_find_child(vfs_node_t *parent,const char *name) { (void)parent; CHECK(tree_owned); return existing && !strcmp(existing->name,name)?existing:NULL; }
static vfs_node_t *vfs_alloc_node(vfs_node_type_t type) {
    if(fail_node) return NULL; vfs_node_t *n=calloc(1,sizeof(*n)); CHECK(n); n->type=type; n->refcount=1; n->mutable=true; n->permissions=type==VFS_NODE_DIR?0777:0666; return n;
}
static bool vfs_node_allows_mutation(const vfs_node_t *n) { return n->write_cb || n->mutable; }
static void vfs_inherit_mutability(vfs_node_t *p,vfs_node_t *n) { n->mutable=p->mutable; }
static void vfs_attach_child(vfs_node_t *p,vfs_node_t *n) { CHECK(tree_owned && !existing); n->uid=p->uid; n->gid=p->gid; existing=n; }
static void vfs_mark_meta_dirty(vfs_node_t *n) { (void)n; }
static void vfs_mark_data_dirty(vfs_node_t *n,size_t count) { (void)n;(void)count; }
static bool ensure_capacity_locked(vfs_node_t *n,size_t size) {
    CHECK(locks); if(fail_capacity) return false;
    if(size+1>n->capacity) { char *p=realloc(n->data,size+1); CHECK(p); n->data=p; n->capacity=size+1; } return true;
}
static void ensure_terminator_locked(vfs_node_t *n) { CHECK(ensure_capacity_locked(n,n->size)); n->data[n->size]=0; }
static void vfs_touch_atime(vfs_node_t *n) { (void)n; }
static void vfs_log(const char *s,uint64_t value) { (void)s;(void)value; }
static void serial_printf(const char *s,...) { (void)s; }
static void vfs_note_file_dirty(vfs_node_t *n,size_t off,size_t count,bool changed) { (void)n;(void)off;(void)count;(void)changed; CHECK(!locks); }
static void vfs_backpressure_wait(mock_mount_t *m,size_t count) {
    (void)count; CHECK(protected_worker && !locks && !preempt); ++m->calls;
    if(m->block) { __atomic_store_n(&m->entered,true,__ATOMIC_RELEASE); while(!__atomic_load_n(&m->resume,__ATOMIC_ACQUIRE)) sched_yield(); }
}
bool vfs_stat(const vfs_node_t *n,size_t *size,vfs_node_type_t *type,uint64_t *at,uint64_t *mt,uint64_t *ct) {
    if(!n) return false; vfs_lock_node_data((vfs_node_t *)n);
    if(size) *size=n->size; if(type) *type=n->type; if(at) *at=1; if(mt) *mt=2; if(ct) *ct=3;
    vfs_unlock_node_data((vfs_node_t *)n); return true;
}
bool vfs_flush_node(vfs_node_t *n) { CHECK(protected_worker && !locks && !preempt); if(n->mount) vfs_backpressure_wait(n->mount,0); return true; }
ssize_t vfs_readlink_snapshot(vfs_node_t *cwd,const char *path,void *buffer,size_t capacity,uint32_t uid,uint32_t gid) {
    CHECK(protected_worker && cwd==root && uid==37 && gid==41 && !strcmp(path,"timezone"));
    size_t bytes=capacity<13?capacity:13; memmove(buffer,"/etc/timezone",bytes); return (ssize_t)bytes;
}
'''
    # Always exercise current VFS data helpers. The older staged request
    # adapter below remains a historical lifetime fixture, not current service
    # coverage; current service behavior is verified by native guest tests.
    vfs = (ROOT / "src/kernel/vfs.c").read_text()
    for signature in ("static int vfs_node_access_locked(", "static vfs_node_t *vfs_open_file_internal(", "vfs_node_t *vfs_open_file(",
                      "int vfs_open_data_owned(", "int vfs_open_data_access_owned(", "static ssize_t vfs_read_at_internal(", "ssize_t vfs_read_data_at(",
                      "ssize_t vfs_read_at(", "static ssize_t vfs_write_at_internal(", "ssize_t vfs_write_data_at(",
                      "ssize_t vfs_write_at(", "bool vfs_set_file_callbacks("):
        code += function_definition(vfs, signature) + "\n"
    code += stripped(fd_tree / "src/kernel/fd/table.c") + r'''
static fd_retirement_queue_t *model_retirement;
int vfs_resolve_owned(vfs_node_t *cwd,const char *path,vfs_node_t **out) {
    CHECK(cwd==root && !strcmp(path,"..")); vfs_node_retain(root); *out=root; return 0;
}
static int cwd_close(void *node) { vfs_node_release(node); return 0; }
fd_description_t *process_cwd_description_create_owned(vfs_node_t *node) {
    return fd_description_create_deferred(&(fd_ops_t){.close=cwd_close},node,model_retirement);
}
'''
    code += stripped(tree / "src/kernel/io/vfs.c") + r'''
static void clear_existing(void) { if(existing) { vfs_node_t *n=existing; existing=NULL; vfs_node_release(n); } }
static void owned_open_contracts(void) {
    vfs_node_t *node=NULL; CHECK(vfs_open_data_owned(NULL,"file",true,false,37,41,&node)==-EINVAL && !node);
    CHECK(vfs_open_data_owned(root,"missing-parent",true,false,37,41,&node)==-ENOENT);
    fail_node=true; CHECK(vfs_open_data_owned(root,"file",true,false,37,41,&node)==-ENOMEM); fail_node=false;
    CHECK(!vfs_open_data_owned(root,"file",true,false,37,41,&node)); CHECK(node==existing && node->refcount==2 && node->uid==37 && node->gid==41); vfs_node_release(node);
    CHECK(vfs_write_data_at(existing,0,"abc",3)==3);
    existing->permissions=0400;
    CHECK(vfs_open_data_owned(root,"file",false,true,1,2,&node)==-EACCES&&existing->size==3&&existing->refcount==1);
    CHECK(!vfs_open_data_access_owned(root,"file",false,false,false,37,41,4,&node));vfs_node_release(node);
    CHECK(vfs_open_data_access_owned(root,"file",false,false,false,37,41,2,&node)==-EACCES&&existing->refcount==1);
    existing->permissions=0040;
    CHECK(!vfs_open_data_access_owned(root,"file",false,false,false,100,41,4,&node));vfs_node_release(node);
    CHECK(vfs_open_data_access_owned(root,"file",false,false,false,100,42,4,&node)==-EACCES);
    root->permissions=0555;
    CHECK(vfs_open_data_owned(root,"denied",true,false,37,41,&node)==-EACCES);
    root->permissions=0777;existing->permissions=0666;
    vfs_set_file_callbacks(existing,forbidden_read,NULL,NULL);
    CHECK(vfs_open_data_owned(root,"file",false,true,1,2,&node)==-ENOTSUP && !node && existing->size==3 && existing->refcount==1);
    char *bytes=calloc(1,8); CHECK(bytes); CHECK(vfs_read_data_at(existing,0,bytes,3)==-ENOTSUP && vfs_write_data_at(existing,0,"x",1)==-ENOTSUP && !callback_calls);
    vfs_set_file_callbacks(existing,NULL,NULL,NULL); existing->refcount=UINT32_MAX;
    CHECK(vfs_open_data_owned(root,"file",false,false,1,2,&node)==-EOVERFLOW); existing->refcount=1;
    install_callback_after_ref=true;
    CHECK(vfs_open_data_owned(root,"file",false,true,1,2,&node)==-ENOTSUP && existing->size==3 && existing->refcount==1);
    vfs_set_file_callbacks(existing,NULL,NULL,NULL); existing->mutable=false;
    CHECK(vfs_open_data_owned(root,"file",false,true,1,2,&node)==-EROFS && existing->refcount==1); existing->mutable=true;
    fail_capacity=true; CHECK(vfs_open_data_owned(root,"file",false,true,1,2,&node)==-ENOMEM && existing->refcount==1); fail_capacity=false;
    unlink_at_unlock=true; CHECK(!vfs_open_data_owned(root,"file",false,false,1,2,&node));
    CHECK(retained_at_unlock==2 && !existing && node->refcount==1); vfs_node_release(node); free(bytes);
    node=vfs_open_file(root,"legacy",true,false); CHECK(node==existing && node->refcount==1 && node->uid==root->uid && node->gid==root->gid); clear_existing();
}
static io_request_t *new_request(size_t bytes,fd_description_t *d) {
    io_request_t *r=calloc(1,sizeof(*r)); CHECK(r); r->bytes=sizeof(io_vfs_operation_t)+bytes; r->buffer=calloc(1,r->bytes); CHECK(r->buffer);
    r->uid=37; r->gid=41; r->cwd=root; r->description=d; if(d) CHECK(fd_description_get(d)); return r;
}
static void free_request(io_request_t *r) { fd_description_put(r->description); free(r->buffer); free(r); }
static io_service_result_t *execute(io_request_t *r,fd_retirement_queue_t *q) {
    io_service_result_t *result=calloc(1,sizeof(*result)); CHECK(result); model_retirement=q; io_vfs_execute(r,result,q); return result;
}
static fd_description_t *open_description(fd_retirement_queue_t *q) {
    io_request_t *r=new_request(16,NULL); io_vfs_operation_t *op=r->buffer; op->opcode=IO_VFS_OPEN; op->flags=SYSCALL_OPEN_READ|SYSCALL_OPEN_WRITE|SYSCALL_OPEN_CREATE; strcpy((char *)op->data,"file");
    io_service_result_t *result=execute(r,q); CHECK(!result->result && result->description_owned); fd_description_t *d=result->description_owned;
    free(result); free_request(r); return d;
}
static void adapter_contracts(void) {
    fd_retirement_queue_t *q=fd_retirement_queue_create(32); CHECK(q); fd_description_t *d=open_description(q);
    CHECK(existing->uid==37 && existing->gid==41 && existing->refcount==2);
    io_request_t *r=new_request(8,d); io_vfs_operation_t *op=r->buffer; op->opcode=IO_VFS_WRITE; op->count=3; memcpy(op->data,"abc",3);
    io_service_result_t *result=execute(r,q); CHECK(result->result==3); free(result);
    op->opcode=IO_VFS_PREAD; op->offset=1; op->count=2; result=execute(r,q); CHECK(result->result==2 && !memcmp(op->data,"bc",2)); free(result);
    op->opcode=IO_VFS_SEEK; op->count=0; op->whence=SYSCALL_SEEK_CUR; op->offset=0; result=execute(r,q); CHECK(result->result==3); free(result);
    op->offset=-4; result=execute(r,q); CHECK(result->result==-EINVAL); free(result);
    op->whence=SYSCALL_SEEK_SET; op->offset=0; result=execute(r,q); CHECK(!result->result); free(result);
    op->opcode=IO_VFS_READ; op->count=8; result=execute(r,q); CHECK(result->result==3 && !memcmp(op->data,"abc",3)); free(result);
    op->opcode=IO_VFS_STAT; op->count=0; result=execute(r,q); CHECK(!result->result && op->stat.size_bytes==3 && op->stat.reserved==0); free(result);
    op->opcode=IO_VFS_WRITE; op->count=9; result=execute(r,q); CHECK(result->result==-EINVAL); free(result);
    op->opcode=IO_VFS_SEEK; op->count=0; op->offset=INT64_MAX; result=execute(r,q); CHECK(result->result==INT64_MAX); free(result);
    op->opcode=IO_VFS_WRITE; op->count=1; result=execute(r,q); CHECK(result->result==-EFBIG); free(result);
    free_request(r); fd_description_put(d); CHECK(existing->refcount==2); CHECK(fd_retirement_queue_drain(q,32)==1 && existing->refcount==1);
    fd_retirement_queue_shutdown(q); CHECK(!fd_retirement_queue_destroy(q)); clear_existing();
    r=new_request(16,NULL); op=r->buffer; op->opcode=IO_VFS_READLINK; op->count=4;
    strcpy((char *)op->data,"timezone"); result=execute(r,NULL);
    CHECK(result->result==4 && !memcmp(op->data,"/etc",4) && op->data[4]=='z'); free(result); free_request(r);
    q=fd_retirement_queue_create(1); CHECK(q); r=new_request(8,NULL); op=r->buffer; op->opcode=IO_VFS_RESOLVE_CWD; strcpy((char *)op->data,"..");
    result=execute(r,q); CHECK(!result->result && result->description_owned && fd_description_context(result->description_owned)==root && root->refcount==2);
    fd_description_put(result->description_owned); free(result); free_request(r); CHECK(fd_retirement_queue_drain(q,2)==1 && root->refcount==1);
    fd_retirement_queue_shutdown(q); CHECK(!fd_retirement_queue_destroy(q));
}
typedef struct { fd_retirement_queue_t *queue; io_request_t *request; unsigned iterations; bool finish_pin; } worker_arg_t;
static void *writer(void *opaque) {
    worker_arg_t *arg=opaque; protected_worker=true;
    io_service_result_t *result=calloc(1,sizeof(*result)); CHECK(result);
    for(unsigned i=0;i<arg->iterations;++i) { io_vfs_execute(arg->request,result,arg->queue); CHECK(result->result==1); }
    if(arg->finish_pin) { fd_description_put(arg->request->description); arg->request->description=NULL; }
    free(result); return NULL;
}
static void concurrent_offsets_and_blocked_owner(void) {
    enum { N=4, EACH=1000 }; fd_retirement_queue_t *q=fd_retirement_queue_create(32); CHECK(q); fd_description_t *d=open_description(q);
    worker_arg_t *args=calloc(N,sizeof(*args)); pthread_t *threads=calloc(N,sizeof(*threads)); CHECK(args && threads);
    for(unsigned i=0;i<N;++i) { args[i].queue=q; args[i].request=new_request(1,d); args[i].iterations=EACH;
        io_vfs_operation_t *op=args[i].request->buffer; op->opcode=IO_VFS_WRITE; op->count=1; op->data[0]=(unsigned char)('a'+i);
        CHECK(!pthread_create(&threads[i],NULL,writer,&args[i])); }
    for(unsigned i=0;i<N;++i) { CHECK(!pthread_join(threads[i],NULL)); free_request(args[i].request); }
    CHECK(existing->size==N*EACH); unsigned totals[N]={0};
    for(size_t i=0;i<existing->size;++i) { CHECK(existing->data[i]>='a' && existing->data[i]<'a'+N); ++totals[existing->data[i]-'a']; }
    for(unsigned i=0;i<N;++i) CHECK(totals[i]==EACH);
    mock_mount_t *mount=calloc(1,sizeof(*mount)); CHECK(mount); mount->block=true; existing->mount=mount;
    args[0].request=new_request(1,d); args[0].iterations=1; args[0].finish_pin=true;
    io_vfs_operation_t *op=args[0].request->buffer; op->opcode=IO_VFS_WRITE; op->count=1; op->data[0]='x';
    CHECK(!pthread_create(&threads[0],NULL,writer,&args[0]));
    while(!__atomic_load_n(&mount->entered,__ATOMIC_ACQUIRE)) sched_yield();
    fd_description_put(d); CHECK(fd_retirement_queue_drain(q,32)==0 && existing->refcount==2);
    __atomic_store_n(&mount->resume,true,__ATOMIC_RELEASE); CHECK(!pthread_join(threads[0],NULL));
    CHECK(existing->size==N*EACH+1 && fd_retirement_queue_drain(q,32)==1 && existing->refcount==1);
    free_request(args[0].request); existing->mount=NULL; free(mount); free(args); free(threads);
    fd_retirement_queue_shutdown(q); CHECK(!fd_retirement_queue_destroy(q)); clear_existing();
}
int main(void) {
    protected_worker=true; root=vfs_alloc_node(VFS_NODE_DIR); root->uid=99; root->gid=101;
    owned_open_contracts(); adapter_contracts(); concurrent_offsets_and_blocked_owner();
    CHECK(!existing && !callback_calls && !locks && !preempt && !tree_owned); vfs_node_release(root);
    puts("owned VFS I/O: PASS retained-open, explicit identity, callback exclusion, offset concurrency, blocked worker ownership"); return 0;
}
'''
    previous = os.environ.get("HOST_CC")
    os.environ["HOST_CC"] = shlex.join(shlex.split(previous or "cc") + ["-pthread"])
    try:
        compile_and_run("vfs-owned-io", code)
    finally:
        if previous is None:
            os.environ.pop("HOST_CC", None)
        else:
            os.environ["HOST_CC"] = previous
    print("Current VFS data helpers and historical request adapter fixture: PASS")


if __name__ == "__main__":
    main()
