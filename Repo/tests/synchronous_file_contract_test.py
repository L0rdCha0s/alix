#!/usr/bin/env python3
"""Production synchronous-write completion, failure and shared-offset contracts."""
import contextlib
import io
import sys
sys.dont_write_bytecode = True
from audio_stream_contract_test import ROOT, compile_and_run, function_definition
import fd_retirement_contract_test as base

captured = []
original = base.compile_and_run
base.compile_and_run = lambda label, code: captured.append(code)
try:
    with contextlib.redirect_stdout(io.StringIO()):
        base.main()
finally:
    base.compile_and_run = original
code = captured[0].replace('int main(void)', 'static int baseline(void)', 1)
code += r'''
typedef struct {
    pthread_mutex_t lock;
    unsigned char data[16384],durable[16384];
    size_t size,durable_size;
    unsigned writes,flushes;
    bool fail_write,fail_flush,short_write,oversized;
    atomic_uint block_flush,entered,release;
} vfs_node_t;
#define VFS_NODE_CHARACTER 5
/* This ownership fixture supplies regular files; device dispatch is separate. */
static unsigned vfs_node_type(vfs_node_t *node){CHECK(node);return 1;}
typedef struct {vfs_node_t *node;uint64_t offset;bool writable;fd_description_t *description;pthread_mutex_t gate;} io_vfs_file_t;
static _Thread_local unsigned offset_gates;
static void io_vfs_offset_lock(io_vfs_file_t *file){CHECK(!pthread_mutex_lock(&file->gate));++offset_gates;}
static void io_vfs_offset_unlock(io_vfs_file_t *file){CHECK(offset_gates==1);--offset_gates;CHECK(!pthread_mutex_unlock(&file->gate));}
static ssize_t write_node(vfs_node_t *node,size_t offset,const void *data,size_t count,bool append,uint64_t *end){
    CHECK(offset_gates==1 && !held_locks);CHECK(!pthread_mutex_lock(&node->lock));
    ssize_t result=-EIO;
    if(!node->fail_write){
        if(append)offset=node->size;
        if(node->short_write)count/=2;
        CHECK(offset<=sizeof(node->data) && count<=sizeof(node->data)-offset);
        if(count){memcpy(node->data+offset,data,count);if(offset+count>node->size)node->size=offset+count;++node->writes;}
        if(end)*end=offset+count;result=(ssize_t)count+(node->oversized?1:0);
    }
    CHECK(!pthread_mutex_unlock(&node->lock));return result;
}
static ssize_t vfs_write_data_at(vfs_node_t *node,size_t offset,const void *data,size_t count){return write_node(node,offset,data,count,false,NULL);}
static ssize_t vfs_write_append(vfs_node_t *node,const void *data,size_t count,bool callbacks,uint64_t *end){CHECK(!callbacks);return write_node(node,0,data,count,true,end);}
static bool vfs_flush_node(vfs_node_t *node){
    CHECK(offset_gates==1 && !held_locks);
    if(atomic_load(&node->block_flush)){atomic_store(&node->entered,1);while(!atomic_load(&node->release))sched_yield();}
    CHECK(!pthread_mutex_lock(&node->lock));++node->flushes;
    bool success=!node->fail_flush;
    if(success){memcpy(node->durable,node->data,node->size);node->durable_size=node->size;}
    CHECK(!pthread_mutex_unlock(&node->lock));return success;
}
'''
code += function_definition((ROOT/'src/kernel/io/vfs.c').read_text(), 'static ssize_t io_vfs_file_write(')
code += r'''
static io_vfs_file_t *new_file(bool synchronous){
    io_vfs_file_t *file=calloc(1,sizeof(*file));CHECK(file);file->node=calloc(1,sizeof(*file->node));CHECK(file->node);
    CHECK(!pthread_mutex_init(&file->gate,NULL) && !pthread_mutex_init(&file->node->lock,NULL));
    static const fd_ops_t ops={0};file->description=fd_description_create(&ops,NULL);CHECK(file->description);
    CHECK(!fd_description_initialize_status(file->description,FD_STATUS_READ|FD_STATUS_WRITE|(synchronous?FD_STATUS_SYNC:0)));
    file->writable=true;return file;
}
static void delete_file(io_vfs_file_t *file){
    CHECK(!offset_gates && !held_locks);CHECK(!pthread_mutex_destroy(&file->gate) && !pthread_mutex_destroy(&file->node->lock));
    CHECK(!fd_description_put(file->description));free(file->node);free(file);
}
static void errors(void){
    io_vfs_file_t *plain=new_file(false),*sync=new_file(true);vfs_node_t *node=sync->node;
    CHECK(io_vfs_file_write(plain,"data",4)==4 && plain->offset==4 && !plain->node->flushes);
    CHECK(!fd_description_set_status_flags(plain->description,FD_STATUS_SYNC) && !(fd_description_status_flags(plain->description)&FD_STATUS_SYNC));
    CHECK(!fd_description_set_status_flags(sync->description,0) && (fd_description_status_flags(sync->description)&FD_STATUS_SYNC));
    CHECK(fd_description_update_status_flags(sync->description,FD_STATUS_SYNC,0)==-EINVAL);
    CHECK(io_vfs_file_write(sync,"data",4)==4 && sync->offset==4 && node->flushes==1 && node->durable_size==4 && !memcmp(node->durable,"data",4));
    CHECK(io_vfs_file_write(sync,NULL,0)==0 && node->flushes==1);
    CHECK(io_vfs_file_write(sync,NULL,1)==-EINVAL && node->flushes==1);
    node->fail_write=true;CHECK(io_vfs_file_write(sync,"fail",4)==-EIO && sync->offset==4 && node->flushes==1);node->fail_write=false;
    node->fail_flush=true;CHECK(io_vfs_file_write(sync,"next",4)==-EIO && sync->offset==8 && node->size==8 && node->durable_size==4 && node->flushes==2);node->fail_flush=false;
    node->short_write=true;CHECK(io_vfs_file_write(sync,"abcd",4)==2 && sync->offset==10 && node->durable_size==10 && node->flushes==3);node->short_write=false;
    node->oversized=true;CHECK(io_vfs_file_write(sync,"bad",3)==-EIO && sync->offset==10 && node->flushes==3);node->oversized=false;
    sync->writable=false;CHECK(io_vfs_file_write(sync,"bad",3)==-EBADF && node->flushes==3);sync->writable=true;
    sync->offset=INT64_MAX;CHECK(io_vfs_file_write(sync,"bad",3)==-EFBIG && node->flushes==3);
    delete_file(plain);delete_file(sync);
}
typedef struct {io_vfs_file_t *file;unsigned rounds;atomic_uint entered,returned;} write_job_t;
static void *writer(void *opaque){
    write_job_t *job=opaque;atomic_store(&job->entered,1);
    for(unsigned round=0;round<job->rounds;++round)CHECK(io_vfs_file_write(job->file,"data",4)==4);
    CHECK(!offset_gates);atomic_store(&job->returned,1);return NULL;
}
static void completion(void){
    io_vfs_file_t *file=new_file(true);write_job_t *jobs=calloc(2,sizeof(*jobs));CHECK(jobs);pthread_t threads[2];
    atomic_store(&file->node->block_flush,1);
    for(unsigned i=0;i<2;++i){jobs[i].file=file;jobs[i].rounds=1;}
    CHECK(!pthread_create(&threads[0],NULL,writer,&jobs[0]));while(!atomic_load(&file->node->entered))sched_yield();
    CHECK(!atomic_load(&jobs[0].returned));CHECK(!pthread_create(&threads[1],NULL,writer,&jobs[1]));
    while(!atomic_load(&jobs[1].entered))sched_yield();
    CHECK(!pthread_mutex_lock(&file->node->lock));CHECK(file->node->writes==1 && !atomic_load(&jobs[1].returned));CHECK(!pthread_mutex_unlock(&file->node->lock));
    atomic_store(&file->node->release,1);
    for(unsigned i=0;i<2;++i)CHECK(!pthread_join(threads[i],NULL) && atomic_load(&jobs[i].returned));
    CHECK(file->offset==8 && file->node->durable_size==8 && file->node->flushes==2);
    free(jobs);delete_file(file);
}
static void concurrent(void){
    io_vfs_file_t *file=new_file(true);write_job_t *jobs=calloc(8,sizeof(*jobs));CHECK(jobs);pthread_t threads[8];
    CHECK(!fd_description_set_status_flags(file->description,FD_STATUS_APPEND|FD_STATUS_NONBLOCK));
    for(unsigned i=0;i<8;++i){jobs[i].file=file;jobs[i].rounds=64;CHECK(!pthread_create(&threads[i],NULL,writer,&jobs[i]));}
    for(unsigned i=0;i<8;++i)CHECK(!pthread_join(threads[i],NULL));
    CHECK(file->offset==2048 && file->node->size==2048 && file->node->durable_size==2048 && file->node->flushes==512);
    CHECK((fd_description_status_flags(file->description)&FD_STATUS_SYNC) && !memcmp(file->node->data,file->node->durable,2048));
    free(jobs);delete_file(file);
}
int main(void){CHECK(!baseline());errors();completion();concurrent();CHECK(!allocations && !held_locks && !preempt_depth);puts("SYNCHRONOUS_FILE_CONTRACT: PASS writes=512 flush_wait=1 alias_gate=1 immutable=1 errors=1 short_write=1");return 0;}
'''
code = code.replace('#include <pthread.h>', '#include <pthread.h>\n#include <stdatomic.h>', 1)
compile_and_run('synchronous-file-contract', code)
print('Production synchronous-write contracts: PASS 512 writes, flush completion, alias serialization, immutable flags and fault handling')
