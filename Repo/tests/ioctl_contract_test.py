#!/usr/bin/env python3
"""Native partial-status updates and serialized regular-file byte snapshots."""
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
typedef struct {size_t size;bool error;} vfs_node_t;
typedef struct {vfs_node_t *node;uint64_t offset;pthread_mutex_t gate;} io_vfs_file_t;
static _Thread_local unsigned vfs_gates;
static void io_vfs_offset_lock(io_vfs_file_t *file){CHECK(!pthread_mutex_lock(&file->gate));++vfs_gates;}
static void io_vfs_offset_unlock(io_vfs_file_t *file){CHECK(vfs_gates);--vfs_gates;CHECK(!pthread_mutex_unlock(&file->gate));}
static bool vfs_stat(const vfs_node_t *node,size_t *size,void *type,void *atime,void *mtime,void *ctime){
    CHECK(vfs_gates && !type && !atime && !mtime && !ctime);if(node->error)return false;*size=node->size;return true;
}
'''
code += function_definition((ROOT / 'src/kernel/io/vfs.c').read_text(), 'static int64_t io_vfs_file_available(')
code += r'''
typedef struct {fd_description_t *description;uint32_t mask;} flags_job_t;
static void *flags_worker(void *opaque){
    flags_job_t *job=opaque;
    for(unsigned i=0;i<10000;++i)CHECK(!fd_description_update_status_flags(job->description,job->mask,i%2?job->mask:0));
    CHECK(!fd_description_update_status_flags(job->description,job->mask,job->mask));return NULL;
}
static void flags(void){
    const fd_ops_t ops={0};fd_description_t *description=fd_description_create(&ops,NULL);CHECK(description);
    CHECK(!fd_description_initialize_status(description,FD_STATUS_READ|FD_STATUS_WRITE|FD_STATUS_APPEND));
    CHECK(!fd_description_update_status_flags(description,FD_STATUS_NONBLOCK,FD_STATUS_NONBLOCK));
    CHECK(fd_description_status_flags(description)==(FD_STATUS_READ|FD_STATUS_WRITE|FD_STATUS_APPEND|FD_STATUS_NONBLOCK));
    CHECK(!fd_description_update_status_flags(description,FD_STATUS_APPEND,0));
    CHECK(fd_description_status_flags(description)==(FD_STATUS_READ|FD_STATUS_WRITE|FD_STATUS_NONBLOCK));
    CHECK(fd_description_update_status_flags(description,FD_STATUS_READ,0)==-EINVAL);
    CHECK(fd_description_update_status_flags(description,FD_STATUS_NONBLOCK,FD_STATUS_APPEND)==-EINVAL);
    flags_job_t *jobs=calloc(2,sizeof(*jobs));pthread_t threads[2];CHECK(jobs);
    jobs[0]=(flags_job_t){description,FD_STATUS_APPEND};jobs[1]=(flags_job_t){description,FD_STATUS_NONBLOCK};
    CHECK(!pthread_create(&threads[0],NULL,flags_worker,&jobs[0]) && !pthread_create(&threads[1],NULL,flags_worker,&jobs[1]));
    CHECK(!pthread_join(threads[0],NULL) && !pthread_join(threads[1],NULL));
    CHECK(fd_description_status_flags(description)==(FD_STATUS_READ|FD_STATUS_WRITE|FD_STATUS_APPEND|FD_STATUS_NONBLOCK));
    free(jobs);fd_description_put(description);
}
typedef struct {io_vfs_file_t *file;bool writing;} available_job_t;
static void *available_worker(void *opaque){
    available_job_t *job=opaque;
    for(unsigned i=0;i<4000;++i){
        if(job->writing){io_vfs_offset_lock(job->file);job->file->offset=i;job->file->node->size=i+7;io_vfs_offset_unlock(job->file);}
        else CHECK(io_vfs_file_available(job->file)==7);
    }CHECK(!vfs_gates);return NULL;
}
static void available(void){
    vfs_node_t *node=calloc(1,sizeof(*node));io_vfs_file_t *file=calloc(1,sizeof(*file));CHECK(node && file);
    file->node=node;CHECK(!pthread_mutex_init(&file->gate,NULL));
    node->size=8;file->offset=2;CHECK(io_vfs_file_available(file)==6 && file->offset==2);
    file->offset=8;CHECK(io_vfs_file_available(file)==0);file->offset=UINT64_C(1)<<40;CHECK(io_vfs_file_available(file)==0);
    node->size=SIZE_MAX;file->offset=0;CHECK(io_vfs_file_available(file)==INT64_MAX);
    node->error=true;CHECK(io_vfs_file_available(file)==-EIO && !vfs_gates);node->error=false;
    node->size=7;file->offset=0;
    available_job_t *jobs=calloc(8,sizeof(*jobs));pthread_t threads[8];CHECK(jobs);
    for(unsigned i=0;i<8;++i){jobs[i]=(available_job_t){file,i==0};CHECK(!pthread_create(&threads[i],NULL,available_worker,&jobs[i]));}
    for(unsigned i=0;i<8;++i)CHECK(!pthread_join(threads[i],NULL));
    CHECK(!pthread_mutex_destroy(&file->gate));free(jobs);free(file);free(node);
}
int main(void){CHECK(!baseline());flags();available();CHECK(!allocations && !held_locks && !preempt_depth);puts("IOCTL_CONTRACT_TEST: PASS atomic_flags=20000 access_preserved=1 offset_gate=1 snapshots=28000 eof=1 bounds=1 errors=1");return 0;}
'''
compile_and_run('ioctl-contract', code)
print('Production ioctl contracts: PASS 20000 atomic flag updates and 28000 serialized byte snapshots')
