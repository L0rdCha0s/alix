#!/usr/bin/env python3
"""Production pipe ring, lifetime, atomic admission and failure rollback."""
import contextlib
import io
from pathlib import Path
import sys

sys.dont_write_bytecode = True
from audio_stream_contract_test import compile_and_run
import fd_retirement_contract_test as base

ROOT = Path(__file__).resolve().parents[1]


def main():
    captured = []
    original = base.compile_and_run
    base.compile_and_run = lambda _label, code: captured.append(code)
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            base.main()
    finally:
        base.compile_and_run = original
    code = captured[0].replace("int main(void)", "static int baseline(void)", 1)
    code += r'''
struct syscall_stat { uint32_t type; uint64_t atime,mtime,ctime; };
#define SYSCALL_NODE_TYPE_FIFO 6
#define SYSCALL_OPEN_READ FD_STATUS_READ
#define SYSCALL_OPEN_WRITE FD_STATUS_WRITE
#define SYSCALL_OPEN_NONBLOCK FD_STATUS_NONBLOCK
struct io_pipe;
typedef struct vfs_node { struct io_pipe *pipe; unsigned refs; } vfs_node_t;
static void vfs_node_release_owned(vfs_node_t *node);
static struct io_pipe *vfs_fifo_state(vfs_node_t *node);
static bool vfs_stat(vfs_node_t *node,void *size,void *type,uint64_t *at,uint64_t *mt,uint64_t *ct) {
    (void)node;(void)size;(void)type; *at=*mt=*ct=0;return true;
}
typedef struct { void *buffer; size_t size; fd_description_t *description; } io_request_t;
typedef struct { int64_t result; fd_description_t *description_owned; } io_service_result_t;
static void *io_request_buffer(io_request_t *request) { return request->buffer; }
static size_t io_request_buffer_size(io_request_t *request) { return request->size; }
static fd_description_t *io_request_description(io_request_t *request) { return request->description; }
static unsigned pipe_allocations, fail_pipe_allocation;
static void *pipe_calloc(size_t n,size_t bytes) {
    if (++pipe_allocations==fail_pipe_allocation) return NULL;
    return owned_calloc(n,bytes);
}
#undef calloc
#define calloc pipe_calloc
'''
    for name in ("include/io_pipe.h", "src/kernel/io/pipe.c"):
        code += "\n".join(line for line in (ROOT / name).read_text().splitlines()
                           if not line.startswith("#include ")) + "\n"
    code += r'''
static struct io_pipe *vfs_fifo_state(vfs_node_t *node) { return node->pipe; }
static void vfs_node_release_owned(vfs_node_t *node) { CHECK(node && node->refs); if(!--node->refs) {io_pipe_named_destroy(node->pipe);free(node);} }
#undef calloc
#define calloc owned_calloc
static int64_t step(fd_description_t *description,unsigned opcode,void *bytes,size_t count,bool expected) {
    io_pipe_operation_t *operation=calloc(1,sizeof(*operation)+count);CHECK(operation);
    operation->opcode=opcode;operation->count=count;
    if(opcode==IO_PIPE_WRITE&&count)memcpy(operation->data,bytes,count);
    io_request_t request={operation,sizeof(*operation)+count,description};io_service_result_t result;
    CHECK(io_pipe_execute(&request,&result)==expected&&!result.description_owned);
    if(expected&&opcode==IO_PIPE_READ&&result.result>0)memcpy(bytes,operation->data,(size_t)result.result);
    free(operation);return result.result;
}
static void failures(void) {
    for(unsigned failure=1;failure<=3;++failure) {
        fd_retirement_queue_t *q=fd_retirement_queue_create(8);CHECK(q);
        pipe_allocations=0;fail_pipe_allocation=failure;
        fd_description_t *reader=(void*)1,*writer=(void*)1;
        spinlock_preempt_disable();CHECK(io_pipe_create_pair(q,&reader,&writer)==-ENOMEM&&!reader&&!writer);spinlock_preempt_enable();
        fail_pipe_allocation=0;destroy_empty(q);
    }
    /* The second deferred description fails admission after the reader exists. */
    fd_retirement_queue_t *q=fd_retirement_queue_create(1);CHECK(q);
    fd_description_t *reader=NULL,*writer=NULL;spinlock_preempt_disable();
    CHECK(io_pipe_create_pair(q,&reader,&writer)==-ENOMEM&&!reader&&!writer);spinlock_preempt_enable();
    CHECK(snapshot(q).pending==1);destroy_empty(q);
}
static void ring_and_ownership(void) {
    fd_retirement_queue_t *q=fd_retirement_queue_create(32);fd_table_t *table=fd_table_create_deferred(4,q);CHECK(q&&table);
    fd_description_t *reader=NULL,*writer=NULL;spinlock_preempt_disable();CHECK(!io_pipe_create_pair(q,&reader,&writer));
    int slots[2]={-7,-9};CHECK(!fd_table_install_pair(table,reader,writer,FD_TABLE_CLOEXEC,slots)&&slots[0]==0&&slots[1]==1);
    CHECK(fd_table_dup(table,1,0,0)==2);
    /* A single remaining slot cannot publish half a pair or modify output. */
    slots[0]=-7;slots[1]=-9;
    CHECK(fd_table_install_pair(table,reader,writer,0,slots)==-EMFILE&&slots[0]==-7&&slots[1]==-9);
    fd_description_t *pin=NULL;CHECK(fd_table_pin(table,3,&pin,NULL)==-EBADF&&!pin);
    CHECK(!fd_table_close(table,2));
    writer->references=UINT32_MAX;
    CHECK(fd_table_install_pair(table,reader,writer,0,slots)==-EOVERFLOW&&reader->references==2);
    writer->references=2;
    CHECK(fd_table_pin(table,2,&pin,NULL)==-EBADF&&!pin);
    spinlock_preempt_enable();
    unsigned char *in=calloc(1,IO_PIPE_CAPACITY),*out=calloc(1,IO_PIPE_CAPACITY);CHECK(in&&out);
    CHECK(step(reader,IO_PIPE_AVAILABLE,NULL,0,true)==0 && step(writer,IO_PIPE_AVAILABLE,NULL,0,true)==0);
    for(unsigned i=0;i<IO_PIPE_CAPACITY;++i)in[i]=(unsigned char)(i*73+11);
    CHECK(step(reader,IO_PIPE_READ,out,1,false)==-EINVAL);
    CHECK(step(reader,IO_PIPE_WRITE,in,1,true)==-EBADF&&step(writer,IO_PIPE_READ,out,1,true)==-EBADF);
    CHECK(step(writer,IO_PIPE_WRITE,in,IO_PIPE_CAPACITY,true)==IO_PIPE_CAPACITY);
    CHECK(step(reader,IO_PIPE_AVAILABLE,NULL,0,true)==IO_PIPE_CAPACITY && step(writer,IO_PIPE_AVAILABLE,NULL,0,true)==IO_PIPE_CAPACITY);
    CHECK(step(writer,IO_PIPE_WRITE,in,IO_PIPE_ATOMIC,false)==-EINVAL);
    CHECK(step(reader,IO_PIPE_READ,out,IO_PIPE_ATOMIC/2,true)==IO_PIPE_ATOMIC/2);
    CHECK(step(reader,IO_PIPE_AVAILABLE,NULL,0,true)==IO_PIPE_CAPACITY-IO_PIPE_ATOMIC/2);
    CHECK(!memcmp(out,in,IO_PIPE_ATOMIC/2));
    CHECK(step(writer,IO_PIPE_WRITE,in,IO_PIPE_ATOMIC,false)==-EINVAL);
    CHECK(step(reader,IO_PIPE_READ,out,IO_PIPE_ATOMIC/2,true)==IO_PIPE_ATOMIC/2);
    CHECK(!memcmp(out,in+IO_PIPE_ATOMIC/2,IO_PIPE_ATOMIC/2));
    CHECK(step(writer,IO_PIPE_WRITE,in,IO_PIPE_ATOMIC,true)==IO_PIPE_ATOMIC);
    CHECK(step(reader,IO_PIPE_READ,out,IO_PIPE_CAPACITY,true)==IO_PIPE_CAPACITY);
    CHECK(!memcmp(out,in+IO_PIPE_ATOMIC,IO_PIPE_CAPACITY-IO_PIPE_ATOMIC));
    CHECK(!memcmp(out+IO_PIPE_CAPACITY-IO_PIPE_ATOMIC,in,IO_PIPE_ATOMIC));
    syscall_stat_t stat;CHECK(!io_pipe_stat(reader,&stat)&&stat.type==SYSCALL_NODE_TYPE_FIFO);
    CHECK(!fd_table_close(table,1));CHECK(!fd_description_put(writer));(void)drain(q,99);
    CHECK(step(reader,IO_PIPE_READ,out,1,true)==0); /* EOF after final writer. */
    CHECK(!fd_table_close(table,0));CHECK(!fd_description_put(reader));fd_table_put(table);destroy_empty(q);
    q=fd_retirement_queue_create(8);spinlock_preempt_disable();CHECK(!io_pipe_create_pair(q,&reader,&writer));spinlock_preempt_enable();
    fd_description_put(reader);(void)drain(q,99);
    CHECK(step(writer,IO_PIPE_WRITE,in,1,true)==-EPIPE&&step(writer,IO_PIPE_WRITE,in,0,true)==0);
    fd_description_put(writer);destroy_empty(q);free(in);free(out);
}
static void inheritance(void) {
    fd_retirement_queue_t *q=fd_retirement_queue_create(32);fd_table_t *parent=fd_table_create_deferred(2,q),*child=NULL;
    fd_description_t *reader=NULL,*writer=NULL;spinlock_preempt_disable();CHECK(!io_pipe_create_pair(q,&reader,&writer));
    int slots[2];CHECK(!fd_table_install_pair(parent,reader,writer,0,slots));
    CHECK(!fd_table_set_flags(parent,0,FD_TABLE_CLOEXEC)&&!fd_table_clone_deferred(parent,true,&child));
    fd_description_t *pin=NULL;CHECK(fd_table_pin(child,0,&pin,NULL)==-EBADF&&!pin);
    CHECK(!fd_table_pin(child,1,&pin,NULL)&&pin==writer);fd_description_put(pin);
    CHECK(!fd_table_close(parent,1));fd_description_put(writer);spinlock_preempt_enable();(void)drain(q,99);
    unsigned char byte=0;CHECK(step(reader,IO_PIPE_READ,&byte,1,false)==-EINVAL);
    CHECK(!fd_table_close(child,1));fd_table_put(child);(void)drain(q,99);
    CHECK(step(reader,IO_PIPE_READ,&byte,1,true)==0);fd_table_put(parent);fd_description_put(reader);destroy_empty(q);
}
typedef struct { fd_description_t *writer;unsigned id;pthread_t thread; } pipe_writer_t;
static void complete_step(fd_description_t *description,unsigned opcode,void *bytes,size_t count) {
    io_pipe_operation_t *operation=calloc(1,sizeof(*operation)+count);CHECK(operation);
    operation->opcode=opcode;operation->count=count;
    if(opcode==IO_PIPE_WRITE)memcpy(operation->data,bytes,count);
    io_request_t request={operation,sizeof(*operation)+count,description};io_service_result_t result;
    unsigned spins=0;
    while(!io_pipe_execute(&request,&result)) { CHECK(++spins<10000000);sched_yield(); }
    CHECK(result.result==(int64_t)count&&!result.description_owned);
    if(opcode==IO_PIPE_READ)memcpy(bytes,operation->data,count);
    free(operation);
}
static void *concurrent_writer(void *argument) {
    pipe_writer_t *worker=argument;uint32_t *record=calloc(32,sizeof(*record));CHECK(record);
    for(unsigned index=0;index<64;++index) {
        for(unsigned word=0;word<32;++word)record[word]=worker->id*64+index;
        complete_step(worker->writer,IO_PIPE_WRITE,record,128);
    }
    fd_description_put(worker->writer);free(record);return NULL;
}
static void concurrent_ring(void) {
    fd_retirement_queue_t *q=fd_retirement_queue_create(16);fd_description_t *reader=NULL,*writer=NULL;
    pipe_writer_t *workers=calloc(8,sizeof(*workers));uint32_t *record=calloc(32,sizeof(*record));unsigned *seen=calloc(512,sizeof(*seen));CHECK(q&&workers&&record&&seen);
    spinlock_preempt_disable();CHECK(!io_pipe_create_pair(q,&reader,&writer));
    for(unsigned i=0;i<8;++i) { CHECK(fd_description_get(writer));workers[i]=(pipe_writer_t){.writer=writer,.id=i};CHECK(!pthread_create(&workers[i].thread,NULL,concurrent_writer,&workers[i])); }
    fd_description_put(writer);spinlock_preempt_enable();
    for(unsigned i=0;i<512;++i) {
        complete_step(reader,IO_PIPE_READ,record,128);CHECK(record[0]<512&&!seen[record[0]]++);
        for(unsigned word=1;word<32;++word)CHECK(record[word]==record[0]);
    }
    for(unsigned i=0;i<8;++i)CHECK(!pthread_join(workers[i].thread,NULL));
    (void)drain(q,99);CHECK(step(reader,IO_PIPE_READ,record,1,true)==0);fd_description_put(reader);destroy_empty(q);
    free(seen);free(record);free(workers);
}
int main(void) {
    CHECK(!baseline());failures();ring_and_ownership();inheritance();concurrent_ring();CHECK(!allocations&&!held_locks&&!preempt_depth);
    puts("Pipe production contracts PASS: ring wrap, atomic writes, EOF/EPIPE, pair rollback and allocation failures");return 0;
}
'''
    compile_and_run("pipe-contract", code)
    print("Pipe production contracts PASS: ring wrap, atomic writes, EOF/EPIPE, pair rollback and allocation failures")
    return 0


if __name__ == "__main__":
    sys.exit(main())
