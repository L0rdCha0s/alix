#!/usr/bin/env python3
"""Run production unbuffered stdio against seekable/nonseekable mock I/O."""
import os
import re
import shlex
import sys

sys.dont_write_bytecode = True
from audio_stream_contract_test import ROOT, compile_and_run


def rename(text):
    names = ("FILE", "fpos_t", "stdout", "stderr", "stdin", "fopen", "freopen", "fclose", "fread", "fwrite",
             "fflush", "fseek", "ftell", "fgetpos", "fsetpos", "rewind", "fputc", "fgetc", "getc",
             "ungetc", "fgets", "feof", "ferror", "clearerr", "fileno", "fputs", "setbuf", "setvbuf", "getchar")
    for name in names:
        text = re.sub(r"\b" + name + r"\b", "native_" + name, text)
    for name in ("read", "write", "lseek", "open", "close", "malloc", "free"):
        text = re.sub(r"\b" + name + r"\b", "model_" + name, text)
    return re.sub(r"\berrno\b", "test_errno", text)


def build_program():
    libc = (ROOT / "user/lib/libc.c").read_text()
    start = libc.index("static FILE g_stdout_obj")
    stop = libc.index("ssize_t read(int fd,", start)
    header = (ROOT / "include/stdio.h").read_text()
    types = header[header.index("typedef struct FILE"):header.index("extern FILE *stdout;")]
    internal = "\n".join(line for line in (ROOT / "user/lib/stdio_internal.h").read_text().splitlines()
                         if line.startswith(("bool __alix_", "size_t __alix_", "int __alix_")))
    code = r'''
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <sched.h>
#include <sys/types.h>
#undef _IONBF
#undef _IOFBF
#undef _IOLBF
#undef BUFSIZ
#define _IONBF 0
#define _IOFBF 1
#define _IOLBF 2
#define BUFSIZ 4096
#define ALIX_WAIT_FOREVER UINT32_MAX
#define CHECK(c) do { if (!(c)) { fprintf(stderr,"stdio contract line %d: %s\n",__LINE__,#c); abort(); } } while(0)
#define SYSCALL_OPEN_READ 1u
#define SYSCALL_OPEN_WRITE 2u
#define SYSCALL_OPEN_CREATE 4u
#define SYSCALL_OPEN_TRUNCATE 8u
#define SYSCALL_OPEN_EXCLUSIVE 16u
#define SYSCALL_OPEN_APPEND (1u << 16)
#define SYSCALL_SEEK_SET 0
#define SYSCALL_SEEK_CUR 1
#define SYSCALL_SEEK_END 2
typedef struct { volatile uint32_t state; } alix_mutex_t;
static pthread_mutex_t mutex_guard=PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t mutex_changed=PTHREAD_COND_INITIALIZER;
static _Thread_local alix_mutex_t *held_stream;
static _Thread_local int test_errno;
static void alix_mutex_init(alix_mutex_t *mutex) { mutex->state=0; }
static void alix_mutex_lock(alix_mutex_t *mutex) {
    CHECK(!held_stream); CHECK(!pthread_mutex_lock(&mutex_guard));
    while (mutex->state) CHECK(!pthread_cond_wait(&mutex_changed,&mutex_guard));
    mutex->state=1; held_stream=mutex; CHECK(!pthread_mutex_unlock(&mutex_guard));
}
static void alix_mutex_unlock(alix_mutex_t *mutex) {
    CHECK(held_stream==mutex); CHECK(!pthread_mutex_lock(&mutex_guard));
    mutex->state=0; held_stream=NULL; CHECK(!pthread_cond_broadcast(&mutex_changed));
    CHECK(!pthread_mutex_unlock(&mutex_guard));
}
static int sys_futex_wait(volatile uint32_t *address,uint32_t expected,uint32_t timeout) {
    CHECK(!held_stream && timeout==ALIX_WAIT_FOREVER);
    if(__atomic_load_n(address,__ATOMIC_ACQUIRE)==expected)sched_yield();
    return 0;
}
static int sys_futex_wake(volatile uint32_t *address,uint32_t maximum) {
    CHECK(address && maximum==UINT32_MAX); return 0;
}
'''
    code += rename(types + "\n" + internal) + r'''
static size_t model_file_allocations;
static bool fail_file_allocation;
static void *model_malloc(size_t bytes) {
    if (fail_file_allocation) { fail_file_allocation=false; test_errno=ENOMEM; return NULL; }
    void *value=malloc(bytes); CHECK(value); __atomic_add_fetch(&model_file_allocations,1,__ATOMIC_RELAXED); return value;
}
static void model_free(void *value) { CHECK(value && __atomic_fetch_sub(&model_file_allocations,1,__ATOMIC_RELAXED)); free(value); }
typedef struct {
    unsigned char *data; size_t size, capacity; int64_t position;
    bool opened, seekable, raw_errors, yield_io, zero_write, overread, overwrite;
    bool block_write;
    unsigned write_entered, release_write;
    size_t read_chunk, write_chunk;
    unsigned read_calls, write_calls, seek_calls, close_calls;
    unsigned read_fail_after, write_fail_after;
    int read_error, write_error, seek_error, close_error;
    int64_t last_seek_offset; int last_seek_whence;
    uint64_t open_flags;
    native_FILE *stream;
} model_file_t;
static model_file_t *files[64];
static unsigned next_fd=3, opens, closes;
static int fail_open_error;
static const char *next_data="";
static bool next_seekable=true;
static int64_t model_error(model_file_t *file,int error) {
    if (file->raw_errors) return -error;
    test_errno=error; return -1;
}
static model_file_t *model_file(int fd) {
    CHECK(fd>=0 && fd<64 && files[fd]); return files[fd];
}
static int model_open(const char *path,uint64_t flags,...) {
    CHECK(path && next_fd<64);
    if (fail_open_error) { int error=fail_open_error; fail_open_error=0; return -error; }
    int fd=(int)next_fd++; model_file_t *file=calloc(1,sizeof(*file)); CHECK(file);
    file->capacity=131072; file->data=calloc(1,file->capacity); CHECK(file->data);
    file->size=strlen(next_data); CHECK(file->size<file->capacity);
    memcpy(file->data,next_data,file->size);
    if (flags & SYSCALL_OPEN_TRUNCATE) file->size=0;
    file->seekable=next_seekable; file->opened=true; file->open_flags=flags;
    file->read_chunk=file->write_chunk=SIZE_MAX;
    file->read_fail_after=file->write_fail_after=UINT_MAX;
    files[fd]=file; ++opens; return fd;
}
static int model_close(int fd) {
    model_file_t *file=model_file(fd); CHECK(file->opened); file->opened=false;
    ++file->close_calls; ++closes;
    return file->close_error ? (int)model_error(file,file->close_error) : 0;
}
static ssize_t model_read(int fd,void *buffer,size_t count) {
    model_file_t *file=model_file(fd); CHECK(file->opened && file->stream && held_stream==&file->stream->mutex);
    ++file->read_calls; if (file->yield_io) sched_yield();
    if (file->read_calls>file->read_fail_after) return model_error(file,file->read_error ? file->read_error : EIO);
    if (file->overread) return (ssize_t)(count+1);
    if ((uint64_t)file->position>=file->size) return 0;
    size_t bytes=file->size-(size_t)file->position;
    if (bytes>count) bytes=count; if (bytes>file->read_chunk) bytes=file->read_chunk;
    memcpy(buffer,file->data+(size_t)file->position,bytes); file->position+=(int64_t)bytes; return (ssize_t)bytes;
}
static ssize_t model_write(int fd,const void *buffer,size_t count) {
    model_file_t *file=model_file(fd); CHECK(file->opened && file->stream && held_stream==&file->stream->mutex);
    if(file->block_write) {
        __atomic_store_n(&file->write_entered,1,__ATOMIC_RELEASE);
        while(!__atomic_load_n(&file->release_write,__ATOMIC_ACQUIRE))sched_yield();
    }
    ++file->write_calls; if (file->yield_io) sched_yield();
    if (file->write_calls>file->write_fail_after) return model_error(file,file->write_error ? file->write_error : EIO);
    if (file->zero_write) return 0;
    if (file->overwrite) return (ssize_t)(count+1);
    size_t bytes=count<file->write_chunk ? count : file->write_chunk;
    CHECK(file->position>=0 && (uint64_t)file->position<=file->capacity && bytes<=file->capacity-(size_t)file->position);
    memcpy(file->data+(size_t)file->position,buffer,bytes); file->position+=(int64_t)bytes;
    if ((size_t)file->position>file->size) file->size=(size_t)file->position;
    return (ssize_t)bytes;
}
static int64_t model_lseek(int fd,int64_t offset,int whence) {
    model_file_t *file=model_file(fd); CHECK(file->opened);
    ++file->seek_calls; file->last_seek_offset=offset; file->last_seek_whence=whence;
    if (!file->seekable) return model_error(file,ESPIPE);
    if (file->seek_error) return model_error(file,file->seek_error);
    int64_t base=whence==SEEK_SET ? 0 : whence==SEEK_CUR ? file->position : (int64_t)file->size;
    int64_t position;
    if (whence<0 || whence>2 || __builtin_add_overflow(base,offset,&position) || position<0)
        return model_error(file,EINVAL);
    file->position=position; return position;
}
'''
    code += rename(libc[start:stop]) + r'''
static native_FILE *open_stream(const char *mode,const char *data,bool seekable) {
    next_data=data; next_seekable=seekable;
    native_FILE *stream=native_fopen("fixture",mode); CHECK(stream);
    model_file(stream->fd)->stream=stream; return stream;
}
static void pushback_and_position(void) {
    native_FILE *stream=open_stream("r+","abc\ndef",true); model_file_t *file=model_file(stream->fd);
    CHECK(native_fgetc(stream)=='a' && native_ftell(stream)==1);
    CHECK(native_ungetc('X',stream)=='X' && native_ftell(stream)==0 && file->position==1);
    CHECK(native_ungetc('Y',stream)==EOF && native_ungetc(EOF,stream)==EOF);
    unsigned calls=file->read_calls;
    CHECK(native_fgetc(stream)=='X' && file->read_calls==calls && native_ftell(stream)==1);
    CHECK(native_ungetc(0x1ff,stream)==255 && native_fgetc(stream)==255);
    CHECK(native_fgetc(stream)=='b');
    native_fpos_t position=-55; CHECK(native_fgetpos(stream,&position)==0 && position==2);
    CHECK(native_ungetc('Z',stream)=='Z' && native_fseek(stream,0,SEEK_CUR)==0);
    CHECK(file->position==1 && !stream->pushback_pending && native_fgetc(stream)=='b');
    CHECK(native_fsetpos(stream,&position)==0 && native_fgetc(stream)=='c');
    CHECK(native_fseek(stream,0,SEEK_SET)==0 && native_fgetc(stream)=='a');
    CHECK(native_ungetc('Z',stream)=='Z' && native_fflush(NULL)==0 && stream->pushback_pending && file->position==1);
    CHECK(native_fflush(stream)==0 && !stream->pushback_pending && file->position==0);
    CHECK(native_fgetc(stream)=='a' && native_ungetc('Z',stream)=='Z');
    CHECK(native_fwrite("Q",1,1,stream)==1 && !memcmp(file->data,"Qbc",3) && file->position==1);
    CHECK(native_ungetc('Z',stream)=='Z'); calls=file->seek_calls;
    CHECK(native_fseek(stream,LONG_MIN,SEEK_CUR)==-1 && test_errno==EOVERFLOW && file->seek_calls==calls);
    CHECK(stream->pushback_pending && native_fgetc(stream)=='Z');
    CHECK(native_fseek(stream,0,SEEK_SET)==0 && native_ungetc('Z',stream)=='Z');
    CHECK(native_ftell(stream)==-1 && test_errno==EINVAL && stream->pushback_pending);
    CHECK(native_fgetc(stream)=='Z' && native_fgetc(stream)=='Q');
    CHECK(native_fclose(stream)==0);
}
static void nonseekable_and_recovery(void) {
    native_FILE *stream=open_stream("r","ab",false); model_file_t *file=model_file(stream->fd);
    file->raw_errors=true;
    CHECK(native_fgetc(stream)=='a' && native_ungetc('Z',stream)=='Z');
    CHECK(native_ftell(stream)==-1 && test_errno==ESPIPE && stream->pushback_pending);
    CHECK(native_fseek(stream,0,SEEK_CUR)==-1 && test_errno==ESPIPE && stream->pushback_pending);
    CHECK(native_fflush(stream)==EOF && test_errno==ESPIPE && native_ferror(stream));
    CHECK(native_fgetc(stream)=='Z'); native_clearerr(stream);
    CHECK(native_fgetc(stream)=='b' && native_fgetc(stream)==EOF && native_feof(stream));
    unsigned calls=file->read_calls; CHECK(native_fgetc(stream)==EOF && file->read_calls==calls);
    CHECK(native_ungetc(EOF,stream)==EOF && native_feof(stream));
    CHECK(native_ungetc('x',stream)=='x' && !native_feof(stream));
    native_clearerr(stream); CHECK(stream->pushback_pending && native_fgetc(stream)=='x');
    CHECK(native_fclose(stream)==0);

    stream=open_stream("r","abc",true); file=model_file(stream->fd);
    unsigned char bytes[8]; CHECK(native_fread(bytes,1,sizeof(bytes),stream)==3 && native_feof(stream));
    file->seek_error=EIO; CHECK(native_fseek(stream,0,SEEK_SET)==-1 && native_feof(stream));
    file->seek_error=0; native_rewind(stream); CHECK(!native_feof(stream) && !native_ferror(stream));
    CHECK(native_fgetc(stream)=='a'); CHECK(native_fclose(stream)==0);
}
static void reads_errors_and_overflow(void) {
    native_FILE *stream=open_stream("r","abcdef",true); model_file_t *file=model_file(stream->fd);
    file->read_chunk=2; unsigned char bytes[16]; memset(bytes,0xa5,sizeof(bytes));
    CHECK(native_fread(bytes,4,2,stream)==1 && !memcmp(bytes,"abcdef",6) && bytes[6]==0xa5 && native_feof(stream));
    CHECK(native_ungetc('Z',stream)=='Z' && !native_feof(stream));
    CHECK(native_fread(bytes,2,1,stream)==0 && bytes[0]=='Z' && native_feof(stream));
    native_rewind(stream); CHECK(native_fgetc(stream)=='a' && native_ungetc('Z',stream)=='Z');
    unsigned calls=file->read_calls;
    CHECK(native_fread(bytes,SIZE_MAX,2,stream)==0 && test_errno==EOVERFLOW && native_ferror(stream));
    CHECK(file->read_calls==calls && stream->pushback_pending); native_clearerr(stream);
    CHECK(native_fread(NULL,0,SIZE_MAX,stream)==0 && !native_ferror(stream));
    CHECK(native_fgetc(stream)=='Z'); native_rewind(stream);
    file->read_chunk=3; file->read_fail_after=file->read_calls+1; file->read_error=EINTR;
    CHECK(native_fread(bytes,4,2,stream)==0 && !memcmp(bytes,"abc",3) && native_ferror(stream));
    CHECK(test_errno==EINTR && !native_feof(stream));
    native_clearerr(stream); file->read_fail_after=UINT_MAX;
    CHECK(native_fread(bytes,3,1,stream)==1 && !memcmp(bytes,"def",3));
    native_rewind(stream); file->overread=true;
    CHECK(native_fread(bytes,1,1,stream)==0 && test_errno==EIO && native_ferror(stream));
    CHECK(native_fclose(stream)==0);
}
static void line_and_write_contracts(void) {
    native_FILE *stream=open_stream("r","ab\ncd",true); model_file_t *file=model_file(stream->fd);
    char line[16]; CHECK(native_fgetc(stream)=='a' && native_ungetc('X',stream)=='X');
    CHECK(native_fgets(line,sizeof(line),stream)==line && !strcmp(line,"Xb\n"));
    CHECK(native_fgets(line,sizeof(line),stream)==line && !strcmp(line,"cd"));
    strcpy(line,"unchanged"); CHECK(!native_fgets(line,sizeof(line),stream) && !strcmp(line,"unchanged"));
    unsigned calls=file->read_calls; CHECK(native_fgets(line,1,stream)==line && !line[0] && file->read_calls==calls);
    native_rewind(stream); file->read_fail_after=file->read_calls+1; file->read_error=EIO;
    CHECK(!native_fgets(line,sizeof(line),stream) && native_ferror(stream));
    native_clearerr(stream); file->read_fail_after=UINT_MAX;
    CHECK(native_fgets(line,sizeof(line),stream)==line && !strcmp(line,"b\n"));
    native_FILE *saved_stdin=native_stdin; native_stdin=stream;
    CHECK(native_ungetc('K',stream)=='K' && native_getchar()=='K'); native_stdin=saved_stdin;
    CHECK(native_fwrite("x",1,1,stream)==0 && test_errno==EBADF && native_ferror(stream));
    CHECK(native_fclose(stream)==0);

    stream=open_stream("w","",true); file=model_file(stream->fd); file->write_chunk=3;
    CHECK(native_ungetc('X',stream)==EOF && test_errno==EBADF);
    file->write_fail_after=1; file->write_error=ENOSPC;
    CHECK(native_fwrite("abcdef",2,3,stream)==1 && file->size==3 && native_ferror(stream) && test_errno==ENOSPC);
    native_clearerr(stream); file->write_fail_after=UINT_MAX;
    CHECK(native_fputs("de",stream)==0 && native_fputc('f',stream)=='f' && !memcmp(file->data,"abcdef",6));
    calls=file->write_calls;
    CHECK(native_fwrite("x",SIZE_MAX,2,stream)==0 && test_errno==EOVERFLOW && file->write_calls==calls);
    native_clearerr(stream); file->zero_write=true;
    CHECK(native_fwrite("x",1,1,stream)==0 && native_ferror(stream) && test_errno==EIO);
    file->zero_write=false; file->overwrite=true; native_clearerr(stream);
    CHECK(native_fputc('x',stream)==EOF && test_errno==EIO);
    file->close_error=EIO; CHECK(native_fclose(stream)==EOF && test_errno==EIO);

    stream=open_stream("a+","abc",true); file=model_file(stream->fd);
    CHECK(native_fseek(stream,0,SEEK_SET)==0 && native_fputc('X',stream)=='X');
    CHECK(file->size==4 && !memcmp(file->data,"abcX",4)); CHECK(native_fclose(stream)==0);
    unsigned before=opens;
    CHECK(!native_fopen("x","invalid") && test_errno==EINVAL && opens==before);
    fail_open_error=EEXIST;
    CHECK(!native_fopen("x","wx") && test_errno==EEXIST && opens==before);
    native_FILE *exclusive=open_stream("wx","",true);
    CHECK(model_file(exclusive->fd)->open_flags & SYSCALL_OPEN_EXCLUSIVE);
    CHECK(native_fclose(exclusive)==0);
    fail_open_error=ENOENT; test_errno=91;
    CHECK(!native_fopen("missing","r") && test_errno==ENOENT);
    fail_file_allocation=true; before=closes;
    CHECK(!native_fopen("x","rb") && test_errno==ENOMEM && closes==before+1);
}
#define LINES 256
#define RECORD_BYTES 32
typedef struct { native_FILE *stream; unsigned index; bool writing; unsigned *seen; char buffer[64]; pthread_t thread; } worker_t;
static void *stream_worker(void *argument) {
    worker_t *worker=argument;
    if (worker->writing) {
        memset(worker->buffer,(int)('A'+worker->index),RECORD_BYTES); worker->buffer[RECORD_BYTES-1]='\n';
        for (unsigned i=0;i<100;++i) CHECK(native_fwrite(worker->buffer,1,RECORD_BYTES,worker->stream)==RECORD_BYTES);
    } else {
        while (native_fgets(worker->buffer,sizeof(worker->buffer),worker->stream)) {
            unsigned index=(unsigned)strtoul(worker->buffer+1,NULL,10); CHECK(index<LINES);
            CHECK(strlen(worker->buffer)==RECORD_BYTES && worker->buffer[RECORD_BYTES-1]=='\n');
            for (unsigned i=6;i<RECORD_BYTES-1;++i) CHECK(worker->buffer[i]=='a'+index%26);
            CHECK(__atomic_fetch_add(&worker->seen[index],1,__ATOMIC_RELAXED)==0);
        }
        CHECK(!native_ferror(worker->stream));
    }
    return NULL;
}
static void concurrent_streams(void) {
    char *content=calloc(1,LINES*RECORD_BYTES+1); CHECK(content);
    for (unsigned i=0;i<LINES;++i) {
        char *line=content+i*RECORD_BYTES; snprintf(line,7,"L%04u:",i);
        memset(line+6,(int)('a'+i%26),RECORD_BYTES-7); line[RECORD_BYTES-1]='\n';
    }
    unsigned *seen=calloc(LINES,sizeof(*seen)); worker_t *workers=calloc(8,sizeof(*workers)); CHECK(seen && workers);
    native_FILE *stream=open_stream("r",content,true); model_file_t *file=model_file(stream->fd);
    file->read_chunk=1; file->yield_io=true;
    for (unsigned i=0;i<8;++i) { workers[i].stream=stream; workers[i].seen=seen; CHECK(!pthread_create(&workers[i].thread,NULL,stream_worker,&workers[i])); }
    for (unsigned i=0;i<8;++i) CHECK(!pthread_join(workers[i].thread,NULL));
    for (unsigned i=0;i<LINES;++i) CHECK(seen[i]==1);
    CHECK(native_fclose(stream)==0);
    stream=open_stream("w","",true); file=model_file(stream->fd); file->write_chunk=1; file->yield_io=true;
    for (unsigned i=0;i<8;++i) { workers[i].stream=stream; workers[i].writing=true; workers[i].index=i; CHECK(!pthread_create(&workers[i].thread,NULL,stream_worker,&workers[i])); }
    for (unsigned i=0;i<8;++i) CHECK(!pthread_join(workers[i].thread,NULL));
    CHECK(file->size==8*100*RECORD_BYTES);
    for (size_t pos=0;pos<file->size;pos+=RECORD_BYTES) {
        CHECK(file->data[pos]>='A' && file->data[pos]<='H');
        for (unsigned i=1;i<RECORD_BYTES-1;++i) CHECK(file->data[pos+i]==file->data[pos]);
        CHECK(file->data[pos+RECORD_BYTES-1]=='\n');
    }
    CHECK(native_fclose(stream)==0); free(workers); free(seen); free(content);
}
int main(void) {
    pushback_and_position(); nonseekable_and_recovery(); reads_errors_and_overflow(); line_and_write_contracts(); concurrent_streams();
    CHECK(model_file_allocations==0 && !held_stream);
    for (unsigned i=0;i<64;++i) if (files[i]) { CHECK(!files[i]->opened); free(files[i]->data); free(files[i]); }
    puts("production stdio pushback, positioning, partial items, errors and concurrent call serialization passed");
    return 0;
}
'''
    return code


def main():
    code = build_program()
    previous = os.environ.get("HOST_CC")
    os.environ["HOST_CC"] = shlex.join(shlex.split(previous or "cc") + ["-pthread"])
    try:
        compile_and_run("stdio-stream", code)
    finally:
        if previous is None:
            os.environ.pop("HOST_CC", None)
        else:
            os.environ["HOST_CC"] = previous
    print("native stdio stream contracts passed")


if __name__ == "__main__":
    main()
