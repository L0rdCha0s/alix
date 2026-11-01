#!/usr/bin/env python3
"""Run production directory cursors under simultaneous protected worker reads."""
import os
import re
import shlex
import sys
sys.dont_write_bytecode = True
from audio_stream_contract_test import ROOT, compile_and_run, function_definition

source = (ROOT / 'src/kernel/io/vfs.c').read_text()
header = (ROOT / 'include/vfs.h').read_text()
wire = (ROOT / 'include/syscall_defs.h').read_text()
record_end = header.index('} vfs_directory_snapshot_t;') + len('} vfs_directory_snapshot_t;')
record_start = header.rfind('typedef struct', 0, header.index('} vfs_directory_record_t;'))
wire_start = wire.index('#define SYSCALL_DIRENT_VERSION')
wire_end = wire.index('} syscall_directory_entry_t;') + len('} syscall_directory_entry_t;')
directory_end = source.index('} io_vfs_directory_t;') + len('} io_vfs_directory_t;')
directory_start = source.rfind('typedef struct', 0, directory_end)
code = r'''
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#define CHECK(x) do { if(!(x)) { fprintf(stderr,"cursor line %d: %s\n",__LINE__,#x); abort(); } } while(0)
typedef struct { unsigned references; } vfs_node_t;
static void vfs_node_release_owned(vfs_node_t *node) { CHECK(node->references==1); node->references=0; }
typedef struct { pthread_mutex_t lock; pthread_cond_t condition; } wait_queue_t;
static void wait_queue_wait(wait_queue_t *q, bool (*ready)(void *), void *context) {
    CHECK(!pthread_mutex_lock(&q->lock));
    while(!ready(context)) CHECK(!pthread_cond_wait(&q->condition,&q->lock));
    CHECK(!pthread_mutex_unlock(&q->lock));
}
static void wait_queue_wake_all(wait_queue_t *q) {
    CHECK(!pthread_mutex_lock(&q->lock)); CHECK(!pthread_cond_broadcast(&q->condition)); CHECK(!pthread_mutex_unlock(&q->lock));
}
''' + header[record_start:record_end] + '\n' + wire[wire_start:wire_end] + '\n'
code += r'''
static void vfs_directory_snapshot_release(vfs_directory_snapshot_t *s) { free(s->data); memset(s,0,sizeof(*s)); }
''' + source[directory_start:directory_end] + r'''
static bool fail_refresh;
static int vfs_directory_snapshot(vfs_node_t *node, vfs_directory_snapshot_t *out) {
    CHECK(node && !out->data && !out->bytes && !out->count);
    if(fail_refresh) { fail_refresh=false; return -ENOMEM; }
    io_vfs_directory_t *directory=(void *)((unsigned char *)node-sizeof(io_vfs_directory_t));
    out->data=malloc(directory->snapshot.bytes); CHECK(out->data);
    memcpy(out->data,directory->snapshot.data,directory->snapshot.bytes);
    out->bytes=directory->snapshot.bytes; out->count=directory->snapshot.count; return 0;
}
'''
for signature in ('static bool io_vfs_directory_ready(', 'static int io_vfs_directory_close(', 'static int io_vfs_directory_next('):
    code += function_definition(source, signature) + '\n'
code += r'''
#define ENTRIES 2048u
typedef struct { io_vfs_directory_t *directory; unsigned *seen; } reader_t;
static void *reader(void *argument) {
    reader_t *reader=argument;
    syscall_directory_entry_t *entry=malloc(sizeof(*entry)); CHECK(entry);
    for(;;) {
        memset(entry,0xa5,sizeof(*entry)); int result=io_vfs_directory_next(reader->directory,entry,false);
        CHECK(result==0||result==1); if(!result) { for(size_t i=0;i<sizeof(*entry);++i) CHECK(((unsigned char *)entry)[i]==0xa5); break; }
        CHECK(entry->version==SYSCALL_DIRENT_VERSION&&entry->size==sizeof(*entry)&&entry->inode>0&&entry->inode<=ENTRIES);
        char expected[32]; snprintf(expected,sizeof(expected),"entry-%llu",(unsigned long long)entry->inode);
        CHECK(!strcmp(entry->name,expected)&&strlen(expected)==entry->name_length&&entry->type==(entry->inode&3));
        __atomic_add_fetch(&reader->seen[entry->inode-1],1,__ATOMIC_RELAXED);
    }
    free(entry); return NULL;
}
int main(void) {
    io_vfs_directory_t *directory=calloc(1,sizeof(*directory)+sizeof(vfs_node_t)); CHECK(directory);
    CHECK(!pthread_mutex_init(&directory->cursor_waiters.lock,NULL)&&!pthread_cond_init(&directory->cursor_waiters.condition,NULL));
    directory->node=(void *)(directory+1); directory->node->references=1;
    directory->snapshot.data=calloc(ENTRIES,64); CHECK(directory->snapshot.data); directory->snapshot.count=ENTRIES;
    size_t bytes=0;
    for(unsigned i=1;i<=ENTRIES;++i) {
        vfs_directory_record_t *record=(void *)(directory->snapshot.data+bytes); record->inode=i; record->type=i&3;
        record->name_length=(unsigned)snprintf((char *)record->name,32,"entry-%u",i);
        bytes+=(sizeof(*record)+record->name_length+1+7)&~(size_t)7;
    }
    directory->snapshot.bytes=bytes;
    unsigned *seen=calloc(ENTRIES,sizeof(*seen)); pthread_t *threads=calloc(8,sizeof(*threads)); reader_t *readers=calloc(8,sizeof(*readers)); CHECK(seen&&threads&&readers);
    for(unsigned round=0;round<4;++round) {
        memset(seen,0,ENTRIES*sizeof(*seen)); CHECK(!io_vfs_directory_next(directory,NULL,true));
        for(unsigned i=0;i<8;++i) { readers[i]=(reader_t){directory,seen}; CHECK(!pthread_create(&threads[i],NULL,reader,&readers[i])); }
        for(unsigned i=0;i<8;++i) CHECK(!pthread_join(threads[i],NULL));
        for(unsigned i=0;i<ENTRIES;++i) CHECK(seen[i]==1);
        CHECK(directory->cursor==directory->snapshot.bytes&&directory->index==ENTRIES&&!directory->cursor_owned);
    }
    CHECK(!io_vfs_directory_next(directory,NULL,true));
    fail_refresh=true;
    CHECK(io_vfs_directory_next(directory,NULL,true)==-ENOMEM&&!directory->cursor&&!directory->index);
    vfs_directory_record_t *first=(void *)directory->snapshot.data; first->name_length=4096;
    syscall_directory_entry_t *entry=calloc(1,sizeof(*entry)); CHECK(entry);
    CHECK(io_vfs_directory_next(directory,entry,false)==-EIO&&!directory->cursor&&!directory->index&&!directory->cursor_owned);
    free(entry); free(readers); free(threads); free(seen);
    CHECK(!pthread_cond_destroy(&directory->cursor_waiters.condition)&&!pthread_mutex_destroy(&directory->cursor_waiters.lock));
    CHECK(!io_vfs_directory_close(directory));
    puts("DIRECTORY_CURSOR: PASS workers=8 exact_once=8192 malformed=1 EOF_preserves_output=1"); return 0;
}
'''
previous = os.environ.get('HOST_CC')
try:
    os.environ['HOST_CC'] = shlex.join(shlex.split(previous or 'cc') + ['-pthread'])
    compile_and_run('directory-cursor', code)
finally:
    if previous is None: os.environ.pop('HOST_CC', None)
    else: os.environ['HOST_CC'] = previous
print('Production directory cursor contracts passed')
