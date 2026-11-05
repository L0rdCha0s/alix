#!/usr/bin/env python3
"""Production gather preparation with modeled request admission and copy faults."""
from audio_stream_contract_test import ROOT,compile_and_run,function_definition

def typedef(path,name,kind='struct'):
    source=(ROOT/path).read_text();end=source.index('} '+name+';')+len('} '+name+';')
    return source[source.rfind('typedef '+kind,0,end):end]+'\n'

program=r'''
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#define CHECK(c) do{if(!(c)){fprintf(stderr,"writev preparation line %d: %s\n",__LINE__,#c);abort();}}while(0)
#define SYSCALL_IOV_MAX 1024u
#define NET_UDP_MAX_PAYLOAD 1472u
#define IO_REQUEST_BUFFER_MAX 65536u
#define SYSCALL_FILE_WRITEV 99u
typedef struct {uint64_t base,length;} syscall_iovec_t;
typedef enum {USER_STORAGE,USER_TCP,USER_DNS,USER_PIPE,USER_AUDIO} user_file_service_t;
'''
for path,name,kind in [('include/syscall_defs.h','syscall_stat_t','struct'),
                       ('include/hda.h','hda_pcm_status_t','struct'),
                       ('include/io_tcp.h','io_tcp_opcode_t','enum'),
                       ('include/io_pipe.h','io_pipe_opcode_t','enum'),
                       ('include/io_audio.h','io_audio_opcode_t','enum'),
                       ('include/io_vfs.h','io_vfs_opcode_t','enum'),
                       ('include/io_tcp.h','io_tcp_operation_t','struct'),
                       ('include/io_pipe.h','io_pipe_operation_t','struct'),
                       ('include/io_audio.h','io_audio_operation_t','struct'),
                       ('include/io_vfs.h','io_vfs_operation_t','struct')]:
    program+=typedef(path,name,kind)
for path,name,kind in [('include/net/udp.h', 'net_udp_packet_info_t', 'struct'), ('include/net/udp.h', 'net_udp_socket_info_t', 'struct'), ('include/alix_network.h', 'alix_udp_packet_info_t', 'struct'), ('include/io_udp.h', 'io_udp_state_t', 'struct')]:
    program+=typedef(path,name,kind)
program+=r'''
typedef struct {unsigned kind,refs;} fd_description_t;
typedef struct {fd_description_t *description;size_t size;unsigned char buffer[65536];} io_request_t;
static fd_description_t description;
static io_request_t pending;
static unsigned guard,live,submits,copy_calls;
static int fail_alloc=-1,fail_copy=-1,fail_create,fail_submit;
static bool registered,cancelled;
static ssize_t worker_result;
static const void *blocked_pointer;
static void spinlock_preempt_disable(void){CHECK(!guard);++guard;}
static void spinlock_preempt_enable(void){CHECK(guard==1 && !live);--guard;}
static void *checked_malloc(size_t bytes){CHECK(guard);if(fail_alloc==0)return NULL;void *p=malloc(bytes);CHECK(p);++live;return p;}
static void checked_free(void *p){if(p){CHECK(live);--live;free(p);}}
static bool user_copy_from_user(void *out,const void *in,size_t bytes){
    CHECK(guard);++copy_calls;if(fail_copy==0 || in==blocked_pointer || (uintptr_t)in<4096)return false;
    if(fail_copy>0)--fail_copy;memcpy(out,in,bytes);return true;
}
static int user_file_pin(uint64_t fd,fd_description_t **out){CHECK(guard);*out=NULL;if(fd!=3)return -EBADF;++description.refs;*out=&description;return 0;}
static void fd_description_put(fd_description_t *d){if(d){CHECK(d->refs);--d->refs;}}
static bool io_tcp_description_valid(fd_description_t *d){return d->kind==1;}
/* Transport sizing is exercised by the native TCP evaluations. */
static size_t io_tcp_capture_limit(fd_description_t*d,bool writing,size_t count){CHECK(guard&&io_tcp_description_valid(d));(void)writing;return count;}
/* This fixture has no local socket descriptions. */
static bool io_local_description_valid(const fd_description_t *d){(void)d;return false;}
/* This fixture models TCP/pipe/audio/storage descriptions, never UDP. */
static bool io_udp_description_valid(const fd_description_t *d){(void)d;return false;}
static bool io_pipe_description_valid(fd_description_t *d){return d->kind==2;}
static bool io_audio_description_valid(fd_description_t *d){return d->kind==3;}
static int user_file_create(user_file_service_t kind,size_t bytes,fd_description_t *d,void *cwd,io_request_t **out){
    (void)kind;CHECK(guard && !registered && !cwd && bytes<=sizeof(pending.buffer));
    if(fail_create){fd_description_put(d);return -ENOMEM;}
    memset(&pending,0,sizeof(pending));pending.description=d;pending.size=bytes;registered=true;*out=&pending;return 0;
}
static void *io_request_buffer(io_request_t *r){CHECK(registered);return r->buffer;}
static void user_file_abort(io_request_t *r){CHECK(guard && registered && r==&pending);registered=false;fd_description_put(r->description);}
static int user_file_submit(user_file_service_t kind,io_request_t *r){
    CHECK(guard && registered && !live && r==&pending);++submits;
    CHECK(kind==(description.kind==1?USER_TCP:description.kind==2?USER_PIPE:description.kind==3?USER_AUDIO:USER_STORAGE));
    if(fail_submit){user_file_abort(r);return -EAGAIN;}return 0;
}
static int64_t user_file_finish(user_file_service_t kind,uint32_t operation,void *out,size_t bytes,uint32_t flags){
    (void)kind;CHECK(!guard && registered && !live && operation==SYSCALL_FILE_WRITEV && !out && !bytes && !flags);
    registered=false;fd_description_put(pending.description);return cancelled?-ECANCELED:worker_result;
}
#define malloc checked_malloc
#define free checked_free
'''
program+=function_definition((ROOT/'src/kernel/io/user_file.c').read_text(),'static int64_t user_file_writev(')
program+=r'''
#undef malloc
#undef free
int main(void){
    syscall_iovec_t *v=calloc(1024,sizeof(*v));CHECK(v);
    unsigned char *a=malloc(70000),*b=malloc(70000);CHECK(a && b);memset(a,0x41,70000);memset(b,0x42,70000);
    v[0]=(syscall_iovec_t){(uintptr_t)a,3};v[1]=(syscall_iovec_t){1,0};v[2]=(syscall_iovec_t){(uintptr_t)b,5};
    for(unsigned kind=0;kind<4;++kind){
        description.kind=kind;worker_result=7;
        CHECK(user_file_writev(3,v,3)==7 && !registered && !description.refs);
        void *data;size_t count;uint32_t opcode;
        if(kind==1){io_tcp_operation_t *w=(void *)pending.buffer;data=w->data;count=w->count;opcode=w->opcode;CHECK(opcode==IO_TCP_WRITE && !w->flags);}
        else if(kind==2){io_pipe_operation_t *w=(void *)pending.buffer;data=w->data;count=w->count;opcode=w->opcode;CHECK(opcode==IO_PIPE_WRITE);}
        else if(kind==3){io_audio_operation_t *w=(void *)pending.buffer;data=w->data;count=w->count;opcode=w->opcode;CHECK(opcode==IO_AUDIO_WRITE);}
        else {io_vfs_operation_t *w=(void *)pending.buffer;data=w->data;count=w->count;opcode=w->opcode;CHECK(opcode==IO_VFS_WRITE);}
        CHECK(count==8 && !memcmp(data,"AAABBBBB",8));
    }
    description.kind=0;unsigned before=submits;
    CHECK(user_file_writev(3,v,1025)==-EINVAL && user_file_writev(9,v,3)==-EBADF && submits==before);
    for(int point=0;point<3;++point){fail_copy=point;CHECK(user_file_writev(3,v,3)==-EFAULT && !live && !registered && !description.refs && submits==before);}
    fail_copy=-1;fail_alloc=0;CHECK(user_file_writev(3,v,3)==-ENOMEM && !description.refs);fail_alloc=-1;
    fail_create=1;CHECK(user_file_writev(3,v,3)==-ENOMEM && !live && !description.refs);fail_create=0;
    fail_submit=1;CHECK(user_file_writev(3,v,3)==-EAGAIN && !registered && !live && !description.refs);fail_submit=0;
    cancelled=true;CHECK(user_file_writev(3,v,3)==-ECANCELED && !live && !description.refs);cancelled=false;
    v[0].length=INT64_MAX;v[2].length=1;before=submits;CHECK(user_file_writev(3,v,3)==-EINVAL && submits==before);
    v[0].length=70000;v[1].length=0;v[2].length=70000;worker_result=123;
    CHECK(user_file_writev(3,v,3)==123);
    io_vfs_operation_t *work=(void *)pending.buffer;CHECK(work->count==65536-sizeof(*work));
    for(size_t i=0;i<work->count;++i)CHECK(work->data[i]==0x41);
    worker_result=0;CHECK(user_file_writev(3,NULL,0)==0 && !live && !registered && !description.refs);
    free(a);free(b);free(v);puts("Production writev preparation contracts: PASS ownership copy faults admission cancellation overflow and bounded payload");return 0;
}
'''
compile_and_run('writev-preparation',program)
print('Production writev preparation contracts: PASS')
