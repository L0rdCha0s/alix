#!/usr/bin/env python3
"""Fault production message preparation/completion with owned request models."""
from audio_stream_contract_test import ROOT, compile_and_run, function_definition


def typedef(path, name, kind="struct"):
    source = (ROOT / path).read_text()
    end = source.index("} " + name + ";") + len("} " + name + ";")
    return source[source.rfind("typedef " + kind, 0, end):end] + "\n"


code = r'''
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#define CHECK(c) do{if(!(c)){fprintf(stderr,"message contract %d: %s\n",__LINE__,#c);abort();}}while(0)
#define SYSCALL_IOV_MAX 1024u
#define NET_UDP_MAX_PAYLOAD 1472u
#define IO_REQUEST_BUFFER_MAX 65536u
#define SYSCALL_FILE_NET_SENDMSG 100u
#define SYSCALL_FILE_NET_RECVMSG 101u
#define SYSCALL_MSG_PEEK 2u
#define SYSCALL_MSG_DONTWAIT 64u
#define SYSCALL_MSG_NOSIGNAL 16384u
#define ALIX_SIGPIPE 13
typedef enum {USER_TCP} user_file_service_t;
typedef struct {uint64_t base,length;} syscall_iovec_t;
'''
for path, name, kind in (
    ("include/syscall_defs.h", "syscall_msghdr_t", "struct"),
    ("include/io_tcp.h", "io_tcp_opcode_t", "enum"),
    ("include/io_tcp.h", "io_tcp_operation_t", "struct"),
    ("src/kernel/io/user_file.c", "user_message_metadata_t", "struct"),
    ("src/kernel/io/user_file.c", "user_message_prepare_t", "struct"),
):
    code += typedef(path, name, kind)
for path,name,kind in [('include/net/udp.h', 'net_udp_packet_info_t', 'struct'), ('include/net/udp.h', 'net_udp_socket_info_t', 'struct'), ('include/alix_network.h', 'alix_udp_packet_info_t', 'struct'), ('include/io_udp.h', 'io_udp_state_t', 'struct')]:
    code+=typedef(path,name,kind)
code += r'''
typedef struct {bool socket;unsigned refs;} fd_description_t;
typedef struct {fd_description_t *description;size_t size;_Alignas(16) unsigned char buffer[65536];} io_request_t;
typedef struct {int64_t result;} io_request_status_t;
static fd_description_t description={true,0};static io_request_t pending;
static unsigned guard, live, submits, signals;
static bool registered, fail_alloc, fail_create, fail_submit, cancelled;
static bool fail_realloc;
static uint64_t g_user_message_prepare_saved_bytes, g_user_message_empty_control_skips;
static int64_t response=8;
static const void *blocked;
static const char *expected_payload;
static void spinlock_preempt_disable(void){CHECK(!guard);++guard;}
static void spinlock_preempt_enable(void){CHECK(guard==1&&!live);--guard;}
static void *checked_calloc(size_t n,size_t bytes){CHECK(guard);if(fail_alloc)return NULL;void*p=calloc(n,bytes);CHECK(p);++live;return p;}
static void *checked_realloc(void*p,size_t bytes){CHECK(guard&&p&&live);if(fail_realloc)return NULL;void*q=realloc(p,bytes);CHECK(q);return q;}
static void checked_free(void*p){if(p){CHECK(guard&&live);--live;free(p);}}
static bool user_copy_from_user(void*out,const void*in,size_t bytes){CHECK(guard);if((uintptr_t)in<4096||in==blocked)return false;memcpy(out,in,bytes);return true;}
static bool user_copy_to_user(void*out,const void*in,size_t bytes){CHECK(guard);if((uintptr_t)out<4096||out==blocked)return false;memcpy(out,in,bytes);return true;}
static int user_file_pin(uint64_t fd,fd_description_t**out){CHECK(guard);*out=NULL;if(fd!=3)return -EBADF;++description.refs;*out=&description;return 0;}
static void fd_description_put(fd_description_t*d){if(d){CHECK(d->refs);--d->refs;}}
static bool io_tcp_description_valid(fd_description_t*d){return d&&d->socket;}
/* TCP-only dependency model; UDP is executed by native socket/Quinn tests. */
static bool io_udp_description_valid(const fd_description_t*d){(void)d;return false;}
static io_udp_state_t *io_udp_state(io_request_t*r){(void)r;CHECK(false);return NULL;}
/* This fixture models TCP messages; native browser/socketpair acceptance owns
 * SCM_RIGHTS behavior. Keep all local-only calls unreachable here. */
typedef struct io_local_control io_local_control_t;
#define IO_LOCAL_CONTROL_BYTES 272u
static bool io_local_description_valid(const fd_description_t*d){(void)d;return false;}
static void *process_fd_retirement_queue(void){CHECK(false);return NULL;}
static void *process_current_fd_table(void){CHECK(false);return NULL;}
static void *fd_description_context(fd_description_t*d){(void)d;CHECK(false);return NULL;}
static void *io_request_cwd(io_request_t*r){(void)r;CHECK(false);return NULL;}
static int io_local_control_create(void*q,fd_description_t**out){(void)q;(void)out;CHECK(false);return -EIO;}
static int io_local_control_capture(io_local_control_t*c,void*t,const void*d,size_t n){(void)c;(void)t;(void)d;(void)n;CHECK(false);return -EIO;}
static int io_local_control_install(io_local_control_t*c,void*t,size_t n,bool cloexec){(void)c;(void)t;(void)n;(void)cloexec;CHECK(false);return -EIO;}
static const void *io_local_control_output(io_local_control_t*c,size_t*n,uint32_t*f){(void)c;(void)n;(void)f;CHECK(false);return NULL;}
static void io_local_control_commit(io_local_control_t*c){(void)c;CHECK(false);}
static int user_file_create(user_file_service_t kind,size_t bytes,fd_description_t*d,void*cwd,io_request_t**out){
    CHECK(kind==USER_TCP&&guard&&!registered&&!cwd&&bytes<=65536);
    if(fail_create){fd_description_put(d);return -ENOMEM;}
    memset(&pending,0,sizeof(pending));pending.description=d;pending.size=bytes;registered=true;*out=&pending;return 0;
}
static void *io_request_buffer(io_request_t*r){CHECK(guard&&registered&&r==&pending);return r->buffer;}
static size_t io_request_buffer_size(io_request_t*r){CHECK(r==&pending);return r->size;}
static fd_description_t *io_request_description(io_request_t*r){CHECK(guard&&registered&&r==&pending);return r->description;}
static void user_file_abort(io_request_t*r){CHECK(guard&&registered&&r==&pending);registered=false;fd_description_put(r->description);}
static int user_file_submit(user_file_service_t kind,io_request_t*r){
    CHECK(kind==USER_TCP&&guard&&registered&&!live&&r==&pending);++submits;
    io_tcp_operation_t*w=(void*)r->buffer;CHECK(!w->reserved&&!w->padding&&w->count<=r->size-sizeof(*w));
    if(expected_payload&&w->opcode==IO_TCP_WRITE)CHECK(w->count==8&&!memcmp(w->data,expected_payload,8));
    if(fail_submit){user_file_abort(r);return -EAGAIN;}return 0;
}
static int process_io_wait_current(io_request_status_t*s){
    CHECK(!guard&&registered&&!live);if(cancelled)return -ECANCELED;
    io_tcp_operation_t*w=(void*)pending.buffer;
    s->result=response;
    if(response>=0){s->result=w->count<(uint64_t)response?(int64_t)w->count:response;
        if(w->opcode==IO_TCP_READ)for(int64_t i=0;i<s->result;++i)w->data[i]=(unsigned char)i;}
    return 0;
}
static int process_io_result_current(io_request_t**r,io_request_status_t*s){(void)s;CHECK(guard&&registered);*r=&pending;return 0;}
static int process_io_finish_current(bool cancel){(void)cancel;CHECK(guard&&registered&&!live);registered=false;fd_description_put(pending.description);return 0;}
static int process_signal_raise(int signal,int code){CHECK(!guard&&!registered&&!live&&signal==13&&!code);++signals;return 0;}
#define calloc checked_calloc
#define realloc checked_realloc
#define free checked_free
'''
source = (ROOT / "src/kernel/io/user_file.c").read_text()
code += function_definition(source, "static int64_t user_file_message_finish(")
code += function_definition(source, "static int64_t user_file_message(")
code += r'''
#undef calloc
#undef realloc
#undef free
static void clean(void){CHECK(!guard&&!registered&&!live&&!description.refs);}
int main(void){
    syscall_msghdr_t*m=calloc(1,sizeof(*m));syscall_iovec_t*v=calloc(1024,sizeof(*v));
    unsigned char*a=calloc(70000,1),*b=calloc(70000,1);CHECK(m&&v&&a&&b);
    memcpy(a,"ABC",3);memcpy(b,"DEFGH",5);v[0]=(syscall_iovec_t){(uintptr_t)a,3};
    v[1]=(syscall_iovec_t){1,0};v[2]=(syscall_iovec_t){(uintptr_t)b,5};
    m->vectors=(uintptr_t)v;m->vector_count=3;expected_payload="ABCDEFGH";
    CHECK(user_file_message(100,3,m,16384)==8);clean();CHECK(submits==1);
    expected_payload=NULL;response=8;memset(a,0xa5,8);memset(b,0xa5,8);
    m->flags=1234;m->control=1;m->control_length=64;
    CHECK(user_file_message(101,3,m,2)==8);clean();
    CHECK(!m->flags&&!m->control_length&&!m->name_length);
    for(unsigned i=0;i<3;++i)CHECK(a[i]==i);for(unsigned i=0;i<5;++i)CHECK(b[i]==i+3);
    unsigned prior=submits;
    CHECK(user_file_message(100,3,NULL,0)==-EFAULT);clean();
    m->vector_count=1025;CHECK(user_file_message(100,3,m,0)==-EINVAL);clean();m->vector_count=3;
    m->vector_count=5;fail_realloc=true;CHECK(user_file_message(100,3,m,0)==-ENOMEM);clean();fail_realloc=false;
    /* Growing captures the original header and copies only the supplied table. */
    m->vector_count=1024;CHECK(user_file_message(101,3,m,0)==8);clean();m->vector_count=3;prior=submits;
    m->vectors=1;CHECK(user_file_message(100,3,m,0)==-EFAULT);clean();m->vectors=(uintptr_t)v;
    v[2].base=1;CHECK(user_file_message(100,3,m,0)==-EFAULT);clean();v[2].base=(uintptr_t)b;
    v[0].length=INT64_MAX;v[2].length=1;
    CHECK(user_file_message(100,3,m,0)==-EINVAL);clean();v[0].length=3;v[2].length=5;
    m->name=1;CHECK(user_file_message(100,3,m,0)==-EOPNOTSUPP);clean();m->name=0;
    m->control_length=1;CHECK(user_file_message(100,3,m,0)==-EOPNOTSUPP);clean();m->control_length=0;
    CHECK(user_file_message(100,3,m,2)==-EOPNOTSUPP);clean();
    CHECK(user_file_message(100,4,m,0)==-EBADF);clean();
    description.socket=false;CHECK(user_file_message(100,3,m,0)==-ENOTSOCK);clean();description.socket=true;
    fail_alloc=true;CHECK(user_file_message(100,3,m,0)==-ENOMEM);clean();fail_alloc=false;
    fail_create=true;CHECK(user_file_message(100,3,m,0)==-ENOMEM);clean();fail_create=false;
    CHECK(submits==prior);
    fail_submit=true;CHECK(user_file_message(100,3,m,0)==-EAGAIN);clean();fail_submit=false;
    cancelled=true;CHECK(user_file_message(101,3,m,0)==-ECANCELED);clean();cancelled=false;
    blocked=b;CHECK(user_file_message(101,3,m,0)==-EFAULT);clean();blocked=NULL;
    blocked=&m->flags;CHECK(user_file_message(101,3,m,0)==-EFAULT);clean();blocked=NULL;
    response=-EPIPE;CHECK(user_file_message(100,3,m,0)==-EPIPE);clean();CHECK(signals==1);
    CHECK(user_file_message(100,3,m,16384)==-EPIPE);clean();CHECK(signals==1);
    response=0;CHECK(!user_file_message(101,3,m,0)&&!m->flags&&!m->control_length);clean();
    free(a);free(b);free(v);free(m);
}
'''
compile_and_run("socket-message", code)
print("Socket message contract: PASS gather/scatter, capture/allocation/admission/submit/cancel faults, output, EOF, SIGPIPE")
