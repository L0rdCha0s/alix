#!/usr/bin/env python3
"""Exercise production TCP pool ownership without replacing transport behavior."""
import os
import shlex
import sys
sys.dont_write_bytecode = True
from audio_stream_contract_test import ROOT, compile_and_run, function_definition

source = (ROOT / 'src/net/tcp.c').read_text()
header = (ROOT / 'include/net/tcp.h').read_text()
enum_end = source.index('} tcp_state_t;') + len('} tcp_state_t;')
enum_start = source.rfind('typedef enum', 0, enum_end)
struct_start = source.index('struct net_tcp_socket\n{')
struct_end = source.index('\n};', struct_start) + 3
status_start = header.index('#define NET_TCP_OWNED_CONNECTED')
status_end = header.index('} net_tcp_owned_info_t;') + len('} net_tcp_owned_info_t;')
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
#define CHECK(x) do { if(!(x)) { fprintf(stderr,"TCP owned line %d: %s\n",__LINE__,#x); abort(); } } while(0)
#define NET_TCP_MAX_SOCKETS 1024
#define NET_TCP_MAX_PAYLOAD 1460
#define NET_TCP_DEFAULT_MSS 1460
#define NET_TCP_LOCAL_WINDOW_SCALE 2
#define TCP_FLAG_FIN 1
#define TCP_FLAG_ACK 16
#define TCP_TRACE_VERBOSE 0
#define TCP_LOG(...) ((void)0)
typedef struct net_tcp_socket net_tcp_socket_t;
typedef struct { unsigned unused; } net_interface_t;
typedef struct { unsigned unused; } tcp_reass_segment_t;
typedef struct { unsigned unused; } thread_t;
typedef struct { unsigned initialized,wakes; } wait_queue_t;
static void wait_queue_init(wait_queue_t *q) { q->initialized=1;q->wakes=0; }
static void wait_queue_wake_all(wait_queue_t *q) { CHECK(q->initialized);++q->wakes; }
static pthread_mutex_t mutex=PTHREAD_MUTEX_INITIALIZER;
static _Thread_local bool locked;
static _Thread_local unsigned preempt;
static uint64_t tcp_lock(void) { CHECK(!locked);CHECK(!pthread_mutex_lock(&mutex));locked=true;return 0; }
static void tcp_unlock(uint64_t flags) { CHECK(!flags&&locked);locked=false;CHECK(!pthread_mutex_unlock(&mutex)); }
static void spinlock_preempt_disable(void) { CHECK(locked);++preempt; }
static void spinlock_preempt_enable(void) { CHECK(locked&&preempt);--preempt; }
static unsigned stage_failure,legacy_allocations,legacy_releases,owner_queries,buffers;
static bool legacy_full,send_succeeds;
static int g_tcp_fd_ops;
static uint64_t g_connect_timeout_ticks=400;
static uint64_t timer_ticks(void) { return 123; }
static thread_t *thread_current(void) { CHECK(locked);++owner_queries;return (thread_t *)(uintptr_t)0x1234; }
static int fd_allocate(const void *ops,void *context) { CHECK(locked&&ops==&g_tcp_fd_ops&&context);++legacy_allocations;return legacy_full?-1:17; }
static void fd_release(int fd) { CHECK(locked&&fd==17);++legacy_releases; }
'''+source[enum_start:enum_end]+'\n'+source[struct_start:struct_end]+'\n'+header[status_start:status_end]+r'''
static net_tcp_socket_t g_sockets[NET_TCP_MAX_SOCKETS];
static void tcp_reassembly_clear(net_tcp_socket_t *socket) { CHECK(locked&&socket); }
static void *buffer_allocate(void) { void *p=malloc(64);CHECK(p);++buffers;return p; }
static void buffer_free(void *p) { CHECK(locked&&buffers);--buffers;free(p); }
static bool tcp_init_rx_buffer(net_tcp_socket_t *s) { CHECK(locked);if(stage_failure==1)return false;s->rx_buffer=buffer_allocate();s->rx_capacity=64;return true; }
static bool tcp_init_tx_buffer(net_tcp_socket_t *s) { CHECK(locked);if(stage_failure==2)return false;s->tx_frame=buffer_allocate();s->tx_frame_capacity=64;return true; }
static uint16_t tcp_allocate_port(void) { CHECK(locked);return stage_failure==3?0:49152; }
static bool tcp_send_segment(net_tcp_socket_t *s,uint32_t seq,uint8_t flags,const uint8_t *data,size_t len,bool advance,bool track) {
    CHECK(locked&&s&&seq==s->seq_next&&flags==(TCP_FLAG_FIN|TCP_FLAG_ACK)&&!data&&!len&&advance&&track);return send_succeeds;
}
'''
for signature in ('static inline void tcp_signal_read_event(', 'static void tcp_mark_error(', 'static void tcp_reset_socket(',
                  'static net_tcp_socket_t *tcp_socket_open_internal(', 'net_tcp_socket_t *net_tcp_socket_open(',
                  'net_tcp_socket_t *net_tcp_socket_open_owned(', 'static bool tcp_socket_in_pool(',
                  'bool net_tcp_socket_get_owned(', 'static bool tcp_owned_retire_poll_locked(',
                  'static int tcp_owned_transport_pin_locked(', 'static void tcp_owned_transport_unpin_locked(', 'int net_tcp_socket_put_owned(',
                  'static size_t tcp_write_capacity_locked(',
                  'int net_tcp_socket_owned_snapshot(', 'int net_tcp_socket_info_owned(',
                  'int net_tcp_socket_error_claim_owned(', 'int net_tcp_socket_error_finish_owned(',
                  'ssize_t net_tcp_socket_peek_owned(', 'void net_tcp_socket_close(',
                  'void net_tcp_socket_release('):
    text = function_definition(source, signature)
    if signature.startswith('static void tcp_reset_socket'):
        text = text.replace('free(socket->rx_buffer);', 'buffer_free(socket->rx_buffer);')
        text = text.replace('free(socket->tx_frame);', 'buffer_free(socket->tx_frame);')
    code += text + '\n'
code += r'''
static void failures_and_modes(void) {
    for(stage_failure=1;stage_failure<=3;++stage_failure) {
        CHECK(!net_tcp_socket_open_owned(NULL)&&!buffers&&!legacy_allocations&&!owner_queries);
        CHECK(g_sockets[0].state==TCP_STATE_UNUSED&&!g_sockets[0].owned_references);
    }
    stage_failure=0;legacy_full=true;
    CHECK(!net_tcp_socket_open(NULL)&&!buffers&&legacy_allocations==1&&!owner_queries);
    net_tcp_socket_t *socket=net_tcp_socket_open_owned(NULL);CHECK(socket==g_sockets&&buffers==2&&legacy_allocations==1&&!owner_queries);
    CHECK(socket->fd==-1&&!socket->fd_registered&&!socket->owner&&socket->owned_references==1);
    CHECK(net_tcp_socket_get_owned(socket));
    net_tcp_socket_release(socket);CHECK(socket->owned_references==2&&socket->state==TCP_STATE_CLOSED&&buffers==2);
    net_tcp_socket_close(socket);CHECK(socket->owned_references==2&&socket->remote_closed&&socket->wait_queue.wakes==1);
    net_tcp_owned_status_t status={0};CHECK(!net_tcp_socket_owned_snapshot(socket,&status)&&status.references==2&&status.flags==NET_TCP_OWNED_EOF&&status.event_sequence==1);
    uint64_t flags=tcp_lock();socket->owned_references=UINT32_MAX;tcp_unlock(flags);
    CHECK(!net_tcp_socket_get_owned(socket));
    flags=tcp_lock();socket->owned_references=2;socket->state=TCP_STATE_ESTABLISHED;socket->remote_closed=false;socket->rx_size=7;tcp_unlock(flags);
    CHECK(!net_tcp_socket_owned_snapshot(socket,&status)&&status.available==7&&status.flags==(NET_TCP_OWNED_CONNECTED|NET_TCP_OWNED_READABLE|NET_TCP_OWNED_WRITABLE));
    CHECK(status.write_capacity==1460);
    flags=tcp_lock();socket->awaiting_ack=true;socket->pending_payload_len=socket->unacked_len=400;tcp_unlock(flags);
    CHECK(!net_tcp_socket_owned_snapshot(socket,&status)&&status.write_capacity==1060&&(status.flags&NET_TCP_OWNED_WRITABLE));
    flags=tcp_lock();socket->remote_window=450;tcp_unlock(flags);
    CHECK(!net_tcp_socket_owned_snapshot(socket,&status)&&status.write_capacity==50&&(status.flags&NET_TCP_OWNED_WRITABLE));
    flags=tcp_lock();socket->remote_window=400;tcp_unlock(flags);
    CHECK(!net_tcp_socket_owned_snapshot(socket,&status)&&!status.write_capacity&&!(status.flags&NET_TCP_OWNED_WRITABLE));
    flags=tcp_lock();socket->remote_window=4096;socket->pending_payload_len=socket->unacked_len=1460;tcp_unlock(flags);
    CHECK(!net_tcp_socket_owned_snapshot(socket,&status)&&!status.write_capacity&&!(status.flags&NET_TCP_OWNED_WRITABLE));
    flags=tcp_lock();socket->awaiting_ack=false;socket->pending_payload_len=socket->unacked_len=0;tcp_unlock(flags);
    unsigned char *peek=malloc(16);CHECK(peek);memset(peek,0x5a,16);
    flags=tcp_lock();socket->rx_head=3;memcpy(socket->rx_buffer+3,"payload",7);tcp_unlock(flags);
    CHECK(net_tcp_socket_peek_owned(socket,peek,4)==4&&!memcmp(peek,"payl",4)&&peek[4]==0x5a);
    CHECK(socket->rx_head==3&&socket->rx_size==7&&socket->read_event_seq==status.event_sequence);
    CHECK(net_tcp_socket_peek_owned(socket,NULL,0)==0&&net_tcp_socket_peek_owned(socket,NULL,1)==-EINVAL);
    CHECK(net_tcp_socket_peek_owned(NULL,peek,4)==-EINVAL);free(peek);
    send_succeeds=true;net_tcp_socket_close(socket);CHECK(socket->state==TCP_STATE_FIN_WAIT_1&&socket->owned_references==2);
    CHECK(!net_tcp_socket_put_owned(socket)&&socket->owned_references==1&&buffers==2);
    CHECK(!net_tcp_socket_put_owned(socket)&&socket->owned_retiring&&socket->state==TCP_STATE_FIN_WAIT_1&&buffers==2&&!legacy_releases);
    CHECK(!net_tcp_socket_get_owned(socket)&&net_tcp_socket_owned_snapshot(socket,&status)==-EBADF);
    flags=tcp_lock();socket->state=TCP_STATE_CLOSED;CHECK(tcp_owned_retire_poll_locked(socket,123));tcp_unlock(flags);
    CHECK(socket->state==TCP_STATE_UNUSED&&!buffers);
    CHECK(net_tcp_socket_put_owned(socket)==-EBADF&&!net_tcp_socket_get_owned(socket)&&net_tcp_socket_owned_snapshot(socket,&status)==-EBADF);
    CHECK(!net_tcp_socket_get_owned(NULL)&&!net_tcp_socket_get_owned((void *)1)&&!net_tcp_socket_get_owned((void *)((char *)g_sockets+1)));
    CHECK(net_tcp_socket_put_owned((void *)1)==-EINVAL&&net_tcp_socket_owned_snapshot(NULL,&status)==-EINVAL&&net_tcp_socket_owned_snapshot(socket,NULL)==-EINVAL);
    legacy_full=false;socket=net_tcp_socket_open(NULL);CHECK(socket==g_sockets&&socket->fd==17&&socket->fd_registered&&socket->owner&&!socket->owned_references&&owner_queries==1);
    CHECK(!net_tcp_socket_get_owned(socket)&&net_tcp_socket_put_owned(socket)==-EBADF);net_tcp_socket_release(socket);CHECK(!buffers&&legacy_releases==1);
}
static void retiring_transport(void) {
    net_tcp_socket_t *socket=net_tcp_socket_open_owned(NULL);CHECK(socket==g_sockets);
    uint64_t flags=tcp_lock();socket->state=TCP_STATE_ESTABLISHED;socket->awaiting_ack=true;tcp_unlock(flags);
    CHECK(!net_tcp_socket_put_owned(socket)&&socket->owned_retiring&&socket->state==TCP_STATE_ESTABLISHED&&buffers==2);
    net_tcp_socket_t *other=net_tcp_socket_open_owned(NULL);CHECK(other&&other!=socket);CHECK(!net_tcp_socket_put_owned(other));
    flags=tcp_lock();CHECK(!tcp_owned_retire_poll_locked(socket,124)&&socket->state==TCP_STATE_ESTABLISHED);
    socket->awaiting_ack=false;send_succeeds=true;
    CHECK(!tcp_owned_retire_poll_locked(socket,125)&&socket->state==TCP_STATE_FIN_WAIT_1);
    socket->state=TCP_STATE_FIN_WAIT_2;
    CHECK(tcp_owned_retire_poll_locked(socket,socket->connect_deadline)&&socket->state==TCP_STATE_UNUSED);tcp_unlock(flags);CHECK(!buffers);
    socket=net_tcp_socket_open_owned(NULL);CHECK(socket==g_sockets);
    flags=tcp_lock();socket->state=TCP_STATE_CLOSE_WAIT;socket->remote_closed=true;tcp_unlock(flags);
    CHECK(!net_tcp_socket_put_owned(socket)&&socket->owned_retiring&&socket->state==TCP_STATE_LAST_ACK);
    flags=tcp_lock();socket->state=TCP_STATE_CLOSED;CHECK(tcp_owned_retire_poll_locked(socket,124));tcp_unlock(flags);CHECK(!buffers);
    socket=net_tcp_socket_open_owned(NULL);CHECK(socket==g_sockets);
    flags=tcp_lock();socket->state=TCP_STATE_ESTABLISHED;tcp_unlock(flags);send_succeeds=false;
    CHECK(!net_tcp_socket_put_owned(socket)&&socket->state==TCP_STATE_UNUSED&&!buffers);
    socket=net_tcp_socket_open_owned(NULL);CHECK(socket==g_sockets);
    flags=tcp_lock();int pin=tcp_owned_transport_pin_locked(socket);CHECK(pin==1&&socket->transport_users==1);tcp_unlock(flags);
    CHECK(!net_tcp_socket_put_owned(socket)&&socket->owned_retiring&&socket->transport_users==1&&buffers==2&&preempt==1);
    flags=tcp_lock();CHECK(!tcp_owned_retire_poll_locked(socket,9999));tcp_owned_transport_unpin_locked(socket,pin);
    CHECK(tcp_owned_retire_poll_locked(socket,9999));tcp_unlock(flags);CHECK(!buffers&&!preempt);
    socket=net_tcp_socket_open_owned(NULL);CHECK(socket==g_sockets);
    flags=tcp_lock();socket->transport_users=UINT32_MAX;CHECK(tcp_owned_transport_pin_locked(socket)==-EOVERFLOW&&socket->transport_users==UINT32_MAX);
    socket->transport_users=0;tcp_unlock(flags);CHECK(!net_tcp_socket_put_owned(socket)&&!buffers);
}
typedef struct { net_tcp_socket_t *socket;unsigned iterations; } worker_t;
static void *churn(void *argument) {
    worker_t *worker=argument;
    for(unsigned i=0;i<worker->iterations;++i) {
        CHECK(net_tcp_socket_get_owned(worker->socket));
        net_tcp_owned_status_t status;CHECK(!net_tcp_socket_owned_snapshot(worker->socket,&status)&&status.references>=2);
        CHECK(!net_tcp_socket_put_owned(worker->socket));
    }
    CHECK(!net_tcp_socket_put_owned(worker->socket));return NULL;
}
static void concurrent_owners(void) {
    net_tcp_socket_t *socket=net_tcp_socket_open_owned(NULL);CHECK(socket==g_sockets);
    pthread_t *threads=calloc(8,sizeof(*threads));worker_t *workers=calloc(8,sizeof(*workers));CHECK(threads&&workers);
    for(unsigned i=0;i<8;++i) { CHECK(net_tcp_socket_get_owned(socket));workers[i]=(worker_t){socket,10000};CHECK(!pthread_create(&threads[i],NULL,churn,&workers[i])); }
    for(unsigned i=0;i<2000;++i) { net_tcp_socket_t *other=net_tcp_socket_open_owned(NULL);CHECK(other&&other!=socket);CHECK(!net_tcp_socket_put_owned(other)); }
    for(unsigned i=0;i<8;++i) CHECK(!pthread_join(threads[i],NULL));
    net_tcp_owned_status_t status;CHECK(!net_tcp_socket_owned_snapshot(socket,&status)&&status.references==1&&buffers==2);
    CHECK(!net_tcp_socket_put_owned(socket)&&!buffers);
    socket=net_tcp_socket_open_owned(NULL);CHECK(socket==g_sockets&&!net_tcp_socket_put_owned(socket)&&!buffers);
    free(workers);free(threads);
}
typedef struct {net_tcp_socket_t *socket;unsigned *seen;} error_worker_t;
static void *read_error(void *argument) {
    error_worker_t *worker=argument;int32_t error=-1;uint64_t generation=0;int result;
    do{result=net_tcp_socket_error_claim_owned(worker->socket,&error,&generation);if(result==-EAGAIN)sched_yield();}while(result==-EAGAIN);
    CHECK(!result);if(error){CHECK(error==ECONNREFUSED);__atomic_add_fetch(worker->seen,1,__ATOMIC_RELAXED);}
    if(generation){sched_yield();CHECK(!net_tcp_socket_error_finish_owned(worker->socket,generation,true));}
    CHECK(!net_tcp_socket_put_owned(worker->socket));return NULL;
}
static void endpoint_and_error_claims(void) {
    net_tcp_socket_t *socket=net_tcp_socket_open_owned(NULL);CHECK(socket);
    net_tcp_owned_info_t info;CHECK(!net_tcp_socket_info_owned(socket,&info)&&!info.local_port&&!info.local_ip&&!info.flags);
    uint64_t flags=tcp_lock();socket->local_ip=0x0a00020f;socket->remote_ip=0x0a000202;socket->remote_port=443;socket->state=TCP_STATE_ESTABLISHED;tcp_unlock(flags);
    CHECK(!net_tcp_socket_info_owned(socket,&info)&&info.local_ip==0x0a00020f&&info.remote_ip==0x0a000202&&info.local_port==49152&&info.remote_port==443&&info.receive_buffer==64&&info.send_buffer==1460&&info.mss==1460&&info.flags==NET_TCP_OWNED_CONNECTED);
    flags=tcp_lock();tcp_mark_error(socket,ECONNREFUSED,"refused");tcp_unlock(flags);
    int32_t error=0;uint64_t generation=0;
    CHECK(!net_tcp_socket_error_claim_owned(socket,&error,&generation)&&error==ECONNREFUSED&&generation);
    int32_t other=88;uint64_t untouched=99;
    CHECK(net_tcp_socket_error_claim_owned(socket,&other,&untouched)==-EAGAIN&&other==88&&untouched==99);
    CHECK(net_tcp_socket_error_finish_owned(socket,generation+1,true)==-EINVAL);
    CHECK(!net_tcp_socket_error_finish_owned(socket,generation,false)&&socket->pending_error==ECONNREFUSED);
    CHECK(!net_tcp_socket_error_claim_owned(socket,&error,&generation));
    flags=tcp_lock();tcp_mark_error(socket,ETIMEDOUT,"duplicate fatal event");CHECK(socket->pending_error==ECONNREFUSED);socket->error=false;tcp_mark_error(socket,ETIMEDOUT,"new generation");tcp_unlock(flags);
    CHECK(!net_tcp_socket_error_finish_owned(socket,generation,true)&&socket->pending_error==ETIMEDOUT);
    CHECK(!net_tcp_socket_error_claim_owned(socket,&error,&generation)&&error==ETIMEDOUT);
    CHECK(!net_tcp_socket_error_finish_owned(socket,generation,false));
    flags=tcp_lock();socket->error=false;tcp_mark_error(socket,ECONNREFUSED,"concurrent consumers");tcp_unlock(flags);
    pthread_t *threads=calloc(8,sizeof(*threads));error_worker_t *workers=calloc(8,sizeof(*workers));unsigned *seen=calloc(1,sizeof(*seen));CHECK(threads&&workers&&seen);
    for(unsigned i=0;i<8;++i){CHECK(net_tcp_socket_get_owned(socket));workers[i]=(error_worker_t){socket,seen};CHECK(!pthread_create(&threads[i],NULL,read_error,&workers[i]));}
    for(unsigned i=0;i<8;++i)CHECK(!pthread_join(threads[i],NULL));
    CHECK(*seen==1&&!socket->pending_error&&!socket->error_claim_generation);
    CHECK(!net_tcp_socket_put_owned(socket)&&!buffers);free(seen);free(workers);free(threads);
}
int main(void) { failures_and_modes();retiring_transport();concurrent_owners();endpoint_and_error_claims();puts("TCP_OWNED: PASS refs=80000 reuse_excluded=1 rollback=1 no_global_fd=1 legacy=1 overflow=1 FIN_lifetime=1 timeout=1 endpoints=1 error_transaction=1 error_once=1");return 0; }
'''
previous = os.environ.get('HOST_CC')
try:
    os.environ['HOST_CC'] = shlex.join(shlex.split(previous or 'cc') + ['-pthread'])
    compile_and_run('tcp-owned', code)
finally:
    if previous is None: os.environ.pop('HOST_CC', None)
    else: os.environ['HOST_CC'] = previous
print('Production TCP ownership contracts passed')
