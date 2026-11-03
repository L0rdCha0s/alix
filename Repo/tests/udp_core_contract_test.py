#!/usr/bin/env python3
"""Execute production UDP/port ownership, packet validation and SMP queue paths."""
import os
import re
import shlex
from audio_stream_contract_test import ROOT, compile_and_run

os.environ["HOST_CC"] = os.environ.get("HOST_CC", "cc") + " -pthread -iquote " + shlex.quote(str(ROOT / "include"))
code = r'''
#define TTF_HOST_BUILD 1
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <stdatomic.h>
#include <pthread.h>
#include <sched.h>
#include "net/udp.h"
#include "net/route.h"
#define CHECK(c) do{if(!(c)){fprintf(stderr,"UDP contract %d: %s\n",__LINE__,#c);abort();}}while(0)
typedef struct {atomic_bool value;} spinlock_t;
static _Thread_local spinlock_t *held[8];static _Thread_local unsigned depth;
static uint64_t spinlock_lock_irqsave(spinlock_t *lock){
    CHECK(depth<8);for(unsigned i=0;i<depth;++i)CHECK(held[i]!=lock);
    while(atomic_exchange_explicit(&lock->value,true,memory_order_acquire))sched_yield();held[depth++]=lock;return 0;
}
static void spinlock_unlock_irqrestore(spinlock_t *lock,uint64_t flags){CHECK(!flags&&depth&&held[depth-1]==lock);--depth;atomic_store_explicit(&lock->value,false,memory_order_release);}
static spinlock_t config_lock;
static atomic_int live,fail_allocation=-1;
static void *checked_malloc(size_t n){int fail=atomic_load(&fail_allocation);if(!fail)return NULL;if(fail>0)atomic_fetch_sub(&fail_allocation,1);void*p=malloc(n);if(p)atomic_fetch_add(&live,1);return p;}
static void *checked_calloc(size_t n,size_t z){void*p=checked_malloc(n*z);if(p)memset(p,0,n*z);return p;}
static void checked_free(void*p){if(p){CHECK(atomic_fetch_sub(&live,1)>0);free(p);}}
static net_interface_t interface={.name="test0",.present=true,.link_up=true,.ipv4_addr=0x0a00020f,.ipv4_netmask=0xffffff00,.ipv4_gateway=0x0a000202,.mtu=1500,.mac={2,3,4,5,6,7}};
uint64_t net_config_lock(void){return spinlock_lock_irqsave(&config_lock);}
void net_config_unlock(uint64_t flags){spinlock_unlock_irqrestore(&config_lock,flags);}
size_t net_if_count(void){return 1;}
net_interface_t *net_if_at(size_t i){return i?NULL:&interface;}
net_interface_t *net_if_by_name(const char*n){return strcmp(n,"test0")?NULL:&interface;}
bool net_route_ipv4_snapshot(uint32_t ip,alix_net_route_info_t*out){
    if(!ip||(ip>>24)==127||(ip>>24)>=224)return false;
    *out=(alix_net_route_info_t){.version=1,.mtu=1500,.source_ipv4=0x0a00020f,.next_hop_ipv4=(ip&0xffffff00)==0x0a000200?ip:0x0a000202,.interface_name="test0"};return true;
}
static uint64_t now_ms=100;static bool arp_ready=true;static unsigned arp_requests,transmissions;
static unsigned char capture[1514];static size_t capture_size;
uint64_t timer_monotonic_millis(void){return now_ms;}
bool net_arp_lookup(uint32_t ip,uint8_t mac[6]){CHECK(ip);if(!arp_ready)return false;memset(mac,0xaa,6);return true;}
bool net_arp_send_request(net_interface_t*iface,uint32_t ip){CHECK(iface==&interface&&ip);++arp_requests;return true;}
bool net_if_send_copy(net_interface_t*iface,const uint8_t*frame,size_t bytes){CHECK(!depth&&iface==&interface&&bytes<=sizeof(capture));memcpy(capture,frame,bytes);capture_size=bytes;++transmissions;return true;}
#define malloc checked_malloc
#define calloc checked_calloc
#define free checked_free
'''
for name in ("src/net/udp_ports.c", "src/net/udp.c"):
    code += re.sub(r'^#include[^\n]*\n', '', (ROOT / name).read_text(), flags=re.M)
code += r'''
#undef malloc
#undef calloc
#undef free
typedef struct {net_udp_socket_t*socket;unsigned number,failed;} worker_t;
static atomic_uint completed;
static void *worker(void*argument){
    worker_t*w=argument;unsigned char *data=calloc(128,1);net_udp_packet_info_t*meta=calloc(1,sizeof(*meta));CHECK(data&&meta);
    for(unsigned n=0;n<128;++n){
        size_t length=n%11?17+n%100:0;
        for(size_t i=0;i<length;++i)data[i]=(unsigned char)(w->number+n+i);
        CHECK(net_udp_socket_get_owned(w->socket));
        ssize_t sent;do{sent=net_udp_socket_send_owned(w->socket,data,length,0,0,-1,0,NULL);if(sent==-EAGAIN)sched_yield();}while(sent==-EAGAIN);CHECK(sent==(ssize_t)length);
        CHECK(!net_udp_socket_put_owned(w->socket));
        ssize_t count;do{count=net_udp_socket_recv_owned(w->socket,data,128,false,meta);if(count==-EAGAIN)sched_yield();}while(count==-EAGAIN);
        CHECK(count==(ssize_t)length&&meta->length==length&&meta->source_ip==0x0a00020f&&meta->source_port==35000&&meta->tos==(w->number&3));
        for(size_t i=0;i<length;++i)CHECK(data[i]==(unsigned char)(w->number+n+i));
    }
    free(meta);free(data);atomic_fetch_add(&completed,1);return NULL;
}
int main(void){
    unsigned char*data=calloc(2048,1);net_udp_packet_info_t*meta=calloc(1,sizeof(*meta));net_udp_socket_info_t*info=calloc(1,sizeof(*info));CHECK(data&&meta&&info);
    void*owner=calloc(1,1);uint16_t claimed=0;
    CHECK(!net_udp_port_claim(owner,0,49152,&claimed)&&claimed==49152);
    net_udp_socket_t*a=net_udp_socket_open_owned(),*b=net_udp_socket_open_owned();CHECK(a&&b);
    CHECK(net_udp_socket_bind_owned(a,0,49152)==-EADDRINUSE);
    CHECK(!net_udp_socket_bind_owned(a,0,0));CHECK(!net_udp_socket_info_owned(a,info)&&info->local_port!=49152);
    net_udp_port_release(owner);CHECK(!net_udp_socket_bind_owned(b,0,49152));
    CHECK(net_udp_socket_bind_owned(b,0,1)==-EINVAL);
    CHECK(net_udp_socket_option_owned(a,NET_UDP_TOS,256)==-EINVAL);
    CHECK(!net_udp_socket_option_owned(a,NET_UDP_TOS,2));
    CHECK(net_udp_socket_send_owned(a,data,1473,0x0a000202,40000,-1,0,NULL)==-EMSGSIZE);
    arp_ready=false;uint64_t next=0;
    CHECK(net_udp_socket_send_owned(a,data,1,0x0a000202,40000,-1,0,&next)==-EAGAIN&&arp_requests==1);
    CHECK(net_udp_socket_send_owned(a,data,1,0x0a000202,40000,-1,0,&next)==-EAGAIN&&arp_requests==1);
    now_ms=351;CHECK(net_udp_socket_send_owned(a,data,1,0x0a000202,40000,-1,0,&next)==-EAGAIN&&arp_requests==2);arp_ready=true;
    CHECK(net_udp_socket_send_owned(a,data,17,0x0a000202,40000,-1,0,&next)==17&&capture_size==59&&transmissions==1);
    CHECK(capture[14]==0x45&&capture[15]==2&&capture[20]==0x40&&capture[23]==17);
    CHECK(udp_sum(0,capture+14,20)==65535&&udp_checksum(capture+14,capture+34,25)==0);
    /* Reflect a valid captured packet to the receiving socket, then corrupt
     * independent length/fragment/checksum fields. Real wire checks follow in QEMU. */
    udp_put32(capture+26,0x0a000202);udp_put32(capture+30,0x0a00020f);
    udp_put16(capture+34,40000);udp_put16(capture+36,49152);
    udp_put16(capture+24,0);udp_put16(capture+24,(uint16_t)~udp_sum(0,capture+14,20));
    udp_put16(capture+40,0);udp_put16(capture+40,udp_checksum(capture+14,capture+34,25));
    CHECK(!net_udp_handle_frame(&interface,capture,30));
    capture[24]^=1;CHECK(!net_udp_handle_frame(&interface,capture,capture_size));capture[24]^=1;
    capture[42]^=1;CHECK(!net_udp_handle_frame(&interface,capture,capture_size));capture[42]^=1;
    CHECK(net_udp_handle_frame(&interface,capture,capture_size));
    CHECK(net_udp_socket_recv_owned(b,data,7,true,meta)==7&&meta->length==17&&meta->source_port==40000&&meta->tos==2);
    CHECK(!net_udp_socket_info_owned(b,info)&&(info->flags&NET_UDP_READABLE)&&info->available==17);
    CHECK(net_udp_socket_recv_owned(b,data,4,false,meta)==4&&net_udp_socket_recv_owned(b,data,128,false,meta)==-EAGAIN);
    atomic_store(&fail_allocation,0);CHECK(net_udp_handle_frame(&interface,capture,capture_size));atomic_store(&fail_allocation,-1);
    CHECK(!net_udp_socket_info_owned(b,info)&&info->dropped_packets==1);
    for(unsigned i=0;i<129;++i)CHECK(net_udp_handle_frame(&interface,capture,capture_size));
    CHECK(!net_udp_socket_info_owned(b,info)&&info->dropped_packets==2&&info->queued_bytes==128*17);
    CHECK(net_udp_socket_option_owned(b,NET_UDP_RECV_BUFFER,256)==-EBUSY);
    for(unsigned i=0;i<128;++i)CHECK(net_udp_socket_recv_owned(b,data,128,false,meta)==17);
    CHECK(!net_udp_socket_put_owned(a)&&!net_udp_socket_put_owned(b));
    CHECK(!net_udp_socket_get_owned(a)&&net_udp_socket_put_owned((void*)1)==-EBADF);
    CHECK(atomic_load(&live)==0);
    net_udp_socket_t*server=net_udp_socket_open_owned();CHECK(server&&!net_udp_socket_bind_owned(server,0,35000));
    worker_t*workers=calloc(8,sizeof(*workers));pthread_t*threads=calloc(8,sizeof(*threads));CHECK(workers&&threads);
    for(unsigned i=0;i<8;++i){workers[i].number=i;workers[i].socket=net_udp_socket_open_owned();CHECK(workers[i].socket);
        CHECK(!net_udp_socket_connect_owned(workers[i].socket,0x0a00020f,35000));CHECK(!net_udp_socket_option_owned(workers[i].socket,NET_UDP_TOS,i&3));
        CHECK(!pthread_create(&threads[i],NULL,worker,&workers[i]));}
    unsigned received=0;
    while(received<1024){ssize_t count=net_udp_socket_recv_owned(server,data,2048,false,meta);
        if(count==-EAGAIN){sched_yield();continue;}CHECK(count>=0&&meta->length==(uint32_t)count&&meta->interface_index==1);
        ssize_t sent;do{sent=net_udp_socket_send_owned(server,data,(size_t)count,meta->source_ip,meta->source_port,meta->tos,0,NULL);if(sent==-EAGAIN)sched_yield();}while(sent==-EAGAIN);CHECK(sent==count);++received;}
    for(unsigned i=0;i<8;++i){CHECK(!pthread_join(threads[i],NULL));CHECK(!net_udp_socket_put_owned(workers[i].socket));}
    CHECK(atomic_load(&completed)==8&&!net_udp_socket_put_owned(server)&&atomic_load(&live)==0);
    free(threads);free(workers);free(owner);free(info);free(meta);free(data);
    puts("UDP_CORE: PASS workers=8 datagrams=2048 lease_conflicts=1 checksums=1 malformed=1 bounds=1 peek=1 truncation=1 zero=1 queue_limits=1 allocation_failure=1 cleanup=1");
}
'''
compile_and_run("udp-core", code)
print("Production UDP core contract: PASS eight workers, 2048 datagrams, ownership/validation/queue and port-lease cases")
