#!/usr/bin/env python3
"""Exercise production registry/routing configuration with concurrent snapshots."""
import os
import re
import shlex
from audio_stream_contract_test import ROOT, compile_and_run, function_definition

os.environ["HOST_CC"] = os.environ.get("HOST_CC", "cc") + " -iquote " + shlex.quote(str(ROOT / "include"))
registry = (ROOT / "src/net/interface.c").read_text()
registry = registry[registry.index("static net_interface_t g_interfaces"):registry.index("static bool net_pointer_on_stack")]
route = re.sub(r'^#include[^\n]*\n', '', (ROOT / "src/net/route.c").read_text(), flags=re.M)
route = route.replace("static spinlock_t g_net_config_lock;",
                      "static spinlock_t g_net_config_lock = { PTHREAD_MUTEX_INITIALIZER };")
code = r'''
#define _XOPEN_SOURCE 700
#define TTF_HOST_BUILD 1
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <stdatomic.h>
#include <errno.h>
#include "net/route.h"
#define CHECK(c) do {if(!(c)){fprintf(stderr,"route contract %d: %s\n",__LINE__,#c);abort();}}while(0)
typedef struct { pthread_mutex_t mutex; } spinlock_t;
static _Thread_local unsigned lock_depth;
static uint64_t spinlock_lock_irqsave(spinlock_t *lock) {
    CHECK(!lock_depth);CHECK(!pthread_mutex_lock(&lock->mutex));++lock_depth;return 0;
}
static void spinlock_unlock_irqrestore(spinlock_t *lock,uint64_t flags) {
    CHECK(!flags&&lock_depth==1);--lock_depth;CHECK(!pthread_mutex_unlock(&lock->mutex));
}
'''
code += registry + route
code += r'''
static net_interface_t *first;
static atomic_uint snapshots;
static void *worker(void *argument) {
    uintptr_t id=(uintptr_t)argument;
    alix_net_route_info_t *reply=calloc(1,sizeof(*reply));CHECK(reply);
    for(unsigned i=0;i<8000;++i){
        if(!id){
            if(i&1)net_if_set_ipv4(first,0x0a00020f,0xffffff00,0x0a000202);
            else net_if_set_ipv4(first,0x0a01020f,0xffffff00,0x0a010202);
        } else {
            CHECK(net_route_ipv4_snapshot(0x08080808,reply));
            CHECK(reply->version==1&&reply->mtu==1500&&!strcmp(reply->interface_name,"eth0"));
            CHECK((reply->source_ipv4==0x0a00020f&&reply->next_hop_ipv4==0x0a000202)||
                  (reply->source_ipv4==0x0a01020f&&reply->next_hop_ipv4==0x0a010202));
            atomic_fetch_add(&snapshots,1);
        }
    }
    free(reply);return NULL;
}
int main(void){
    _Static_assert(sizeof(alix_net_route_info_t)==24,"route ABI");
    _Static_assert(offsetof(alix_net_route_info_t,interface_name)==16,"route name ABI");
    net_if_init();first=net_if_register("eth0",NULL);CHECK(first&&first->mtu==1500);
    net_if_set_link_up(first,true);net_if_set_ipv4(first,0x0a00020f,0xffffff00,0x0a000202);
    net_interface_t *second=net_if_register("eth1",NULL);CHECK(second);
    net_if_set_link_up(second,true);net_if_set_ipv4(second,0xc0a83201,0xffffff00,0);
    alix_net_route_info_t *reply=calloc(1,sizeof(*reply));CHECK(reply);
    CHECK(net_route_ipv4_snapshot(0x0a000202,reply)&&reply->next_hop_ipv4==0x0a000202);
    CHECK(net_route_ipv4_snapshot(0xc0a83223,reply)&&!strcmp(reply->interface_name,"eth1")&&
          reply->next_hop_ipv4==0xc0a83223&&reply->source_ipv4==0xc0a83201);
    CHECK(net_route_ipv4_snapshot(0x08080808,reply)&&reply->next_hop_ipv4==0x0a000202);
    net_if_set_link_up(first,false);CHECK(!net_route_ipv4_snapshot(0x08080808,reply));
    CHECK(net_route_ipv4_snapshot(0xc0a83223,reply));net_if_set_link_up(first,true);
    for(unsigned i=0;i<4;++i){
        const uint32_t invalid[]={0,0x7f000001,0xe0000001,0xffffffff};
        memset(reply,0xa5,sizeof(*reply));CHECK(!net_route_ipv4_snapshot(invalid[i],reply));
        for(size_t j=0;j<sizeof(*reply);++j)CHECK(((unsigned char *)reply)[j]==0xa5);
    }
    pthread_t *threads=calloc(8,sizeof(*threads));CHECK(threads);
    for(uintptr_t i=0;i<8;++i)CHECK(!pthread_create(&threads[i],NULL,worker,(void *)i));
    for(unsigned i=0;i<8;++i)CHECK(!pthread_join(threads[i],NULL));
    CHECK(atomic_load(&snapshots)==56000);
    net_if_set_ipv4(first,0,0,0);CHECK(!net_route_get_default(NULL,NULL));
    CHECK(!net_route_ipv4_snapshot(0x08080808,reply));
    free(threads);free(reply);
    puts("Native routing configuration: PASS snapshots=56000 concurrent_reconfigure=8000 local=1 default=1 link=1 unsupported=1");
}
'''
compile_and_run("network-route", code)
print("Native routing contract: PASS 56000 coherent snapshots during 8000 configuration changes")
