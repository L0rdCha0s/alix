#!/usr/bin/env python3
"""Fault production route-query allocation/copy paths and check ownership guards."""
import os
import shlex
from audio_stream_contract_test import ROOT, compile_and_run, function_definition

os.environ["HOST_CC"] = os.environ.get("HOST_CC", "cc") + " -iquote " + shlex.quote(str(ROOT / "include"))
function = function_definition((ROOT / "src/kernel/syscall.c").read_text(),
                               "static int64_t syscall_do_net_route(")
code = r'''
#define TTF_HOST_BUILD 1
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include "alix_network.h"
#define CHECK(c) do {if(!(c)){fprintf(stderr,"route syscall %d: %s\n",__LINE__,#c);abort();}}while(0)
static unsigned depth, allocations, route_calls, copies;
static bool fail_allocation, no_route, fail_copy;
static void spinlock_preempt_disable(void){CHECK(!depth);++depth;}
static void spinlock_preempt_enable(void){CHECK(depth==1&&!allocations);--depth;}
static bool user_ptr_range_valid(const void *p,size_t bytes){CHECK(bytes==24);return p!=(void*)1;}
static void *model_calloc(size_t count,size_t bytes){CHECK(depth==1&&count==1&&bytes==24);if(fail_allocation)return NULL;void*p=calloc(count,bytes);CHECK(p);++allocations;return p;}
static void model_free(void *p){CHECK(depth==1&&allocations==1);--allocations;free(p);}
static bool net_route_ipv4_snapshot(uint32_t address,alix_net_route_info_t *info){
    CHECK(depth==1&&allocations==1&&address==0x0a000202);++route_calls;
    if(no_route)return false;info->version=1;info->mtu=1500;return true;
}
static bool user_copy_to_user(void *output,const void *info,size_t bytes){
    CHECK(depth==1&&allocations==1&&bytes==24);++copies;
    if(fail_copy)return false;memcpy(output,info,bytes);return true;
}
#define calloc model_calloc
#define free model_free
'''
code += function
code += r'''
#undef calloc
#undef free
int main(void){
    alix_net_route_info_t *info=calloc(1,sizeof(*info));CHECK(info);
    CHECK(!syscall_do_net_route(0x0a000202,info,24)&&info->version==1&&info->mtu==1500);
    CHECK(!depth&&!allocations&&route_calls==1&&copies==1);
    CHECK(syscall_do_net_route(0x100000000ull,info,24)==-EINVAL);
    CHECK(syscall_do_net_route(0x0a000202,info,23)==-EINVAL);
    CHECK(syscall_do_net_route(0x0a000202,NULL,24)==-EFAULT);
    CHECK(syscall_do_net_route(0x0a000202,(void*)1,24)==-EFAULT);
    CHECK(route_calls==1&&copies==1&&!depth&&!allocations);
    fail_allocation=true;CHECK(syscall_do_net_route(0x0a000202,info,24)==-ENOMEM);fail_allocation=false;
    memset(info,0xa5,24);no_route=true;
    CHECK(syscall_do_net_route(0x0a000202,info,24)==-ENETUNREACH);no_route=false;
    CHECK(copies==1&&!depth&&!allocations);
    for(size_t i=0;i<24;++i)CHECK(((unsigned char*)info)[i]==0xa5);
    fail_copy=true;CHECK(syscall_do_net_route(0x0a000202,info,24)==-EFAULT);fail_copy=false;
    CHECK(copies==2&&!depth&&!allocations);
    CHECK(!syscall_do_net_route(0x0a000202,info,24));
    CHECK(!depth&&!allocations);free(info);
}
'''
compile_and_run("network-route-syscall", code)
print("Route syscall ownership contract: PASS allocation/copy faults, no-route output, preemption balance")
