#!/usr/bin/env python3
"""Test production uptime conversion/ownership with overflow and SMP models."""
from pathlib import Path
import sys
sys.dont_write_bytecode = True
from audio_stream_contract_test import compile_and_run

ROOT = Path(__file__).resolve().parents[1]
production_path = ROOT / "src/kernel/process/process_uptime.c"
if not production_path.is_file(): production_path = ROOT / "ports/zen/uptime/process_uptime.c"
production = production_path.read_text().replace('#include "process_internal.h"', '')
program = r'''
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
typedef struct { uint64_t started_monotonic_millis; } process_t;
static _Thread_local process_t *current;
static _Thread_local unsigned pin_depth;
static _Thread_local bool release_on_unpin;
static uint64_t ticks;
#define CHECK(c) do{if(!(c)){fprintf(stderr,"uptime line %d: %s\n",__LINE__,#c);abort();}}while(0)
static void spinlock_preempt_disable(void){++pin_depth;}
static void spinlock_preempt_enable(void){CHECK(pin_depth==1);--pin_depth;if(release_on_unpin){free(current);current=NULL;release_on_unpin=false;}}
static process_t *current_process_local(void){CHECK(pin_depth==1);return current;}
static uint64_t timer_monotonic_millis(void){return __atomic_load_n(&ticks,__ATOMIC_RELAXED);}
''' + production + r'''
static void *worker(void *argument){(void)argument;current=malloc(sizeof(*current));CHECK(current);current->started_monotonic_millis=10;
    uint64_t previous=0;for(unsigned i=0;i<10000;++i){__atomic_fetch_add(&ticks,1,__ATOMIC_RELAXED);uint64_t now=process_current_uptime_ns();CHECK(now>=previous);previous=now;CHECK(pin_depth==0);}free(current);current=NULL;return NULL;}
int main(void){
    const uint32_t frequencies[]={1,3,1000,1024,UINT32_MAX};
    const uint64_t inputs[]={0,1,2,999,1000,1001,UINT64_MAX/1000000000ULL,UINT64_MAX/1000000000ULL+1,UINT64_MAX-1,UINT64_MAX};
    for(unsigned f=0;f<5;++f)for(unsigned i=0;i<10;++i){
        __uint128_t wide=(__uint128_t)inputs[i]*1000000000ULL/frequencies[f];
        uint64_t expected=wide>UINT64_MAX?UINT64_MAX:(uint64_t)wide;
        CHECK(process_uptime_ticks_to_ns(inputs[i],frequencies[f])==expected);
    }
    CHECK(process_uptime_ticks_to_ns(UINT64_MAX,0)==0);
    CHECK(process_current_uptime_ns()==0 && pin_depth==0);
    current=malloc(sizeof(*current));current->started_monotonic_millis=100;ticks=125;
    CHECK(process_current_uptime_ns()==25000000);
    ticks=99;CHECK(process_current_uptime_ns()==0);ticks=100;CHECK(process_current_uptime_ns()==0);
    /* A huge absolute boot time must not saturate a young process's uptime. */
    current->started_monotonic_millis=UINT64_MAX-30;ticks=UINT64_MAX-5;
    CHECK(process_current_uptime_ns()==25000000);
    release_on_unpin=true;CHECK(process_current_uptime_ns()==25000000 && current==NULL);
    ticks=100;pthread_t threads[8];for(unsigned i=0;i<8;++i)CHECK(!pthread_create(&threads[i],NULL,worker,NULL));
    for(unsigned i=0;i<8;++i)CHECK(!pthread_join(threads[i],NULL));
    CHECK(ticks==80100);puts("Production process uptime: PASS conversion=50 overflow=1 lifetime=1 threads=8 samples=80000");
}
'''
compile_and_run("process_uptime_contract", program)
print("Production uptime: conversion/overflow/lifetime and eight-thread 80,000-sample contracts PASS")
