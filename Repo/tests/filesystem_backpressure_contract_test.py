#!/usr/bin/env python3
"""Run production VFS budget waits with oversized and overflowing requests."""
import sys
sys.dont_write_bytecode = True
from audio_stream_contract_test import ROOT, compile_and_run, function_definition


def main():
    source = (ROOT / "src/kernel/vfs.c").read_text()
    pre = r"""
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <assert.h>
typedef struct { int dirty_lock; size_t dirty_bytes_limit,dirty_bytes; } vfs_mount_t;
static vfs_mount_t *active;
static unsigned locked,flushes,yields;
static void spinlock_lock(int *l){(void)l;assert(!locked);locked=1;}
static void spinlock_unlock(int *l){(void)l;assert(locked);locked=0;}
uint64_t timer_ticks(void){return 0;}
uint64_t timer_frequency(void){return 1000;}
bool vfs_mount_writeback(vfs_mount_t *m,bool force){(void)force;assert(!locked && ++flushes<3);m->dirty_bytes=0;return true;}
static void vfs_log_backpressure_event(vfs_mount_t *m,const char *p,size_t d,size_t l,size_t b){(void)m;(void)p;(void)d;(void)l;(void)b;}
void storage_request_flush(void){assert(!locked && ++flushes<3);active->dirty_bytes=0;}
void process_yield(void){assert(!locked && ++yields<3);}
"""
    post = r"""
int main(void){
 active=calloc(1,sizeof(*active));assert(active);
 active->dirty_bytes_limit=64;vfs_backpressure_wait(active,70);assert(!flushes && !yields);
 active->dirty_bytes=1;vfs_backpressure_wait(active,70);assert(flushes==1 && yields==(ENABLE_FLUSHD?1u:0u));
 flushes=yields=0;active->dirty_bytes_limit=SIZE_MAX-1;active->dirty_bytes=SIZE_MAX-5;
 vfs_backpressure_wait(active,16);assert(flushes==1 && yields==(ENABLE_FLUSHD?1u:0u));
 flushes=yields=0;active->dirty_bytes_limit=0;active->dirty_bytes=SIZE_MAX;
 vfs_backpressure_wait(active,SIZE_MAX);assert(!flushes && !yields);free(active);return 0;
}
"""
    for mode in (0, 1):
        program = f"#define ENABLE_FLUSHD {mode}\n" + pre + function_definition(source, "static void vfs_backpressure_wait(") + post
        compile_and_run("filesystem-backpressure", program)
    print("Production VFS backpressure: PASS oversized admission, drain/retry, sum overflow and unlimited policy in both flush modes")


if __name__ == "__main__":
    main()
