#!/usr/bin/env python3
"""Exercise the vendored generator/state API with host race/memory sanitizers."""
import sys
sys.dont_write_bytecode = True
from audio_stream_contract_test import ROOT, compile_and_run


def main():
    generator = (ROOT / "user/lib/vendor/musl/prng/random.c").read_text()
    fixture = (ROOT / "tests/random_test.c").read_text()
    code = r'''
#include <stdlib.h>
#define random native_random
#define srandom native_srandom
#define initstate native_initstate
#define setstate native_setstate
#include <stdint.h>
#include <sched.h>
#include <stdio.h>
typedef struct { uint32_t state; } alix_mutex_t;
static void alix_mutex_lock(alix_mutex_t *mutex) {
    while (__atomic_exchange_n(&mutex->state, 1, __ATOMIC_ACQUIRE)) sched_yield();
}
static void alix_mutex_unlock(alix_mutex_t *mutex) {
    __atomic_store_n(&mutex->state, 0, __ATOMIC_RELEASE);
}
static _Thread_local unsigned current_cpu;
static int sys_thread_set_affinity(unsigned cpu) { current_cpu = cpu; return 0; }
static unsigned sys_thread_cpu(void) { return current_cpu; }
#define serial_printf printf
'''
    code += generator.replace('#include "alix_mutex.h"', '')
    code += fixture.replace('#include "serial.h"', '').replace('#include "usyscall.h"', '')
    compile_and_run("random-state", code)
    print("POSIX random state/concurrency contracts PASS")


if __name__ == "__main__":
    main()
