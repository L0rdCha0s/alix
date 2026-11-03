#!/usr/bin/env python3
"""Exercise the shared sleep/nanosleep code with faultable timer responses."""
from audio_stream_contract_test import ROOT, compile_and_run, function_definition

source = (ROOT / "user/lib/libc.c").read_text()
program = r'''
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>
static unsigned calls;
static uint64_t total;
static uint32_t left;
static int response, success_errno;
static int sys_sleep_interruptible(uint32_t milliseconds, uint32_t *remaining) {
    ++calls; total += milliseconds;
    *remaining = left;
    if (!response && success_errno) errno = success_errno;
    return response;
}
#define nanosleep alix_nanosleep
#define sleep alix_sleep
'''
program += function_definition(source, "int nanosleep(") + "\n"
program += function_definition(source, "unsigned int sleep(") + "\n"
program += r'''
static void reset(void) { calls=0; total=0; left=0; response=0; success_errno=0; errno=EDOM; }
int main(void) {
    reset(); assert(!sleep(0) && total==0 && errno==EDOM);
    reset(); assert(!sleep(1) && total==1000 && errno==EDOM);
    reset(); success_errno=ERANGE; assert(!sleep(2) && total==2000 && errno==EDOM);
    reset(); assert(!sleep(UINT_MAX) && calls>1 && total==(uint64_t)UINT_MAX*1000 && errno==EDOM);
    reset(); response=-EINTR; left=1501; assert(sleep(3)==1 && errno==EINTR);
    reset(); response=-EINTR; left=999; assert(sleep(1)==0 && errno==EINTR);
    reset(); response=-EINTR; left=4294966975u; assert(sleep(UINT_MAX)==UINT_MAX-1 && errno==EINTR);
    reset(); response=-EIO; assert(sleep(7)==7 && errno==EIO);
    puts("SLEEP_API_CONTRACT: PASS milliseconds=1 whole_seconds=1 uint_max=1 errors=1 errno=1");
    return 0;
}
'''
compile_and_run("sleep-api", program)
print("Shared sleep API: PASS timing, interrupted whole seconds, UINT_MAX and errno")
