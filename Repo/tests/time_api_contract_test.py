#!/usr/bin/env python3
"""Check production time conversion against the millisecond syscall contract."""
from pathlib import Path
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
from audio_stream_contract_test import function_definition

ROOT = Path(__file__).resolve().parents[1]
source = (ROOT / "user/lib/libc.c").read_text()
code = r'''
#include <stdint.h>
#include <sys/time.h>
#include <errno.h>
#include <assert.h>
#include <stdio.h>
static uint64_t wall_millis;
static unsigned reads;
static uint64_t sys_time_millis(void) { ++reads; return wall_millis; }
#define gettimeofday alix_gettimeofday
'''
code += function_definition(source, "int gettimeofday(")
code += r'''
int main(void) {
    const uint64_t samples[] = {0, 1, 999, 1000, 1001, 1793412998123ULL, UINT64_MAX};
    for (unsigned i = 0; i < sizeof(samples) / sizeof(samples[0]); ++i) {
        wall_millis = samples[i]; reads = 0;
        struct timeval value = {-1, -1};
        errno = EDOM;
        assert(gettimeofday(&value, NULL) == 0 && reads == 1 && errno == EDOM);
        assert(value.tv_sec >= 0 && value.tv_usec >= 0 && value.tv_usec < 1000000);
        assert((uint64_t)value.tv_sec * 1000 + value.tv_usec / 1000 == wall_millis);
        unsigned obsolete = 0x42;
        assert(gettimeofday(&value, &obsolete) == 0 && obsolete == 0x42);
    }
    reads = 0;
    assert(gettimeofday(NULL, NULL) == -1 && errno == EFAULT && reads == 0);
    puts("Native gettimeofday conversion and errno contract: PASS");
}
'''
with tempfile.TemporaryDirectory(prefix="alix-time-api-") as directory:
    source_path = Path(directory) / "test.c"
    binary = Path(directory) / "test"
    source_path.write_text(code)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=address,undefined", str(source_path), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
