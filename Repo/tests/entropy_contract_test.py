#!/usr/bin/env python3
"""Execute production entropy paths with controlled hardware and copy failures."""
from pathlib import Path
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
from audio_stream_contract_test import function_definition

kernel = (ROOT / "src/kernel/entropy.c").read_text()
user = (ROOT / "user/lib/random.c").read_text()
code = r'''
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sys/types.h>
#define EINVAL 22
#define EFAULT 14
#define ENOSYS 38
#define ENOMEM 12
#define EIO 5
#define EAGAIN 11
#define EINTR 4
#define ENTROPY_NONBLOCK 1u
#define ENTROPY_MAX_BYTES 256u
#define ENTROPY_WORD_ATTEMPTS 10u
#define GRND_NONBLOCK 1u
static int target_errno;
#define errno target_errno

static unsigned pin_depth, pin_entries, feature_checks, attempts, successes;
static unsigned failures_before_success, fail_after_successes;
static unsigned allocations, releases, copies;
static bool supported, allocation_fails, zero_words;
static size_t allocated_bytes, copy_limit, validated_bytes;
static unsigned char heap[288], output[512];
static const uintptr_t user_address = 0x12345000;

static void spinlock_preempt_disable(void) { assert(pin_depth == 0); ++pin_depth; ++pin_entries; }
static void spinlock_preempt_enable(void) { assert(pin_depth == 1); --pin_depth; }
static bool entropy_cpu_has_rdrand(void) { assert(pin_depth == 1); ++feature_checks; return supported; }
static bool entropy_rdrand_step(uint64_t *word) {
    assert(pin_depth == 1 && supported && allocations == releases + 1);
    ++attempts;
    *word = UINT64_C(0xBADBADBADBADBADB); // CF=0 must never become output.
    if (failures_before_success) { --failures_before_success; return false; }
    if (successes >= fail_after_successes) return false;
    ++successes;
    *word = zero_words ? 0 : UINT64_C(0x1020304050607080) + successes;
    return true;
}
static bool user_ptr_range_valid(const void *ptr, size_t length) {
    validated_bytes = length;
    return (uintptr_t)ptr == user_address && length <= 256;
}
static void *test_malloc(size_t length) {
    assert(pin_depth == 1 && supported && allocations == releases);
    if (allocation_fails) return NULL;
    assert(length > 0 && length <= 256);
    allocated_bytes = length;
    ++allocations;
    memset(heap, 0xC7, sizeof(heap));
    return heap + 16;
}
static void test_free(void *ptr) {
    assert(pin_depth == 1 && ptr == heap + 16 && allocations == releases + 1);
    for (unsigned i = 0; i < sizeof(heap); ++i)
        assert(heap[i] == (i >= 16 && i < 16 + allocated_bytes ? 0 : 0xC7));
    ++releases;
}
static bool user_copy_to_user(void *ptr, const void *src, size_t length) {
    assert(pin_depth == 1 && (uintptr_t)ptr == user_address && src == heap + 16);
    assert(length == allocated_bytes);
    ++copies;
    size_t count = length < copy_limit ? length : copy_limit;
    memcpy(output, src, count);
    return count == length;
}
static void reset(void) {
    assert(pin_depth == 0 && allocations == releases);
    pin_entries = feature_checks = attempts = successes = 0;
    failures_before_success = allocations = releases = copies = 0;
    fail_after_successes = UINT32_MAX;
    supported = true; allocation_fails = zero_words = false;
    allocated_bytes = validated_bytes = 0; copy_limit = SIZE_MAX;
    memset(output, 0xA5, sizeof(output));
    target_errno = 0;
}
static void unchanged(size_t first) {
    for (size_t i = first; i < sizeof(output); ++i) assert(output[i] == 0xA5);
}
#define malloc test_malloc
#define free test_free
'''
# Host CPUs may not execute x86 RDRAND. Only the hardware instruction/CPUID
# boundary is replaced; production retry, ownership, wiping and copy code runs.
for name in ("static bool entropy_fill(", "static void entropy_clear(",
             "ssize_t syscall_do_getrandom("):
    definition = function_definition(kernel, name)
    # PAUSE is a performance hint, not part of the contract, and the host may be ARM.
    code += definition.replace('__asm__ volatile ("pause");', '(void)0;') + "\n"
code += r'''
#undef malloc
#undef free
static ssize_t syscall_results[8];
static size_t syscall_count, syscall_index, syscall_requested[8];
static void *syscall_buffers[8];
static uint32_t syscall_flags[8];
static ssize_t sys_getrandom(void *buffer, size_t length, uint32_t flags) {
    assert(syscall_index < syscall_count);
    size_t i = syscall_index++;
    syscall_requested[i] = length; syscall_buffers[i] = buffer; syscall_flags[i] = flags;
    return syscall_results[i];
}
#define getrandom alix_getrandom
#define getentropy alix_getentropy
'''
code += function_definition(user, "ssize_t getrandom(") + "\n"
code += function_definition(user, "int getentropy(") + "\n"
code += r'''
int main(void) {
    void *user = (void *)user_address;
    reset();
    assert(syscall_do_getrandom(user, 32, 2) == -EINVAL);
    assert(syscall_do_getrandom(user, 0, 2) == -EINVAL);
    assert(syscall_do_getrandom(NULL, 0, 0) == 0 && pin_entries == 0);
    assert(syscall_do_getrandom(NULL, 1, 0) == -EFAULT && pin_entries == 0);
    unchanged(0);

    reset(); supported = false;
    assert(syscall_do_getrandom(user, 256, 0) == -ENOSYS);
    assert(feature_checks == 1 && attempts == 0 && allocations == 0 && copies == 0 && pin_depth == 0);
    unchanged(0);

    reset(); allocation_fails = true;
    assert(syscall_do_getrandom(user, 256, 0) == -ENOMEM);
    assert(attempts == 0 && copies == 0 && pin_depth == 0); unchanged(0);

    reset(); fail_after_successes = 0;
    assert(syscall_do_getrandom(user, 256, 0) == -EIO);
    assert(attempts == 10 && copies == 0 && allocations == releases && pin_depth == 0); unchanged(0);
    reset(); fail_after_successes = 2;
    assert(syscall_do_getrandom(user, 25, ENTROPY_NONBLOCK) == -EAGAIN);
    assert(attempts == 12 && copies == 0 && allocations == releases && pin_depth == 0); unchanged(0);

    reset(); failures_before_success = 9;
    assert(syscall_do_getrandom(user, 9, 0) == 9 && attempts == 11);
    uint64_t first = UINT64_C(0x1020304050607081), second = first + 1;
    assert(memcmp(output, &first, 8) == 0 && output[8] == *(unsigned char *)&second);
    unchanged(9);

    reset(); zero_words = true;
    assert(syscall_do_getrandom(user, 7, 0) == 7 && attempts == 1);
    for (unsigned i = 0; i < 7; ++i) assert(output[i] == 0);
    unchanged(7);

    reset();
    assert(syscall_do_getrandom(user, SIZE_MAX, ENTROPY_NONBLOCK) == 256);
    assert(validated_bytes == 256 && attempts == 32 && copies == 1 && allocations == releases);
    unchanged(256);

    reset(); copy_limit = 0;
    assert(syscall_do_getrandom(user, 32, 0) == -EFAULT);
    assert(copies == 1 && attempts == 4 && allocations == releases && pin_depth == 0); unchanged(0);
    reset(); copy_limit = 5;
    assert(syscall_do_getrandom(user, 32, 0) == -EFAULT);
    assert(memcmp(output, &first, 5) == 0 && allocations == releases && pin_depth == 0); unchanged(5);

    // The next CPU may lack RDRAND: no positive feature cache may bypass it.
    reset(); supported = false;
    assert(syscall_do_getrandom(user, 1, 0) == -ENOSYS && feature_checks == 1 && attempts == 0);

    unsigned char bytes[256];
    syscall_index = 0; syscall_count = 1; syscall_results[0] = -ENOSYS;
    assert(getrandom(bytes, 10, GRND_NONBLOCK) == -1 && errno == ENOSYS);
    assert(syscall_requested[0] == 10 && syscall_flags[0] == GRND_NONBLOCK);
    syscall_index = 0; syscall_results[0] = 7; errno = 99;
    assert(getrandom(bytes, 10, 0) == 7 && errno == 99);
    syscall_index = syscall_count = 0;
    assert(getentropy(NULL, 0) == 0);
    assert(getentropy(bytes, 257) == -1 && errno == EIO && syscall_index == 0);
    assert(getentropy(NULL, 1) == -1 && errno == EFAULT && syscall_index == 0);

    syscall_index = 0; syscall_count = 4;
    syscall_results[0] = 7; syscall_results[1] = -EINTR; syscall_results[2] = 3; syscall_results[3] = 246;
    assert(getentropy(bytes, 256) == 0 && syscall_index == 4);
    assert(syscall_requested[0] == 256 && syscall_requested[1] == 249 && syscall_requested[2] == 249 && syscall_requested[3] == 246);
    assert(syscall_buffers[0] == bytes && syscall_buffers[1] == bytes + 7 && syscall_buffers[2] == bytes + 7 && syscall_buffers[3] == bytes + 10);
    for (unsigned i = 0; i < 4; ++i) assert(syscall_flags[i] == 0);

    syscall_index = 0; syscall_count = 1; syscall_results[0] = 0;
    assert(getentropy(bytes, 32) == -1 && errno == EIO);
    syscall_index = 0; syscall_results[0] = 33;
    assert(getentropy(bytes, 32) == -1 && errno == EIO);
    syscall_index = 0; syscall_results[0] = -EIO;
    assert(getentropy(bytes, 32) == -1 && errno == EIO);
    assert(pin_depth == 0 && allocations == releases);
    puts("ENTROPY_CONTRACT: PASS CF retries, unsupported CPU, no failed-generation output, wipe/free, copy faults, libc short reads");
}
'''
with tempfile.TemporaryDirectory(prefix="alix-entropy-") as temporary:
    program = Path(temporary) / "test.c"
    binary = Path(temporary) / "test"
    program.write_text(code)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=address,undefined", "-g", str(program), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
