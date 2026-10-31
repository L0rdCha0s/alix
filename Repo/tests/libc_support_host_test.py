#!/usr/bin/env python3
"""Sanitize the production libc allocator/parsers against deterministic stress cases."""
from pathlib import Path
import sys, subprocess, tempfile
sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tests'))
from audio_stream_contract_test import function_definition
source = (ROOT / 'user/lib/libc.c').read_text()
test = (ROOT / 'tests/thread_libc_support_test.c').read_text()
names = ['static size_t align_size(', 'static void split_block(', 'static void coalesce(', 'static heap_block_t *find_free_block(', 'static heap_block_t *request_block_unlinked(', 'static heap_block_t *payload_to_block(', 'static void user_heap_lock_acquire(', 'static void user_heap_lock_release(', 'static void *malloc_locked(', 'static void free_locked(', 'static void *realloc_locked(', 'void *malloc(', 'void free(', 'void *aligned_alloc(', 'int posix_memalign(', 'void *realloc(', 'void *calloc(', 'static unsigned libc_integer_digit(', 'static uint64_t libc_parse_integer(', 'unsigned long long strtoull(', 'long long strtoll(', 'long strtol(', 'unsigned long strtoul(', 'void *bsearch(', 'static void libc_sort_swap(', 'static void libc_sort_sift(', 'void qsort(']
code = r'''
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <assert.h>
#define ALIGNMENT 16UL
#define SIZE_MAX_VALUE ((size_t)-1)
#define MAX_SIZE ((size_t)-1)
#define USER_HEAP_LARGE_THRESHOLD ((size_t)(64u * 1024u * 1024u))
#define user_heap_log(...) ((void)0)
#define user_heap_log_caller(...) ((void)0)
#define user_heap_log_caller_size(...) ((void)0)
#define user_heap_log_enabled() false
#define user_heap_log_corruption(...) abort()
#define serial_printf(...) ((void)0)
static inline void libc_cpu_relax(void) {}
typedef struct heap_block { size_t size; struct heap_block *next, *prev; bool free; } heap_block_t;
static heap_block_t *g_heap_head, *g_heap_tail;
static volatile int g_heap_lock;
static unsigned char arena[16*1024*1024] __attribute__((aligned(4096)));
static size_t arena_used;
static unsigned char dso_a;
static void *sys_sbrk(int64_t increment) {
    assert(increment >= 0);
    if ((uint64_t)increment > sizeof(arena) - arena_used) return (void *)-1;
    void *result = arena + arena_used;
    arena_used += increment;
    return result;
}
static bool user_heap_addr_in_bounds(uintptr_t address) {
    return address >= (uintptr_t)arena && address < (uintptr_t)(arena + arena_used);
}
#define malloc alix_malloc
#define free(pointer) alix_free(pointer)
#define calloc alix_calloc
#define realloc alix_realloc
#define aligned_alloc alix_aligned_alloc
#define posix_memalign alix_posix_memalign
#define qsort alix_qsort
#define bsearch alix_bsearch
#define strtoll alix_strtoll
#define strtoull alix_strtoull
#define strtol alix_strtol
#define strtoul alix_strtoul
'''
code += '\n\n'.join(function_definition(source, name) for name in names)
code += '\n' + function_definition(test, 'static bool bytes_equal(')
code += '\n' + function_definition(test, 'static bool allocation_tests(')
code += '\ntypedef struct { unsigned char key, identity, check; } sort_item_t;\n'
code += '\n' + function_definition(test, 'static int compare_items(')
code += '\n' + function_definition(test, 'static bool sorting_tests(')
code += '\n' + function_definition(test, 'static bool integer_tests(')
code += r'''
#undef strtoll
#undef strtoull
static uint64_t random_state = 0x589302ef38bd1ULL;
static uint64_t random_word(void) {
    random_state = random_state * 6364136223846793005ULL + 1442695040888963407ULL;
    return random_state;
}
static void verify_heap(void) {
    heap_block_t *last = NULL;
    for (heap_block_t *block = g_heap_head; block; block = block->next) {
        assert(block->prev == last);
        assert(((uintptr_t)block & 15) == 0);
        assert((block->size & 15) == 0);
        assert((unsigned char *)(block + 1) + block->size <= arena + arena_used);
        if (block->next) assert((unsigned char *)(block + 1) + block->size == (unsigned char *)block->next);
        last = block;
    }
    assert(last == g_heap_tail);
}
int main(void) {
    assert(allocation_tests()); verify_heap();
    assert(sorting_tests()); verify_heap();
    assert(integer_tests());
    static unsigned char *allocations[128];
    static size_t sizes[128];
    for (unsigned round = 0; round < 25000; ++round) {
        unsigned slot = random_word() % 128;
        if (allocations[slot]) {
            assert(bytes_equal(allocations[slot], sizes[slot], (unsigned char)slot));
            if (round % 3 == 0) {
                size_t newsize = random_word() % 8192 + 1;
                unsigned char *p = realloc(allocations[slot], newsize);
                assert(p && bytes_equal(p, newsize < sizes[slot] ? newsize : sizes[slot], (unsigned char)slot));
                memset(p, slot, newsize); allocations[slot] = p; sizes[slot] = newsize;
            } else { free(allocations[slot]); allocations[slot] = NULL; }
        } else {
            size_t alignment = (size_t)16 << (random_word() % 9);
            sizes[slot] = alignment * (random_word() % 4 + 1);
            allocations[slot] = aligned_alloc(alignment, sizes[slot]);
            assert(allocations[slot] && !((uintptr_t)allocations[slot] & (alignment - 1)));
            memset(allocations[slot], slot, sizes[slot]);
        }
        if (!(round % 100)) verify_heap();
    }
    for (unsigned slot = 0; slot < 128; ++slot) free(allocations[slot]);
    verify_heap();
    for (unsigned round = 0; round < 50000; ++round) {
        char input[96], *p = input, *actual_end, *expected_end;
        unsigned base = 2 + random_word() % 35;
        if (round % 3 == 0) *p++ = ' ';
        if (round % 2 == 0) *p++ = '-';
        unsigned count = 1 + random_word() % 75;
        for (unsigned i = 0; i < count; ++i) *p++ = "0123456789abcdefghijklmnopqrstuvwxyz"[random_word() % base];
        *p++ = '!'; *p = 0;
        errno = 0; long long actual = alix_strtoll(input, &actual_end, base); int actual_errno = errno;
        errno = 0; long long expected = strtoll(input, &expected_end, base); int expected_errno = errno;
        assert(actual == expected && actual_end == expected_end && actual_errno == expected_errno);
        errno = 0; unsigned long long unsigned_actual = alix_strtoull(input, &actual_end, base); actual_errno = errno;
        errno = 0; unsigned long long unsigned_expected = strtoull(input, &expected_end, base); expected_errno = errno;
        assert(unsigned_actual == unsigned_expected && actual_end == expected_end && actual_errno == expected_errno);
    }
    puts("LIBC_SUPPORT_HOST: PASS allocation cases + 25000 heap mutations + 50000 signed/unsigned parser cases + sorting 0..256");
}
'''
with tempfile.TemporaryDirectory(prefix="alix-libc-support-") as temporary:
    program = Path(temporary) / "test.c"
    binary = Path(temporary) / "test"
    program.write_text(code)
    subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Wno-unused-variable',
                    '-fsanitize=address,undefined', '-g', str(program), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
