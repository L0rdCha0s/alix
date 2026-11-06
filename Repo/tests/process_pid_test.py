#!/usr/bin/env python3
"""Execute the production PID allocator at exhaustion and under contention."""
import os
import shlex
import sys

sys.dont_write_bytecode = True
from audio_stream_contract_test import ROOT, compile_and_run, function_definition


def main():
    source = (ROOT / "src/kernel/process/process_memory.c").read_text()
    allocator = function_definition(source, "static uint64_t process_allocate_pid")
    process = function_definition(source, "process_t *allocate_process")
    # Retain the actual allocation/rejection path, ending before page-table
    # construction. The rest of process creation has its own lifecycle tests.
    boundary = "    bool space_ready = false;"
    if boundary not in process:
        raise AssertionError("process page-table setup boundary changed")
    allocation_prefix = process.split(boundary, 1)[0] + "    return proc;\n}"
    program = r'''
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sched.h>
#define CHECK(c) do { if (!(c)) { fprintf(stderr, "PID contract line %d: %s\n", __LINE__, #c); abort(); } } while (0)
#define PID_MAXIMUM UINT64_C(0x7fffffff)
#define PID_EXHAUSTED UINT64_C(0x80000000)
static uint64_t g_next_pid;
'''
    program += allocator + r'''

typedef struct {
    uint64_t *results;
    size_t calls;
    unsigned *ready;
    bool *go;
} worker_t;

static void *allocate_worker(void *argument)
{
    worker_t *worker = argument;
    __atomic_fetch_add(worker->ready, 1, __ATOMIC_RELEASE);
    while (!__atomic_load_n(worker->go, __ATOMIC_ACQUIRE)) sched_yield();
    for (size_t index = 0; index < worker->calls; ++index)
        worker->results[index] = process_allocate_pid();
    return NULL;
}

static void concurrent_allocations(uint64_t first, size_t available,
                                   size_t thread_count, size_t calls)
{
    /* Nothing shared with another worker resides on a process/thread stack. */
    worker_t *workers = calloc(thread_count, sizeof(*workers));
    pthread_t *threads = calloc(thread_count, sizeof(*threads));
    uint64_t *results = calloc(thread_count * calls, sizeof(*results));
    unsigned char *seen = calloc(available ? available : 1, sizeof(*seen));
    unsigned *ready = calloc(1, sizeof(*ready));
    bool *go = calloc(1, sizeof(*go));
    CHECK(workers && threads && results && seen && ready && go);
    __atomic_store_n(&g_next_pid, first, __ATOMIC_RELAXED);
    for (size_t index = 0; index < thread_count; ++index)
    {
        workers[index] = (worker_t){ results + index * calls, calls, ready, go };
        CHECK(pthread_create(&threads[index], NULL, allocate_worker, &workers[index]) == 0);
    }
    while (__atomic_load_n(ready, __ATOMIC_ACQUIRE) != thread_count) sched_yield();
    __atomic_store_n(go, true, __ATOMIC_RELEASE);
    for (size_t index = 0; index < thread_count; ++index)
        CHECK(pthread_join(threads[index], NULL) == 0);

    size_t successful = 0;
    for (size_t index = 0; index < thread_count * calls; ++index)
    {
        uint64_t pid = results[index];
        if (!pid) continue;
        CHECK(pid >= first && pid <= PID_MAXIMUM && pid - first < available);
        CHECK(!seen[pid - first]);
        seen[pid - first] = 1;
        ++successful;
    }
    CHECK(successful == available);
    for (size_t index = 0; index < available; ++index) CHECK(seen[index]);
    CHECK(__atomic_load_n(&g_next_pid, __ATOMIC_RELAXED) == first + available);
    free(go); free(ready); free(seen); free(results); free(threads); free(workers);
}

static void serial_boundaries(void)
{
    g_next_pid = 1;
    for (uint64_t expected = 1; expected != 65; ++expected)
        CHECK(process_allocate_pid() == expected);
    CHECK(g_next_pid == 65);
    g_next_pid = PID_MAXIMUM - 1;
    CHECK(process_allocate_pid() == PID_MAXIMUM - 1);
    CHECK(process_allocate_pid() == PID_MAXIMUM);
    CHECK(g_next_pid == PID_EXHAUSTED);
    for (unsigned index = 0; index < 128; ++index)
        CHECK(process_allocate_pid() == 0 && g_next_pid == PID_EXHAUSTED);

    g_next_pid = 0;
    CHECK(process_allocate_pid() == 0 && g_next_pid == 0);
    g_next_pid = PID_EXHAUSTED + 1;
    CHECK(process_allocate_pid() == 0 && g_next_pid == PID_EXHAUSTED + 1);
    g_next_pid = UINT64_MAX - 1;
    CHECK(process_allocate_pid() == 0 && g_next_pid == UINT64_MAX - 1);
    g_next_pid = UINT64_MAX;
    CHECK(process_allocate_pid() == 0 && g_next_pid == UINT64_MAX);
}

enum { PROCESS_STATE_READY = 1, PROCESS_LIFETIME_ALIVE = 2 };
typedef struct { uint64_t pid, started_monotonic_millis; unsigned state, lifetime_state; } process_t;
static uint64_t timer_monotonic_millis(void) { return 123456; }
static bool heap_failure, trace_enabled;
static unsigned allocations, releases, trace_enables, trace_disables;
static void *owned_process;
static bool string_name_equals(const char *name, const char *expected)
{ return name && !strcmp(name, expected); }
static void heap_debug_verify(const char *label) { (void)label; }
static void heap_debug_dump(const char *label) { (void)label; }
static void serial_printf(const char *format, ...) { (void)format; }
static void process_create_log(const char *name, const char *event)
{ (void)name; CHECK(!strcmp(event, "pid_exhausted")); }
static void paging_set_clone_trace(bool enabled)
{
    trace_enabled = enabled;
    if (enabled) ++trace_enables; else ++trace_disables;
}
static void *tracked_malloc(size_t bytes)
{
    ++allocations;
    CHECK(!owned_process);
    if (heap_failure) return NULL;
    owned_process = malloc(bytes);
    CHECK(owned_process);
    memset(owned_process, 0xa5, bytes);
    return owned_process;
}
static void tracked_free(void *pointer)
{
    CHECK(pointer && pointer == owned_process);
    ++releases;
    free(pointer);
    owned_process = NULL;
}
#define malloc tracked_malloc
#define free tracked_free
'''
    program += allocation_prefix + r'''
#undef malloc
#undef free

static void allocation_rejection(void)
{
    g_next_pid = PID_EXHAUSTED;
    CHECK(allocate_process("shell", true) == NULL);
    CHECK(allocations == 1 && releases == 1 && !owned_process);
    CHECK(g_next_pid == PID_EXHAUSTED && !trace_enabled);
    CHECK(trace_enables == 1 && trace_disables == 1);
    CHECK(allocate_process("usb_initd", false) == NULL);
    CHECK(allocate_process(NULL, true) == NULL);
    CHECK(allocations == 3 && releases == 3 && !owned_process);
    CHECK(g_next_pid == PID_EXHAUSTED && !trace_enabled);

    heap_failure = true;
    g_next_pid = 67;
    CHECK(allocate_process("shell", true) == NULL);
    CHECK(allocations == 4 && releases == 3 && !owned_process);
    CHECK(g_next_pid == 67 && !trace_enabled);
    CHECK(trace_enables == 2 && trace_disables == 2);
    heap_failure = false;

    /* A successful last allocation reaches the actual page-table boundary. */
    g_next_pid = PID_MAXIMUM;
    process_t *process = allocate_process("ordinary", true);
    CHECK(process && process->pid == PID_MAXIMUM);
    CHECK(process->started_monotonic_millis == 123456);
    CHECK(process->state == PROCESS_STATE_READY && process->lifetime_state == PROCESS_LIFETIME_ALIVE);
    CHECK(g_next_pid == PID_EXHAUSTED);
    tracked_free(process);
    CHECK(allocate_process("ordinary", false) == NULL);
    CHECK(allocations == 6 && releases == 5 && !owned_process);
    CHECK(g_next_pid == PID_EXHAUSTED);
}

int main(void)
{
    serial_boundaries();
    concurrent_allocations(1, 65536, 8, 8192);
    /* More contenders than the final available IDs must never wrap/reuse. */
    for (unsigned iteration = 0; iteration < 16; ++iteration)
        concurrent_allocations(PID_MAXIMUM - 126, 127, 8, 1024);
    concurrent_allocations(PID_EXHAUSTED, 0, 8, 1024);
    concurrent_allocations(0, 0, 8, 1024);
    allocation_rejection();
    puts("production PID boundaries, contention, saturation and allocation cleanup passed");
    return 0;
}
'''
    # The common harness accepts a compiler command, allowing native pthreads
    # and optional caller-supplied sanitizers without a second build runner.
    previous = os.environ.get("HOST_CC")
    os.environ["HOST_CC"] = shlex.join(shlex.split(previous or "cc") + ["-pthread"])
    try:
        compile_and_run("process-pid", program)
    finally:
        if previous is None:
            os.environ.pop("HOST_CC", None)
        else:
            os.environ["HOST_CC"] = previous
    print("process PID allocation contracts passed")


if __name__ == "__main__":
    main()
