#!/usr/bin/env python3
"""Run production descriptor ownership primitives with real host threads."""
import os
import shlex
import sys
from pathlib import Path

sys.dont_write_bytecode = True
from audio_stream_contract_test import ROOT, compile_and_run


def without_includes(path):
    tree = Path(os.environ.get("FD_TABLE_SOURCE_TREE", str(ROOT)))
    source_path = tree / path
    if not source_path.exists():
        source_path = ROOT / path
    return "\n".join(line for line in source_path.read_text().splitlines()
                     if not line.startswith("#include "))


def main():
    program = r'''
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <sys/types.h>
#define CHECK(c) do { if (!(c)) { fprintf(stderr, "FD ownership line %d: %s\n", __LINE__, #c); abort(); } } while (0)
typedef struct syscall_stat syscall_stat_t;
typedef struct { uint32_t value; } spinlock_t;
static _Thread_local unsigned held_locks, fail_allocations;
static _Thread_local unsigned preempt_depth;
static void spinlock_preempt_disable(void) { ++preempt_depth; }
static void spinlock_preempt_enable(void) { CHECK(preempt_depth); --preempt_depth; }
static bool __attribute__((unused)) spinlock_preempt_disabled(void) { return preempt_depth!=0; }
static uint64_t live_allocations;
static void spinlock_init(spinlock_t *lock) { lock->value = 0; }
static void spinlock_lock(spinlock_t *lock)
{
    while (__atomic_exchange_n(&lock->value, 1, __ATOMIC_ACQUIRE)) sched_yield();
    ++held_locks;
}
static void spinlock_unlock(spinlock_t *lock)
{
    CHECK(held_locks != 0); --held_locks;
    __atomic_store_n(&lock->value, 0, __ATOMIC_RELEASE);
}
static void *owned_calloc(size_t count, size_t size)
{
    CHECK(held_locks == 0);
    if (fail_allocations) { --fail_allocations; return NULL; }
    void *allocation = calloc(count, size);
    if (allocation) __atomic_fetch_add(&live_allocations, 1, __ATOMIC_RELAXED);
    return allocation;
}
static void owned_free(void *allocation)
{
    CHECK(held_locks == 0);
    if (allocation) { CHECK(__atomic_fetch_sub(&live_allocations, 1, __ATOMIC_RELAXED) != 0); free(allocation); }
}
#define calloc owned_calloc
#define free owned_free
'''
    program += without_includes("include/fd.h") + "\n"
    program += without_includes("include/fd_table.h") + "\n"
    program += without_includes("src/kernel/fd/table.c") + r'''

typedef struct { uint64_t created, closed, reads; } totals_t;
typedef struct {
    uint64_t magic, offset;
    totals_t *totals;
    int close_result;
    bool blocked, entered, resume;
    fd_table_t *reenter_table;
    fd_description_t *replacement;
    int reenter_fd;
} context_t;
#define CONTEXT_LIVE UINT64_C(0xfdfd112233445566)

static ssize_t context_read(void *opaque, void *buffer, size_t count)
{
    context_t *context = opaque;
    CHECK(held_locks == 0 && context->magic == CONTEXT_LIVE);
    if (context->blocked)
    {
        __atomic_store_n(&context->entered, true, __ATOMIC_RELEASE);
        while (!__atomic_load_n(&context->resume, __ATOMIC_ACQUIRE)) sched_yield();
        CHECK(context->magic == CONTEXT_LIVE);
    }
    if (count)
    {
        *(unsigned char *)buffer = (unsigned char)__atomic_fetch_add(&context->offset, 1, __ATOMIC_RELAXED);
        __atomic_fetch_add(&context->totals->reads, 1, __ATOMIC_RELAXED);
        return 1;
    }
    return 0;
}

static int context_close(void *opaque)
{
    context_t *context = opaque;
    CHECK(held_locks == 0 && context->magic == CONTEXT_LIVE);
    if (context->reenter_table)
        CHECK(fd_table_install_at(context->reenter_table, context->reenter_fd,
                                  context->replacement, 0) == context->reenter_fd);
    int result = context->close_result;
    context->magic = 0;
    __atomic_fetch_add(&context->totals->closed, 1, __ATOMIC_RELAXED);
    free(context);
    return result;
}

static const fd_ops_t context_ops = { .read = context_read, .close = context_close };

static fd_description_t *new_description(totals_t *totals)
{
    context_t *context = calloc(1, sizeof(*context)); CHECK(context);
    context->magic = CONTEXT_LIVE;
    context->totals = totals;
    fd_description_t *description = fd_description_create(&context_ops, context); CHECK(description);
    __atomic_fetch_add(&totals->created, 1, __ATOMIC_RELAXED);
    return description;
}

static void bounds_and_failures(void)
{
    CHECK(!fd_table_create(0) && !fd_table_create(FD_TABLE_MAX_ENTRIES + 1));
    CHECK(!fd_table_create(SIZE_MAX));
    CHECK(!fd_description_create(NULL, NULL));
    fail_allocations = 1; CHECK(!fd_table_create(8));
    fail_allocations = 1; CHECK(!fd_description_create(&context_ops, (void *)1));
    CHECK(!fd_table_get(NULL) && !fd_description_get(NULL));
    CHECK(!fd_description_ops(NULL) && !fd_description_context(NULL));
    CHECK(fd_description_put(NULL) == 0);
    fd_table_shutdown(NULL); fd_table_put(NULL);
    CHECK(fd_table_capacity(NULL) == 0);
    fd_table_t *table = fd_table_create(4); CHECK(table);
    totals_t *totals = calloc(1, sizeof(*totals)); CHECK(totals);
    fd_description_t *description = new_description(totals);
    fd_description_t *pin = description;
    uint32_t flags = 99;
    CHECK(fd_table_capacity(table) == 4);
    CHECK(fd_table_install(table, description, -1, 0) == -EINVAL);
    CHECK(fd_table_install(table, description, 4, 0) == -EINVAL);
    CHECK(fd_table_install(table, description, 0, 2) == -EINVAL);
    CHECK(fd_table_install_at(table, -1, description, 0) == -EBADF);
    CHECK(fd_table_install_at(table, 0, NULL, 0) == -EINVAL);
    CHECK(fd_table_pin(table, 0, NULL, NULL) == -EINVAL);
    CHECK(fd_table_pin(table, 0, &pin, &flags) == -EBADF && !pin && flags == 0);
    CHECK(fd_table_close(table, 0) == -EBADF);
    CHECK(fd_table_close_if(table, 0, NULL) == -EINVAL);
    CHECK(fd_table_get_flags(table, 0, NULL) == -EINVAL);
    CHECK(fd_table_get_flags(table, 0, &flags) == -EBADF && flags == 0);
    CHECK(fd_table_set_flags(table, 0, 0) == -EBADF);
    CHECK(fd_table_dup(table, 0, 0, 0) == -EBADF);
    CHECK(fd_table_dup2(table, 0, 1) == -EBADF);
    CHECK(fd_table_dup3(table, 0, 0, 0) == -EINVAL);
    for (int fd = 0; fd < 4; ++fd) CHECK(fd_table_install(table, description, 0, 0) == fd);
    CHECK(fd_table_install(table, description, 0, 0) == -EMFILE);
    CHECK(fd_table_dup(table, 0, 0, 0) == -EMFILE);
    CHECK(fd_table_install_at(table, 0, description, 0) == -EEXIST);
    fd_description_put(description);
    fd_table_shutdown(table);
    CHECK(totals->closed == 1);
    CHECK(fd_table_pin(table, 0, &pin, NULL) == -EBADF);
    CHECK(fd_table_close(table, 0) == -EBADF);
    fd_table_shutdown(table); fd_table_put(table);
    CHECK(totals->created == totals->closed); free(totals);
}

static void shared_description_and_duplication(void)
{
    totals_t *totals = calloc(1, sizeof(*totals)); CHECK(totals);
    fd_table_t *table = fd_table_create(8); CHECK(table);
    fd_description_t *original = new_description(totals);
    fd_description_t *victim = new_description(totals);
    ((context_t *)fd_description_context(victim))->close_result = -EIO;
    CHECK(fd_table_install_at(table, 0, original, FD_TABLE_CLOEXEC) == 0);
    CHECK(fd_table_install_at(table, 4, victim, FD_TABLE_CLOEXEC) == 4);
    fd_description_put(victim);
    CHECK(fd_table_dup(table, 0, 1, 0) == 1);
    CHECK(fd_table_dup(table, 0, 2, FD_TABLE_CLOEXEC) == 2);
    uint32_t flags = 0;
    CHECK(fd_table_get_flags(table, 0, &flags) == 0 && flags == FD_TABLE_CLOEXEC);
    CHECK(fd_table_get_flags(table, 1, &flags) == 0 && flags == 0);
    CHECK(fd_table_dup2(table, 0, 0) == 0);
    CHECK(fd_table_get_flags(table, 0, &flags) == 0 && flags == FD_TABLE_CLOEXEC);
    CHECK(fd_table_dup2(table, 7, 4) == -EBADF && totals->closed == 0);
    CHECK(fd_table_dup3(table, 0, 4, 2) == -EINVAL && totals->closed == 0);
    CHECK(fd_table_dup2(table, 0, 4) == 4 && totals->closed == 1);
    CHECK(fd_table_get_flags(table, 4, &flags) == 0 && flags == 0);
    CHECK(fd_table_dup3(table, 0, 4, FD_TABLE_CLOEXEC) == 4);
    CHECK(fd_table_get_flags(table, 4, &flags) == 0 && flags == FD_TABLE_CLOEXEC);
    CHECK(fd_table_set_flags(table, 1, FD_TABLE_CLOEXEC) == 0);
    CHECK(fd_table_set_flags(table, 1, 2) == -EINVAL);
    CHECK(fd_table_get_flags(table, 1, &flags) == 0 && flags == FD_TABLE_CLOEXEC);
    unsigned char *byte = calloc(1, 1); CHECK(byte);
    for (int fd = 0; fd < 3; ++fd)
    {
        fd_description_t *pin = NULL;
        CHECK(fd_table_pin(table, fd, &pin, NULL) == 0 && pin == original);
        CHECK(fd_description_ops(pin)->read(fd_description_context(pin), byte, 1) == 1);
        CHECK(*byte == (unsigned char)fd); /* dup shares the context/offset. */
        fd_description_put(pin);
    }
    fd_description_put(original);
    CHECK(fd_table_close(table, 0) == 0 && totals->closed == 1);
    fd_table_put(table);
    CHECK(totals->created == 2 && totals->closed == 2 && totals->reads == 3);
    free(byte); free(totals);
}

static void overflow_preserves_slots(void)
{
    totals_t *totals = calloc(1, sizeof(*totals)); CHECK(totals);
    fd_table_t *table = fd_table_create(4); CHECK(table);
    fd_description_t *description = new_description(totals);
    fd_description_t *victim = new_description(totals);
    CHECK(fd_table_install_at(table, 0, description, FD_TABLE_CLOEXEC) == 0);
    CHECK(fd_table_install_at(table, 1, victim, 0) == 1);
    /* Exercise real overflow branches without billions of retained refs. */
    uint32_t saved = description->references;
    description->references = UINT32_MAX;
    CHECK(!fd_description_get(description));
    CHECK(fd_table_install_at(table, 2, description, 0) == -EOVERFLOW);
    CHECK(fd_table_install(table, description, 2, 0) == -EOVERFLOW);
    CHECK(fd_table_dup(table, 0, 2, 0) == -EOVERFLOW);
    CHECK(fd_table_dup2(table, 0, 1) == -EOVERFLOW);
    fd_description_t *pin = victim; uint32_t flags = 99;
    CHECK(fd_table_pin(table, 0, &pin, &flags) == -EOVERFLOW && !pin && flags == 0);
    CHECK(description->references == UINT32_MAX);
    CHECK(fd_table_pin(table, 1, &pin, NULL) == 0 && pin == victim);
    fd_description_put(pin);
    description->references = 0; CHECK(!fd_description_get(description));
    description->references = saved;
    table->references = UINT32_MAX; CHECK(!fd_table_get(table) && table->references == UINT32_MAX);
    table->references = 0; CHECK(!fd_table_get(table)); table->references = 1;
    fd_description_put(description); fd_description_put(victim); fd_table_put(table);
    CHECK(totals->closed == totals->created); free(totals);
}

static void copied_ops_and_reentrant_close(void)
{
    totals_t *totals = calloc(1, sizeof(*totals)); CHECK(totals);
    fd_table_t *table = fd_table_create(2); CHECK(table);
    fd_description_t *replacement = new_description(totals);
    context_t *context = calloc(1, sizeof(*context)); CHECK(context);
    context->magic = CONTEXT_LIVE; context->totals = totals;
    context->reenter_table = table; context->replacement = replacement; context->reenter_fd = 0;
    fd_ops_t *ops = calloc(1, sizeof(*ops)); CHECK(ops); *ops = context_ops;
    fd_description_t *old = fd_description_create(ops, context); CHECK(old); ++totals->created;
    memset(ops, 0, sizeof(*ops)); free(ops); /* Description owns a copy. */
    CHECK(fd_table_install_at(table, 0, old, 0) == 0); fd_description_put(old);
    CHECK(fd_table_close(table, 0) == 0 && totals->closed == 1);
    fd_description_t *pin = NULL;
    CHECK(fd_table_pin(table, 0, &pin, NULL) == 0 && pin == replacement);
    fd_description_put(pin); fd_description_put(replacement); fd_table_put(table);
    CHECK(totals->closed == totals->created); free(totals);
}

typedef struct { fd_table_t *table; fd_description_t *pin; unsigned char byte; } blocked_worker_t;
static void *blocked_worker(void *argument)
{
    blocked_worker_t *worker = argument;
    CHECK(fd_table_pin(worker->table, 0, &worker->pin, NULL) == 0);
    /* In the kernel this heap-owned worker record is cancellation ownership. */
    CHECK(fd_description_ops(worker->pin)->read(fd_description_context(worker->pin), &worker->byte, 1) == 1);
    fd_description_put(worker->pin);
    worker->pin = NULL;
    fd_table_put(worker->table);
    return NULL;
}

static void blocked_pin_survives_close_and_shutdown(void)
{
    totals_t *totals = calloc(1, sizeof(*totals)); CHECK(totals);
    blocked_worker_t *worker = calloc(1, sizeof(*worker)); CHECK(worker);
    pthread_t *thread = calloc(1, sizeof(*thread)); CHECK(thread);
    fd_table_t *table = fd_table_create(2); CHECK(table);
    fd_description_t *old = new_description(totals);
    context_t *context = fd_description_context(old); context->blocked = true;
    CHECK(fd_table_install_at(table, 0, old, 0) == 0); fd_description_put(old);
    CHECK(fd_table_get(table)); worker->table = table;
    CHECK(pthread_create(thread, NULL, blocked_worker, worker) == 0);
    while (!__atomic_load_n(&context->entered, __ATOMIC_ACQUIRE)) sched_yield();
    CHECK(fd_table_close(table, 0) == 0 && totals->closed == 0);
    fd_description_t *replacement = new_description(totals);
    CHECK(fd_table_install_at(table, 0, replacement, FD_TABLE_CLOEXEC) == 0);
    CHECK(fd_table_close_if(table, 0, worker->pin) == -EAGAIN);
    fd_description_t *pin = NULL;
    CHECK(fd_table_pin(table, 0, &pin, NULL) == 0 && pin == replacement);
    fd_description_put(pin); fd_description_put(replacement);
    fd_table_shutdown(table);
    CHECK(totals->closed == 1); /* New descriptor closes, blocked old pin survives. */
    fd_table_put(table); /* Worker alone keeps the closed table alive. */
    __atomic_store_n(&context->resume, true, __ATOMIC_RELEASE);
    CHECK(pthread_join(*thread, NULL) == 0);
    CHECK(totals->created == 2 && totals->closed == 2 && totals->reads == 1);
    free(thread); free(worker); free(totals);
}

typedef struct { fd_table_t *table; totals_t *totals; unsigned *ready; bool *go; unsigned char byte; } churn_worker_t;
static void *churn_worker(void *argument)
{
    churn_worker_t *worker = argument;
    __atomic_fetch_add(worker->ready, 1, __ATOMIC_RELEASE);
    while (!__atomic_load_n(worker->go, __ATOMIC_ACQUIRE)) sched_yield();
    for (unsigned iteration = 0; iteration < 2000; ++iteration)
    {
        fd_description_t *description = new_description(worker->totals);
        int fd = fd_table_install(worker->table, description, 0, iteration & 1);
        CHECK(fd >= 0 || fd == -EMFILE);
        if (fd >= 0)
        {
            fd_description_t *pin = NULL;
            int pinned = fd_table_pin(worker->table, fd, &pin, NULL);
            CHECK(pinned == 0 || pinned == -EBADF);
            if (pinned == 0)
            {
                CHECK(fd_description_ops(pin)->read(fd_description_context(pin), &worker->byte, 1) == 1);
                fd_description_put(pin);
            }
            int duplicate = fd_table_dup3(worker->table, fd, 7, FD_TABLE_CLOEXEC);
            CHECK(duplicate == 7 || duplicate == -EBADF || (fd == 7 && duplicate == -EINVAL));
            int closed = fd_table_close_if(worker->table, fd, description);
            CHECK(closed == 0 || closed == -EBADF || closed == -EAGAIN);
            if (fd != 7)
            {
                closed = fd_table_close_if(worker->table, 7, description);
                CHECK(closed == 0 || closed == -EBADF || closed == -EAGAIN);
            }
        }
        fd_description_put(description);
    }
    fd_table_put(worker->table);
    return NULL;
}

static void concurrent_reuse(void)
{
    totals_t *totals = calloc(1, sizeof(*totals)); CHECK(totals);
    fd_table_t *table = fd_table_create(8); CHECK(table);
    churn_worker_t *workers = calloc(8, sizeof(*workers)); CHECK(workers);
    pthread_t *threads = calloc(8, sizeof(*threads)); CHECK(threads);
    unsigned *ready = calloc(1, sizeof(*ready)); bool *go = calloc(1, sizeof(*go)); CHECK(ready && go);
    for (unsigned index = 0; index < 8; ++index)
    {
        CHECK(fd_table_get(table));
        workers[index] = (churn_worker_t){ .table = table, .totals = totals, .ready = ready, .go = go };
        CHECK(pthread_create(&threads[index], NULL, churn_worker, &workers[index]) == 0);
    }
    while (__atomic_load_n(ready, __ATOMIC_ACQUIRE) != 8) sched_yield();
    __atomic_store_n(go, true, __ATOMIC_RELEASE);
    for (unsigned index = 0; index < 8; ++index) CHECK(pthread_join(threads[index], NULL) == 0);
    fd_table_put(table);
    CHECK(totals->created == 16000 && totals->closed == totals->created && totals->reads != 0);
    free(go); free(ready); free(threads); free(workers); free(totals);
}

int main(void)
{
    bounds_and_failures();
    shared_description_and_duplication();
    overflow_preserves_slots();
    copied_ops_and_reentrant_close();
    blocked_pin_survives_close_and_shutdown();
    concurrent_reuse();
    CHECK(live_allocations == 0 && held_locks == 0);
    puts("production FD ownership, atomic duplication, blocked pins and concurrent reuse passed");
    return 0;
}
'''
    previous = os.environ.get("HOST_CC")
    os.environ["HOST_CC"] = shlex.join(shlex.split(previous or "cc") + ["-pthread"])
    try:
        compile_and_run("fd-table", program)
    finally:
        if previous is None:
            os.environ.pop("HOST_CC", None)
        else:
            os.environ["HOST_CC"] = previous
    print("descriptor table ownership contracts passed")


if __name__ == "__main__":
    main()
