#!/usr/bin/env python3
"""Exercise production I/O request owners, cancellation and deferred cleanup."""
import os
import shlex
import sys

sys.dont_write_bytecode = True
from audio_stream_contract_test import ROOT, compile_and_run


def source(path):
    return "\n".join(line for line in (ROOT / path).read_text().splitlines()
                     if not line.startswith("#include "))


def main():
    code = r'''
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#define CHECK(c) do { if (!(c)) { fprintf(stderr, "I/O request line %d: %s\n", __LINE__, #c); abort(); } } while (0)
typedef struct syscall_stat syscall_stat_t;
typedef struct { uint32_t value; } spinlock_t;
static _Thread_local unsigned held_locks;
static _Thread_local bool cleanup_worker;
static _Thread_local int fail_after = -1;
static void (*allocation_hook)(void);
static uint64_t allocations;
static void spinlock_init(spinlock_t *lock) { lock->value = 0; }
static void spinlock_lock(spinlock_t *lock) {
    while (__atomic_exchange_n(&lock->value, 1, __ATOMIC_ACQUIRE)) sched_yield();
    ++held_locks;
}
static void spinlock_unlock(spinlock_t *lock) {
    CHECK(held_locks); --held_locks; __atomic_store_n(&lock->value, 0, __ATOMIC_RELEASE);
}
static void *owned_calloc(size_t n, size_t bytes) {
    CHECK(!held_locks);
    if (allocation_hook) { void (*hook)(void) = allocation_hook; allocation_hook = NULL; hook(); }
    if (fail_after == 0) { fail_after = -1; return NULL; }
    if (fail_after > 0) --fail_after;
    void *value = calloc(n, bytes);
    if (value) __atomic_fetch_add(&allocations, 1, __ATOMIC_RELAXED);
    return value;
}
static void owned_free(void *value) {
    CHECK(!held_locks);
    if (value) { CHECK(__atomic_fetch_sub(&allocations, 1, __ATOMIC_RELAXED)); free(value); }
}
#define calloc owned_calloc
#define free owned_free
'''
    for path in ("include/fd.h", "include/fd_table.h", "include/io_request.h",
                 "src/kernel/fd/table.c", "src/kernel/io/request.c"):
        code += source(path) + "\n"
    code += r'''
typedef struct { uint64_t created, closed, cwd_created, cwd_closed; } counts_t;
typedef struct { counts_t *counts; io_queue_t *reenter; uint64_t magic; unsigned number; } asset_t;
#define ASSET_MAGIC UINT64_C(0x1122ffdd33445566)
static int close_asset(void *value) {
    asset_t *asset = value;
    CHECK(cleanup_worker && !held_locks && asset->magic == ASSET_MAGIC);
    __atomic_fetch_add(&asset->counts->closed, 1, __ATOMIC_RELAXED);
    if (asset->reenter) {
        CHECK(io_queue_destroy(asset->reenter) == -EBUSY);
        io_request_t *nested = NULL;
        CHECK(io_request_create(asset->reenter, 0, 12, 34, &nested) == 0);
        CHECK(io_request_waiter_abandon(nested) == 0);
    }
    asset->magic = 0; free(asset); return 0;
}
static void release_cwd(void *value) {
    asset_t *asset = value;
    CHECK(cleanup_worker && !held_locks && asset->magic == ASSET_MAGIC);
    __atomic_fetch_add(&asset->counts->cwd_closed, 1, __ATOMIC_RELAXED);
    asset->magic = 0; free(asset);
}
static const fd_ops_t asset_ops = { .close = close_asset };
static fd_description_t *description(counts_t *counts, unsigned number) {
    asset_t *asset = calloc(1, sizeof(*asset)); CHECK(asset);
    asset->counts = counts; asset->magic = ASSET_MAGIC; asset->number = number;
    fd_description_t *desc = fd_description_create(&asset_ops, asset); CHECK(desc);
    __atomic_fetch_add(&counts->created, 1, __ATOMIC_RELAXED); return desc;
}
static io_request_t *request_with_assets(io_queue_t *queue, counts_t *counts, unsigned number) {
    io_request_t *request = NULL;
    CHECK(io_request_create(queue, 16, 1000 + number, 2000 + number, &request) == 0);
    fd_description_t *desc = description(counts, number);
    asset_t *cwd = calloc(1, sizeof(*cwd)); CHECK(cwd);
    cwd->counts = counts; cwd->magic = ASSET_MAGIC;
    ++counts->cwd_created;
    CHECK(io_request_bind(request, desc, cwd, release_cwd) == 0);
    CHECK(io_request_uid(request) == 1000 + number && io_request_gid(request) == 2000 + number);
    CHECK(io_request_description(request) == desc && io_request_cwd(request) == cwd);
    CHECK(io_request_buffer_size(request) == 16);
    for (unsigned i=0; i<16; ++i) CHECK(((unsigned char *)io_request_buffer(request))[i] == 0);
    return request;
}
static size_t drain(io_queue_t *queue, size_t budget) {
    CHECK(!cleanup_worker); cleanup_worker = true;
    size_t result = io_queue_drain(queue, budget);
    cleanup_worker = false; return result;
}
static void finish_queue(io_queue_t *queue) {
    io_queue_shutdown(queue); drain(queue, SIZE_MAX);
    io_queue_status_t status;
    CHECK(io_queue_snapshot(queue, &status) == 0 && status.closed && status.live == 0);
    CHECK(io_queue_destroy(queue) == 0);
}
static io_queue_t *allocation_queue;
static void shutdown_during_allocation(void) { io_queue_shutdown(allocation_queue); }

static void failures_and_capacity(void) {
    CHECK(!io_queue_create(0) && !io_queue_create(IO_QUEUE_MAX_REQUESTS + 1));
    fail_after = 0; CHECK(!io_queue_create(1));
    io_queue_t *queue = io_queue_create(2); CHECK(queue);
    io_request_t *request = (io_request_t *)1;
    CHECK(io_request_create(queue, IO_REQUEST_BUFFER_MAX + 1, 0, 0, &request) == -EINVAL && !request);
    for (int step=0; step<2; ++step) {
        fail_after = step;
        CHECK(io_request_create(queue, 16, 0, 0, &request) == -ENOMEM && !request);
        io_queue_status_t status; CHECK(io_queue_snapshot(queue, &status) == 0 && status.live == 0);
    }
    io_request_t *first, *second;
    CHECK(io_request_create(queue, 0, 1, 2, &first) == 0);
    CHECK(io_request_create(queue, 0, 3, 4, &second) == 0);
    CHECK(io_request_create(queue, 0, 0, 0, &request) == -EAGAIN && !request);
    CHECK(io_request_waiter_abandon(first) == 0);
    CHECK(io_request_create(queue, 0, 0, 0, &request) == -EAGAIN && !request);
    CHECK(drain(queue, 0) == 0 && drain(queue, 1) == 1);
    CHECK(io_request_create(queue, 0, 0, 0, &request) == 0);
    CHECK(io_request_waiter_release(second) == 0 && io_request_waiter_release(request) == 0);
    finish_queue(queue);

    allocation_queue = io_queue_create(1); CHECK(allocation_queue);
    allocation_hook = shutdown_during_allocation;
    CHECK(io_request_create(allocation_queue, 16, 0, 0, &request) == -ECANCELED && !request);
    CHECK(io_queue_destroy(allocation_queue) == 0);
}

static void cancellation_and_results(void) {
    counts_t *counts = calloc(1, sizeof(*counts)); CHECK(counts);
    io_queue_t *queue = io_queue_create(8); CHECK(queue);
    io_request_t *request = request_with_assets(queue, counts, 0);
    CHECK(io_request_submit(request) == 0 && io_request_submit(request) == -EINVAL);
    CHECK(io_request_cancel(request) == 0 && !io_queue_take(queue));
    io_request_status_t status;
    CHECK(io_request_status(request, &status) == 0 && status.state == IO_REQUEST_COMPLETED);
    CHECK(status.cancelled && status.result == -ECANCELED);
    fd_description_t *output = (fd_description_t *)1;
    CHECK(io_request_take_result(request, &output) == -ECANCELED && !output);
    CHECK(io_request_waiter_release(request) == 0 && counts->closed == 0 && counts->cwd_closed == 0);
    CHECK(drain(queue, 1) == 1 && counts->closed == 1 && counts->cwd_closed == 1);

    request = request_with_assets(queue, counts, 1);
    CHECK(io_request_submit(request) == 0 && io_queue_take(queue) == request);
    CHECK(io_request_worker_release(request) == -EINVAL); /* Continuation still running. */
    CHECK(io_request_waiter_abandon(request) == 0 && drain(queue, 1) == 0);
    CHECK(io_request_status(request, &status) == 0 && status.state == IO_REQUEST_RUNNING && status.cancelled);
    memset(io_request_buffer(request), 0x71, 16); /* Running storage still owns buffer. */
    output = description(counts, 99);
    CHECK(io_request_publish_complete(request, 16, output) == 0);
    CHECK(io_request_worker_release(request) == 0);
    CHECK(counts->closed == 1 && drain(queue, 1) == 1 && counts->closed == 3);

    request = request_with_assets(queue, counts, 2);
    CHECK(io_request_submit(request) == 0 && io_queue_take(queue) == request);
    CHECK(io_request_take_result(request, &output) == -EAGAIN && !output);
    output = description(counts, 100);
    CHECK(io_request_publish_complete(request, 123, output) == 0);
    CHECK(io_request_publish_complete(request, 1, NULL) == -EINVAL);
    CHECK(io_request_worker_release(request) == 0 && drain(queue, 1) == 0);
    CHECK(io_request_status(request, &status) == 0 && status.result == 123 && !status.cancelled);
    fd_description_t *taken = NULL;
    CHECK(io_request_take_result(request, &taken) == 0 && taken == output);
    CHECK(io_request_take_result(request, &output) == 0 && !output);
    CHECK(io_request_waiter_release(request) == 0 && drain(queue, 1) == 1 && counts->closed == 4);
    /* Transfer an OPEN result to another registered owner; only its eventual
     * cleanup worker is allowed to perform the final description put. */
    CHECK(io_request_create(queue, 0, 0, 0, &request) == 0);
    CHECK(io_request_bind(request, taken, NULL, NULL) == 0);
    CHECK(io_request_waiter_abandon(request) == 0 && drain(queue, 1) == 1 && counts->closed == 5);

    request = request_with_assets(queue, counts, 3);
    CHECK(io_request_submit(request) == 0 && io_request_waiter_release(request) == 0);
    CHECK(io_queue_take(queue) == request);
    CHECK(io_request_publish_complete(request, -EIO, NULL) == 0);
    CHECK(io_request_worker_release(request) == 0 && drain(queue, 1) == 1);

    request = request_with_assets(queue, counts, 4);
    asset_t *asset = fd_description_context(io_request_description(request)); asset->reenter = queue;
    CHECK(io_request_waiter_abandon(request) == 0 && drain(queue, 1) == 1);
    io_queue_status_t snapshot;
    CHECK(io_queue_snapshot(queue, &snapshot) == 0 && snapshot.live == 1 && snapshot.cleanup == 1);
    CHECK(drain(queue, 1) == 1);
    finish_queue(queue);
    CHECK(counts->created == counts->closed && counts->cwd_created == counts->cwd_closed);
    free(counts);
}

static void shutdown_mixed_owners(void) {
    counts_t *counts = calloc(1, sizeof(*counts)); CHECK(counts);
    io_queue_t *queue = io_queue_create(4); CHECK(queue);
    io_request_t *fresh = request_with_assets(queue, counts, 0);
    io_request_t *running = request_with_assets(queue, counts, 1);
    CHECK(io_request_submit(running) == 0 && io_queue_take(queue) == running);
    io_request_t *queued = request_with_assets(queue, counts, 2);
    CHECK(io_request_submit(queued) == 0 && io_request_waiter_release(queued) == 0);
    io_queue_shutdown(queue); io_queue_shutdown(queue);
    CHECK(!io_queue_take(queue) && io_queue_destroy(queue) == -EBUSY);
    CHECK(io_request_submit(fresh) == -ECANCELED);
    CHECK(io_request_waiter_abandon(fresh) == 0);
    CHECK(io_request_waiter_abandon(running) == 0 && drain(queue, 4) == 2);
    CHECK(counts->closed == 2);
    CHECK(io_request_publish_complete(running, 3, description(counts, 12)) == 0);
    CHECK(io_request_worker_release(running) == 0 && drain(queue, 4) == 1);
    CHECK(io_queue_destroy(queue) == 0);
    CHECK(counts->created == counts->closed && counts->cwd_created == counts->cwd_closed);
    free(counts);
}

#define RACE_REQUESTS 512
typedef struct {
    io_queue_t *queue; counts_t *counts; io_request_t **requests;
    unsigned ready, worker_done, waiter_done; bool go;
} race_t;
typedef struct { race_t *race; unsigned index; pthread_t thread; } participant_t;
static void begin(race_t *race) {
    __atomic_fetch_add(&race->ready, 1, __ATOMIC_RELEASE);
    while (!__atomic_load_n(&race->go, __ATOMIC_ACQUIRE)) sched_yield();
}
static void *race_worker(void *argument) {
    participant_t *participant = argument; race_t *race = participant->race; begin(race);
    for (;;) {
        io_request_t *request = io_queue_take(race->queue);
        if (!request) {
            if (__atomic_load_n(&race->waiter_done, __ATOMIC_ACQUIRE) == 4) break;
            sched_yield(); continue;
        }
        asset_t *asset = fd_description_context(io_request_description(request));
        CHECK(asset->magic == ASSET_MAGIC);
        memset(io_request_buffer(request), 0x5a, 16);
        sched_yield();
        fd_description_t *output = asset->number & 1 ? description(race->counts, asset->number) : NULL;
        CHECK(io_request_publish_complete(request, 16, output) == 0);
        sched_yield(); /* Publication must remain alive until executor release. */
        CHECK(io_request_worker_release(request) == 0);
    }
    __atomic_fetch_add(&race->worker_done, 1, __ATOMIC_RELEASE); return NULL;
}
static void *race_waiter(void *argument) {
    participant_t *participant = argument; race_t *race = participant->race; begin(race);
    for (unsigned index = participant->index; index<RACE_REQUESTS; index+=4) {
        io_request_t *request = race->requests[index];
        if ((index & 1) == 0) {
            CHECK(io_request_waiter_abandon(request) == 0);
        } else {
            io_request_status_t status;
            do { CHECK(io_request_status(request, &status) == 0); sched_yield(); }
            while (status.state != IO_REQUEST_COMPLETED);
            if (!status.cancelled) {
                CHECK(status.result == 16);
                for (unsigned i=0; i<16; ++i) CHECK(((unsigned char *)io_request_buffer(request))[i] == 0x5a);
            }
            CHECK(io_request_waiter_release(request) == 0);
        }
    }
    __atomic_fetch_add(&race->waiter_done, 1, __ATOMIC_RELEASE); return NULL;
}
static void *race_drainer(void *argument) {
    race_t *race = argument; cleanup_worker = true; begin(race);
    for (;;) {
        io_queue_drain(race->queue, 8);
        io_queue_status_t status; CHECK(io_queue_snapshot(race->queue, &status) == 0);
        if (__atomic_load_n(&race->worker_done, __ATOMIC_ACQUIRE) == 4 &&
            __atomic_load_n(&race->waiter_done, __ATOMIC_ACQUIRE) == 4 && status.live == 0) break;
        sched_yield();
    }
    cleanup_worker = false; return NULL;
}
static void concurrent_completion(bool shutdown) {
    race_t *race = calloc(1, sizeof(*race)); CHECK(race);
    race->queue = io_queue_create(RACE_REQUESTS); race->counts = calloc(1, sizeof(*race->counts));
    race->requests = calloc(RACE_REQUESTS, sizeof(*race->requests)); CHECK(race->queue && race->counts && race->requests);
    for (unsigned index=0; index<RACE_REQUESTS; ++index) {
        race->requests[index] = request_with_assets(race->queue, race->counts, index);
        CHECK(io_request_submit(race->requests[index]) == 0);
    }
    participant_t *participants = calloc(8, sizeof(*participants)); pthread_t *drainer = calloc(1, sizeof(*drainer));
    CHECK(participants && drainer);
    for (unsigned index=0; index<8; ++index) {
        participants[index].race = race; participants[index].index = index & 3;
        CHECK(pthread_create(&participants[index].thread, NULL, index<4 ? race_worker : race_waiter, &participants[index]) == 0);
    }
    CHECK(pthread_create(drainer, NULL, race_drainer, race) == 0);
    while (__atomic_load_n(&race->ready, __ATOMIC_ACQUIRE) != 9) sched_yield();
    __atomic_store_n(&race->go, true, __ATOMIC_RELEASE);
    if (shutdown) io_queue_shutdown(race->queue);
    for (unsigned index=0; index<8; ++index) CHECK(pthread_join(participants[index].thread, NULL) == 0);
    CHECK(pthread_join(*drainer, NULL) == 0);
    finish_queue(race->queue);
    CHECK(race->counts->created == race->counts->closed && race->counts->cwd_created == race->counts->cwd_closed);
    free(drainer); free(participants); free(race->requests); free(race->counts); free(race);
}
int main(void) {
    failures_and_capacity(); cancellation_and_results(); shutdown_mixed_owners();
    concurrent_completion(false); concurrent_completion(true);
    CHECK(allocations == 0 && !held_locks);
    puts("production I/O request fixed owners, cancellation, OPEN transfer, shutdown and cleanup races passed");
    return 0;
}
'''
    previous = os.environ.get("HOST_CC")
    os.environ["HOST_CC"] = shlex.join(shlex.split(previous or "cc") + ["-pthread"])
    try:
        compile_and_run("io-request", code)
    finally:
        if previous is None:
            os.environ.pop("HOST_CC", None)
        else:
            os.environ["HOST_CC"] = previous
    print("worker-owned I/O request contracts passed")


if __name__ == "__main__":
    main()
