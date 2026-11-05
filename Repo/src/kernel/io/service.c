#include "io_service.h"
#include "process_internal.h"
#include "heap.h"
#include "errno.h"

typedef struct
{
    io_service_t *service;
    process_t *process;
    io_request_t *request;
    io_service_result_t result;
} io_storage_worker_t;

struct io_service
{
    io_queue_t *queue;
    wait_queue_t available;
    io_service_handler_t handler;
    io_storage_worker_t *workers;
    process_t *cleanup_process;
    uint32_t worker_count, workers_created, active_workers;
    bool stopping, joining, stopped;
};

static bool io_storage_ready(void *context)
{
    io_storage_worker_t *worker = context;
    worker->request = io_queue_take(worker->service->queue);
    return worker->request != NULL || __atomic_load_n(&worker->service->stopping, __ATOMIC_ACQUIRE);
}

static void io_storage_entry(void *context)
{
    io_storage_worker_t *worker = context;
    io_service_t *service = worker->service;
    for (;;)
    {
        wait_queue_wait(&service->available, io_storage_ready, worker);
        io_request_t *request = worker->request;
        if (!request)
        {
            if (__atomic_load_n(&service->stopping, __ATOMIC_ACQUIRE)) break;
            continue;
        }
        worker->result.result = -EIO;
        worker->result.description_owned = NULL;
        io_request_status_t status;
        if (io_request_status(request, &status) != 0)
            fatal("I/O worker lost its request");
        if (status.cancelled)
            worker->result.result = -ECANCELED;
        else
            service->handler(request, &worker->result);

        /* Request and result are owned heap records throughout the callback.
         * Once execution begins, cancellation never discards this stack or
         * attempts to release storage locks/DMA buffers on another CPU. */
        if (process_io_complete_request(request, worker->result.result,
                                         worker->result.description_owned) != 0)
            fatal("I/O worker completion ownership mismatch");
        worker->result.description_owned = NULL;
        worker->request = NULL; /* The request may already be freed by cleanup. */
    }
    __atomic_sub_fetch(&service->active_workers, 1u, __ATOMIC_ACQ_REL);
    process_io_notify_cleanup_for((uintptr_t)service->queue);
}

static bool io_storage_cleanup_ready(void *context)
{
    io_service_t *service = context;
    io_queue_status_t status;
    if (io_queue_snapshot(service->queue, &status)) fatal("I/O cleanup lost its queue");
    return status.cleanup || (__atomic_load_n(&service->stopping, __ATOMIC_ACQUIRE) &&
        __atomic_load_n(&service->active_workers, __ATOMIC_ACQUIRE) == 0 && !status.live);
}

static void io_cleanup_entry(void *context)
{
    io_service_t *service = context;
    for (;;)
    {
        /* No scheduler, availability or request lock surrounds destructors.
         * This worker remains available even when every storage worker blocks. */
        size_t drained = io_queue_drain(service->queue, 64);
        if (drained) process_io_notify_cleanup();
        io_queue_status_t status;
        if (io_queue_snapshot(service->queue, &status) != 0)
            fatal("I/O cleanup lost its queue");
        if (__atomic_load_n(&service->stopping, __ATOMIC_ACQUIRE) &&
            __atomic_load_n(&service->active_workers, __ATOMIC_ACQUIRE) == 0 && status.live == 0)
            break;
        /* Retired requests still consume admission slots. Do not throttle a
         * backlog to 64 frees per timer tick while short reads are arriving. */
        if (status.cleanup) continue;
        /* Completion and waiter retirement already notify this global queue.
         * Wake promptly instead of leaving freeable admission slots asleep
         * until the next 10 ms timer tick. Keep the timeout for abandoned
         * records published by scheduler-side cancellation. */
        (void)process_io_wait_cleanup_for((uintptr_t)service->queue, io_storage_cleanup_ready, service, 1);
    }
}

static bool io_service_is_worker(io_service_t *service)
{
    process_t *current = process_current();
    if (!current) return false;
    if (__atomic_load_n(&service->cleanup_process, __ATOMIC_ACQUIRE) == current) return true;
    for (uint32_t index = 0; index < service->worker_count; ++index)
        if (__atomic_load_n(&service->workers[index].process, __ATOMIC_ACQUIRE) == current) return true;
    return false;
}

io_service_t *io_service_create(size_t capacity, uint32_t workers, io_service_handler_t handler)
{
    if (spinlock_preempt_disabled() || !handler || !workers || workers > IO_SERVICE_MAX_WORKERS ||
        !capacity || capacity > IO_QUEUE_MAX_REQUESTS) return NULL;
    io_service_t *service = calloc(1, sizeof(*service));
    if (!service) return NULL;
    service->queue = io_queue_create(capacity);
    service->workers = calloc(workers, sizeof(*service->workers));
    if (!service->queue || !service->workers)
    {
        if (service->queue)
        {
            io_queue_shutdown(service->queue);
            (void)io_queue_destroy(service->queue);
        }
        free(service->workers);
        free(service);
        return NULL;
    }
    wait_queue_init(&service->available);
    service->handler = handler;
    service->worker_count = workers;
    /* Set before any worker can run, including an immediate startup exit. */
    service->active_workers = workers;
    for (uint32_t index = 0; index < workers; ++index) service->workers[index].service = service;
    process_t *cleanup = process_create_kernel_service("io-cleanup", io_cleanup_entry, service, 0);
    if (!cleanup)
    {
        io_queue_shutdown(service->queue);
        (void)io_queue_destroy(service->queue);
        free(service->workers);
        free(service);
        return NULL;
    }
    __atomic_store_n(&service->cleanup_process, cleanup, __ATOMIC_RELEASE);
    for (uint32_t index = 0; index < workers; ++index)
    {
        process_t *process = process_create_kernel_service("io-storage", io_storage_entry,
                                                           &service->workers[index], 0);
        if (!process)
        {
            __atomic_sub_fetch(&service->active_workers, workers - index, __ATOMIC_ACQ_REL);
            if (io_service_shutdown(service) != 0)
                fatal("I/O startup rollback could not join its retained workers");
            (void)io_service_destroy(service);
            return NULL;
        }
        __atomic_store_n(&service->workers[index].process, process, __ATOMIC_RELEASE);
        ++service->workers_created;
    }
    return service;
}

int io_service_request_create(io_service_t *service, size_t bytes, uint32_t uid,
                              uint32_t gid, io_request_t **out)
{
    if (!out) return -EINVAL;
    *out = NULL;
    if (!service || !spinlock_preempt_disabled()) return -EINVAL;
    if (__atomic_load_n(&service->stopping, __ATOMIC_ACQUIRE)) return -ECANCELED;
    uint64_t admission_sequence = process_io_admission_sequence();
    int result = io_request_create(service->queue, bytes, uid, gid, out);
    process_t *caller = process_current();
    if (result == -EAGAIN && caller && caller->is_user)
    {
        process_io_record_admission(admission_sequence);
        return IO_REQUEST_ADMISSION_RETRY;
    }
    return result;
}

int io_service_submit(io_service_t *service, io_request_t *request)
{
    if (!service || !request || !spinlock_preempt_disabled() ||
        !io_request_uses_queue(request, service->queue)) return -EINVAL;
    if (__atomic_load_n(&service->stopping, __ATOMIC_ACQUIRE)) return -ECANCELED;
    int result = io_request_submit(request);
    if (!result) wait_queue_wake_all(&service->available);
    return result;
}

int io_service_shutdown(io_service_t *service)
{
    if (!service || spinlock_preempt_disabled()) return -EINVAL;
    if (io_service_is_worker(service)) return -EDEADLK;
    if (__atomic_load_n(&service->stopped, __ATOMIC_ACQUIRE)) return 0;
    bool expected = false;
    if (!__atomic_compare_exchange_n(&service->joining, &expected, true, false,
                                     __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) return -EBUSY;
    __atomic_store_n(&service->stopping, true, __ATOMIC_RELEASE);
    io_queue_shutdown(service->queue);
    process_io_notify_completion();
    process_io_notify_cleanup_for((uintptr_t)service->queue);
    wait_queue_wake_all(&service->available);

    for (uint32_t index = 0; index < service->workers_created; ++index)
    {
        process_t *process = __atomic_load_n(&service->workers[index].process, __ATOMIC_ACQUIRE);
        if (!process) continue;
        int result = process_join_kernel_service(process, NULL);
        if (result)
        {
            __atomic_store_n(&service->joining, false, __ATOMIC_RELEASE);
            return result;
        }
        __atomic_store_n(&service->workers[index].process, NULL, __ATOMIC_RELEASE);
    }
    process_t *cleanup = __atomic_load_n(&service->cleanup_process, __ATOMIC_ACQUIRE);
    if (cleanup)
    {
        int result = process_join_kernel_service(cleanup, NULL);
        if (result)
        {
            __atomic_store_n(&service->joining, false, __ATOMIC_RELEASE);
            return result;
        }
        __atomic_store_n(&service->cleanup_process, NULL, __ATOMIC_RELEASE);
    }
    __atomic_store_n(&service->stopped, true, __ATOMIC_RELEASE);
    __atomic_store_n(&service->joining, false, __ATOMIC_RELEASE);
    return 0;
}

int io_service_destroy(io_service_t *service)
{
    if (!service || spinlock_preempt_disabled()) return -EINVAL;
    if (!__atomic_load_n(&service->stopped, __ATOMIC_ACQUIRE)) return -EBUSY;
    int result = io_queue_destroy(service->queue);
    if (result) return result;
    free(service->workers);
    free(service);
    return 0;
}

int io_service_snapshot(io_service_t *service, io_service_status_t *out)
{
    if (!service || !out) return -EINVAL;
    int result = io_queue_snapshot(service->queue, &out->queue);
    if (result) return result;
    out->workers = service->worker_count;
    out->active_workers = __atomic_load_n(&service->active_workers, __ATOMIC_ACQUIRE);
    out->stopping = __atomic_load_n(&service->stopping, __ATOMIC_ACQUIRE);
    out->stopped = __atomic_load_n(&service->stopped, __ATOMIC_ACQUIRE);
    return 0;
}
