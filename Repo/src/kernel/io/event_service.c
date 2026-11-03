#include "io_event_service.h"
#include "io_record_lock.h"
#include "process_internal.h"
#include "heap.h"
#include "errno.h"

struct io_event_service
{
    io_queue_t *queue;
    wait_queue_t available;
    io_event_handler_t handler;
    io_request_t **requests;
    io_service_result_t result;
    process_t *worker_process, *cleanup_process;
    size_t capacity, pending, cursor;
    bool worker_alive, stopping, joining, stopped;
};

static bool io_event_ready(void *context)
{
    io_event_service_t *service = context;
    io_queue_status_t status;
    if (io_queue_snapshot(service->queue, &status)) fatal("event worker lost its queue");
    return status.queued != 0 || __atomic_load_n(&service->stopping, __ATOMIC_ACQUIRE);
}

static void io_event_entry(void *context)
{
    io_event_service_t *service = context;
    for (;;)
    {
        /* Each admitted request gets one step per scan. An indefinitely
         * unready socket cannot occupy this worker or starve a fresh request. */
        size_t pending = 0;
        for (size_t count = 0; count < service->capacity; ++count)
        {
            size_t index = (service->cursor + count) % service->capacity;
            io_request_t *request = service->requests[index];
            if (!request)
            {
                request = io_queue_take(service->queue);
                service->requests[index] = request;
            }
            if (!request) continue;
            io_request_status_t status;
            if (io_request_status(request, &status)) fatal("event worker lost its request");
            service->result.result = -ECANCELED;
            service->result.description_owned = NULL;
            bool complete = status.cancelled;
            if (!complete)
            {
                service->result.result = -EIO;
                complete = service->handler(request, &service->result);
                if (!complete && service->result.description_owned)
                    fatal("pending event step returned an unregistered owner");
            }
            if (complete)
            {
                /* EXECUTOR protects the heap request through publication and
                 * wake, even after its original caller has been reaped. */
                service->requests[index] = NULL;
                if (process_io_complete_request(request, service->result.result,
                                                  service->result.description_owned))
                    fatal("event completion ownership mismatch");
                service->result.description_owned = NULL;
            }
            else ++pending;
        }
        service->cursor = (service->cursor + 1u) % service->capacity;
        __atomic_store_n(&service->pending, pending, __ATOMIC_RELEASE);
        if (__atomic_load_n(&service->stopping, __ATOMIC_ACQUIRE) && !pending) break;
        if (pending) process_sleep_ms(1);
        else wait_queue_wait(&service->available, io_event_ready, service);
    }
    __atomic_store_n(&service->worker_alive, false, __ATOMIC_RELEASE);
}

static bool io_event_cleanup_ready(void *context)
{
    io_event_service_t *service = context;
    io_queue_status_t status;
    if (io_queue_snapshot(service->queue, &status)) fatal("event cleanup lost its queue");
    return status.cleanup || (__atomic_load_n(&service->stopping, __ATOMIC_ACQUIRE) &&
        !__atomic_load_n(&service->worker_alive, __ATOMIC_ACQUIRE));
}
static void io_event_cleanup_entry(void *context)
{
    io_event_service_t *service = context;
    for (;;)
    {
        size_t drained = io_queue_drain(service->queue, 64);
        (void)io_record_lock_drain(64);
        if (drained) process_io_notify_cleanup();
        io_queue_status_t status;
        if (io_queue_snapshot(service->queue, &status)) fatal("event cleanup lost its queue");
        if (__atomic_load_n(&service->stopping, __ATOMIC_ACQUIRE) &&
            !__atomic_load_n(&service->worker_alive, __ATOMIC_ACQUIRE) && !status.live) break;
        /* Request retirement wakes us immediately. The bounded timer also
         * collects records retired by an allocation-free descriptor close. */
        (void)process_io_wait_cleanup(io_event_cleanup_ready, service, 1);
    }
}

static bool io_event_is_worker(io_event_service_t *service)
{
    process_t *current = process_current();
    return current && (current == __atomic_load_n(&service->worker_process, __ATOMIC_ACQUIRE) ||
                       current == __atomic_load_n(&service->cleanup_process, __ATOMIC_ACQUIRE));
}

io_event_service_t *io_event_service_create(size_t capacity, io_event_handler_t handler)
{
    if (spinlock_preempt_disabled() || !handler || !capacity || capacity > IO_QUEUE_MAX_REQUESTS) return NULL;
    io_event_service_t *service = calloc(1, sizeof(*service));
    if (!service) return NULL;
    service->queue = io_queue_create(capacity);
    service->requests = calloc(capacity, sizeof(*service->requests));
    if (!service->queue || !service->requests)
    {
        if (service->queue)
        {
            io_queue_shutdown(service->queue);
            (void)io_queue_destroy(service->queue);
        }
        free(service->requests); free(service);
        return NULL;
    }
    service->capacity = capacity;
    service->handler = handler;
    service->worker_alive = true;
    wait_queue_init(&service->available);
    process_t *cleanup = process_create_kernel_service("event-cleanup", io_event_cleanup_entry, service, 0);
    if (!cleanup)
    {
        io_queue_shutdown(service->queue);
        (void)io_queue_destroy(service->queue);
        free(service->requests); free(service);
        return NULL;
    }
    __atomic_store_n(&service->cleanup_process, cleanup, __ATOMIC_RELEASE);
    process_t *worker = process_create_kernel_service("io-event", io_event_entry, service, 0);
    if (!worker)
    {
        __atomic_store_n(&service->worker_alive, false, __ATOMIC_RELEASE);
        if (io_event_service_shutdown(service)) fatal("event startup rollback could not join cleanup");
        (void)io_event_service_destroy(service);
        return NULL;
    }
    __atomic_store_n(&service->worker_process, worker, __ATOMIC_RELEASE);
    return service;
}

int io_event_service_request_create(io_event_service_t *service, size_t bytes,
                                    uint32_t uid, uint32_t gid, io_request_t **out)
{
    if (!out) return -EINVAL;
    *out = NULL;
    if (!service || !spinlock_preempt_disabled()) return -EINVAL;
    if (__atomic_load_n(&service->stopping, __ATOMIC_ACQUIRE)) return -ECANCELED;
    return io_request_create(service->queue, bytes, uid, gid, out);
}

int io_event_service_submit(io_event_service_t *service, io_request_t *request)
{
    if (!service || !request || !spinlock_preempt_disabled() ||
        !io_request_uses_queue(request, service->queue)) return -EINVAL;
    if (__atomic_load_n(&service->stopping, __ATOMIC_ACQUIRE)) return -ECANCELED;
    int result = io_request_submit(request);
    if (!result) wait_queue_wake_all(&service->available);
    return result;
}

int io_event_service_shutdown(io_event_service_t *service)
{
    if (!service || spinlock_preempt_disabled()) return -EINVAL;
    if (io_event_is_worker(service)) return -EDEADLK;
    if (__atomic_load_n(&service->stopped, __ATOMIC_ACQUIRE)) return 0;
    bool expected = false;
    if (!__atomic_compare_exchange_n(&service->joining, &expected, true, false,
                                      __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) return -EBUSY;
    __atomic_store_n(&service->stopping, true, __ATOMIC_RELEASE);
    io_queue_shutdown(service->queue);
    process_io_notify_completion();
    wait_queue_wake_all(&service->available);
    process_t *worker = __atomic_load_n(&service->worker_process, __ATOMIC_ACQUIRE);
    if (worker)
    {
        int result = process_join_kernel_service(worker, NULL);
        if (result) { __atomic_store_n(&service->joining, false, __ATOMIC_RELEASE); return result; }
        __atomic_store_n(&service->worker_process, NULL, __ATOMIC_RELEASE);
    }
    process_t *cleanup = __atomic_load_n(&service->cleanup_process, __ATOMIC_ACQUIRE);
    if (cleanup)
    {
        int result = process_join_kernel_service(cleanup, NULL);
        if (result) { __atomic_store_n(&service->joining, false, __ATOMIC_RELEASE); return result; }
        __atomic_store_n(&service->cleanup_process, NULL, __ATOMIC_RELEASE);
    }
    __atomic_store_n(&service->stopped, true, __ATOMIC_RELEASE);
    __atomic_store_n(&service->joining, false, __ATOMIC_RELEASE);
    return 0;
}

int io_event_service_destroy(io_event_service_t *service)
{
    if (!service || spinlock_preempt_disabled()) return -EINVAL;
    if (!__atomic_load_n(&service->stopped, __ATOMIC_ACQUIRE)) return -EBUSY;
    int result = io_queue_destroy(service->queue);
    if (result) return result;
    free(service->requests); free(service);
    return 0;
}

int io_event_service_snapshot(io_event_service_t *service, io_event_service_status_t *out)
{
    if (!service || !out) return -EINVAL;
    int result = io_queue_snapshot(service->queue, &out->queue);
    if (result) return result;
    out->pending = __atomic_load_n(&service->pending, __ATOMIC_ACQUIRE);
    out->worker_alive = __atomic_load_n(&service->worker_alive, __ATOMIC_ACQUIRE);
    out->stopping = __atomic_load_n(&service->stopping, __ATOMIC_ACQUIRE);
    out->stopped = __atomic_load_n(&service->stopped, __ATOMIC_ACQUIRE);
    return 0;
}
