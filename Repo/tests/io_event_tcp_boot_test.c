#include "process_internal.h"
#include "io_tcp.h"
#include "heap.h"
#include "libc.h"
#include "errno.h"

#define EVENT_TCP_IDLE 3u
typedef struct event_tcp_state event_tcp_state_t;
typedef struct
{
    event_tcp_state_t *state;
    process_t *process;
    fd_description_t *socket; /* Borrowed from the controller until joined. */
    unsigned char output[128];
    bool returned;
} event_tcp_caller_t;
struct event_tcp_state
{
    io_event_service_t *service;
    fd_description_t *sockets[EVENT_TCP_IDLE + 1u];
    event_tcp_caller_t callers[EVENT_TCP_IDLE];
    io_event_service_status_t service_status;
    unsigned char *response;
    size_t response_bytes;
    const char *failure;
};

static bool event_tcp_handler(io_request_t *request, io_service_result_t *result)
{
    return io_tcp_execute(request, result, process_fd_retirement_queue());
}

/* Only the current caller uses its output pointer, after its registered wait.
 * The event worker receives operation bytes and a retained description only. */
static int64_t event_tcp_call(event_tcp_state_t *state, fd_description_t *socket,
                              uint32_t opcode, void *buffer, size_t count,
                              fd_description_t **opened)
{
    spinlock_preempt_disable();
    io_request_t *request = NULL;
    int result = io_event_service_request_create(state->service, sizeof(io_tcp_operation_t) + count,
                                                  0, 0, &request);
    fd_description_t *pin = NULL;
    if (!result && socket)
    {
        if (!fd_description_get(socket)) result = -EOVERFLOW;
        else pin = socket;
    }
    if (!result)
    {
        result = io_request_bind(request, pin, NULL, NULL);
        if (!result) pin = NULL;
    }
    if (result)
    {
        fd_description_put(pin);
        if (request) io_request_waiter_abandon(request);
        spinlock_preempt_enable();
        return result;
    }
    result = process_io_register_current(request);
    if (result)
    {
        io_request_waiter_abandon(request);
        spinlock_preempt_enable();
        return result;
    }
    io_tcp_operation_t *work = io_request_buffer(request);
    work->opcode = opcode;
    work->count = count;
    work->ipv4 = UINT32_C(0x0a000202);
    work->port = TCP_OWNED_TEST_PORT;
    if (opcode == IO_TCP_WRITE && count) memcpy(work->data, buffer, count);
    result = io_event_service_submit(state->service, request);
    if (result) (void)process_io_finish_current(true);
    spinlock_preempt_enable();
    if (result) return result;
    io_request_status_t status;
    result = process_io_wait_current(&status);
    spinlock_preempt_disable();
    request = NULL;
    if (!result) result = process_io_result_current(&request, &status);
    int64_t value = result ? result : status.result;
    if (!result && value >= 0 && opcode == IO_TCP_OPEN)
    {
        fd_description_t *description = NULL;
        int taken = io_request_take_result(request, &description);
        if (taken) value = taken;
        else *opened = description; /* Registered heap controller owns it now. */
    }
    else if (!result && value > 0 && opcode == IO_TCP_READ)
    {
        work = io_request_buffer(request);
        if ((uint64_t)value > count) value = -EIO;
        else memcpy(buffer, work->data, (size_t)value);
    }
    (void)process_io_finish_current(result != 0);
    spinlock_preempt_enable();
    return value;
}

static void event_tcp_caller_entry(void *argument)
{
    event_tcp_caller_t *caller = argument;
    (void)event_tcp_call(caller->state, caller->socket, IO_TCP_READ,
                          caller->output, sizeof(caller->output), NULL);
    __atomic_store_n(&caller->returned, true, __ATOMIC_RELEASE);
}

static bool event_tcp_caller_blocked(process_t *process)
{
    uint64_t flags = scheduler_lock_acquire("event_tcp_boot_probe");
    spinlock_lock(&process->threads_lock);
    thread_t *thread = process->main_thread;
    bool blocked = thread && thread->state == THREAD_STATE_BLOCKED && thread->waiting_queue &&
                   !thread->in_transition && !thread_in_run_queue_load(thread) &&
                   __atomic_load_n(&thread->running_cpu, __ATOMIC_ACQUIRE) == RUN_QUEUE_CPU_INVALID;
    spinlock_unlock(&process->threads_lock);
    scheduler_lock_release(flags);
    return blocked;
}

static void event_tcp_drop(fd_description_t **owner)
{
    spinlock_preempt_disable();
    fd_description_t *description = *owner;
    *owner = NULL;
    fd_description_put(description);
    spinlock_preempt_enable();
}

bool io_event_tcp_boot_test(void)
{
    event_tcp_state_t *state = calloc(1, sizeof(*state));
    if (!state) { serial_printf("EVENT_TCP_TEST: FAIL controller allocation"); return false; }
#define REQUIRE(test,label) do { if (!(test)) { state->failure = (label); goto failed; } } while (0)
    serial_printf("EVENT_TCP_TEST: start pending socket multiplexing");
    state->response = malloc(65536);
    REQUIRE(state->response, "heap response");
    state->service = io_event_service_create(32, event_tcp_handler);
    REQUIRE(state->service, "create protected event service");
    for (unsigned index = 0; index <= EVENT_TCP_IDLE; ++index)
    {
        REQUIRE(event_tcp_call(state, NULL, IO_TCP_OPEN, NULL, 0, &state->sockets[index]) == 0,
                "owned socket open");
        REQUIRE(event_tcp_call(state, state->sockets[index], IO_TCP_CONNECT, NULL, 0, NULL) == 0,
                "owned socket connect");
        if (index < EVENT_TCP_IDLE)
        {
            event_tcp_caller_t *caller = &state->callers[index];
            caller->state = state;
            caller->socket = state->sockets[index];
            memset(caller->output, 0xa5, sizeof(caller->output));
            caller->process = process_create_kernel("event-tcp-wait", event_tcp_caller_entry, caller, 0, -1);
            REQUIRE(caller->process, "create pending reader");
        }
    }
    uint64_t deadline = timer_ticks() + (uint64_t)timer_frequency() * 5u;
    for (;;)
    {
        REQUIRE(!io_event_service_snapshot(state->service, &state->service_status), "pending service snapshot");
        bool blocked = state->service_status.pending == EVENT_TCP_IDLE;
        for (unsigned index = 0; index < EVENT_TCP_IDLE; ++index)
            blocked = blocked && event_tcp_caller_blocked(state->callers[index].process);
        if (blocked) break;
        REQUIRE(timer_ticks() < deadline, "all idle readers really blocked");
        process_sleep_ms(1);
    }
    static unsigned char request[] = "GET /event HTTP/1.0\r\nHost: alix-test\r\nConnection: close\r\n\r\n";
    REQUIRE(event_tcp_call(state, state->sockets[EVENT_TCP_IDLE], IO_TCP_WRITE,
                            request, sizeof(request) - 1u, NULL) == sizeof(request) - 1u,
            "fresh write while idle readers pending");
    for (;;)
    {
        REQUIRE(state->response_bytes <= 65535u - 4096u, "bounded event response");
        int64_t bytes = event_tcp_call(state, state->sockets[EVENT_TCP_IDLE], IO_TCP_READ,
                                       state->response + state->response_bytes, 4096u, NULL);
        REQUIRE(bytes >= 0, "fresh read while idle readers pending");
        if (!bytes) break;
        state->response_bytes += (size_t)bytes;
    }
    state->response[state->response_bytes] = 0;
    REQUIRE(state->response_bytes >= 12 && !memcmp(state->response, "HTTP/1.0 200", 12), "event HTTP status");
    unsigned char *body = (unsigned char *)strstr((char *)state->response, "\r\n\r\n");
    REQUIRE(body, "event HTTP headers"); body += 4;
    REQUIRE(state->response_bytes - (size_t)(body - state->response) == 16384u, "complete event HTTP payload");
    for (unsigned index = 0; index < 16384u; ++index)
        REQUIRE(body[index] == (unsigned char)(index * 73u + 19u), "event HTTP payload bytes");
    event_tcp_drop(&state->sockets[EVENT_TCP_IDLE]);
    for (unsigned index = 0; index < EVENT_TCP_IDLE; ++index)
    {
        event_tcp_caller_t *caller = &state->callers[index];
        REQUIRE(!__atomic_load_n(&caller->returned, __ATOMIC_ACQUIRE), "idle reader did not finish spuriously");
        REQUIRE(process_kill(caller->process, -77), "kill blocked event caller");
        (void)process_join(caller->process, NULL);
        REQUIRE(!__atomic_load_n(&caller->returned, __ATOMIC_ACQUIRE), "killed continuation did not resume");
        process_destroy(caller->process); caller->process = NULL;
        for (unsigned byte = 0; byte < sizeof(caller->output); ++byte)
            REQUIRE(caller->output[byte] == 0xa5, "killed output remains untouched");
        event_tcp_drop(&state->sockets[index]);
    }
    deadline = timer_ticks() + (uint64_t)timer_frequency() * 5u;
    do
    {
        REQUIRE(!io_event_service_snapshot(state->service, &state->service_status), "cleanup snapshot");
        if (!state->service_status.queue.live) break;
        REQUIRE(timer_ticks() < deadline, "canceled event requests cleaned");
        process_sleep_ms(1);
    } while (1);
    REQUIRE(!io_event_service_shutdown(state->service), "quiescent event shutdown");
    REQUIRE(!io_event_service_destroy(state->service), "destroy event service");
    state->service = NULL;
    process_sleep_ms(100); /* Let deferred socket closes finish their FIN/ACK. */
    free(state->response); free(state);
    serial_printf("EVENT_TCP_TEST: PASS idle_reads=3 fresh_HTTP=16384 killed_callers=3 outputs_untouched=1 cleanup=1 shutdown=1");
    return true;
failed:
    /* Retain the heap controller/owners for debugger evidence. The boot gate
     * exposes no shell and keeps timer/serial service alive on failure. */
    serial_printf("EVENT_TCP_TEST: FAIL %s", state->failure ? state->failure : "unknown");
    return false;
#undef REQUIRE
}
