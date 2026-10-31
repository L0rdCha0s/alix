#include "userlib.h"
#include "errno.h"
#include "serial.h"

#define TLS_BYTES (2u * 1024u * 1024u)
#define ROUNDS 256u

static __thread volatile uint8_t large_tls[TLS_BYTES];

typedef struct
{
    alix_thread_t thread;
    uint32_t round;
    uint32_t failed;
    uintptr_t thread_pointer;
} reuse_state_t;

static void worker(void *argument)
{
    reuse_state_t *state = argument;
    if (large_tls[0] != 0 || large_tls[TLS_BYTES - 1] != 0 || errno != 0)
    {
        state->failed = 1;
        return;
    }
    uint8_t value = (uint8_t)(state->round + 1);
    large_tls[0] = value;
    large_tls[TLS_BYTES - 1] = (uint8_t)~value;
    errno = 1000 + (int)state->round;
    state->thread_pointer = sys_thread_get_tls();
    sys_yield();
    if (!state->thread_pointer || large_tls[0] != value ||
        large_tls[TLS_BYTES - 1] != (uint8_t)~value || errno != 1000 + (int)state->round)
    {
        state->failed = 1;
    }
}

int main(void)
{
    reuse_state_t *state = calloc(1, sizeof(*state));
    if (!state)
    {
        serial_printf("THREAD_POOL_REUSE_TEST: FAIL allocation\n");
        return 1;
    }
    large_tls[0] = 0xA1;
    large_tls[TLS_BYTES - 1] = 0xB2;
    errno = 777;
    for (uint32_t round = 0; round < ROUNDS; ++round)
    {
        state->round = round;
        state->thread_pointer = 0;
        if (alix_thread_create(&state->thread, "pool_reuse", worker, state) != 0)
        {
            serial_printf("THREAD_POOL_REUSE_TEST: FAIL create round=%u\n", round);
            return 1;
        }
        if (alix_thread_join(state->thread, NULL) != 0)
        {
            /* Failed join does not prove the worker released its argument. */
            serial_printf("THREAD_POOL_REUSE_TEST: FAIL join round=%u\n", round);
            return 1;
        }
        if (state->failed || !state->thread_pointer || large_tls[0] != 0xA1 ||
            large_tls[TLS_BYTES - 1] != 0xB2 || errno != 777)
        {
            serial_printf("THREAD_POOL_REUSE_TEST: FAIL TLS isolation round=%u\n", round);
            free(state);
            return 1;
        }
        sys_yield();
    }
    free(state);
    serial_printf("THREAD_POOL_REUSE_TEST: PASS rounds=256 tls_bytes=2097152 cumulative_tls=536870912\n");
    return 0;
}
