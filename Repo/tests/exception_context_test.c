#include "userlib.h"
#include "sys/mman.h"
#include "fenv.h"
#include "serial.h"
#include <stddef.h>
#include <stdint.h>

typedef struct
{
    uint64_t registers[16];
    uint64_t expected_rsp, flags, vector[2];
    long double extended;
    uint32_t mxcsr;
} result_t;
_Static_assert(offsetof(result_t, expected_rsp) == 128, "probe stack field");
_Static_assert(offsetof(result_t, flags) == 136, "probe flags field");
_Static_assert(offsetof(result_t, vector) == 144, "probe SSE field");
_Static_assert(offsetof(result_t, extended) == 160, "probe x87 field");
_Static_assert(offsetof(result_t, mxcsr) == 176, "probe MXCSR field");
extern void exception_context_probe(void *page, result_t *result);

#define CHECK(condition, label) do { if (!(condition)) { \
    serial_printf("EXCEPTION_CONTEXT_TEST: FAIL %s\n", label); return 1; } } while (0)

int main(void)
{
    result_t *result = calloc(1, sizeof(*result));
    uint8_t *page = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(result && page != MAP_FAILED, "allocation");
    CHECK(fesetround(FE_UPWARD) == 0, "rounding setup");
    unsigned mask = 0, faults = 0;
    for (unsigned cpu = 0; cpu < 8; ++cpu)
    {
        CHECK(sys_thread_set_affinity(cpu) == 0 && sys_thread_cpu() == cpu, "CPU affinity");
        for (unsigned round = 0; round < 16; ++round)
        {
            memset(page, 0xa5, 4096);
            CHECK(madvise(page, 4096, MADV_DONTNEED) == 0, "discard");
            memset(result, 0, sizeof(*result));
            exception_context_probe(page, result);
            for (unsigned index = 0; index < 15; ++index)
            {
                uint64_t expected = UINT64_C(0x1111111111111111) * (index + 1u);
                if (index == 13) expected = (uintptr_t)page;
                CHECK(result->registers[index] == expected, "general register preservation");
            }
            CHECK(result->registers[15] == result->expected_rsp, "stack preservation");
            CHECK((result->flags & 0x601) == 0x601, "carry/direction/interrupt flags");
            CHECK(result->vector[0] == UINT64_C(0x0123456789abcdef) &&
                  result->vector[1] == UINT64_C(0xfedcba9876543210), "SSE preservation");
            CHECK(result->extended == 1.0L + 0x1p-60L && fegetround() == FE_UPWARD &&
                  (result->mxcsr & (0xc00u << 3)) == (FE_UPWARD << 3), "x87/MXCSR preservation");
            CHECK(page[0] == 0x5a && page[1] == 0, "fault-backed zero fill");
            ++faults;
        }
        mask |= 1u << cpu;
    }
    CHECK(fesetround(FE_TONEAREST) == 0 && munmap(page, 4096) == 0, "cleanup");
    free(result);
    serial_printf("EXCEPTION_CONTEXT_TEST: PASS cpu_mask=0x%X faults=%u gpr=15 flags=1 x87=1 sse=1\n", mask, faults);
    return 0;
}
