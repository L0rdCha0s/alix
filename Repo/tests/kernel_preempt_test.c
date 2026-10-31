#include "userlib.h"
#include "serial.h"
#include <stdint.h>
#include <stddef.h>

typedef struct { uint64_t registers[16], expected_rsp, flags; } result_t;
_Static_assert(offsetof(result_t, expected_rsp) == 128, "probe stack offset");
_Static_assert(offsetof(result_t, flags) == 136, "probe flags offset");
uint64_t test_resume_rip, test_hook_errors, test_probe_shift;
result_t *test_probe_output;
extern void kernel_preempt_probe(result_t *output, unsigned alignment_shift);

#define CHECK(condition, label) do { if (!(condition)) { \
    serial_printf("KERNEL_PREEMPT_TEST: FAIL %s\n", label); return 1; } } while (0)

int main(void)
{
    result_t *result = calloc(1, sizeof(*result));
    CHECK(result, "heap record");
    for (unsigned cpu = 0; cpu < 8; ++cpu)
    {
        CHECK(sys_thread_set_affinity(cpu) == 0 && sys_thread_cpu() == cpu, "CPU affinity");
        for (unsigned shift = 0; shift < 2; ++shift)
        {
            memset(result, 0, sizeof(*result));
            kernel_preempt_probe(result, shift);
            CHECK(!test_hook_errors, "C call alignment/direction/early resume capture");
            for (unsigned index = 0; index < 15; ++index)
                CHECK(result->registers[index] == UINT64_C(0x1111111111111111) * (index + 1u), "GPR preservation");
            CHECK(result->registers[15] == result->expected_rsp, "interrupted stack restored");
            CHECK((result->flags & 0xcd5) == 0xcd5, "arithmetic and direction flags");
        }
    }
    free(result);
    serial_printf("KERNEL_PREEMPT_TEST: PASS cpus=8 alignments=2 flags=1 gpr=15 early_resume=1\n");
    return 0;
}
