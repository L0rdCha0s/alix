#include "types.h"
#include "serial.h"
#include "string.h"

extern uintptr_t __stack_chk_guard;
static volatile unsigned phase;
static bool failed;

__attribute__((noinline))
static unsigned protected_value(bool corrupt)
{
    unsigned char bytes[32];
    /* This external libc call keeps the array addressable after optimization,
     * so -fstack-protector-strong instruments the real stack buffer. */
    memset(bytes, 42, sizeof(bytes));
    if (corrupt)
    {
        /* Change the guard after the compiler has saved it in this frame.
         * The real instrumented epilogue must call __stack_chk_fail. */
        __stack_chk_guard ^= 1;
    }
    return bytes[31];
}

static void preinitialize(void)
{
    failed = __stack_chk_guard == 0 || phase != 0 || protected_value(false) != 42;
    phase = 1;
}

typedef void (*runtime_hook_t)(void);
__attribute__((section(".preinit_array"), used))
static runtime_hook_t preinit_hook = preinitialize;

__attribute__((constructor(101)))
static void initialize(void)
{
    failed = failed || __stack_chk_guard == 0 || phase != 1 || protected_value(false) != 42;
    phase = 2;
}

int main(int argc, char **argv)
{
    if (failed || phase != 2 || __stack_chk_guard == 0 || protected_value(false) != 42)
    {
        serial_printf("STACK_PROTECTOR_TEST: FAIL startup\n");
        return 1;
    }
    if (argc > 1 && strcmp(argv[1], "corrupt") == 0)
    {
        protected_value(true);
        serial_printf("STACK_PROTECTOR_TEST: FAIL corruption returned\n");
        return 1;
    }
    serial_printf("STACK_PROTECTOR_TEST: PASS preinit=1 constructor=1 protected=42\n");
    return 0;
}
