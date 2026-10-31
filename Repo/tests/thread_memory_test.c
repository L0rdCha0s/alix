#include "userlib.h"
#include "serial.h"

#define PAGE_BYTES 4096u
#define PAGES 16u
#define HALF_BYTES (PAGE_BYTES * (PAGES / 2u))

int main(void)
{
    /* Do not call malloc while temporarily extending its underlying break.
     * Every iteration returns the exact break before touching libc again. */
    uintptr_t initial = (uintptr_t)sys_sbrk(0);
    size_t padding = (size_t)((0u - initial) & (PAGE_BYTES - 1u));
    size_t total = padding + PAGE_BYTES * PAGES;
    const uintptr_t failed = (uintptr_t)-1;
    if ((uintptr_t)sys_sbrk((int64_t)0x8000000000000000ULL) != failed ||
        (uintptr_t)sys_sbrk(0x7FFFFFFFFFFFFFFFLL) != failed ||
        (uintptr_t)sys_sbrk(0) != initial)
    {
        serial_printf("MEMORY_PLATFORM_TEST: FAIL overflow bounds\n");
        return 1;
    }
    for (unsigned round = 0; round < 32; ++round)
    {
        if ((uintptr_t)sys_sbrk((int64_t)total) != initial)
        {
            serial_printf("MEMORY_PLATFORM_TEST: FAIL grow\n");
            return 1;
        }
        volatile uint8_t *bytes = (volatile uint8_t *)(initial + padding);
        uint8_t pattern = (uint8_t)(round + 1);
        for (size_t i = 0; i < PAGE_BYTES * PAGES; ++i)
        {
            if (bytes[i] != 0)
            {
                serial_printf("MEMORY_PLATFORM_TEST: FAIL initial zeroing\n");
                return 1;
            }
            bytes[i] = pattern;
        }
        uintptr_t end = initial + total;
        if ((uintptr_t)sys_sbrk(-(int64_t)HALF_BYTES) != end ||
            (uintptr_t)sys_sbrk(HALF_BYTES) != end - HALF_BYTES)
        {
            serial_printf("MEMORY_PLATFORM_TEST: FAIL shrink/regrow\n");
            return 1;
        }
        for (size_t i = 0; i < PAGE_BYTES * PAGES; ++i)
        {
            uint8_t expected = i < HALF_BYTES ? pattern : 0;
            if (bytes[i] != expected)
            {
                serial_printf("MEMORY_PLATFORM_TEST: FAIL preserved or zeroed pages\n");
                return 1;
            }
        }
        if ((uintptr_t)sys_sbrk(-(int64_t)total) != end ||
            (uintptr_t)sys_sbrk(0) != initial)
        {
            serial_printf("MEMORY_PLATFORM_TEST: FAIL restore break\n");
            return 1;
        }
        sys_yield();
    }
    void *check = malloc(64);
    if (!check)
    {
        serial_printf("MEMORY_PLATFORM_TEST: FAIL libc heap after shrink\n");
        return 1;
    }
    memset(check, 0x5A, 64);
    free(check);
    serial_printf("MEMORY_PLATFORM_TEST: PASS rounds=32 pages=16\n");
    return 0;
}
