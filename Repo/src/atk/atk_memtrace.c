#include "atk_internal.h"

#include "libc.h"
#if ATK_TRACE_MEM && defined(KERNEL_BUILD)

#include "serial.h"

#undef malloc
#undef calloc
#undef free

static void atk_trace_log(const char *op,
                          size_t a,
                          size_t b,
                          void *ptr,
                          const char *file,
                          int line,
                          void *retaddr)
{
    serial_printf("%s", "[atk][mem] ");
    serial_printf("%s", op);
    serial_printf("%s", " ptr=0x");
    serial_printf("%016llX", (unsigned long long)(uintptr_t)ptr);
    serial_printf("%s", " a=0x");
    serial_printf("%016llX", (unsigned long long)a);
    serial_printf("%s", " b=0x");
    serial_printf("%016llX", (unsigned long long)b);
    serial_printf("%s", " file=");
    serial_printf("%s", file ? file : "?");
    serial_printf("%s", ":");
    serial_printf("%016llX", (unsigned long long)(uint64_t)line);
    serial_printf("%s", " ret=0x");
    serial_printf("%016llX", (unsigned long long)(uintptr_t)retaddr);
    serial_printf("%s", "\r\n");
}

void *atk_trace_malloc(size_t size, const char *file, int line, void *retaddr)
{
    void *ptr = malloc(size);
    atk_trace_log("malloc", size, 0, ptr, file, line, retaddr);
    return ptr;
}

void *atk_trace_calloc(size_t count, size_t size, const char *file, int line, void *retaddr)
{
    void *ptr = calloc(count, size);
    atk_trace_log("calloc", count, size, ptr, file, line, retaddr);
    return ptr;
}

void atk_trace_free(void *ptr, const char *file, int line, void *retaddr)
{
    free(ptr);
    atk_trace_log("free", 0, 0, ptr, file, line, retaddr);
}

#endif /* ATK_TRACE_MEM && KERNEL_BUILD */
