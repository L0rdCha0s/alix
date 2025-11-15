#include "net/net_debug.h"

#include "serial.h"
#include "process.h"
#include "libc.h"

static bool pointer_on_current_stack(const thread_t *thread, uintptr_t addr, size_t len)
{
    uintptr_t lower = 0;
    uintptr_t upper = 0;
    if (!process_thread_stack_bounds(thread, &lower, &upper))
    {
        return false;
    }
    if (upper <= lower)
    {
        return false;
    }
    if (addr < lower || addr >= upper)
    {
        return false;
    }
    if (len > 0 && addr + len > upper)
    {
        return true;
    }
    return true;
}

static void net_debug_log_copy(const char *tag,
                               const thread_t *thread,
                               uintptr_t dest,
                               size_t len)
{
    serial_printf("%s", "[net-copy] tag=");
    serial_printf("%s", tag ? tag : "<none>");
    serial_printf("%s", " thread=");
    const char *name = process_thread_name_const(thread);
    if (name)
    {
        serial_printf("%s", name);
    }
    else if (thread)
    {
        serial_printf("%s", "<unnamed>");
    }
    else
    {
        serial_printf("%s", "<none>");
    }
    serial_printf("%s", " pid=0x");
    process_t *owner = process_thread_owner(thread);
    serial_printf("%016llX", (unsigned long long)(owner ? process_get_pid(owner) : 0));
    serial_printf("%s", " dest=0x");
    serial_printf("%016llX", (unsigned long long)(dest));
    serial_printf("%s", " len=0x");
    serial_printf("%016llX", (unsigned long long)(len));
    uintptr_t lower = 0;
    uintptr_t upper = 0;
    if (process_thread_stack_bounds(thread, &lower, &upper))
    {
        serial_printf("%s", " stack_base=0x");
        serial_printf("%016llX", (unsigned long long)(lower));
        serial_printf("%s", " stack_top=0x");
        serial_printf("%016llX", (unsigned long long)(upper));
    }
    serial_printf("%s", "\r\n");
}

void *net_debug_memcpy(const char *tag, void *dest, const void *src, size_t len)
{
    thread_t *thread = thread_current();
    uintptr_t dest_addr = (uintptr_t)dest;
    if (pointer_on_current_stack(thread, dest_addr, len))
    {
        net_debug_log_copy(tag, thread, dest_addr, len);
    }
    return memcpy(dest, src, len);
}
