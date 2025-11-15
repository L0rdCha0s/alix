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
    serial_write_string("[net-copy] tag=");
    serial_write_string(tag ? tag : "<none>");
    serial_write_string(" thread=");
    const char *name = process_thread_name_const(thread);
    if (name)
    {
        serial_write_string(name);
    }
    else if (thread)
    {
        serial_write_string("<unnamed>");
    }
    else
    {
        serial_write_string("<none>");
    }
    serial_write_string(" pid=0x");
    process_t *owner = process_thread_owner(thread);
    serial_write_hex64(owner ? process_get_pid(owner) : 0);
    serial_write_string(" dest=0x");
    serial_write_hex64(dest);
    serial_write_string(" len=0x");
    serial_write_hex64(len);
    uintptr_t lower = 0;
    uintptr_t upper = 0;
    if (process_thread_stack_bounds(thread, &lower, &upper))
    {
        serial_write_string(" stack_base=0x");
        serial_write_hex64(lower);
        serial_write_string(" stack_top=0x");
        serial_write_hex64(upper);
    }
    serial_write_string("\r\n");
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
