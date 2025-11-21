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
    const char *name = process_thread_name_const(thread);
    process_t *owner = process_thread_owner(thread);
    const char *thread_name = name ? name : (thread ? "<unnamed>" : "<none>");
    uint64_t pid = owner ? process_get_pid(owner) : 0;
    uintptr_t lower = 0;
    uintptr_t upper = 0;
    if (process_thread_stack_bounds(thread, &lower, &upper))
    {
        serial_printf("[net-copy] tag=%s thread=%s pid=0x%016llX dest=0x%016llX len=0x%016llX "
                      "stack_base=0x%016llX stack_top=0x%016llX\r\n",
                      tag ? tag : "<none>",
                      thread_name,
                      (unsigned long long)pid,
                      (unsigned long long)dest,
                      (unsigned long long)len,
                      (unsigned long long)lower,
                      (unsigned long long)upper);
        return;
    }
    serial_printf("[net-copy] tag=%s thread=%s pid=0x%016llX dest=0x%016llX len=0x%016llX\r\n",
                  tag ? tag : "<none>",
                  thread_name,
                  (unsigned long long)pid,
                  (unsigned long long)dest,
                  (unsigned long long)len);
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
