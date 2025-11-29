#include "libc.h"

#include "fd.h"
#include "process.h"
#include "serial.h"

static inline void libc_mem_debug(const char *label, void *dst, const void *src, size_t count)
{
    if (!dst || count == 0)
    {
        return;
    }
    void *caller = __builtin_return_address(0);
    thread_t *dst_owner = process_find_stack_owner(dst, count);
    thread_t *src_owner = src ? process_find_stack_owner(src, count) : NULL;
    bool overlap = false;
    if (src && dst)
    {
        uintptr_t d = (uintptr_t)dst;
        uintptr_t s = (uintptr_t)src;
        if ((d < s + count) && (s < d + count))
        {
            overlap = true;
        }
    }

    if (dst_owner || src_owner || overlap)
    {
        serial_printf("[memcpy dbg] label=%s dst=0x%016llX src=0x%016llX len=0x%016llX dst_owner=0x%016llX src_owner=0x%016llX overlap=%s caller=0x%016llX\r\n",
                      label ? label : "<none>",
                      (unsigned long long)(uintptr_t)dst,
                      (unsigned long long)(uintptr_t)src,
                      (unsigned long long)count,
                      (unsigned long long)(uintptr_t)dst_owner,
                      (unsigned long long)(uintptr_t)src_owner,
                      overlap ? "true" : "false",
                      (unsigned long long)(uintptr_t)caller);
    }

    process_debug_log_stack_write(label, caller, dst, count);
}

void *memset(void *dst, int value, size_t count)
{
    uint8_t *ptr = (uint8_t *)dst;
    uint8_t byte = (uint8_t)value;
    libc_mem_debug("memset", dst, NULL, count);
    for (size_t i = 0; i < count; ++i)
    {
        ptr[i] = byte;
    }
    return dst;
}

void *memmove(void *dst, const void *src, size_t count)
{
    uint8_t *d = (uint8_t *)dst;
    const uint8_t *s = (const uint8_t *)src;

    libc_mem_debug("memmove", dst, src, count);

    if (d == s || count == 0)
    {
        return dst;
    }

    if (d < s)
    {
        for (size_t i = 0; i < count; ++i)
        {
            d[i] = s[i];
        }
    }
    else
    {
        for (size_t i = count; i > 0; --i)
        {
            d[i - 1] = s[i - 1];
        }
    }

    return dst;
}

void *memcpy(void *dst, const void *src, size_t count)
{
    uint8_t *d = (uint8_t *)dst;
    const uint8_t *s = (const uint8_t *)src;
    libc_mem_debug("memcpy", dst, src, count);
    for (size_t i = 0; i < count; ++i)
    {
        d[i] = s[i];
    }
    return dst;
}

size_t strlen(const char *str)
{
    size_t len = 0;
    while (str[len] != '\0')
    {
        ++len;
    }
    return len;
}

int strcmp(const char *a, const char *b)
{
    while (*a && (*a == *b))
    {
        ++a;
        ++b;
    }
    return (unsigned char)*a - (unsigned char)*b;
}

int strncmp(const char *a, const char *b, size_t n)
{
    for (size_t i = 0; i < n; ++i)
    {
        unsigned char ca = a[i];
        unsigned char cb = b[i];
        if (ca != cb || ca == '\0' || cb == '\0')
        {
            return ca - cb;
        }
    }
    return 0;
}

int memcmp(const void *a, const void *b, size_t count)
{
    const uint8_t *pa = (const uint8_t *)a;
    const uint8_t *pb = (const uint8_t *)b;

    for (size_t i = 0; i < count; ++i)
    {
        uint8_t va = pa[i];
        uint8_t vb = pb[i];
        if (va != vb)
        {
            // Return difference of the first differing bytes (unsigned comparison)
            return (int)va - (int)vb;
        }
    }
    return 0;
}

ssize_t read(int fd, void *buffer, size_t count)
{
    return fd_read(fd, buffer, count);
}

ssize_t write(int fd, const void *buffer, size_t count)
{
    return fd_write(fd, buffer, count);
}

int close(int fd)
{
    return fd_close(fd);
}
