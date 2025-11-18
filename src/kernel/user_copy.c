#include "user_copy.h"

#include "libc.h"

static inline bool user_pointer_canonical(uintptr_t addr)
{
    uint64_t sign = (uint64_t)addr >> 47;
    return sign == 0 || sign == 0x1FFFFu;
}

bool user_ptr_range_valid(const void *ptr, size_t len)
{
    if (len == 0)
    {
        return true;
    }
    if (!ptr)
    {
        return false;
    }

    uintptr_t start = (uintptr_t)ptr;
    uintptr_t end = start + len - 1;
    if (end < start)
    {
        return false;
    }

    if (!user_pointer_canonical(start) || !user_pointer_canonical(end))
    {
        return false;
    }

    if (start < USER_POINTER_BASE || end > USER_POINTER_LIMIT)
    {
        return false;
    }
    return true;
}

bool user_copy_from_user(void *dst, const void *src_user, size_t len)
{
    if (!dst || len == 0)
    {
        return len == 0;
    }
    if (!user_ptr_range_valid(src_user, len))
    {
        return false;
    }
    memcpy(dst, src_user, len);
    return true;
}

bool user_copy_to_user(void *dst_user, const void *src, size_t len)
{
    if (!src || len == 0)
    {
        return len == 0;
    }
    if (!user_ptr_range_valid(dst_user, len))
    {
        return false;
    }
    memcpy(dst_user, src, len);
    return true;
}

bool user_copy_string_from_user(char *dst,
                                size_t capacity,
                                const char *src_user,
                                size_t *out_len)
{
    if (!dst || !src_user || capacity == 0)
    {
        return false;
    }

    size_t max_copy = capacity - 1;
    size_t len = 0;

    /* Walk byte-by-byte so we don't require the entire max_copy range to be valid up front. */
    while (len < max_copy)
    {
        if (!user_ptr_range_valid(src_user + len, 1))
        {
            return false;
        }
        char c = ((const char *)src_user)[len];
        dst[len] = c;
        if (c == '\0')
        {
            if (out_len)
            {
                *out_len = len;
            }
            return true;
        }
        ++len;
    }

    /* No terminator found within capacity. */
    return false;
}
