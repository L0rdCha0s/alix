#include "user_copy.h"

#include "libc.h"

/*
 * src/kernel/user_copy.c
 *
 * User pointer validation and copy helpers used by syscalls.
 *
 * IMPORTANT LIMITATION:
 * `user_ptr_range_valid` validates canonicality and that the range lies within
 * the configured user pointer window. It does not guarantee that pages are
 * mapped/present; callers must still be prepared for page faults if user space
 * passes an unmapped address.
 */

static inline bool user_pointer_canonical(uintptr_t addr)
{
    uint64_t sign = (uint64_t)addr >> 47;
    return sign == 0 || sign == 0x1FFFFu;
}

/*
 * Validate a user pointer range against the configured user address window.
 *
 * This checks:
 * - non-NULL (unless `len == 0`)
 * - no overflow in `start + len - 1`
 * - canonical x86_64 address form
 * - range within `[USER_POINTER_BASE, USER_POINTER_LIMIT]`
 */
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

/*
 * Copy bytes from user space into kernel memory.
 *
 * Returns false if the user pointer range is invalid.
 */
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

/*
 * Copy bytes from kernel memory into user space.
 *
 * Returns false if the user pointer range is invalid.
 */
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

/*
 * Copy a NUL-terminated string from user space into a kernel buffer.
 *
 * Validates user pointers one byte at a time so callers can pass a pointer to
 * a shorter string without requiring the full `capacity` range to be valid.
 */
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
