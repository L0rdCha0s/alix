#include "user_copy.h"
#include "errno.h"

#include "libc.h"
#include "process_internal.h"

/*
 * Syscall copies never dereference the supplied user virtual address. Each
 * page is resolved to owned physical backing with memory_lock held, then
 * copied through the kernel physmap before releasing that lock. VM changes
 * cannot revoke or recycle backing during that bounded copy. The next page
 * is checked again, so a concurrent unmap/protection change returns false
 * rather than faulting in kernel mode. A failed multi-page copy may have
 * copied an earlier prefix; callers must not assume transactional output.
 */

static inline bool user_pointer_canonical(uintptr_t addr)
{
    uint64_t sign = (uint64_t)addr >> 47;
    return sign == 0 || sign == 0x1FFFFu;
}

/* Shape validation only. Actual ownership and permissions are checked while
 * copying; this helper alone never authorizes dereferencing a user pointer. */
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
    return end >= start && user_pointer_canonical(start) && user_pointer_canonical(end) &&
           start >= USER_POINTER_BASE && end <= USER_POINTER_LIMIT;
}

static bool user_copy_bytes(void *kernel_buffer, uintptr_t user_address, size_t len,
                            bool to_user)
{
    if (len == 0)
    {
        return true;
    }
    if (!kernel_buffer || !user_ptr_range_valid((const void *)user_address, len))
    {
        return false;
    }
    process_t *process = process_current();
    if (!process || !process->is_user)
    {
        return false;
    }
    size_t copied = 0;
    while (copied < len)
    {
        uint8_t *host = NULL;
        size_t available = 0;
        uint64_t flags = process_memory_lock(process);
        if (!process_memory_resolve_user_locked(process, user_address + copied,
                                                to_user, &host, &available) || available == 0)
        {
            process_memory_unlock(process, flags);
            return false;
        }
        /* Enforce the bounded critical section even for a future resolver that
         * can return a physically contiguous range larger than one page. */
        size_t page_left = PAGE_SIZE_BYTES_LOCAL - ((user_address + copied) & (PAGE_SIZE_BYTES_LOCAL - 1));
        if (available > page_left)
        {
            available = page_left;
        }
        size_t chunk = len - copied;
        if (chunk > available)
        {
            chunk = available;
        }
        if (to_user)
        {
            memcpy(host, (const uint8_t *)kernel_buffer + copied, chunk);
        }
        else
        {
            memcpy((uint8_t *)kernel_buffer + copied, host, chunk);
        }
        process_memory_unlock(process, flags);
        copied += chunk;
    }
    return true;
}

bool user_copy_from_user(void *dst, const void *src_user, size_t len)
{
    return user_copy_bytes(dst, (uintptr_t)src_user, len, false);
}

bool user_copy_to_user(void *dst_user, const void *src, size_t len)
{
    return user_copy_bytes((void *)src, (uintptr_t)dst_user, len, true);
}

int user_copy_cstring_from_user(char *dst, size_t capacity, const char *src_user,
                                size_t *out_len)
{
    if (!dst || capacity == 0) return -EINVAL;
    if (!user_ptr_range_valid(src_user, 1))
    {
        return -EFAULT;
    }
    process_t *process = process_current();
    if (!process || !process->is_user)
    {
        return -EFAULT;
    }
    uintptr_t address = (uintptr_t)src_user;
    size_t copied = 0;
    while (copied < capacity)
    {
        /* Only validate the page containing bytes actually inspected. A NUL
         * at a mapped page's end must not require the next page to exist. */
        if (copied > UINTPTR_MAX - address ||
            !user_ptr_range_valid((const void *)(address + copied), 1))
        {
            return -EFAULT;
        }
        uint8_t *host = NULL;
        size_t available = 0;
        uint64_t flags = process_memory_lock(process);
        if (!process_memory_resolve_user_locked(process, address + copied, false,
                                                &host, &available) || available == 0)
        {
            process_memory_unlock(process, flags);
            return -EFAULT;
        }
        size_t page_left = PAGE_SIZE_BYTES_LOCAL - ((address + copied) & (PAGE_SIZE_BYTES_LOCAL - 1));
        if (available > page_left)
        {
            available = page_left;
        }
        size_t chunk = capacity - copied;
        if (chunk > available)
        {
            chunk = available;
        }
        for (size_t i = 0; i < chunk; ++i)
        {
            /* Single-fetch each byte: concurrent user writes cannot remove a
             * terminator between a separate length scan and the copy. */
            char value = (char)host[i];
            dst[copied + i] = value;
            if (value == '\0')
            {
                process_memory_unlock(process, flags);
                if (out_len)
                {
                    *out_len = copied + i;
                }
                return 0;
            }
        }
        process_memory_unlock(process, flags);
        copied += chunk;
    }
    return -ENAMETOOLONG;
}

bool user_copy_string_from_user(char *dst, size_t capacity, const char *src_user,
                                size_t *out_len)
{
    return user_copy_cstring_from_user(dst, capacity, src_user, out_len) == 0;
}
