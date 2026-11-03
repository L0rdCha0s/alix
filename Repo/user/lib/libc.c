#include <stdarg.h>

#include "userlib.h"
#include "serial.h"
#include "stdio.h"
#ifndef TTF_HOST_BUILD
#include "stdio_internal.h"
#endif
#include "errno.h"
#include "unistd.h"
#include "stdlib.h"
#include "time.h"
#include "sys/time.h"
#include "sys/statvfs.h"
#include "fenv.h"
#include "printf_float.h"
#include <limits.h>
#include <stdint.h>
#include <stddef.h>
#include "signal.h"
#include "wchar.h"

#ifdef TTF_HOST_BUILD
int errno = 0;
#else
static _Thread_local int alix_errno;
int *__errno_location(void)
{
    return &alix_errno;
}
#endif

#define ALIGNMENT 16UL
#define SIZE_MAX_VALUE ((size_t)-1)
#define LIBC_MAX_PASSWD_BYTES (64u * 1024u)
#define USER_HEAP_LARGE_THRESHOLD ((size_t)(64u * 1024u * 1024u))
#define ENABLE_USER_MEM_DEBUG_LOGS 1

typedef struct heap_block
{
    size_t size;
    struct heap_block *next;
    struct heap_block *prev;
    bool free;
    struct heap_block *free_next, *free_prev;
} heap_block_t;

static heap_block_t *g_heap_head = NULL;
static heap_block_t *g_heap_tail = NULL;
static uintptr_t g_heap_committed_end;
static alix_mutex_t g_heap_lock;
static heap_block_t *g_heap_free_bins[64];
_Static_assert(sizeof(heap_block_t) % ALIGNMENT == 0, "heap payload alignment");

typedef struct
{
    char *name;
    char *value;
    /* putenv retains the supplied storage; normally name/value are NULL for
     * those entries. value may retain our old allocation when the supplied
     * string aliases it. Never cache an offset into a mutable assignment. */
    char *assignment;
} libc_env_entry_t;

static libc_env_entry_t *g_env_entries = NULL;
static size_t g_env_count = 0;
static size_t g_env_capacity = 0;
static alix_mutex_t g_env_mutex;

static int libc_env_find(const char *name)
{
    if (!name)
    {
        return -1;
    }
    for (size_t i = 0; i < g_env_count; ++i)
    {
        libc_env_entry_t *entry = &g_env_entries[i];
        const char *separator = entry->assignment ? strchr(entry->assignment, '=') : NULL;
        bool matches = entry->assignment ?
            separator && (size_t)(separator - entry->assignment) == strlen(name) &&
                !memcmp(entry->assignment, name, (size_t)(separator - entry->assignment)) :
            !strcmp(entry->name, name);
        if (matches)
        {
            return (int)i;
        }
    }
    return -1;
}

static bool libc_env_reserve(size_t needed)
{
    if (g_env_capacity >= needed)
    {
        return true;
    }
    size_t new_cap = g_env_capacity == 0 ? 4 : g_env_capacity * 2;
    if (new_cap < needed)
    {
        new_cap = needed;
    }

    size_t bytes = 0;
    if (__builtin_mul_overflow(new_cap, sizeof(libc_env_entry_t), &bytes))
    {
        return false;
    }
    libc_env_entry_t *entries = (libc_env_entry_t *)realloc(g_env_entries, bytes);
    if (!entries)
    {
        return false;
    }
    g_env_entries = entries;
    g_env_capacity = new_cap;
    return true;
}

#ifdef ENABLE_USER_MEM_DEBUG_LOGS
#define USER_HEAP_LOG_PROC_PATH "/proc/sys/mem/uheap_log_enable"
#define USER_HEAP_LOG_POLL_MASK 0xFFFFu
#define USER_HEAP_LOG_CHECK_INTERVAL_MS 60000u

static uint32_t g_user_heap_log_enable = 0;
static uint32_t g_user_heap_log_poll = 0;
static uint64_t g_user_heap_log_last_check_ms = 0;

static bool user_heap_log_enabled(void)
{
    uint32_t poll = __atomic_add_fetch(&g_user_heap_log_poll, 1, __ATOMIC_RELAXED);
    if ((poll & USER_HEAP_LOG_POLL_MASK) != 0)
    {
        return __atomic_load_n(&g_user_heap_log_enable, __ATOMIC_ACQUIRE) != 0;
    }

    uint32_t enabled = __atomic_load_n(&g_user_heap_log_enable, __ATOMIC_ACQUIRE);
    uint64_t now_ms = sys_time_millis();
    uint64_t last_ms = __atomic_load_n(&g_user_heap_log_last_check_ms, __ATOMIC_RELAXED);
    if ((now_ms - last_ms) < USER_HEAP_LOG_CHECK_INTERVAL_MS)
    {
        return enabled != 0;
    }
    __atomic_store_n(&g_user_heap_log_last_check_ms, now_ms, __ATOMIC_RELAXED);
    int fd = sys_open(USER_HEAP_LOG_PROC_PATH, SYSCALL_OPEN_READ);
    if (fd >= 0)
    {
        char buf[4];
        ssize_t got = sys_read(fd, buf, sizeof(buf));
        sys_close(fd);
        if (got > 0)
        {
            for (ssize_t i = 0; i < got; ++i)
            {
                if (buf[i] == '0')
                {
                    enabled = 0;
                    break;
                }
                if (buf[i] == '1')
                {
                    enabled = 1;
                    break;
                }
            }
        }
        __atomic_store_n(&g_user_heap_log_enable, enabled, __ATOMIC_RELEASE);
    }
    return enabled != 0;
}

static void user_heap_log(const char *msg, uintptr_t value)
{
    if (!user_heap_log_enabled())
    {
        return;
    }
    serial_printf("[uheap] %s0x%016llX\n",
                  msg ? msg : "",
                  (unsigned long long)((uint64_t)value));
}

static void user_heap_log_caller(const char *msg, uintptr_t value, uintptr_t caller)
{
    if (!user_heap_log_enabled())
    {
        return;
    }
    serial_printf("[uheap] %s0x%016llX caller=0x%016llX\n",
                  msg ? msg : "",
                  (unsigned long long)((uint64_t)value),
                  (unsigned long long)((uint64_t)caller));
}

static void user_heap_log_caller_size(const char *msg, uintptr_t value, size_t size, uintptr_t caller)
{
    if (!user_heap_log_enabled())
    {
        return;
    }
    serial_printf("[uheap] %s0x%016llX size=0x%016llX caller=0x%016llX\n",
                  msg ? msg : "",
                  (unsigned long long)((uint64_t)value),
                  (unsigned long long)((uint64_t)size),
                  (unsigned long long)((uint64_t)caller));
}
#else
static bool user_heap_log_enabled(void)
{
    return false;
}

static void user_heap_log(const char *msg, uintptr_t value)
{
    (void)msg;
    (void)value;
}

static void user_heap_log_caller(const char *msg, uintptr_t value, uintptr_t caller)
{
    (void)msg;
    (void)value;
    (void)caller;
}

static void user_heap_log_caller_size(const char *msg, uintptr_t value, size_t size, uintptr_t caller)
{
    (void)msg;
    (void)value;
    (void)size;
    (void)caller;
}
#endif

static inline bool user_heap_addr_is_canonical(uintptr_t addr)
{
    return (addr >> 48) == 0;
}

static inline bool user_heap_ptr_is_aligned(uintptr_t addr)
{
    return (addr & (ALIGNMENT - 1)) == 0;
}

static uintptr_t user_heap_current_brk(void)
{
    void *brk = sys_sbrk(0);
    if (brk == (void *)-1 || brk == NULL)
    {
        return 0;
    }
    return (uintptr_t)brk;
}

static bool user_heap_addr_in_bounds(uintptr_t addr)
{
    if (addr == 0)
    {
        return true;
    }
    if (!user_heap_addr_is_canonical(addr))
    {
        return false;
    }
    if (!user_heap_ptr_is_aligned(addr))
    {
        return false;
    }

    uintptr_t low = (uintptr_t)g_heap_head;
    uintptr_t high = g_heap_committed_end;
    if (low == 0 || high == 0)
    {
        return true;
    }
    return addr >= low && addr <= high - sizeof(heap_block_t);
}

static void user_heap_log_corruption(const char *where,
                                     const heap_block_t *block,
                                     size_t request_size,
                                     const heap_block_t *new_block,
                                     const heap_block_t *suspect)
{
    if (!user_heap_log_enabled())
    {
        return;
    }
    uint64_t caller = (uint64_t)__builtin_return_address(0);
    uintptr_t brk = user_heap_current_brk();

    serial_printf("[uheap] CORRUPTION where=%s caller=0x%016llX head=0x%016llX tail=0x%016llX block=0x%016llX free=%u bsz=0x%016llX req=0x%016llX prev=0x%016llX next=0x%016llX new=0x%016llX suspect=0x%016llX brk=0x%016llX\n",
                  where ? where : "<null>",
                  (unsigned long long)caller,
                  (unsigned long long)(uintptr_t)g_heap_head,
                  (unsigned long long)(uintptr_t)g_heap_tail,
                  (unsigned long long)(uintptr_t)block,
                  (unsigned)(block ? block->free : 0),
                  (unsigned long long)(block ? (uint64_t)block->size : 0),
                  (unsigned long long)(uint64_t)request_size,
                  (unsigned long long)(block ? (uintptr_t)block->prev : 0),
                  (unsigned long long)(block ? (uintptr_t)block->next : 0),
                  (unsigned long long)(uintptr_t)new_block,
                  (unsigned long long)(uintptr_t)suspect,
                  (unsigned long long)brk);
}

static size_t align_size(size_t size)
{
    if (size == 0)
    {
        return 0;
    }
    size_t mask = ALIGNMENT - 1;
    return (size + mask) & ~mask;
}

static unsigned free_bin_index(size_t size)
{
    return size ? 63u - (unsigned)__builtin_clzll((unsigned long long)size) : 0;
}

static void free_bin_insert(heap_block_t *block)
{
    unsigned index = free_bin_index(block->size);
    block->free_prev = NULL;
    block->free_next = g_heap_free_bins[index];
    if (block->free_next) block->free_next->free_prev = block;
    g_heap_free_bins[index] = block;
}

static void free_bin_remove(heap_block_t *block)
{
    if (block->free_prev) block->free_prev->free_next = block->free_next;
    else g_heap_free_bins[free_bin_index(block->size)] = block->free_next;
    if (block->free_next) block->free_next->free_prev = block->free_prev;
    block->free_next = block->free_prev = NULL;
}

/* The incoming block is free but has not yet entered a bin. */
static void coalesce(heap_block_t *block);

static void split_block(heap_block_t *block, size_t size)
{
    if (!block || block->size <= size + sizeof(heap_block_t) + ALIGNMENT)
    {
        return;
    }

    if (block->next && !user_heap_addr_in_bounds((uintptr_t)block->next))
    {
        user_heap_log_corruption("split_block next", block, size, NULL, block->next);
        return;
    }

    uintptr_t base = (uintptr_t)block;
    uintptr_t new_block_addr = base + sizeof(heap_block_t) + size;
    heap_block_t *new_block = (heap_block_t *)new_block_addr;
    new_block->size = block->size - size - sizeof(heap_block_t);
    new_block->free = true;
    new_block->next = block->next;
    new_block->prev = block;
    if (new_block->next)
    {
        if (!user_heap_addr_in_bounds((uintptr_t)new_block->next))
        {
            user_heap_log_corruption("split_block next", block, size, new_block, new_block->next);
            new_block->next = NULL;
            g_heap_tail = new_block;
            block->next = new_block;
            block->size = size;
            free_bin_insert(new_block);
            return;
        }
        new_block->next->prev = new_block;
    }
    else
    {
        g_heap_tail = new_block;
    }
    block->next = new_block;
    block->size = size;
    coalesce(new_block);
}

static void coalesce(heap_block_t *block)
{
    if (!block)
    {
        return;
    }

    if (block->next && block->next->free)
    {
        heap_block_t *next = block->next;
        uintptr_t expected = (uintptr_t)block + sizeof(heap_block_t) + block->size;
        if ((uintptr_t)next != expected)
        {
            user_heap_log_corruption("coalesce nonadjacent", block, 0, next, next);
        }
        else
        {
            free_bin_remove(next);
            block->size += sizeof(heap_block_t) + next->size;
            block->next = next->next;
            if (block->next) block->next->prev = block;
            else g_heap_tail = block;
        }
    }

    if (block->prev && block->prev->free)
    {
        heap_block_t *previous = block->prev;
        uintptr_t expected = (uintptr_t)previous + sizeof(heap_block_t) + previous->size;
        if ((uintptr_t)block == expected)
        {
            free_bin_remove(previous);
            previous->size += sizeof(heap_block_t) + block->size;
            previous->next = block->next;
            if (previous->next) previous->next->prev = previous;
            else g_heap_tail = previous;
            block = previous;
        }
        else user_heap_log_corruption("coalesce nonadjacent previous", block, 0, previous, previous);
    }
    free_bin_insert(block);
}

static heap_block_t *find_free_block(size_t size)
{
    for (unsigned index = free_bin_index(size); index < 64; ++index)
    {
        for (heap_block_t *block = g_heap_free_bins[index]; block; block = block->free_next)
        {
            if (block->size >= size)
            {
                free_bin_remove(block);
                return block;
            }
        }
    }
    return NULL;
}

static heap_block_t *request_block_unlinked(size_t size)
{
    /* sys_sbrk takes a signed increment. Never turn an oversized positive
     * allocation into a negative increment that shrinks a live heap. */
    if (size > (((size_t)-1) >> 1) - sizeof(heap_block_t))
    {
        errno = ENOMEM;
        return NULL;
    }
    size_t total = sizeof(heap_block_t) + size;
    if (total < 64u * 1024u) total = 64u * 1024u;
    void *base = sys_sbrk((int64_t)total);
    user_heap_log("sbrk size=", total);
    user_heap_log("sbrk result=", (uintptr_t)base);
    if (base == (void *)-1 || base == NULL)
    {
        user_heap_log("sbrk failed size=", total);
        errno = ENOMEM;
        return NULL;
    }
    g_heap_committed_end = (uintptr_t)base + total;
    heap_block_t *block = (heap_block_t *)base;
    block->size = total - sizeof(heap_block_t);
    block->next = NULL;
    block->prev = NULL;
    block->free = false;
    block->free_next = block->free_prev = NULL;
    return block;
}

static heap_block_t *payload_to_block(void *ptr)
{
    if (!ptr)
    {
        return NULL;
    }
    return (heap_block_t *)((uint8_t *)ptr - sizeof(heap_block_t));
}

static void user_heap_lock_acquire(void)
{
    alix_mutex_lock(&g_heap_lock);
}

static void user_heap_lock_release(void)
{
    alix_mutex_unlock(&g_heap_lock);
}

static void *malloc_locked(size_t size)
{
    if (size > SIZE_MAX_VALUE - (ALIGNMENT - 1u))
    {
        errno = ENOMEM;
        return NULL;
    }
    size = align_size(size);
    if (size == 0)
    {
        return NULL;
    }

    heap_block_t *block = find_free_block(size);
    if (block)
    {
        block->free = false;
        split_block(block, size);
        return (uint8_t *)block + sizeof(heap_block_t);
    }

    /* Grow the heap with the lock held to preserve heap list ordering. */
    heap_block_t *new_block = request_block_unlinked(size);
    if (!new_block)
    {
        return NULL;
    }

    new_block->prev = g_heap_tail;
    new_block->next = NULL;
    if (g_heap_tail)
    {
        g_heap_tail->next = new_block;
    }
    else
    {
        g_heap_head = new_block;
    }
    g_heap_tail = new_block;
    split_block(new_block, size);
    return (uint8_t *)new_block + sizeof(heap_block_t);
}

static void free_locked(void *ptr)
{
    heap_block_t *block = payload_to_block(ptr);
    if (!block || block->free)
    {
        return;
    }

    block->free = true;
    coalesce(block);
}

static void *realloc_locked(void *ptr, size_t size)
{
    if (!ptr)
    {
        return malloc_locked(size);
    }
    if (size == 0)
    {
        free_locked(ptr);
        return NULL;
    }
    if (size > SIZE_MAX_VALUE - (ALIGNMENT - 1u))
    {
        errno = ENOMEM;
        return NULL;
    }

    heap_block_t *block = payload_to_block(ptr);
    if (!block)
    {
        return NULL;
    }

    size = align_size(size);
    if (size <= block->size)
    {
        split_block(block, size);
        return ptr;
    }

    void *new_ptr = malloc_locked(size);
    if (!new_ptr)
    {
        return NULL;
    }
    size_t copy_size = block->size;
    if (size < copy_size)
    {
        copy_size = size;
    }
    memcpy(new_ptr, ptr, copy_size);
    block->free = true;
    coalesce(block);
    return new_ptr;
}

static inline size_t libc_word_repeat(uint8_t byte)
{
    size_t word = (size_t)byte;
    word |= word << 8;
    word |= word << 16;
    if (sizeof(size_t) >= 8)
    {
        word |= word << 32;
    }
    return word;
}

#define LIBC_WORD_ONES ((size_t)-1 / 0xFF)
#define LIBC_WORD_HIGHS (LIBC_WORD_ONES << 7)

static inline bool libc_word_has_zero(size_t word)
{
    return ((word - LIBC_WORD_ONES) & ~word & LIBC_WORD_HIGHS) != 0;
}

static inline bool libc_word_has_byte(size_t word, size_t byte_mask)
{
    return libc_word_has_zero(word ^ byte_mask);
}

void *memset(void *dst, int value, size_t count)
{
    uint8_t *d = (uint8_t *)dst;
    uint8_t byte = (uint8_t)value;
    if (count == 0)
    {
        return dst;
    }

    size_t word = libc_word_repeat(byte);
    size_t word_size = sizeof(size_t);
    size_t word_mask = word_size - 1u;

    while (count && (((uintptr_t)d) & word_mask))
    {
        *d++ = byte;
        count--;
    }
    size_t *dw = (size_t *)d;
    while (count >= word_size)
    {
        *dw++ = word;
        count -= word_size;
    }
    d = (uint8_t *)dw;
    while (count--)
    {
        *d++ = byte;
    }
    return dst;
}

void *memcpy(void *dst, const void *src, size_t count)
{
    uint8_t *d = (uint8_t *)dst;
    const uint8_t *s = (const uint8_t *)src;
    if (count == 0 || d == s)
    {
        return dst;
    }

    size_t word_size = sizeof(size_t);
    size_t word_mask = word_size - 1u;
    if ((((uintptr_t)d ^ (uintptr_t)s) & word_mask) == 0)
    {
        while (count && (((uintptr_t)d) & word_mask))
        {
            *d++ = *s++;
            count--;
        }
        size_t *dw = (size_t *)d;
        const size_t *sw = (const size_t *)s;
        while (count >= word_size * 4u)
        {
            dw[0] = sw[0];
            dw[1] = sw[1];
            dw[2] = sw[2];
            dw[3] = sw[3];
            dw += 4;
            sw += 4;
            count -= word_size * 4u;
        }
        while (count >= word_size)
        {
            *dw++ = *sw++;
            count -= word_size;
        }
        d = (uint8_t *)dw;
        s = (const uint8_t *)sw;
    }

    while (count >= 8)
    {
        d[0] = s[0];
        d[1] = s[1];
        d[2] = s[2];
        d[3] = s[3];
        d[4] = s[4];
        d[5] = s[5];
        d[6] = s[6];
        d[7] = s[7];
        d += 8;
        s += 8;
        count -= 8;
    }
    while (count--)
    {
        *d++ = *s++;
    }
    return dst;
}

void *memmove(void *dst, const void *src, size_t count)
{
    uint8_t *d = (uint8_t *)dst;
    const uint8_t *s = (const uint8_t *)src;
    if (d == s || count == 0)
    {
        return dst;
    }

    if (d < s)
    {
        return memcpy(dst, src, count);
    }

    size_t word_size = sizeof(size_t);
    size_t word_mask = word_size - 1u;
    d += count;
    s += count;

    if ((((uintptr_t)d ^ (uintptr_t)s) & word_mask) == 0)
    {
        while (count && (((uintptr_t)d) & word_mask))
        {
            *--d = *--s;
            count--;
        }
        size_t *dw = (size_t *)d;
        const size_t *sw = (const size_t *)s;
        while (count >= word_size)
        {
            dw--;
            sw--;
            *dw = *sw;
            count -= word_size;
        }
        d = (uint8_t *)dw;
        s = (const uint8_t *)sw;
    }

    while (count--)
    {
        *--d = *--s;
    }
    return dst;
}

int memcmp(const void *a, const void *b, size_t count)
{
    const uint8_t *pa = (const uint8_t *)a;
    const uint8_t *pb = (const uint8_t *)b;
    size_t word_size = sizeof(size_t);
    size_t word_mask = word_size - 1u;

    if ((((uintptr_t)pa ^ (uintptr_t)pb) & word_mask) == 0)
    {
        while (count && (((uintptr_t)pa) & word_mask))
        {
            if (*pa != *pb)
            {
                return (int)*pa - (int)*pb;
            }
            pa++;
            pb++;
            count--;
        }

        const size_t *wa = (const size_t *)pa;
        const size_t *wb = (const size_t *)pb;
        while (count >= word_size)
        {
            if (*wa != *wb)
            {
                const uint8_t *ba = (const uint8_t *)wa;
                const uint8_t *bb = (const uint8_t *)wb;
                for (size_t i = 0; i < word_size; ++i)
                {
                    if (ba[i] != bb[i])
                    {
                        return (int)ba[i] - (int)bb[i];
                    }
                }
            }
            wa++;
            wb++;
            count -= word_size;
        }
        pa = (const uint8_t *)wa;
        pb = (const uint8_t *)wb;
    }

    while (count--)
    {
        if (*pa != *pb)
        {
            return (int)*pa - (int)*pb;
        }
        pa++;
        pb++;
    }
    return 0;
}

void *memchr(const void *src, int ch, size_t count)
{
    const uint8_t *s = (const uint8_t *)src;
    uint8_t needle = (uint8_t)ch;
    size_t word_size = sizeof(size_t);
    size_t byte_mask = libc_word_repeat(needle);

    while (count && (((uintptr_t)s) & (word_size - 1u)))
    {
        if (*s == needle)
        {
            return (void *)s;
        }
        ++s;
        --count;
    }

    const size_t *w = (const size_t *)s;
    while (count >= word_size)
    {
        size_t word = *w;
        if (libc_word_has_byte(word, byte_mask))
        {
            s = (const uint8_t *)w;
            for (size_t i = 0; i < word_size; ++i)
            {
                if (s[i] == needle)
                {
                    return (void *)(s + i);
                }
            }
        }
        ++w;
        count -= word_size;
    }

    s = (const uint8_t *)w;
    while (count--)
    {
        if (*s == needle)
        {
            return (void *)s;
        }
        ++s;
    }
    return NULL;
}

size_t strnlen(const char *str, size_t maximum)
{
    size_t length = 0;
    while (length < maximum && str[length]) ++length;
    return length;
}

size_t strlen(const char *str)
{
    if (!str)
    {
        return 0;
    }
    const unsigned char *start = (const unsigned char *)str;
    const unsigned char *s = start;
    size_t word_size = sizeof(size_t);
    size_t word_mask = word_size - 1u;
    while (((uintptr_t)s & word_mask) != 0u)
    {
        if (*s == '\0')
        {
            return (size_t)(s - start);
        }
        ++s;
    }
    const size_t *w = (const size_t *)s;
    while (!libc_word_has_zero(*w))
    {
        ++w;
    }
    s = (const unsigned char *)w;
    while (*s)
    {
        ++s;
    }
    return (size_t)(s - start);
}

int strcmp(const char *a, const char *b)
{
    const unsigned char *pa = (const unsigned char *)a;
    const unsigned char *pb = (const unsigned char *)b;
    size_t word_size = sizeof(size_t);
    size_t word_mask = word_size - 1u;

    if ((((uintptr_t)pa ^ (uintptr_t)pb) & word_mask) == 0u)
    {
        while (((uintptr_t)pa & word_mask) != 0u)
        {
            unsigned char ca = *pa;
            unsigned char cb = *pb;
            if (ca != cb)
            {
                return (int)ca - (int)cb;
            }
            if (ca == '\0')
            {
                return 0;
            }
            ++pa;
            ++pb;
        }
        for (;;)
        {
            size_t wa = *(const size_t *)pa;
            size_t wb = *(const size_t *)pb;
            if (wa == wb)
            {
                if (libc_word_has_zero(wa))
                {
                    return 0;
                }
                pa += word_size;
                pb += word_size;
                continue;
            }
            for (size_t i = 0; i < word_size; ++i)
            {
                unsigned char ca = pa[i];
                unsigned char cb = pb[i];
                if (ca != cb)
                {
                    return (int)ca - (int)cb;
                }
                if (ca == '\0')
                {
                    return 0;
                }
            }
        }
    }

    for (;;)
    {
        unsigned char ca = *pa;
        unsigned char cb = *pb;
        if (ca != cb)
        {
            return (int)ca - (int)cb;
        }
        if (ca == '\0')
        {
            return 0;
        }
        ++pa;
        ++pb;
    }
}

int strncmp(const char *a, const char *b, size_t n)
{
    const unsigned char *pa = (const unsigned char *)a;
    const unsigned char *pb = (const unsigned char *)b;
    size_t word_size = sizeof(size_t);
    size_t word_mask = word_size - 1u;

    if (n == 0)
    {
        return 0;
    }

    if ((((uintptr_t)pa ^ (uintptr_t)pb) & word_mask) == 0u)
    {
        while (n && (((uintptr_t)pa & word_mask) != 0u))
        {
            unsigned char ca = *pa;
            unsigned char cb = *pb;
            if (ca != cb)
            {
                return (int)ca - (int)cb;
            }
            if (ca == '\0')
            {
                return 0;
            }
            ++pa;
            ++pb;
            --n;
        }
        while (n >= word_size)
        {
            size_t wa = *(const size_t *)pa;
            size_t wb = *(const size_t *)pb;
            if (wa == wb && !libc_word_has_zero(wa))
            {
                pa += word_size;
                pb += word_size;
                n -= word_size;
                continue;
            }
            for (size_t i = 0; i < word_size && i < n; ++i)
            {
                unsigned char ca = pa[i];
                unsigned char cb = pb[i];
                if (ca != cb)
                {
                    return (int)ca - (int)cb;
                }
                if (ca == '\0')
                {
                    return 0;
                }
            }
            pa += word_size;
            pb += word_size;
            n -= word_size;
        }
    }

    while (n--)
    {
        unsigned char ca = *pa++;
        unsigned char cb = *pb++;
        if (ca != cb)
        {
            return (int)ca - (int)cb;
        }
        if (ca == '\0')
        {
            return 0;
        }
    }
    return 0;
}

char *strcpy(char *dst, const char *src)
{
    if (!dst || !src)
    {
        return dst;
    }
    char *out = dst;
    while (*src)
    {
        *dst++ = *src++;
    }
    *dst = '\0';
    return out;
}

char *strncpy(char *dst, const char *src, size_t n)
{
    if (!dst || !src || n == 0)
    {
        return dst;
    }
    size_t i = 0;
    for (; i < n && src[i] != '\0'; ++i)
    {
        dst[i] = src[i];
    }
    for (; i < n; ++i)
    {
        dst[i] = '\0';
    }
    return dst;
}

char *strcat(char *dst, const char *src)
{
    if (!dst || !src)
    {
        return dst;
    }
    char *out = dst;
    while (*dst)
    {
        ++dst;
    }
    while (*src)
    {
        *dst++ = *src++;
    }
    *dst = '\0';
    return out;
}

char *strncat(char *dst, const char *src, size_t n)
{
    if (!dst || !src || n == 0)
    {
        return dst;
    }
    char *out = dst;
    while (*dst)
    {
        ++dst;
    }
    size_t copied = 0;
    while (copied < n && src[copied] != '\0')
    {
        dst[copied] = src[copied];
        ++copied;
    }
    /* n bounds source characters, not total destination capacity. Append
     * exactly one terminator; unlike strncpy, do not pad the remainder. */
    dst[copied] = '\0';
    return out;
}

char *strchr(const char *str, int ch)
{
    if (!str)
    {
        return NULL;
    }
    unsigned char target = (unsigned char)ch;
    const unsigned char *s = (const unsigned char *)str;
    size_t word_size = sizeof(size_t);
    size_t word_mask = word_size - 1u;
    while (((uintptr_t)s & word_mask) != 0u)
    {
        if (*s == target)
        {
            return (char *)s;
        }
        if (*s == '\0')
        {
            return (target == '\0') ? (char *)s : NULL;
        }
        ++s;
    }
    size_t mask = LIBC_WORD_ONES * target;
    for (;;)
    {
        size_t w = *(const size_t *)s;
        if (libc_word_has_zero(w) || libc_word_has_byte(w, mask))
        {
            for (size_t i = 0; i < word_size; ++i)
            {
                unsigned char c = s[i];
                if (c == target)
                {
                    return (char *)(s + i);
                }
                if (c == '\0')
                {
                    return (target == '\0') ? (char *)(s + i) : NULL;
                }
            }
        }
        s += word_size;
    }
}

char *strrchr(const char *str, int ch)
{
    if (!str)
    {
        return NULL;
    }
    char target = (char)ch;
    const char *last = NULL;
    while (*str)
    {
        if (*str == target)
        {
            last = str;
        }
        ++str;
    }
    if (target == '\0')
    {
        return (char *)str;
    }
    return (char *)last;
}

char *strstr(const char *haystack, const char *needle)
{
    if (!haystack || !needle)
    {
        return NULL;
    }
    if (*needle == '\0')
    {
        return (char *)haystack;
    }

    size_t needle_len = strlen(needle);
    for (const char *p = haystack; *p; ++p)
    {
        if (*p == *needle && strncmp(p, needle, needle_len) == 0)
        {
            return (char *)p;
        }
    }
    return NULL;
}

static int libc_tolower_char(int ch)
{
    if (ch >= 'A' && ch <= 'Z')
    {
        return ch - 'A' + 'a';
    }
    return ch;
}

int strcasecmp(const char *a, const char *b)
{
    if (a == b)
    {
        return 0;
    }
    if (!a || !b)
    {
        int ca = a ? libc_tolower_char((unsigned char)*a) : 0;
        int cb = b ? libc_tolower_char((unsigned char)*b) : 0;
        return ca - cb;
    }
    for (;;)
    {
        int ca = libc_tolower_char((unsigned char)a[0]);
        int cb = libc_tolower_char((unsigned char)b[0]);
        if (ca != cb)
        {
            return ca - cb;
        }
        if (ca == 0)
        {
            return 0;
        }
        ca = libc_tolower_char((unsigned char)a[1]);
        cb = libc_tolower_char((unsigned char)b[1]);
        if (ca != cb)
        {
            return ca - cb;
        }
        if (ca == 0)
        {
            return 0;
        }
        ca = libc_tolower_char((unsigned char)a[2]);
        cb = libc_tolower_char((unsigned char)b[2]);
        if (ca != cb)
        {
            return ca - cb;
        }
        if (ca == 0)
        {
            return 0;
        }
        ca = libc_tolower_char((unsigned char)a[3]);
        cb = libc_tolower_char((unsigned char)b[3]);
        if (ca != cb)
        {
            return ca - cb;
        }
        if (ca == 0)
        {
            return 0;
        }
        a += 4;
        b += 4;
    }
}

int strncasecmp(const char *a, const char *b, size_t n)
{
    if (n == 0)
    {
        return 0;
    }
    if (!a || !b)
    {
        int ca = a ? libc_tolower_char((unsigned char)*a) : 0;
        int cb = b ? libc_tolower_char((unsigned char)*b) : 0;
        return ca - cb;
    }
    while (n >= 4)
    {
        int ca = libc_tolower_char((unsigned char)a[0]);
        int cb = libc_tolower_char((unsigned char)b[0]);
        if (ca != cb || ca == 0 || cb == 0)
        {
            return ca - cb;
        }
        ca = libc_tolower_char((unsigned char)a[1]);
        cb = libc_tolower_char((unsigned char)b[1]);
        if (ca != cb || ca == 0 || cb == 0)
        {
            return ca - cb;
        }
        ca = libc_tolower_char((unsigned char)a[2]);
        cb = libc_tolower_char((unsigned char)b[2]);
        if (ca != cb || ca == 0 || cb == 0)
        {
            return ca - cb;
        }
        ca = libc_tolower_char((unsigned char)a[3]);
        cb = libc_tolower_char((unsigned char)b[3]);
        if (ca != cb || ca == 0 || cb == 0)
        {
            return ca - cb;
        }
        a += 4;
        b += 4;
        n -= 4;
    }
    while (n--)
    {
        int ca = libc_tolower_char((unsigned char)*a++);
        int cb = libc_tolower_char((unsigned char)*b++);
        if (ca != cb || ca == 0 || cb == 0)
        {
            return ca - cb;
        }
    }
    return 0;
}

int toupper(int ch)
{
    if (ch >= 'a' && ch <= 'z')
    {
        return ch - ('a' - 'A');
    }
    return ch;
}

int tolower(int ch)
{
    return libc_tolower_char(ch);
}

int isdigit(int ch)
{
    return (ch >= '0' && ch <= '9') ? 1 : 0;
}

int isprint(int ch)
{
    return (ch >= 0x20 && ch <= 0x7E) ? 1 : 0;
}

int isspace(int ch)
{
    return (ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r' || ch == '\v' || ch == '\f') ? 1 : 0;
}

int isalpha(int ch)
{
    return ((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z')) ? 1 : 0;
}

int isalnum(int ch)
{
    return (isalpha(ch) || isdigit(ch)) ? 1 : 0;
}

int isxdigit(int ch) { return isdigit(ch) || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F'); }
int islower(int ch) { return ch >= 'a' && ch <= 'z'; }
int isupper(int ch) { return ch >= 'A' && ch <= 'Z'; }
int iscntrl(int ch) { return (ch >= 0 && ch < 32) || ch == 127; }
int isgraph(int ch) { return ch > 32 && ch < 127; }
int ispunct(int ch) { return isgraph(ch) && !isalnum(ch); }
int isblank(int ch) { return ch == ' ' || ch == '\t'; }

int abs(int value)
{
    return (value < 0) ? -value : value;
}

int atoi(const char *str)
{
    if (!str)
    {
        return 0;
    }
    while (isspace((unsigned char)*str))
    {
        ++str;
    }
    int sign = 1;
    if (*str == '+' || *str == '-')
    {
        if (*str == '-')
        {
            sign = -1;
        }
        ++str;
    }
    int result = 0;
    while (isdigit((unsigned char)*str))
    {
        result = result * 10 + (*str - '0');
        ++str;
    }
    return result * sign;
}

double atof(const char *str)
{
    return strtod(str, NULL);
}

static uint32_t g_rand_state = 1u;

void srand(unsigned int seed)
{
    __atomic_store_n(&g_rand_state, seed ? (uint32_t)seed : 1u, __ATOMIC_RELAXED);
}

int rand(void)
{
    /* ANSI C compatible LCG; returns 0..32767. */
    uint32_t previous = __atomic_load_n(&g_rand_state, __ATOMIC_RELAXED), next;
    do { next = previous * 1103515245u + 12345u; }
    while (!__atomic_compare_exchange_n(&g_rand_state, &previous, next, false,
                                         __ATOMIC_RELAXED, __ATOMIC_RELAXED));
    return (int)((next >> 16) & 0x7FFFu);
}

static char *libc_getenv_unlocked(const char *name)
{
    if (!name || name[0] == '\0' || name[0] == '=')
    {
        return NULL;
    }
    int index = libc_env_find(name);
    if (index < 0)
    {
        return NULL;
    }
    libc_env_entry_t *entry = &g_env_entries[index];
    return entry->assignment ? strchr(entry->assignment, '=') + 1 : entry->value;
}

char *getenv(const char *name)
{
    alix_mutex_lock(&g_env_mutex);
    char *value = libc_getenv_unlocked(name);
    alix_mutex_unlock(&g_env_mutex);
    return value;
}

uint32_t getuid(void)
{
    return sys_getuid();
}

static char *libc_strdup_len(const char *src, size_t len)
{
    if (!src && len != 0)
    {
        return NULL;
    }
    char *dst = (char *)malloc(len + 1);
    if (!dst)
    {
        return NULL;
    }
    if (len > 0)
    {
        memcpy(dst, src, len);
    }
    dst[len] = '\0';
    return dst;
}

static char *libc_strdup(const char *src)
{
    if (!src)
    {
        return NULL;
    }
    return libc_strdup_len(src, strlen(src));
}

char *strdup(const char *src)
{
    if (!src)
    {
        errno = EINVAL;
        return NULL;
    }
    char *copy = libc_strdup(src);
    if (!copy) errno = ENOMEM;
    return copy;
}

static bool libc_parse_u32_range(const char *start, const char *end, uint32_t *out)
{
    if (!start || !end || !out || start >= end)
    {
        return false;
    }
    uint32_t value = 0;
    for (const char *cur = start; cur < end; ++cur)
    {
        if (*cur < '0' || *cur > '9')
        {
            return false;
        }
        uint32_t digit = (uint32_t)(*cur - '0');
        uint32_t next = value * 10u + digit;
        if (next < value)
        {
            return false;
        }
        value = next;
    }
    *out = value;
    return true;
}

static char *libc_read_file_all(const char *path, size_t *len_out, size_t max_bytes)
{
    if (len_out)
    {
        *len_out = 0;
    }
    if (!path || path[0] == '\0')
    {
        return NULL;
    }

    int fd = sys_open(path, SYSCALL_OPEN_READ);
    if (fd < 0)
    {
        return NULL;
    }

    syscall_stat_t st;
    if (sys_fstat(fd, &st) != 0)
    {
        sys_close(fd);
        return NULL;
    }

    if (st.size_bytes == 0 || st.size_bytes > max_bytes)
    {
        sys_close(fd);
        return NULL;
    }

    size_t size = (size_t)st.size_bytes;
    char *buf = (char *)malloc(size + 1);
    if (!buf)
    {
        sys_close(fd);
        return NULL;
    }

    size_t offset = 0;
    while (offset < size)
    {
        ssize_t got = sys_read(fd, buf + offset, size - offset);
        if (got <= 0)
        {
            free(buf);
            sys_close(fd);
            return NULL;
        }
        offset += (size_t)got;
    }
    buf[size] = '\0';
    sys_close(fd);

    if (len_out)
    {
        *len_out = size;
    }
    return buf;
}

static bool libc_passwd_line_home(const char *line,
                                  const char *end,
                                  uint32_t *uid_out,
                                  const char **home_start_out,
                                  size_t *home_len_out)
{
    if (!line || !end || line >= end || !uid_out || !home_start_out || !home_len_out)
    {
        return false;
    }

    const char *colon1 = NULL;
    const char *colon2 = NULL;
    const char *colon3 = NULL;
    const char *colon4 = NULL;
    for (const char *cur = line; cur < end; ++cur)
    {
        if (*cur == ':')
        {
            if (!colon1)
            {
                colon1 = cur;
            }
            else if (!colon2)
            {
                colon2 = cur;
            }
            else if (!colon3)
            {
                colon3 = cur;
            }
            else
            {
                colon4 = cur;
                break;
            }
        }
    }

    if (!colon1 || !colon2 || !colon3 || !colon4)
    {
        return false;
    }

    uint32_t uid = 0;
    if (!libc_parse_u32_range(colon1 + 1, colon2, &uid))
    {
        return false;
    }

    const char *home_start = colon4 + 1;
    if (home_start > end)
    {
        return false;
    }
    size_t home_len = (size_t)(end - home_start);
    if (home_len == 0)
    {
        return false;
    }

    *uid_out = uid;
    *home_start_out = home_start;
    *home_len_out = home_len;
    return true;
}

char *alix_home_dir(void)
{
    size_t data_len = 0;
    char *data = libc_read_file_all("/etc/passwd", &data_len, LIBC_MAX_PASSWD_BYTES);
    if (!data || data_len == 0)
    {
        free(data);
        return NULL;
    }

    uint32_t uid = getuid();
    char *home = NULL;
    char *root_home = NULL;
    size_t pos = 0;
    while (pos < data_len)
    {
        size_t line_end = pos;
        while (line_end < data_len && data[line_end] != '\n' && data[line_end] != '\r')
        {
            ++line_end;
        }

        if (line_end > pos)
        {
            const char *line = data + pos;
            const char *end = data + line_end;
            uint32_t line_uid = 0;
            const char *home_start = NULL;
            size_t home_len = 0;
            if (libc_passwd_line_home(line, end, &line_uid, &home_start, &home_len))
            {
                if (!home && line_uid == uid)
                {
                    home = libc_strdup_len(home_start, home_len);
                }
                if (!root_home && line_uid == 0)
                {
                    root_home = libc_strdup_len(home_start, home_len);
                }
            }
        }

        while (line_end < data_len && (data[line_end] == '\n' || data[line_end] == '\r'))
        {
            ++line_end;
        }
        pos = line_end;
    }

    free(data);
    if (home)
    {
        free(root_home);
        return home;
    }
    return root_home;
}

static bool libc_dir_exists(const char *path)
{
    if (!path || path[0] == '\0')
    {
        return false;
    }
    syscall_dirent_t *scratch = (syscall_dirent_t *)malloc(sizeof(*scratch));
    if (!scratch)
    {
        return false;
    }
    ssize_t count = sys_list_dir(path, scratch, 1);
    free(scratch);
    return count >= 0;
}

bool alix_ensure_dir_path(const char *path)
{
    if (!path || path[0] == '\0')
    {
        return false;
    }

    char *copy = libc_strdup(path);
    if (!copy)
    {
        return false;
    }

    size_t len = strlen(copy);
    if (len == 0)
    {
        free(copy);
        return false;
    }

    size_t pos = 0;
    if (copy[0] == '/')
    {
        pos = 1;
        while (copy[pos] == '/')
        {
            pos++;
        }
    }

    for (; pos <= len; ++pos)
    {
        if (copy[pos] == '/' || copy[pos] == '\0')
        {
            char saved = copy[pos];
            copy[pos] = '\0';
            if (copy[0] != '\0' && !(copy[0] == '/' && copy[1] == '\0'))
            {
                if (mkdir(copy, 0) != 0)
                {
                    if (!libc_dir_exists(copy))
                    {
                        free(copy);
                        return false;
                    }
                }
            }
            copy[pos] = saved;
            while (copy[pos] == '/')
            {
                pos++;
            }
        }
    }

    free(copy);
    return true;
}

static int libc_setenv_unlocked(const char *name, const char *value, int overwrite)
{
    if (!name || name[0] == '\0' || strchr(name, '='))
    {
        errno = EINVAL;
        return -1;
    }
    if (!value)
    {
        value = "";
    }

    int index = libc_env_find(name);
    if (index >= 0 && !overwrite)
    {
        return 0;
    }

    size_t name_len = strlen(name) + 1;
    size_t value_len = strlen(value) + 1;

    char *name_copy = NULL;
    char *value_copy = (char *)malloc(value_len);
    if (!value_copy)
    {
        errno = ENOMEM;
        return -1;
    }
    memcpy(value_copy, value, value_len);

    if (index < 0)
    {
        if (!libc_env_reserve(g_env_count + 1))
        {
            free(value_copy);
            errno = ENOMEM;
            return -1;
        }
        name_copy = (char *)malloc(name_len);
        if (!name_copy)
        {
            free(value_copy);
            errno = ENOMEM;
            return -1;
        }
        memcpy(name_copy, name, name_len);
        g_env_entries[g_env_count] = (libc_env_entry_t){ name_copy, value_copy, NULL };
        g_env_count++;
        return 0;
    }

    if (g_env_entries[index].assignment)
    {
        name_copy = malloc(name_len);
        if (!name_copy) { free(value_copy); errno = ENOMEM; return -1; }
        memcpy(name_copy, name, name_len);
        free(g_env_entries[index].name);
        free(g_env_entries[index].value);
        g_env_entries[index] = (libc_env_entry_t){ name_copy, value_copy, NULL };
        return 0;
    }
    free(g_env_entries[index].value);
    g_env_entries[index].value = value_copy;
    return 0;
}

#ifdef TTF_HOST_BUILD
int mkdir(const char *path, mode_t mode)
#else
int mkdir(const char *path, uint32_t mode)
#endif
{
    (void)mode;
#if defined(ALIX_OWNED_FDS) && !defined(TTF_HOST_BUILD)
    int64_t result = sys_file_io(SYSCALL_FILE_MKDIR_MODE, (uintptr_t)path, mode, 0, 0);
    if (result < 0) { errno = (int)-result; return -1; }
    return 0;
#else
    if (!path || path[0] == '\0')
    {
        errno = EINVAL;
        return -1;
    }
    if (sys_mkdir(path) != 0)
    {
        errno = EINVAL;
        return -1;
    }
    return 0;
#endif
}

int setenv(const char *name, const char *value, int overwrite)
{
    alix_mutex_lock(&g_env_mutex);
    int result = libc_setenv_unlocked(name, value, overwrite);
    alix_mutex_unlock(&g_env_mutex);
    return result;
}

static int libc_unsetenv_unlocked(const char *name)
{
    if (!name || name[0] == '\0' || strchr(name, '='))
    {
        errno = EINVAL;
        return -1;
    }
    int index = libc_env_find(name);
    if (index < 0)
    {
        return 0;
    }
    free(g_env_entries[index].name);
    free(g_env_entries[index].value);
    for (size_t i = (size_t)index + 1; i < g_env_count; ++i)
    {
        g_env_entries[i - 1] = g_env_entries[i];
    }
    if (g_env_count > 0)
    {
        g_env_count--;
    }
    return 0;
}

int unsetenv(const char *name)
{
    alix_mutex_lock(&g_env_mutex);
    int result = libc_unsetenv_unlocked(name);
    alix_mutex_unlock(&g_env_mutex);
    return result;
}

int putenv(char *assignment)
{
    if (!assignment || !assignment[0] || assignment[0] == '=') { errno = EINVAL; return -1; }
    const char *separator = strchr(assignment, '=');
    /* Match the widely used removal extension without retaining that string. */
    if (!separator) return unsetenv(assignment);
    size_t length = (size_t)(separator - assignment);
    char *name = malloc(length + 1);
    if (!name) { errno = ENOMEM; return -1; }
    memcpy(name, assignment, length); name[length] = 0;
    alix_mutex_lock(&g_env_mutex);
    int index = libc_env_find(name);
    int result = 0;
    char *retained = NULL;
    if (index < 0)
    {
        if (!libc_env_reserve(g_env_count + 1)) { errno = ENOMEM; result = -1; }
        else index = (int)g_env_count++;
    }
    else
    {
        char *old = g_env_entries[index].value;
        if (old && (uintptr_t)assignment >= (uintptr_t)old &&
            (uintptr_t)assignment - (uintptr_t)old <= strlen(old)) retained = old;
        free(g_env_entries[index].name);
        if (!retained) free(old);
    }
    if (!result) g_env_entries[index] = (libc_env_entry_t){ NULL, retained, assignment };
    alix_mutex_unlock(&g_env_mutex);
    free(name);
    return result;
}

void alix_environment_free(char **environment)
{
    if (!environment) return;
    for (size_t index = 0; environment[index]; ++index) free(environment[index]);
    free(environment);
}

char **alix_environment_copy(void)
{
    alix_mutex_lock(&g_env_mutex);
    char **copy = calloc(g_env_count + 1, sizeof(*copy));
    if (copy)
        for (size_t index = 0; index < g_env_count; ++index)
        {
            if (g_env_entries[index].assignment)
            {
                copy[index] = strdup(g_env_entries[index].assignment);
                if (!copy[index]) { alix_environment_free(copy); copy = NULL; break; }
                continue;
            }
            size_t name = strlen(g_env_entries[index].name), value = strlen(g_env_entries[index].value);
            if (name > SIZE_MAX - value - 2 || !(copy[index] = malloc(name + value + 2)))
            { alix_environment_free(copy); copy = NULL; break; }
            memcpy(copy[index], g_env_entries[index].name, name);
            copy[index][name] = '=';
            memcpy(copy[index] + name + 1, g_env_entries[index].value, value + 1);
        }
    alix_mutex_unlock(&g_env_mutex);
    if (!copy) errno = ENOMEM;
    return copy;
}

int __alix_environment_initialize(char **environment)
{
    if (!environment) return 0;
    for (size_t index = 0; environment[index]; ++index)
    {
        const char *separator = strchr(environment[index], '=');
        if (!separator || separator == environment[index]) continue;
        size_t bytes = (size_t)(separator - environment[index]);
        char *name = malloc(bytes + 1);
        if (!name) return -1;
        memcpy(name, environment[index], bytes); name[bytes] = 0;
        int result = setenv(name, separator + 1, 0);
        free(name);
        if (result) return result;
    }
    return 0;
}

static const char *libc_error_message(int errnum)
{
    switch (errnum)
    {
        case 0: return "Success";
        case EPERM: return "Operation not permitted";
        case ESRCH: return "No such process";
        case EACCES: return "Permission denied";
        case EBADF: return "Bad file descriptor";
        case EBUSY: return "Resource busy";
        case EFAULT: return "Bad address";
        case EINVAL: return "Invalid argument";
        case ENOMEM: return "Out of memory";
        case ENOENT: return "No such file or directory";
        case EAGAIN: return "Resource temporarily unavailable";
        case EINTR:  return "Interrupted system call";
        case EEXIST: return "File exists";
        case EIO:    return "I/O error";
        case ENOSYS: return "Function not implemented";
        case ENOSPC: return "No space left on device";
        case EDOM: return "Numerical argument out of domain";
        case ERANGE: return "Result out of range";
        case EOVERFLOW: return "Value too large";
        case ETIMEDOUT: return "Operation timed out";
        case EHOSTDOWN: return "Host is down";
        case EHOSTUNREACH: return "No route to host";
        case EDEADLK: return "Resource deadlock avoided";
        case EILSEQ: return "Invalid byte sequence";
        case ENOTSUP: return "Operation not supported";
        default: return NULL;
    }
}

char *strerror(int errnum)
{
    const char *message = libc_error_message(errnum);
    return (char *)(message ? message : "Unknown error");
}

int strerror_r(int errnum, char *buffer, size_t capacity)
{
    if (!buffer || capacity == 0) return ERANGE;
    const char *message = libc_error_message(errnum);
    if (!message) { buffer[0] = '\0'; return EINVAL; }
    size_t length = strlen(message);
    size_t copied = length < capacity - 1 ? length : capacity - 1;
    memcpy(buffer, message, copied);
    buffer[copied] = '\0';
    return copied == length ? 0 : ERANGE;
}

#ifndef TTF_HOST_BUILD
static size_t file_write_bytes_unlocked(FILE *stream, const void *data, size_t count);

typedef struct
{
    FILE *stream;
    char *buffer;
    size_t capacity;
    size_t length;
    bool error;
    bool buffer_mode;
    bool dynamic_buffer;
} printf_sink_t;

static bool printf_sink_reserve(printf_sink_t *sink, size_t added)
{
    if (sink->error) return false;
    if (added > (size_t)INT_MAX - sink->length)
    { errno = EOVERFLOW; sink->error = true; return false; }
    if (!sink->dynamic_buffer) return true;
    size_t needed = sink->length + added + 1;
    if (needed <= sink->capacity) return true;
    size_t capacity = sink->capacity ? sink->capacity : 128;
    while (capacity < needed)
    {
        if (capacity > ((size_t)INT_MAX + 1) / 2) { capacity = needed; break; }
        capacity *= 2;
    }
    char *buffer = realloc(sink->buffer, capacity);
    if (!buffer) { errno = ENOMEM; sink->error = true; return false; }
    sink->buffer = buffer;
    sink->capacity = capacity;
    return true;
}

static void printf_sink_write(printf_sink_t *sink, const char *data, size_t len)
{
    if (!sink || sink->error || !data || len == 0)
    {
        return;
    }

    if (!printf_sink_reserve(sink, len)) return;

    if (sink->buffer_mode)
    {
        if (sink->buffer && sink->capacity > 0 && sink->length < sink->capacity)
        {
            size_t space = sink->capacity - sink->length;
            if (space > 0)
            {
                /* Keep one byte for the null terminator. */
                if (space > 0)
                {
                    size_t copy = len;
                    if (copy > space - 1)
                    {
                        copy = space - 1;
                    }
                    if (copy > 0)
                    {
                        memcpy(sink->buffer + sink->length, data, copy);
                    }
                }
            }
        }
        sink->length += len;
        return;
    }

    size_t result = file_write_bytes_unlocked(sink->stream, data, len);
    sink->length += result;
    if (result != len) sink->error = true;
}

static void printf_sink_putc(printf_sink_t *sink, char c)
{
    printf_sink_write(sink, &c, 1);
}

static void printf_sink_pad(printf_sink_t *sink, char ch, int count)
{
    if (!sink || sink->error || count <= 0) return;
    if (!printf_sink_reserve(sink, (size_t)count)) return;
    if (sink->buffer_mode)
    {
        if (sink->buffer && sink->capacity && sink->length < sink->capacity - 1)
        {
            size_t space = sink->capacity - 1 - sink->length;
            size_t copy = (size_t)count < space ? (size_t)count : space;
            memset(sink->buffer + sink->length, ch, copy);
        }
        sink->length += (size_t)count;
        return;
    }
    char padding[64];
    memset(padding, ch, sizeof(padding));
    while (count && !sink->error)
    {
        size_t chunk = (unsigned)count < sizeof(padding) ? (unsigned)count : sizeof(padding);
        printf_sink_write(sink, padding, chunk);
        count -= (int)chunk;
    }
}

static void printf_sink_print_uint_formatted(printf_sink_t *sink,
                                             uint64_t value,
                                             unsigned base,
                                             bool uppercase,
                                             int width,
                                             bool left_align,
                                             bool zero_pad,
                                             bool has_precision,
                                             int precision,
                                             const char *prefix,
                                             size_t prefix_len,
                                             bool alternate)
{
    if (base < 2 || base > 16)
    {
        return;
    }

    const char *digits = uppercase ? "0123456789ABCDEF" : "0123456789abcdef";
    char buffer[64];
    size_t digit_count = 0;

    if (has_precision && precision < 0)
    {
        has_precision = false;
    }

    if (has_precision && precision == 0 && value == 0)
    {
        digit_count = 0;
    }
    else
    {
        do
        {
            buffer[digit_count++] = digits[value % base];
            value /= base;
        } while (value != 0 && digit_count < sizeof(buffer));
    }

    int zeroes = 0;
    if (has_precision)
    {
        if (precision > (int)digit_count)
        {
            zeroes = precision - (int)digit_count;
        }
        /* When precision is specified, the 0 flag is ignored. */
        zero_pad = false;
    }

    if (alternate && base == 8 && zeroes == 0)
    {
        if (digit_count == 0) buffer[digit_count++] = '0';
        else if (buffer[digit_count - 1] != '0') zeroes = 1;
    }
    if (prefix_len + (size_t)zeroes + digit_count > INT_MAX)
    { errno = EOVERFLOW; sink->error = true; return; }
    int total = (int)prefix_len + zeroes + (int)digit_count;
    int pad = 0;
    if (width > total)
    {
        pad = width - total;
    }

    if (!left_align)
    {
        if (zero_pad)
        {
            /* For numeric conversions, zero padding follows the prefix/sign. */
            if (prefix_len)
            {
                printf_sink_write(sink, prefix, prefix_len);
            }
            printf_sink_pad(sink, '0', pad);
        }
        else
        {
            printf_sink_pad(sink, ' ', pad);
            if (prefix_len)
            {
                printf_sink_write(sink, prefix, prefix_len);
            }
        }
    }
    else
    {
        if (prefix_len)
        {
            printf_sink_write(sink, prefix, prefix_len);
        }
    }

    printf_sink_pad(sink, '0', zeroes);

    while (digit_count > 0)
    {
        printf_sink_putc(sink, buffer[--digit_count]);
    }

    if (left_align)
    {
        printf_sink_pad(sink, ' ', pad);
    }
}

static void printf_sink_print_int_formatted(printf_sink_t *sink,
                                            int64_t value,
                                            int width,
                                            bool left_align,
                                            bool zero_pad,
                                            bool has_precision,
                                            int precision,
                                            char positive_prefix)
{
    const char *prefix = "";
    size_t prefix_len = 0;
    uint64_t magnitude = (uint64_t)value;

    if (value < 0)
    {
        prefix = "-";
        prefix_len = 1;
        magnitude = (uint64_t)(-(value + 1)) + 1;
    }
    else if (positive_prefix)
    {
        prefix = &positive_prefix;
        prefix_len = 1;
    }

    printf_sink_print_uint_formatted(sink,
                                     magnitude,
                                     10,
                                     false,
                                     width,
                                     left_align,
                                     zero_pad,
                                     has_precision,
                                     precision,
                                     prefix,
                                     prefix_len,
                                     false);
}

static void printf_float_write(void *context, const char *data, size_t length)
{
    printf_sink_write((printf_sink_t *)context, data, length);
}

static void printf_float_pad(void *context, char byte, int count)
{
    printf_sink_pad((printf_sink_t *)context, byte, count);
}

static void printf_format(printf_sink_t *sink, const char *format, va_list args)
{
    while (*format && !sink->error)
    {
        if (*format != '%')
        {
            const char *start = format;
            while (*format && *format != '%') ++format;
            printf_sink_write(sink, start, (size_t)(format - start));
            continue;
        }
        ++format;
        unsigned flags = 0;
        for (;; ++format)
        {
            if (*format == '-') flags |= ALIX_PRINTF_LEFT;
            else if (*format == '0') flags |= ALIX_PRINTF_ZERO;
            else if (*format == '#') flags |= ALIX_PRINTF_ALT;
            else if (*format == '+') flags |= ALIX_PRINTF_PLUS;
            else if (*format == ' ') flags |= ALIX_PRINTF_SPACE;
            else if (*format != '\'') break; /* C locale has no digit grouping. */
        }
        bool left = (flags & ALIX_PRINTF_LEFT) != 0;
        int width = 0, precision = -1;
        if (*format == '*')
        {
            width = va_arg(args, int); ++format;
            if (width == INT_MIN) goto overflow;
            if (width < 0) { width = -width; left = true; flags |= ALIX_PRINTF_LEFT; }
        }
        else while (*format >= '0' && *format <= '9')
        {
            int digit = *format++ - '0';
            if (width > (INT_MAX - digit) / 10) goto overflow;
            width = width * 10 + digit;
        }
        if (*format == '.')
        {
            ++format; precision = 0;
            if (*format == '*')
            {
                precision = va_arg(args, int); ++format;
                if (precision < 0) precision = -1;
            }
            else while (*format >= '0' && *format <= '9')
            {
                int digit = *format++ - '0';
                if (precision > (INT_MAX - digit) / 10) goto overflow;
                precision = precision * 10 + digit;
            }
        }
        enum { NORMAL, LONG, LLONG, SHORT, CHAR, SIZET, PTRDIFF, INTMAX, LDOUBLE } length = NORMAL;
        if (*format == 'l') { ++format; length = LONG; if (*format == 'l') { ++format; length = LLONG; } }
        else if (*format == 'h') { ++format; length = SHORT; if (*format == 'h') { ++format; length = CHAR; } }
        else if (*format == 'z') { ++format; length = SIZET; }
        else if (*format == 't') { ++format; length = PTRDIFF; }
        else if (*format == 'j') { ++format; length = INTMAX; }
        else if (*format == 'L') { ++format; length = LDOUBLE; }
        char conversion = *format;
        if (!conversion) { errno = EINVAL; sink->error = true; return; }
        ++format;
        bool zero = (flags & ALIX_PRINTF_ZERO) != 0;
        bool alternate = (flags & ALIX_PRINTF_ALT) != 0;
        switch (conversion)
        {
            case '%': printf_sink_putc(sink, '%'); break;
            case 'c':
            {
                char value;
                if (length == LONG)
                {
                    wint_t wide = va_arg(args, wint_t);
                    int converted = wctob(wide);
                    if (converted == EOF) { errno = EILSEQ; sink->error = true; return; }
                    value = (char)converted;
                }
                else if (length == NORMAL) value = (char)va_arg(args, int);
                else { errno = EINVAL; sink->error = true; return; }
                if (!left) printf_sink_pad(sink, ' ', width - 1);
                printf_sink_putc(sink, value);
                if (left) printf_sink_pad(sink, ' ', width - 1);
                break;
            }
            case 's':
            {
                const char *text = NULL;
                const wchar_t *wide = NULL;
                size_t count = 0;
                if (length == LONG)
                {
                    static const wchar_t null_wide[] = {'(', 'n', 'u', 'l', 'l', ')', 0};
                    wide = va_arg(args, const wchar_t *);
                    if (!wide) wide = null_wide;
                    /* C/POSIX has one byte per representable wide unit. Do
                     * not inspect a unit beyond the byte precision bound. */
                    while (precision < 0 || count < (size_t)precision)
                    {
                        wchar_t unit = wide[count];
                        if (!unit) break;
                        if (wctob((wint_t)unit) == EOF) { errno = EILSEQ; sink->error = true; return; }
                        if (count == INT_MAX) { errno = EOVERFLOW; sink->error = true; return; }
                        ++count;
                    }
                }
                else if (length == NORMAL)
                {
                    text = va_arg(args, const char *);
                    if (!text) text = "(null)";
                    count = precision < 0 ? strlen(text) : strnlen(text, (size_t)precision);
                }
                else { errno = EINVAL; sink->error = true; return; }
                int padding = width > 0 && (size_t)width > count ? width - (int)count : 0;
                if (!left) printf_sink_pad(sink, ' ', padding);
                if (wide)
                {
                    for (size_t index = 0; index < count && !sink->error; ++index)
                        printf_sink_putc(sink, (char)wide[index]);
                }
                else printf_sink_write(sink, text, count);
                if (left) printf_sink_pad(sink, ' ', padding);
                break;
            }
            case 'd': case 'i':
            {
                int64_t value;
                if (length == LONG) value = va_arg(args, long);
                else if (length == LLONG) value = va_arg(args, long long);
                else if (length == SIZET) value = va_arg(args, ssize_t);
                else if (length == PTRDIFF) value = va_arg(args, ptrdiff_t);
                else if (length == INTMAX) value = va_arg(args, intmax_t);
                else { int promoted = va_arg(args, int); value = length == CHAR ? (signed char)promoted : length == SHORT ? (short)promoted : promoted; }
                printf_sink_print_int_formatted(sink, value, width, left, zero, precision >= 0, precision,
                    flags & ALIX_PRINTF_PLUS ? '+' : flags & ALIX_PRINTF_SPACE ? ' ' : 0);
                break;
            }
            case 'u': case 'o': case 'x': case 'X': case 'p':
            {
                uint64_t value;
                if (conversion == 'p') value = (uintptr_t)va_arg(args, void *);
                else if (length == LONG) value = va_arg(args, unsigned long);
                else if (length == LLONG) value = va_arg(args, unsigned long long);
                else if (length == SIZET) value = va_arg(args, size_t);
                else if (length == PTRDIFF) value = va_arg(args, uintptr_t);
                else if (length == INTMAX) value = va_arg(args, uintmax_t);
                else { unsigned promoted = va_arg(args, unsigned); value = length == CHAR ? (unsigned char)promoted : length == SHORT ? (unsigned short)promoted : promoted; }
                unsigned base = conversion == 'u' ? 10 : conversion == 'o' ? 8 : 16;
                const char *prefix = ""; size_t prefix_size = 0;
                if (conversion == 'p' || (base == 16 && alternate && value))
                { prefix = conversion == 'X' ? "0X" : "0x"; prefix_size = 2; }
                printf_sink_print_uint_formatted(sink, value, base, conversion == 'X', width, left, zero,
                    precision >= 0, precision, prefix, prefix_size, alternate);
                break;
            }
            case 'f': case 'F': case 'e': case 'E': case 'g': case 'G': case 'a': case 'A':
            {
                long double value = length == LDOUBLE ? va_arg(args, long double) : (long double)va_arg(args, double);
                alix_printf_float_output_t output = {sink, printf_float_write, printf_float_pad};
                if (alix_printf_float(&output, value, width, precision, flags, conversion) < 0) sink->error = true;
                break;
            }
            case 'n':
                if (length == LONG) *va_arg(args, long *) = (long)sink->length;
                else if (length == LLONG) *va_arg(args, long long *) = (long long)sink->length;
                else if (length == SIZET) *va_arg(args, ssize_t *) = (ssize_t)sink->length;
                else if (length == PTRDIFF) *va_arg(args, ptrdiff_t *) = (ptrdiff_t)sink->length;
                else if (length == INTMAX) *va_arg(args, intmax_t *) = (intmax_t)sink->length;
                else if (length == SHORT) *va_arg(args, short *) = (short)sink->length;
                else if (length == CHAR) *va_arg(args, signed char *) = (signed char)sink->length;
                else *va_arg(args, int *) = (int)sink->length;
                break;
            default:
                printf_sink_putc(sink, '%'); printf_sink_putc(sink, conversion); break;
        }
    }
    return;
 overflow:
    errno = EOVERFLOW; sink->error = true;
}

static void printf_sink_finalize_buffer(printf_sink_t *sink)
{
    if (!sink || !sink->buffer_mode || !sink->buffer || sink->capacity == 0)
    {
        return;
    }
    size_t pos = sink->length;
    if (pos >= sink->capacity)
    {
        pos = sink->capacity - 1;
    }
    sink->buffer[pos] = '\0';
}

static int vprintf_stream_unlocked(FILE *stream, const char *format, va_list args)
{
    if (!format)
    {
        errno = EINVAL;
        return -1;
    }

    printf_sink_t sink = {
        .stream = stream,
        .buffer = NULL,
        .capacity = 0,
        .length = 0,
        .error = false,
        .buffer_mode = false,
    };

    printf_format(&sink, format, args);
    if (sink.error)
    {
        return -1;
    }
    return (int)sink.length;
}

static int vsnprintf_internal(char *buf, size_t size, const char *format, va_list args)
{
    if (!format || (size && !buf))
    {
        errno = EINVAL;
        return -1;
    }
    printf_sink_t sink = {
        .stream = NULL,
        .buffer = buf,
        .capacity = size,
        .length = 0,
        .error = false,
        .buffer_mode = true,
    };
    printf_format(&sink, format, args);
    printf_sink_finalize_buffer(&sink);
    return sink.error ? -1 : (int)sink.length;
}

int printf(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    int result = vfprintf(stdout, format, args);
    va_end(args);
    return result;
}

int vfprintf(FILE *stream, const char *format, va_list args)
{
    if (!stream)
    {
        errno = EBADF;
        return -1;
    }
    alix_mutex_lock(&stream->mutex);
    int result = __alix_stdio_orient_unlocked(stream, -1)
                     ? vprintf_stream_unlocked(stream, format, args) : -1;
    if (result < 0) stream->error = 1;
    alix_mutex_unlock(&stream->mutex);
    return result;
}

int vprintf(const char *format, va_list args)
{
    return vfprintf(stdout, format, args);
}

void perror(const char *prefix)
{
    int saved_errno = errno;
    const char *message = strerror(saved_errno);
    if (prefix && *prefix)
        (void)fprintf(stderr, "%s: %s\n", prefix, message);
    else
        (void)fprintf(stderr, "%s\n", message);
}

int fprintf(FILE *stream, const char *format, ...)
{
    va_list args;
    va_start(args, format);
    int result = vfprintf(stream, format, args);
    va_end(args);
    return result;
}

int vsprintf(char *buf, const char *format, va_list args)
{
    return vsnprintf_internal(buf, (size_t)-1, format, args);
}

int sprintf(char *buf, const char *format, ...)
{
    va_list args;
    va_start(args, format);
    int result = vsnprintf_internal(buf, (size_t)-1, format, args);
    va_end(args);
    return result;
}

int vsnprintf(char *buf, size_t size, const char *format, va_list args)
{
    return vsnprintf_internal(buf, size, format, args);
}

int snprintf(char *buf, size_t size, const char *format, ...)
{
    va_list args;
    va_start(args, format);
    int result = vsnprintf_internal(buf, size, format, args);
    va_end(args);
    return result;
}

int vasprintf(char **result, const char *format, va_list args)
{
    if (!result) { errno = EINVAL; return -1; }
    *result = NULL;
    if (!format) { errno = EINVAL; return -1; }
    printf_sink_t sink = {.buffer_mode = true, .dynamic_buffer = true};
    if (printf_sink_reserve(&sink, 0)) printf_format(&sink, format, args);
    if (sink.error) { free(sink.buffer); return -1; }
    printf_sink_finalize_buffer(&sink);
    *result = sink.buffer;
    return (int)sink.length;
}

int asprintf(char **result, const char *format, ...)
{
    va_list args;
    va_start(args, format);
    int count = vasprintf(result, format, args);
    va_end(args);
    return count;
}
#endif /* TTF_HOST_BUILD */

void *malloc(size_t size)
{
    uintptr_t caller = (uintptr_t)__builtin_return_address(0);
    user_heap_log_caller("malloc req=", size, caller);
    if (size >= USER_HEAP_LARGE_THRESHOLD && user_heap_log_enabled())
    {
        serial_printf("[uheap] large malloc size=0x%016llX caller=0x%016llX",
                      (unsigned long long)size,
                      (unsigned long long)(uintptr_t)__builtin_return_address(0));
    }
    user_heap_lock_acquire();
    void *ptr = malloc_locked(size);
    user_heap_lock_release();
    user_heap_log_caller_size("malloc ptr=", (uintptr_t)ptr, size, caller);
    return ptr;
}

void free(void *ptr)
{
    if (!ptr)
    {
        return;
    }
    uintptr_t caller = (uintptr_t)__builtin_return_address(0);
    user_heap_log_caller("free ptr=", (uintptr_t)ptr, caller);
    user_heap_lock_acquire();
    free_locked(ptr);
    user_heap_lock_release();
}

void *aligned_alloc(size_t alignment, size_t size)
{
    if (alignment == 0 || (alignment & (alignment - 1u)) != 0 || size % alignment != 0)
    {
        errno = EINVAL;
        return NULL;
    }
    if (size == 0)
    {
        return NULL;
    }
    size_t effective = alignment < ALIGNMENT ? ALIGNMENT : alignment;
    if (effective > SIZE_MAX_VALUE - sizeof(heap_block_t) - 2 * ALIGNMENT ||
        size > SIZE_MAX_VALUE - effective - sizeof(heap_block_t) - 2 * ALIGNMENT)
    {
        errno = ENOMEM;
        return NULL;
    }
    size_t reserve = size + effective + sizeof(heap_block_t) + ALIGNMENT;
    user_heap_lock_acquire();
    void *allocation = malloc_locked(reserve);
    if (!allocation)
    {
        user_heap_lock_release();
        errno = ENOMEM;
        return NULL;
    }
    heap_block_t *block = payload_to_block(allocation);
    uintptr_t address = (uintptr_t)allocation;
    uintptr_t aligned = (address + effective - 1u) & ~(uintptr_t)(effective - 1u);
    if (aligned != address && aligned - address < sizeof(heap_block_t) + ALIGNMENT)
    {
        aligned += effective;
    }
    if (aligned != address)
    {
        size_t prefix = aligned - address;
        heap_block_t *allocated = (heap_block_t *)(aligned - sizeof(heap_block_t));
        allocated->size = block->size - prefix;
        allocated->free = false;
        allocated->free_next = allocated->free_prev = NULL;
        allocated->next = block->next;
        allocated->prev = block;
        if (allocated->next) allocated->next->prev = allocated;
        else g_heap_tail = allocated;
        block->next = allocated;
        block->size = prefix - sizeof(heap_block_t);
        block->free = true;
        split_block(allocated, align_size(size));
        coalesce(block);
    }
    else
    {
        split_block(block, align_size(size));
    }
    user_heap_lock_release();
    return (void *)aligned;
}

int posix_memalign(void **result, size_t alignment, size_t size)
{
    if (!result || alignment < sizeof(void *) || (alignment & (alignment - 1u)) != 0)
    {
        return EINVAL;
    }
    if (size > SIZE_MAX_VALUE - (alignment - 1u))
    {
        return ENOMEM;
    }
    size_t rounded = (size + alignment - 1u) & ~(alignment - 1u);
    void *allocation = aligned_alloc(alignment, rounded);
    if (!allocation && size != 0) return ENOMEM;
    *result = allocation;
    return 0;
}

void *memalign(size_t alignment, size_t size)
{
    if (!alignment || (alignment & (alignment - 1u))) { errno = EINVAL; return NULL; }
    if (alignment < sizeof(void *)) alignment = sizeof(void *);
    int saved = errno;
    void *allocation = NULL;
    int error = posix_memalign(&allocation, alignment, size ? size : 1u);
    errno = error ? error : saved;
    return error ? NULL : allocation;
}

void *realloc(void *ptr, size_t size)
{
    uintptr_t caller = (uintptr_t)__builtin_return_address(0);
    user_heap_log_caller_size("realloc ptr=", (uintptr_t)ptr, size, caller);
    user_heap_log_caller("realloc size=", size, caller);
    if (size >= USER_HEAP_LARGE_THRESHOLD && user_heap_log_enabled())
    {
        serial_printf("[uheap] large realloc ptr=0x%016llX size=0x%016llX caller=0x%016llX",
                      (unsigned long long)(uintptr_t)ptr,
                      (unsigned long long)size,
                      (unsigned long long)(uintptr_t)__builtin_return_address(0));
    }
    user_heap_lock_acquire();
    void *res = realloc_locked(ptr, size);
    user_heap_lock_release();
    return res;
}

void *calloc(size_t count, size_t size)
{
    uintptr_t caller = (uintptr_t)__builtin_return_address(0);
    user_heap_log_caller("calloc count=", count, caller);
    user_heap_log_caller("calloc size=", size, caller);
    if (count != 0 && size > SIZE_MAX_VALUE / count)
    {
        errno = ENOMEM;
        return NULL;
    }
    size_t total = count * size;
    user_heap_log_caller("calloc total=", total, caller);
    if (total >= USER_HEAP_LARGE_THRESHOLD && user_heap_log_enabled())
    {
        serial_printf("[uheap] large calloc count=0x%016llX size=0x%016llX total=0x%016llX caller=0x%016llX",
                      (unsigned long long)count,
                      (unsigned long long)size,
                      (unsigned long long)total,
                      (unsigned long long)(uintptr_t)__builtin_return_address(0));
    }
    user_heap_lock_acquire();
    /* A zero-element allocation still owns a distinct, freeable block. This
     * C11-permitted policy also supports upstream users that treat NULL as an
     * allocation failure even when their element count is zero. */
    void *ptr = malloc_locked(total ? total : 1);
    user_heap_lock_release();
    if (!ptr)
    {
        return NULL;
    }
    memset(ptr, 0, total);
    return ptr;
}

#ifndef TTF_HOST_BUILD
static FILE g_stdout_obj;
static FILE g_stdin_obj;
static FILE g_stderr_obj;
static FILE g_stdout_obj = { .fd = 1, .access_flags = SYSCALL_OPEN_WRITE,
                            .registry_id = 1, .registry_next = &g_stderr_obj };
static FILE g_stderr_obj = { .fd = 2, .access_flags = SYSCALL_OPEN_WRITE,
                            .registry_id = 2, .registry_next = &g_stdin_obj };
static FILE g_stdin_obj = { .fd = 0, .access_flags = SYSCALL_OPEN_READ, .registry_id = 3 };
FILE *stdout = &g_stdout_obj;
FILE *stderr = &g_stderr_obj;
FILE *stdin = &g_stdin_obj;
static FILE *g_file_registry = &g_stdout_obj;
static alix_mutex_t g_file_registry_lock;
static uint64_t g_file_registry_id = 3;

static void file_io_errno(int64_t result);
static int file_flush_output_unlocked(FILE *stream);

static bool file_register(FILE *stream)
{
    alix_mutex_lock(&g_file_registry_lock);
    bool okay = g_file_registry_id != UINT64_MAX;
    if (okay)
    {
        stream->registry_id = ++g_file_registry_id;
        stream->registry_next = g_file_registry;
        g_file_registry = stream;
    }
    alix_mutex_unlock(&g_file_registry_lock);
    if (!okay) errno = EOVERFLOW;
    return okay;
}

static void file_unregister(FILE *stream)
{
    alix_mutex_lock(&g_file_registry_lock);
    FILE **cursor = &g_file_registry;
    while (*cursor && *cursor != stream) cursor = &(*cursor)->registry_next;
    if (*cursor) *cursor = stream->registry_next;
    stream->registry_next = NULL;
    alix_mutex_unlock(&g_file_registry_lock);
}

/* Global flushing uses pins, never a registry lock held across file I/O.
 * Monotonic IDs allow an allocation-free snapshot walk despite concurrent
 * close/unlink. Streams opened after the walk begins belong to a later flush. */
static int file_flush_all(bool lines_only, FILE *except)
{
    alix_mutex_lock(&g_file_registry_lock);
    uint64_t ceiling = g_file_registry_id;
    alix_mutex_unlock(&g_file_registry_lock);
    uint64_t cursor = 0;
    int result = 0, first_error = 0;
    for (;;)
    {
        alix_mutex_lock(&g_file_registry_lock);
        FILE *selected = NULL;
        for (FILE *item = g_file_registry; item; item = item->registry_next)
            if (item != except && item->registry_id > cursor && item->registry_id <= ceiling &&
                (!selected || item->registry_id < selected->registry_id)) selected = item;
        if (!selected) { alix_mutex_unlock(&g_file_registry_lock); break; }
        cursor = selected->registry_id;
        if (__atomic_load_n(&selected->flush_pins, __ATOMIC_RELAXED) == UINT32_MAX)
        {
            result = EOF;
            if (!first_error) first_error = EOVERFLOW;
            alix_mutex_unlock(&g_file_registry_lock);
            continue;
        }
        __atomic_add_fetch(&selected->flush_pins, 1u, __ATOMIC_RELAXED);
        alix_mutex_unlock(&g_file_registry_lock);
        alix_mutex_lock(&selected->mutex);
        if (selected->fd >= 0 && (!lines_only || selected->buffering == _IOLBF) &&
            file_flush_output_unlocked(selected) != 0)
        {
            result = EOF;
            if (!first_error) first_error = errno;
        }
        alix_mutex_unlock(&selected->mutex);
        alix_mutex_lock(&g_file_registry_lock);
        if (__atomic_sub_fetch(&selected->flush_pins, 1u, __ATOMIC_RELEASE) == 0)
            (void)sys_futex_wake(&selected->flush_pins, UINT32_MAX);
        alix_mutex_unlock(&g_file_registry_lock);
    }
    if (first_error) errno = first_error;
    return result;
}

void __alix_stdio_before_read(FILE *stream)
{
    if (!stream) return;
    alix_mutex_lock(&stream->mutex);
    bool flush_lines = stream->buffering != _IOFBF;
    alix_mutex_unlock(&stream->mutex);
    if (flush_lines) (void)file_flush_all(true, stream);
}

static FILE *file_alloc(int fd, uint64_t flags, bool append)
{
    FILE *stream = (FILE *)malloc(sizeof(FILE));
    if (!stream)
    {
        errno = ENOMEM;
        return NULL;
    }
    memset(stream, 0, sizeof(*stream));
    stream->fd = fd;
    stream->access_flags = flags;
    stream->append = append;
    alix_mutex_init(&stream->mutex);
    if (!file_register(stream)) { free(stream); return NULL; }
    return stream;
}

static uint64_t fopen_mode_to_flags(const char *mode, bool *append_out)
{
    if (append_out)
    {
        *append_out = false;
    }
    if (!mode || mode[0] == '\0')
    {
        errno = EINVAL;
        return 0;
    }

    bool plus = false;
    bool append = false;
    uint64_t flags = 0;

    switch (mode[0])
    {
        case 'r':
            flags = SYSCALL_OPEN_READ;
            break;
        case 'w':
            flags = SYSCALL_OPEN_WRITE | SYSCALL_OPEN_CREATE | SYSCALL_OPEN_TRUNCATE;
            break;
        case 'a':
            flags = SYSCALL_OPEN_WRITE | SYSCALL_OPEN_CREATE | SYSCALL_OPEN_APPEND;
            append = true;
            break;
        default:
            errno = EINVAL;
            return 0;
    }

    bool binary = false, exclusive = false;
    for (const char *c = mode + 1; *c; ++c)
    {
        if (*c == '+')
        {
            if (plus) { errno = EINVAL; return 0; }
            plus = true;
        }
        else if (*c == 'b' && !binary)
        {
            binary = true;
        }
        else if (*c == 'x' && !exclusive && mode[0] == 'w')
        {
            exclusive = true;
            flags |= SYSCALL_OPEN_EXCLUSIVE;
        }
        else { errno = EINVAL; return 0; }
    }
    if (plus)
    {
        flags |= SYSCALL_OPEN_READ | SYSCALL_OPEN_WRITE;
    }

    if (append_out)
    {
        *append_out = append;
    }
    return flags;
}

FILE *fopen(const char *path, const char *mode)
{
    bool append = false;
    uint64_t flags = fopen_mode_to_flags(mode, &append);
    if (!path || !flags)
    {
        if (!path) errno = EINVAL;
        return NULL;
    }
    int saved_errno = errno;
    errno = 0;
    int fd = open(path, flags);
    if (fd < 0)
    {
        file_io_errno(fd);
        return NULL;
    }
    errno = saved_errno;
    if (append)
    {
        (void)lseek(fd, 0, SYSCALL_SEEK_END);
        errno = saved_errno;
    }

    FILE *stream = file_alloc(fd, flags, append);
    if (!stream)
    {
        int saved_errno = errno;
        close(fd);
        errno = saved_errno ? saved_errno : ENOMEM;
        return NULL;
    }
    return stream;
}

FILE *fdopen(int descriptor, const char *mode)
{
    bool append = false;
    uint64_t flags = fopen_mode_to_flags(mode, &append);
    if (!flags) return NULL;
    if (flags & SYSCALL_OPEN_EXCLUSIVE) { errno = EINVAL; return NULL; }
#ifndef ALIX_OWNED_FDS
    /* New POSIX descriptor APIs use the private namespace. A legacy integer
     * must never fall through to a similarly numbered private descriptor. */
    (void)descriptor;
    errno = ENOTSUP;
    return NULL;
#else
    int64_t status = sys_file_io(SYSCALL_FILE_GETFL, (uint64_t)(int64_t)descriptor, 0, 0, 0);
    if (status < 0) { errno = (int)-status; return NULL; }
    uint64_t access = flags & (SYSCALL_OPEN_READ | SYSCALL_OPEN_WRITE);
    if ((access & (uint64_t)status) != access) { errno = EINVAL; return NULL; }
    struct stat *metadata = malloc(sizeof(*metadata));
    if (!metadata) { errno = ENOMEM; return NULL; }
    if (fstat(descriptor, metadata)) { free(metadata); return NULL; }
    bool seek_append = append && S_ISREG(metadata->st_mode);
    free(metadata);
    FILE *stream = file_alloc(descriptor, flags, seek_append);
    if (!stream) { if (!errno) errno = ENOMEM; return NULL; }
    if (append && !((uint64_t)status & SYSCALL_OPEN_APPEND))
    {
        int64_t result = sys_file_io(SYSCALL_FILE_SETFL, (uint64_t)(int64_t)descriptor,
                                      (uint64_t)status | SYSCALL_OPEN_APPEND, 0, 0);
        if (result < 0)
        {
            int error = (int)-result;
            alix_mutex_lock(&stream->mutex); stream->fd = -1; alix_mutex_unlock(&stream->mutex);
            (void)fclose(stream); errno = error;
            return NULL;
        }
    }
    return stream;
#endif
}

FILE *freopen(const char *path, const char *mode, FILE *stream)
{
    if (!stream) { errno = EINVAL; return NULL; }
    bool append = false;
    uint64_t flags = fopen_mode_to_flags(mode, &append);
    alix_mutex_lock(&stream->mutex);
    (void)file_flush_output_unlocked(stream);
    if (stream->fd >= 0) (void)close(stream->fd);
    stream->fd = -1;
    stream->access_flags = 0;
    stream->pushback_pending = false;
    stream->pushback_length = 0;
    stream->read_position = stream->read_end = stream->write_length = 0;
    stream->error = stream->eof = stream->orientation = 0;
    stream->io_started = false;
    int fd = path && flags ? open(path, flags) : -EINVAL;
    if (fd < 0)
    {
        file_io_errno(fd);
        alix_mutex_unlock(&stream->mutex);
        return NULL;
    }
    stream->fd = fd;
    stream->access_flags = flags;
    stream->append = append;
    if (append) (void)lseek(fd, 0, SYSCALL_SEEK_END);
    alix_mutex_unlock(&stream->mutex);
    return stream;
}

int fclose(FILE *stream)
{
    if (!stream) { errno = EBADF; return EOF; }
    /* Ordinary concurrent use/fclose remains the caller's lifetime duty.
     * Registry pins separately protect an in-flight fflush(NULL) traversal. */
    file_unregister(stream);
    alix_mutex_lock(&stream->mutex);
    int saved_errno = errno;
    int failure = file_flush_output_unlocked(stream) == 0 ? 0 : errno;
    int fd = stream->fd;
    errno = 0;
    int result = fd >= 0 ? close(fd) : -EBADF;
    if (result < 0)
    {
        file_io_errno(result);
        if (!failure) failure = errno;
    }
    stream->fd = -1;
    stream->access_flags = 0;
    stream->pushback_pending = false;
    stream->pushback_length = 0;
    if (stream->pushback_buffer) free(stream->pushback_buffer);
    stream->pushback_buffer = NULL;
    stream->pushback_capacity = 0;
    if (stream->buffer) free(stream->buffer);
    stream->buffer = NULL;
    stream->buffer_capacity = stream->read_position = stream->read_end = stream->write_length = 0;
    if (failure) stream->error = 1;
    alix_mutex_unlock(&stream->mutex);
    for (;;)
    {
        alix_mutex_lock(&g_file_registry_lock);
        uint32_t pins = __atomic_load_n(&stream->flush_pins, __ATOMIC_ACQUIRE);
        alix_mutex_unlock(&g_file_registry_lock);
        if (!pins) break;
        (void)sys_futex_wait(&stream->flush_pins, pins, ALIX_WAIT_FOREVER);
    }
    if (stream != &g_stdout_obj && stream != &g_stderr_obj && stream != &g_stdin_obj) free(stream);
    errno = failure ? failure : saved_errno;
    return failure ? EOF : 0;
}

static void file_io_errno(int64_t result)
{
    /* Current native wrappers may return -errno directly; POSIX-style wrappers
     * return -1 after setting errno. Accept both without retaining stale errno. */
    if (result < -1 && result >= -2147483647LL) errno = (int)-result;
    else if (!errno) errno = EIO;
}

static int64_t file_lseek_unlocked(FILE *stream, int64_t offset, int whence)
{
    if (stream->fd < 0) { errno = EBADF; return -1; }
    int saved_errno = errno;
    errno = 0;
    int64_t result = lseek(stream->fd, offset, whence);
    if (result < 0) file_io_errno(result);
    else errno = saved_errno;
    return result;
}

static int file_sync_pushback_unlocked(FILE *stream)
{
    size_t unread = stream->read_end - stream->read_position;
    if (stream->pushback_pending &&
        (__builtin_add_overflow(unread, stream->pushback_length, &unread) ||
         __builtin_add_overflow(unread, (size_t)1, &unread)))
    { errno = EOVERFLOW; stream->error = 1; return EOF; }
    if (unread && (unread > INT64_MAX || file_lseek_unlocked(stream, -(int64_t)unread, SEEK_CUR) < 0))
    {
        if (unread > INT64_MAX) errno = EOVERFLOW;
        stream->error = 1;
        return EOF;
    }
    stream->read_position = stream->read_end = 0;
    stream->pushback_pending = false;
    stream->pushback_length = 0;
    return 0;
}

bool __alix_stdio_orient_unlocked(FILE *stream, int orientation)
{
    if (stream->fd < 0) { errno = EBADF; stream->error = 1; return false; }
    int desired = orientation > 0 ? 1 : -1;
    stream->io_started = true;
    if (!stream->orientation) stream->orientation = desired;
    if (stream->orientation != desired)
    {
        errno = EINVAL;
        stream->error = 1;
        return false;
    }
    return true;
}

size_t __alix_stdio_read_unlocked(FILE *stream, void *ptr, size_t total, bool *failed)
{
    *failed = false;
    if (stream->fd < 0 || !(stream->access_flags & SYSCALL_OPEN_READ))
    { errno = EBADF; stream->error = 1; *failed = true; return 0; }
    stream->io_started = true;
    if (file_flush_output_unlocked(stream) != 0) { *failed = true; return 0; }
    size_t done = 0;
    unsigned char *destination = ptr;
    while (stream->pushback_pending && done < total)
    {
        destination[done++] = stream->pushback;
        if (stream->pushback_length)
            stream->pushback = stream->pushback_buffer[--stream->pushback_length];
        else stream->pushback_pending = false;
    }
    while (done < total)
    {
        if (stream->buffering != _IONBF && stream->read_position < stream->read_end)
        {
            size_t count = stream->read_end - stream->read_position;
            if (count > total - done) count = total - done;
            memcpy(destination + done, stream->buffer + stream->read_position, count);
            stream->read_position += count;
            done += count;
            if (*failed) break;
            continue;
        }
        if (stream->eof || *failed) break;
        stream->read_position = stream->read_end = 0;
        bool buffered = stream->buffering != _IONBF;
        do
        {
            size_t want = buffered ? stream->buffer_capacity - stream->read_end : total - done;
            if (buffered && stream->buffering == _IOLBF) want = 1;
            unsigned char *target = buffered ? stream->buffer + stream->read_end : destination + done;
            int saved_errno = errno;
            errno = 0;
            ssize_t got = read(stream->fd, target, want);
            if (got <= 0)
            {
                if (!got) { stream->eof = 1; errno = saved_errno; }
                else { file_io_errno(got); stream->error = 1; *failed = true; }
                break;
            }
            errno = saved_errno;
            if ((size_t)got > want)
            { errno = EIO; stream->error = 1; *failed = true; break; }
            if (!buffered) { done += (size_t)got; break; }
            stream->read_end += (size_t)got;
            if (stream->buffering != _IOLBF || target[got - 1] == '\n') break;
        } while (stream->read_end < stream->buffer_capacity);
    }
    return done;
}

static size_t file_read_bytes_unlocked(FILE *stream, void *ptr, size_t total, bool *failed)
{
    if (!__alix_stdio_orient_unlocked(stream, -1)) { *failed = true; return 0; }
    return __alix_stdio_read_unlocked(stream, ptr, total, failed);
}

static size_t file_write_raw_unlocked(FILE *stream, const void *ptr, size_t total)
{
    if (stream->append && file_lseek_unlocked(stream, 0, SEEK_END) < 0)
    { stream->error = 1; return 0; }
    size_t written = 0;
    while (written < total)
    {
        int saved_errno = errno;
        errno = 0;
        ssize_t count = write(stream->fd, (const unsigned char *)ptr + written, total - written);
        if (count <= 0) { file_io_errno(count); stream->error = 1; break; }
        errno = saved_errno;
        if ((size_t)count > total - written)
        { errno = EIO; stream->error = 1; break; }
        written += (size_t)count;
    }
    return written;
}

static int file_flush_output_unlocked(FILE *stream)
{
    if (!stream->write_length) return 0;
    size_t written = file_write_raw_unlocked(stream, stream->buffer, stream->write_length);
    stream->write_length -= written;
    if (written && stream->write_length) memmove(stream->buffer, stream->buffer + written, stream->write_length);
    return stream->write_length ? EOF : 0;
}

size_t __alix_stdio_write_unlocked(FILE *stream, const void *ptr, size_t total)
{
    if (!total) return 0;
    if (stream->fd < 0 || !(stream->access_flags & SYSCALL_OPEN_WRITE))
    { errno = EBADF; stream->error = 1; return 0; }
    if (!ptr) { errno = EINVAL; stream->error = 1; return 0; }
    stream->io_started = true;
    if (stream->append)
    {
        stream->read_position = stream->read_end = 0;
        stream->pushback_pending = false;
        stream->pushback_length = 0;
    }
    else if (file_sync_pushback_unlocked(stream) != 0) return 0;
    if (stream->buffering == _IONBF) return file_write_raw_unlocked(stream, ptr, total);
    const unsigned char *bytes = ptr;
    size_t accepted = 0;
    while (accepted < total)
    {
        if (stream->write_length == stream->buffer_capacity && file_flush_output_unlocked(stream) != 0) break;
        size_t count = stream->buffer_capacity - stream->write_length;
        if (count > total - accepted) count = total - accepted;
        bool newline = false;
        if (stream->buffering == _IOLBF)
        {
            const unsigned char *end = memchr(bytes + accepted, '\n', count);
            if (end) { count = (size_t)(end - (bytes + accepted)) + 1; newline = true; }
        }
        size_t previous = stream->write_length;
        memcpy(stream->buffer + previous, bytes + accepted, count);
        stream->write_length += count;
        if ((newline || stream->write_length == stream->buffer_capacity) && file_flush_output_unlocked(stream) != 0)
        {
            size_t delivered = previous + count - stream->write_length;
            /* Keep only earlier accepted bytes on failure. Newly supplied
             * unwritten bytes are not reported accepted or silently duplicated
             * if the caller retries after clearing the stream error. */
            stream->write_length = delivered < previous ? previous - delivered : 0;
            if (delivered > previous) accepted += delivered - previous;
            break;
        }
        accepted += count;
    }
    return accepted;
}

/* Caller holds stream->mutex. Also used by the formatted-output sink. */
static size_t file_write_bytes_unlocked(FILE *stream, const void *ptr, size_t total)
{
    if (!__alix_stdio_orient_unlocked(stream, -1)) return 0;
    return __alix_stdio_write_unlocked(stream, ptr, total);
}

size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream)
{
    if (!size || !nmemb) return 0;
    if (!stream) { errno = EBADF; return 0; }
    __alix_stdio_before_read(stream);
    alix_mutex_lock(&stream->mutex);
    size_t total = 0, bytes = 0;
    if (__builtin_mul_overflow(size, nmemb, &total)) { errno = EOVERFLOW; stream->error = 1; }
    else if (!ptr) { errno = EINVAL; stream->error = 1; }
    else
    {
        bool failed;
        bytes = file_read_bytes_unlocked(stream, ptr, total, &failed);
    }
    alix_mutex_unlock(&stream->mutex);
    return bytes / size;
}

size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream)
{
    if (!size || !nmemb) return 0;
    if (!stream) { errno = EBADF; return 0; }
    alix_mutex_lock(&stream->mutex);
    size_t total = 0, bytes = 0;
    if (__builtin_mul_overflow(size, nmemb, &total)) { errno = EOVERFLOW; stream->error = 1; }
    else bytes = file_write_bytes_unlocked(stream, ptr, total);
    alix_mutex_unlock(&stream->mutex);
    return bytes / size;
}

int fflush(FILE *stream)
{
    if (!stream) return file_flush_all(false, NULL);
    alix_mutex_lock(&stream->mutex);
    stream->io_started = true;
    int result;
    if (stream->fd < 0) { errno = EBADF; stream->error = 1; result = EOF; }
    else if (file_flush_output_unlocked(stream) != 0) result = EOF;
    else result = file_sync_pushback_unlocked(stream);
    alix_mutex_unlock(&stream->mutex);
    return result;
}

static int file_seek_unlocked(FILE *stream, int64_t offset, int whence)
{
    stream->io_started = true;
    if (whence != SEEK_SET && whence != SEEK_CUR && whence != SEEK_END)
    { errno = EINVAL; return -1; }
    if (file_flush_output_unlocked(stream) != 0) return -1;
    if (whence == SEEK_CUR)
    {
        size_t unread = stream->read_end - stream->read_position;
        if ((stream->pushback_pending &&
             (__builtin_add_overflow(unread, stream->pushback_length, &unread) ||
              __builtin_add_overflow(unread, (size_t)1, &unread))) ||
            unread > INT64_MAX || __builtin_sub_overflow(offset, (int64_t)unread, &offset))
        { errno = EOVERFLOW; return -1; }
    }
    if (file_lseek_unlocked(stream, offset, whence) < 0) return -1;
    stream->eof = 0;
    stream->pushback_pending = false;
    stream->pushback_length = 0;
    stream->read_position = stream->read_end = 0;
    return 0;
}

static int64_t file_tell_unlocked(FILE *stream)
{
    stream->io_started = true;
    int64_t position = file_lseek_unlocked(stream, 0, stream->append && stream->write_length ? SEEK_END : SEEK_CUR);
    if (position < 0) return -1;
    size_t unread = stream->read_end - stream->read_position;
    if ((stream->pushback_pending &&
         (__builtin_add_overflow(unread, stream->pushback_length, &unread) ||
          __builtin_add_overflow(unread, (size_t)1, &unread))) || unread > INT64_MAX ||
        position < (int64_t)unread)
    { errno = EINVAL; return -1; }
    position -= (int64_t)unread;
    if (stream->write_length > INT64_MAX || __builtin_add_overflow(position, (int64_t)stream->write_length, &position))
    { errno = EOVERFLOW; return -1; }
    return position;
}

int fseek(FILE *stream, long offset, int whence)
{
    if (!stream) { errno = EBADF; return -1; }
    alix_mutex_lock(&stream->mutex);
    int result = file_seek_unlocked(stream, offset, whence);
    alix_mutex_unlock(&stream->mutex);
    return result;
}

long ftell(FILE *stream)
{
    if (!stream) { errno = EBADF; return -1; }
    alix_mutex_lock(&stream->mutex);
    int64_t position = file_tell_unlocked(stream);
    if (position >= 0 && (int64_t)(long)position != position) { errno = EOVERFLOW; position = -1; }
    alix_mutex_unlock(&stream->mutex);
    return (long)position;
}

int fseeko(FILE *stream, off_t offset, int whence)
{
    if (!stream) { errno = EBADF; return -1; }
    alix_mutex_lock(&stream->mutex);
    int result = file_seek_unlocked(stream, offset, whence);
    alix_mutex_unlock(&stream->mutex);
    return result;
}

off_t ftello(FILE *stream)
{
    if (!stream) { errno = EBADF; return -1; }
    alix_mutex_lock(&stream->mutex);
    int64_t result = file_tell_unlocked(stream);
    alix_mutex_unlock(&stream->mutex);
    return (off_t)result;
}

int fgetpos(FILE *stream, fpos_t *position)
{
    if (!stream || !position) { errno = !stream ? EBADF : EINVAL; return -1; }
    alix_mutex_lock(&stream->mutex);
    int64_t value = file_tell_unlocked(stream);
    if (value >= 0) *position = value;
    alix_mutex_unlock(&stream->mutex);
    return value < 0 ? -1 : 0;
}

int fsetpos(FILE *stream, const fpos_t *position)
{
    if (!stream || !position) { errno = !stream ? EBADF : EINVAL; return -1; }
    alix_mutex_lock(&stream->mutex);
    int result = file_seek_unlocked(stream, *position, SEEK_SET);
    alix_mutex_unlock(&stream->mutex);
    return result;
}

void rewind(FILE *stream)
{
    if (!stream) { errno = EBADF; return; }
    alix_mutex_lock(&stream->mutex);
    (void)file_seek_unlocked(stream, 0, SEEK_SET);
    stream->error = 0;
    alix_mutex_unlock(&stream->mutex);
}

int fputc(int ch, FILE *stream)
{
    if (!stream) { errno = EBADF; return EOF; }
    unsigned char c = (unsigned char)ch;
    alix_mutex_lock(&stream->mutex);
    size_t wrote = file_write_bytes_unlocked(stream, &c, 1);
    alix_mutex_unlock(&stream->mutex);
    return wrote == 1 ? (int)c : EOF;
}

static int file_getc_unlocked(FILE *stream, bool *failed)
{
    unsigned char ch = 0;
    return file_read_bytes_unlocked(stream, &ch, 1, failed) == 1 ? (int)ch : EOF;
}

int fgetc(FILE *stream)
{
    if (!stream) { errno = EBADF; return EOF; }
    __alix_stdio_before_read(stream);
    alix_mutex_lock(&stream->mutex);
    bool failed;
    int result = file_getc_unlocked(stream, &failed);
    alix_mutex_unlock(&stream->mutex);
    return result;
}

int getc(FILE *stream)
{
    return fgetc(stream);
}

int ungetc(int ch, FILE *stream)
{
    if (ch == EOF) return EOF;
    if (!stream) { errno = EBADF; return EOF; }
    alix_mutex_lock(&stream->mutex);
    int result = __alix_stdio_orient_unlocked(stream, -1)
                     ? __alix_stdio_pushback_unlocked(stream, (unsigned char)ch) : EOF;
    alix_mutex_unlock(&stream->mutex);
    return result;
}

int __alix_stdio_pushback_unlocked(FILE *stream, unsigned char ch)
{
    if (stream->fd < 0 || !(stream->access_flags & SYSCALL_OPEN_READ))
    { errno = EBADF; return EOF; }
    if (stream->pushback_pending)
    {
        if (stream->pushback_length == stream->pushback_capacity)
        {
            if (stream->pushback_capacity > SIZE_MAX / 2)
            { errno = ENOMEM; return EOF; }
            size_t capacity = stream->pushback_capacity ? stream->pushback_capacity * 2 : 16;
            unsigned char *buffer = malloc(capacity);
            if (!buffer) { errno = ENOMEM; return EOF; }
            if (stream->pushback_length)
                memcpy(buffer, stream->pushback_buffer, stream->pushback_length);
            if (stream->pushback_buffer) free(stream->pushback_buffer);
            stream->pushback_buffer = buffer;
            stream->pushback_capacity = capacity;
        }
        stream->pushback_buffer[stream->pushback_length++] = stream->pushback;
    }
    stream->pushback = ch;
    stream->pushback_pending = true;
    stream->eof = 0;
    return ch;
}

char *fgets(char *s, int size, FILE *stream)
{
    if (!s || size <= 0 || !stream)
    {
        errno = !stream ? EBADF : EINVAL;
        return NULL;
    }
    __alix_stdio_before_read(stream);
    alix_mutex_lock(&stream->mutex);
    if (size == 1)
    {
        s[0] = '\0';
        alix_mutex_unlock(&stream->mutex);
        return s;
    }
    int idx = 0;
    bool failed = false;
    while (idx < size - 1)
    {
        int ch = file_getc_unlocked(stream, &failed);
        if (ch == EOF)
        {
            break;
        }
        s[idx++] = (char)ch;
        if (ch == '\n')
        {
            break;
        }
    }

    if (idx == 0 || failed)
    {
        alix_mutex_unlock(&stream->mutex);
        return NULL;
    }
    s[idx] = '\0';
    alix_mutex_unlock(&stream->mutex);
    return s;
}

int feof(FILE *stream)
{
    if (!stream)
    {
        return 1;
    }
    alix_mutex_lock(&stream->mutex);
    int result = stream->eof != 0;
    alix_mutex_unlock(&stream->mutex);
    return result;
}

int ferror(FILE *stream)
{
    if (!stream) return 1;
    alix_mutex_lock(&stream->mutex);
    int result = stream->error != 0;
    alix_mutex_unlock(&stream->mutex);
    return result;
}

void clearerr(FILE *stream)
{
    if (stream)
    {
        alix_mutex_lock(&stream->mutex);
        stream->error = 0;
        stream->eof = 0;
        alix_mutex_unlock(&stream->mutex);
    }
}

int fileno(FILE *stream)
{
    if (!stream) { errno = EBADF; return -1; }
    alix_mutex_lock(&stream->mutex);
    int result = stream->fd;
    if (result < 0) errno = EBADF;
    alix_mutex_unlock(&stream->mutex);
    return result;
}

int fputs(const char *s, FILE *stream)
{
    if (!s)
    {
        return -1;
    }
    size_t len = strlen(s);
    return (fwrite(s, 1, len, stream) == len) ? 0 : -1;
}

int setvbuf(FILE *stream, char *buf, int mode, size_t size)
{
    if (!stream) { errno = EBADF; return -1; }
    if (mode != _IONBF && mode != _IOFBF && mode != _IOLBF) { errno = EINVAL; return -1; }
    if (mode != _IONBF && buf && !size) { errno = EINVAL; return -1; }
    alix_mutex_lock(&stream->mutex);
    if (stream->fd < 0 || stream->io_started)
    {
        errno = stream->fd < 0 ? EBADF : EBUSY;
        alix_mutex_unlock(&stream->mutex);
        return -1;
    }
    size_t capacity = mode == _IONBF ? 0 : size ? size : BUFSIZ;
    /* C permits the supplied array to be unused. Always owning heap storage
     * avoids retaining a caller stack that another stream user could access. */
    unsigned char *buffer = capacity ? malloc(capacity) : NULL;
    if (capacity && !buffer) { errno = ENOMEM; alix_mutex_unlock(&stream->mutex); return -1; }
    if (stream->buffer) free(stream->buffer);
    stream->buffer = buffer;
    stream->buffer_capacity = capacity;
    stream->buffering = mode;
    alix_mutex_unlock(&stream->mutex);
    return 0;
}

void setbuf(FILE *stream, char *buf)
{
    (void)setvbuf(stream, buf, buf ? _IOFBF : _IONBF, BUFSIZ);
}

int getchar(void)
{
    return fgetc(stdin);
}

ssize_t read(int fd, void *buffer, size_t count)
{
    return sys_read(fd, buffer, count);
}

ssize_t write(int fd, const void *buffer, size_t count)
{
    return sys_write(fd, buffer, count);
}

int close(int fd)
{
    return sys_close(fd);
}

int fsync(int fd)
{
#ifdef ALIX_OWNED_FDS
    int64_t result = sys_file_io(SYSCALL_FILE_SYNC, (uint64_t)(int64_t)fd, 0, 0, 0);
    if (result < 0) { errno = (int)-result; return -1; }
    return 0;
#else
    /* Legacy global descriptors cannot name a slot in the private table. */
    (void)fd;
    errno = ENOTSUP;
    return -1;
#endif
}

int unlink(const char *path)
{
    int64_t result = sys_file_io(SYSCALL_FILE_REMOVE, (uintptr_t)path, 0, 0, 0);
    if (result < 0) { errno = (int)-result; return -1; }
    return 0;
}

int ftruncate(int fd, off_t length)
{
#ifdef ALIX_OWNED_FDS
    if (length < 0) { errno = EINVAL; return -1; }
    int64_t result = sys_file_io(SYSCALL_FILE_TRUNCATE, (uint64_t)(int64_t)fd, (uint64_t)length, 0, 0);
    if (result < 0) { errno = (int)-result; return -1; }
    return 0;
#else
    (void)fd; (void)length;
    errno = ENOTSUP;
    return -1;
#endif
}

int truncate(const char *path, off_t length)
{
    if (length < 0) { errno = EINVAL; return -1; }
    int64_t result = sys_file_io(SYSCALL_FILE_TRUNCATE_PATH, (uintptr_t)path, (uint64_t)length, 0, 0);
    if (result < 0) { errno = (int)-result; return -1; }
    return 0;
}

int puts(const char *text)
{
    if (!text)
    {
        errno = EINVAL;
        return EOF;
    }
    size_t length = strlen(text);
    if (length == SIZE_MAX_VALUE)
    {
        errno = EOVERFLOW;
        return EOF;
    }
    /* A heap-owned complete line also avoids splitting concurrent output into
     * separate string/newline syscalls or retaining another thread's stack. */
    char *line = malloc(length + 1);
    if (!line)
    {
        errno = ENOMEM;
        return EOF;
    }
    memcpy(line, text, length);
    line[length] = '\n';
    size_t written = fwrite(line, 1, length + 1, stdout);
    free(line);
    return written == length + 1 ? 0 : EOF;
}

int remove(const char *path)
{
    int64_t result = sys_file_io(SYSCALL_FILE_REMOVE, (uintptr_t)path, 0, 1, 0);
    if (result < 0) { errno = (int)-result; return -1; }
    return 0;
}

int64_t lseek(int fd, int64_t offset, int whence)
{
    return sys_lseek(fd, offset, whence);
}

ssize_t alix_get_executable_path(char *buffer, size_t capacity)
{
    int64_t result = sys_process(SYSCALL_PROCESS_EXECUTABLE_PATH, (uintptr_t)buffer, capacity, 0);
    if (result < 0) { errno = (int)-result; return -1; }
    return (ssize_t)result;
}

int __alix_stat_decode(const syscall_stat_t *input, struct stat *st)
{
    if (!st || !input) { errno = EFAULT; return -1; }
    uint32_t mode;
    switch (input->type)
    {
        case SYSCALL_NODE_TYPE_DIR: mode = S_IFDIR; break;
        case SYSCALL_NODE_TYPE_FILE: mode = S_IFREG; break;
        case SYSCALL_NODE_TYPE_BLOCK: mode = S_IFBLK; break;
        case SYSCALL_NODE_TYPE_SYMLINK: mode = S_IFLNK; break;
        case SYSCALL_NODE_TYPE_SOCKET: mode = S_IFSOCK; break;
        case SYSCALL_NODE_TYPE_CHARACTER: mode = S_IFCHR; break;
        case SYSCALL_NODE_TYPE_FIFO: mode = S_IFIFO; break;
        default: errno = EIO; return -1;
    }
    memset(st, 0, sizeof(*st));
    st->st_size = input->size_bytes;
    st->st_mode = mode;
    st->st_type = input->type;
    st->st_atime = input->atime;
    st->st_mtime = input->mtime;
    st->st_ctime = input->ctime;
    st->st_atim.tv_sec = (time_t)input->atime;
    st->st_mtim.tv_sec = (time_t)input->mtime;
    st->st_ctim.tv_sec = (time_t)input->ctime;
    return 0;
}

int fstat(int fd, struct stat *st)
{
    if (!st) { errno = EFAULT; return -1; }
#ifdef ALIX_OWNED_FDS
    int64_t result = sys_file_io(SYSCALL_FILE_STAT_TIMES, (uint64_t)(int64_t)fd, (uintptr_t)st, 0, 0);
    if (result < 0) { errno = (int)-result; return -1; }
    return 0;
#else
    syscall_stat_t value;
    int result = sys_fstat(fd, &value);
    return result ? result : __alix_stat_decode(&value, st);
#endif
}

int __alix_fstat_v2(int fd, void *output) __asm__("alix_fstat_v2");
int __alix_fstat_v2(int fd, void *output)
{
    if (!output) { errno = EFAULT; return -1; }
#ifdef ALIX_OWNED_FDS
    int64_t result = sys_file_io(SYSCALL_FILE_STAT_INFO, (uint64_t)(int64_t)fd, (uintptr_t)output, 0, 0);
    if (result < 0) { errno = (int)-result; return -1; }
    return 0;
#else
    struct stat value;
    int result = fstat(fd, &value);
    if (!result) memcpy(output, &value, sizeof(syscall_stat_info_t));
    return result;
#endif
}

/* Original ELF ABI: only its 40 bytes may be written. Existing std binaries
 * still call this symbol, while newly compiled C/Rust libc consumers use v2. */
int __alix_stat_decode_legacy(syscall_stat_t *value, void *output)
{
    if (!output) { errno = EFAULT; return -1; }
    uint32_t type = value->type, mode;
    switch (type)
    {
        case SYSCALL_NODE_TYPE_DIR: mode = S_IFDIR; break;
        case SYSCALL_NODE_TYPE_FILE: mode = S_IFREG; break;
        case SYSCALL_NODE_TYPE_BLOCK: mode = S_IFBLK; break;
        case SYSCALL_NODE_TYPE_SYMLINK: mode = S_IFLNK; break;
        case SYSCALL_NODE_TYPE_SOCKET: mode = S_IFSOCK; break;
        case SYSCALL_NODE_TYPE_CHARACTER: mode = S_IFCHR; break;
        case SYSCALL_NODE_TYPE_FIFO: mode = S_IFIFO; break;
        default: errno = EIO; return -1;
    }
    value->type = mode; value->reserved = type;
    memcpy(output, value, sizeof(*value));
    return 0;
}
int __alix_fstat_legacy(int fd, void *output) __asm__("fstat");
int __alix_fstat_legacy(int fd, void *output)
{
    if (!output) { errno = EFAULT; return -1; }
    syscall_stat_t value;
    int result = sys_fstat(fd, &value);
    return result ? result : __alix_stat_decode_legacy(&value, output);
}

int fchown(int fd, uid_t uid, gid_t gid)
{
#ifdef ALIX_OWNED_FDS
    int64_t result = sys_file_io(SYSCALL_FILE_CHOWN, (uint64_t)(int64_t)fd, uid, gid, 0);
    if (result < 0) { errno = (int)-result; return -1; }
    return 0;
#else
    (void)fd; (void)uid; (void)gid;
    errno = ENOTSUP; return -1;
#endif
}

int fchmod(int fd, mode_t mode)
{
#ifdef ALIX_OWNED_FDS
    int64_t result = sys_file_io(SYSCALL_FILE_CHMOD, (uint64_t)(int64_t)fd, mode, 0, 0);
    if (result < 0) { errno = (int)-result; return -1; }
    return 0;
#else
    (void)fd; (void)mode;
    errno = ENOTSUP; return -1;
#endif
}

int putc(int ch, FILE *stream) { return fputc(ch, stream); }
int putchar(int ch) { return fputc(ch, stdout); }

ssize_t pread(int fd, void *buffer, size_t count, off_t offset)
{
    if (offset < 0) { errno = EINVAL; return -1; }
    return sys_pread(fd, buffer, count, (size_t)offset);
}

int sched_yield(void)
{
    return sys_yield();
}

int sched_getcpu(void)
{
    return (int)sys_thread_cpu();
}

int open(const char *path, uint64_t flags, ...)
{
    uint64_t mode_flags = flags;
    if ((mode_flags & (SYSCALL_OPEN_READ | SYSCALL_OPEN_WRITE)) == 0)
    {
        mode_flags |= SYSCALL_OPEN_READ;
    }
#ifndef TTF_HOST_BUILD
    uint32_t mode = 0666u;
    if (flags & SYSCALL_OPEN_CREATE)
    {
        va_list arguments;
        va_start(arguments, flags);
        mode = va_arg(arguments, uint32_t);
        va_end(arguments);
    }
    return sys_open_mode(path, mode_flags, mode);
#else
    return sys_open(path, mode_flags);
#endif
}

#ifndef TTF_HOST_BUILD
int __alix_open_legacy(const char *path, uint64_t flags, ...) __asm__("open");
int __alix_open_legacy(const char *path, uint64_t flags, ...)
{
    if (!(flags & (SYSCALL_OPEN_READ | SYSCALL_OPEN_WRITE))) flags |= SYSCALL_OPEN_READ;
    return sys_open(path, flags);
}

int creat(const char *path, mode_t mode)
{
    return open(path, SYSCALL_OPEN_WRITE | SYSCALL_OPEN_CREATE | SYSCALL_OPEN_TRUNCATE, mode);
}

mode_t umask(mode_t mask)
{
    int64_t result = sys_process(SYSCALL_PROCESS_UMASK, mask, 0, 0);
    if (result < 0) { errno = (int)-result; return (mode_t)-1; }
    return (mode_t)result;
}
#endif

int socket_open(const char *iface_name)
{
    return sys_socket_open(iface_name);
}

int socket_connect(int fd, const char *ipv4_text, uint16_t port)
{
    return sys_socket_connect(fd, ipv4_text, port);
}

ssize_t socket_available(int fd)
{
    return sys_socket_available(fd);
}

void *sbrk(int64_t increment)
{
    return sys_sbrk(increment);
}

_Static_assert(sizeof(struct statvfs) == sizeof(syscall_statvfs_t) &&
               offsetof(struct statvfs, f_namemax) == offsetof(syscall_statvfs_t, name_max), "native statvfs ABI");
int statvfs(const char *path, struct statvfs *output)
{
    int64_t result = sys_file_io(SYSCALL_FILE_PATH_STATVFS, (uintptr_t)path, (uintptr_t)output, sizeof(*output), 0);
    if (result < 0) { errno = (int)-result; return -1; }
    return 0;
}
int fstatvfs(int descriptor, struct statvfs *output)
{
#ifdef ALIX_OWNED_FDS
    int64_t result = sys_file_io(SYSCALL_FILE_STATVFS, (uint64_t)(int64_t)descriptor, (uintptr_t)output, sizeof(*output), 0);
    if (result < 0) { errno = (int)-result; return -1; }
    return 0;
#else
    (void)descriptor; (void)output; errno = ENOTSUP; return -1;
#endif
}

int access(const char *path, int mode)
{
    int64_t result = sys_file_io(SYSCALL_FILE_ACCESS, (uintptr_t)path, (uint64_t)(int64_t)mode, 0, (uint64_t)(int64_t)-100);
    if (result < 0) { errno = (int)-result; return -1; }
    return 0;
}

int faccessat(int directory, const char *path, int mode, int flags)
{
    int64_t result = sys_file_io(SYSCALL_FILE_ACCESS, (uintptr_t)path, (uint64_t)(int64_t)mode,
                                 (uint64_t)(int64_t)flags, (uint64_t)(int64_t)directory);
    if (result < 0) { errno = (int)-result; return -1; }
    return 0;
}

int symlink(const char *target, const char *path)
{
    int64_t result = sys_file_io(SYSCALL_FILE_SYMLINK, (uintptr_t)target, (uintptr_t)path, 0, 0);
    if (result < 0) { errno = (int)-result; return -1; }
    return 0;
}

int mkfifo(const char *path, mode_t mode)
{
    int64_t result = sys_file_io(SYSCALL_FILE_MKFIFO, (uintptr_t)path, mode, 0, 0);
    if (result < 0) { errno = (int)-result; return -1; }
    return 0;
}

#endif /* TTF_HOST_BUILD */

void exit(int status)
{
#ifndef TTF_HOST_BUILD
    static uint64_t exiting_thread;
    static volatile uint32_t exit_wait;
    uint64_t expected = 0;
    uint64_t self = alix_thread_self();
    if (!__atomic_compare_exchange_n(&exiting_thread, &expected, self, false,
                                     __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
    {
        if (expected == self)
        {
            /* Recursive exit from an exit handler must not invoke it twice. */
            sys_exit(status);
        }
        /* A concurrent exit must not kill the first thread halfway through
         * global destructors. Process termination will cancel this wait. */
        for (;;) (void)sys_futex_wait(&exit_wait, 0, ALIX_WAIT_FOREVER);
    }
    alix_thread_run_tls_destructors();
    alix_run_exit_handlers();
    typedef void (*fini_hook_t)(void);
    extern fini_hook_t __fini_array_start[];
    extern fini_hook_t __fini_array_end[];
    static uint32_t fini_started;
    if (!__atomic_exchange_n(&fini_started, 1, __ATOMIC_ACQ_REL))
    {
        fini_hook_t *hook = __fini_array_end;
        while (hook != __fini_array_start)
        {
            (*--hook)();
        }
    }
    (void)fflush(NULL);
#endif
    sys_exit(status);
    for (;;)
    {
    }
}

typedef struct
{
    void (*start)(void *);
    void *arg;
} alix_thread_start_info_t;

static void alix_thread_trampoline(void *arg) __attribute__((noreturn));
static void alix_thread_trampoline(void *arg)
{
    alix_thread_start_info_t *info = (alix_thread_start_info_t *)arg;
    void (*start)(void *) = info ? info->start : NULL;
    void *start_arg = info ? info->arg : NULL;
    if (info)
    {
        free(info);
    }
    if (start)
    {
        start(start_arg);
    }
    alix_thread_exit(0);
}

void alix_mutex_init(alix_mutex_t *mutex)
{
    if (!mutex)
    {
        return;
    }
    __atomic_store_n(&mutex->state, 0, __ATOMIC_RELEASE);
}

void alix_mutex_lock(alix_mutex_t *mutex)
{
    if (!mutex)
    {
        return;
    }

    uint32_t expected = 0;
    if (__atomic_compare_exchange_n(&mutex->state, &expected, 1, false,
                                    __ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
    {
        return;
    }
    /* State 2 retains the contention marker until unlock wakes a waiter.
     * The expected-value wait closes the unlock-before-sleep race. */
    while (__atomic_exchange_n(&mutex->state, 2, __ATOMIC_ACQUIRE) != 0)
    {
        int result = sys_futex_wait(&mutex->state, 2, SYSCALL_FUTEX_WAIT_FOREVER);
        if (result == -ENOSYS)
        {
            /* The host test syscall adapter has no kernel wait queues. */
            (void)sys_yield();
        }
        else if (result != SYSCALL_FUTEX_OK && result != SYSCALL_FUTEX_AGAIN && result != -EINTR)
        {
            serial_printf("libc: mutex wait failed result=%d\n", result);
            exit(1);
        }
    }
}

void alix_mutex_unlock(alix_mutex_t *mutex)
{
    if (!mutex)
    {
        return;
    }
    uint32_t previous = __atomic_exchange_n(&mutex->state, 0, __ATOMIC_RELEASE);
    if (previous == 2)
    {
        int result = sys_futex_wake(&mutex->state, 1);
        if (result < 0 && result != -ENOSYS)
        {
            serial_printf("libc: mutex wake failed result=%d\n", result);
            exit(1);
        }
    }
}

void alix_cond_init(alix_cond_t *condition)
{
    if (condition)
    {
        __atomic_store_n(&condition->sequence, 0, __ATOMIC_RELEASE);
    }
}

int alix_cond_timedwait(alix_cond_t *condition, alix_mutex_t *mutex, uint32_t timeout_ms)
{
    if (!condition || !mutex)
    {
        return SYSCALL_FUTEX_INVALID;
    }
    /* The caller's mutex protects its predicate. Take the sequence before
     * releasing that mutex: signal between unlock and kernel registration is
     * detected by the kernel's expected-value check instead of being lost. */
    uint32_t sequence = __atomic_load_n(&condition->sequence, __ATOMIC_ACQUIRE);
    alix_mutex_unlock(mutex);
    uint64_t now = sys_monotonic_millis();
    uint64_t deadline = timeout_ms > UINT64_MAX - now ? UINT64_MAX : now + timeout_ms;
    uint32_t remaining = timeout_ms;
    int result;
    for (;;)
    {
        result = sys_futex_wait(&condition->sequence, sequence, remaining);
        if (result != -EINTR) break;
        if (timeout_ms != ALIX_WAIT_FOREVER)
        {
            now = sys_monotonic_millis();
            if (now >= deadline) { result = SYSCALL_FUTEX_TIMED_OUT; break; }
            remaining = (uint32_t)(deadline - now);
        }
    }
    alix_mutex_lock(mutex);
    return result == SYSCALL_FUTEX_AGAIN ? SYSCALL_FUTEX_OK : result;
}

int alix_cond_wait(alix_cond_t *condition, alix_mutex_t *mutex)
{
    return alix_cond_timedwait(condition, mutex, ALIX_WAIT_FOREVER);
}

int alix_cond_signal(alix_cond_t *condition)
{
    if (!condition)
    {
        return SYSCALL_FUTEX_INVALID;
    }
    __atomic_add_fetch(&condition->sequence, 1u, __ATOMIC_RELEASE);
    int result = sys_futex_wake(&condition->sequence, 1);
    return result < 0 ? result : SYSCALL_FUTEX_OK;
}

int alix_cond_broadcast(alix_cond_t *condition)
{
    if (!condition)
    {
        return SYSCALL_FUTEX_INVALID;
    }
    __atomic_add_fetch(&condition->sequence, 1u, __ATOMIC_RELEASE);
    int result = sys_futex_wake(&condition->sequence, (uint32_t)-1);
    return result < 0 ? result : SYSCALL_FUTEX_OK;
}

alix_thread_t alix_thread_self(void)
{
    return (alix_thread_t)sys_thread_self();
}

int alix_thread_create(alix_thread_t *thread_out,
                       const char *name,
                       void (*start)(void *),
                       void *arg)
{
    if (!thread_out || !start)
    {
        return -1;
    }

    alix_thread_start_info_t *info = (alix_thread_start_info_t *)malloc(sizeof(*info));
    if (!info)
    {
        return -1;
    }
    info->start = start;
    info->arg = arg;

    const size_t default_stack = 256u * 1024u;
    int64_t tid = sys_thread_create((uintptr_t)alix_thread_trampoline,
                                   (uintptr_t)info,
                                   default_stack,
                                   name);
    if (tid < 0)
    {
        free(info);
        return -1;
    }

    *thread_out = (alix_thread_t)tid;
    return 0;
}

int alix_thread_join(alix_thread_t thread, int *status_out)
{
    return sys_thread_join((uint64_t)thread, status_out);
}

void alix_thread_exit(int status)
{
    alix_thread_run_tls_destructors();
    if (sys_thread_prepare_exit() == 1)
    {
        /* The last surviving user thread owns process-wide finalization,
         * even when the initial thread previously called thread_exit. */
        exit(status);
    }
    sys_thread_exit(status);
    for (;;)
    {
    }
}

bool alix_mutex_trylock(alix_mutex_t *mutex)
{
    if (!mutex)
    {
        return false;
    }
    uint32_t expected = 0;
    return __atomic_compare_exchange_n(&mutex->state, &expected, 1, false,
                                       __ATOMIC_ACQUIRE, __ATOMIC_RELAXED);
}

void alix_recursive_mutex_init(alix_recursive_mutex_t *mutex)
{
    if (mutex)
    {
        alix_mutex_init(&mutex->mutex);
        __atomic_store_n(&mutex->owner, 0, __ATOMIC_RELEASE);
        mutex->depth = 0;
    }
}

int alix_recursive_mutex_lock(alix_recursive_mutex_t *mutex)
{
    if (!mutex)
    {
        return -EINVAL;
    }
    uint64_t self = alix_thread_self();
    if (__atomic_load_n(&mutex->owner, __ATOMIC_ACQUIRE) == self)
    {
        if (mutex->depth == (uint32_t)-1)
        {
            return -EAGAIN;
        }
        ++mutex->depth;
        return 0;
    }
    alix_mutex_lock(&mutex->mutex);
    mutex->depth = 1;
    __atomic_store_n(&mutex->owner, self, __ATOMIC_RELEASE);
    return 0;
}

bool alix_recursive_mutex_trylock(alix_recursive_mutex_t *mutex)
{
    if (!mutex)
    {
        return false;
    }
    uint64_t self = alix_thread_self();
    if (__atomic_load_n(&mutex->owner, __ATOMIC_ACQUIRE) == self)
    {
        if (mutex->depth == (uint32_t)-1)
        {
            return false;
        }
        ++mutex->depth;
        return true;
    }
    if (!alix_mutex_trylock(&mutex->mutex))
    {
        return false;
    }
    mutex->depth = 1;
    __atomic_store_n(&mutex->owner, self, __ATOMIC_RELEASE);
    return true;
}

int alix_recursive_mutex_unlock(alix_recursive_mutex_t *mutex)
{
    if (!mutex || __atomic_load_n(&mutex->owner, __ATOMIC_ACQUIRE) != alix_thread_self() ||
        mutex->depth == 0)
    {
        return -EPERM;
    }
    if (--mutex->depth == 0)
    {
        __atomic_store_n(&mutex->owner, 0, __ATOMIC_RELEASE);
        alix_mutex_unlock(&mutex->mutex);
    }
    return 0;
}

int alix_call_once(alix_once_t *once, void (*initialize)(void))
{
    if (!once || !initialize)
    {
        return -EINVAL;
    }
    uint32_t expected = 0;
    if (__atomic_compare_exchange_n(&once->state, &expected, 1, false,
                                    __ATOMIC_ACQUIRE, __ATOMIC_ACQUIRE))
    {
        initialize();
        __atomic_store_n(&once->state, 2, __ATOMIC_RELEASE);
        int status = sys_futex_wake(&once->state, (uint32_t)-1);
        return status == -ENOSYS ? 0 : (status < 0 ? status : 0);
    }
    while (__atomic_load_n(&once->state, __ATOMIC_ACQUIRE) != 2)
    {
        int status = sys_futex_wait(&once->state, 1, ALIX_WAIT_FOREVER);
        if (status == -ENOSYS)
        {
            sys_yield();
        }
        else if (status != 0 && status != SYSCALL_FUTEX_AGAIN && status != -EINTR)
        {
            return status;
        }
    }
    return 0;
}

int alix_thread_detach(alix_thread_t thread)
{
    return sys_thread_detach(thread);
}

/* TSD keys are process-wide; values and destructor stacks are native ELF TLS.
 * No pointer to one thread's stack is published to another thread. */
#define ALIX_TLS_KEYS 128u
#define ALIX_TLS_DESTRUCTOR_ITERATIONS 4u
typedef struct
{
    uint32_t generation;
    bool active;
    void (*destroy)(void *);
} libc_tls_key_t;
typedef struct { uint32_t generation; void *value; } libc_tls_value_t;
typedef struct libc_thread_destructor
{
    struct libc_thread_destructor *next;
    void (*function)(void *);
    void *argument;
    void *module;
} libc_thread_destructor_t;
static libc_tls_key_t g_tls_keys[ALIX_TLS_KEYS];
static alix_mutex_t g_tls_keys_lock;
static _Thread_local libc_tls_value_t g_tls_values[ALIX_TLS_KEYS];
static _Thread_local libc_thread_destructor_t *g_thread_destructors;
static _Thread_local bool g_tls_cleanup_active;
static _Thread_local bool g_tls_cleanup_done;

static bool libc_tls_key_index(alix_tls_key_t key, uint32_t *index, uint32_t *generation)
{
    uint32_t slot = (uint32_t)key;
    *generation = (uint32_t)(key >> 32);
    if (slot == 0 || slot > ALIX_TLS_KEYS || *generation == 0)
    {
        return false;
    }
    *index = slot - 1;
    return true;
}

int alix_tls_key_create(alix_tls_key_t *key, void (*destroy)(void *))
{
    if (!key)
    {
        return -EINVAL;
    }
    alix_mutex_lock(&g_tls_keys_lock);
    for (uint32_t index = 0; index < ALIX_TLS_KEYS; ++index)
    {
        if (!g_tls_keys[index].active)
        {
            uint32_t generation = g_tls_keys[index].generation + 1;
            /* A wrapped generation is never reused: stale keys stay invalid. */
            if (generation == 0)
            {
                continue;
            }
            g_tls_keys[index].generation = generation;
            g_tls_keys[index].destroy = destroy;
            g_tls_keys[index].active = true;
            *key = ((uint64_t)generation << 32) | (index + 1u);
            alix_mutex_unlock(&g_tls_keys_lock);
            return 0;
        }
    }
    alix_mutex_unlock(&g_tls_keys_lock);
    return -EAGAIN;
}

int alix_tls_key_delete(alix_tls_key_t key)
{
    uint32_t index, generation;
    if (!libc_tls_key_index(key, &index, &generation))
    {
        return -EINVAL;
    }
    alix_mutex_lock(&g_tls_keys_lock);
    bool valid = g_tls_keys[index].active && g_tls_keys[index].generation == generation;
    if (valid)
    {
        g_tls_keys[index].active = false;
        g_tls_keys[index].destroy = NULL;
    }
    alix_mutex_unlock(&g_tls_keys_lock);
    return valid ? 0 : -EINVAL;
}

void *alix_tls_get(alix_tls_key_t key)
{
    uint32_t index, generation;
    if (!libc_tls_key_index(key, &index, &generation))
    {
        return NULL;
    }
    alix_mutex_lock(&g_tls_keys_lock);
    void *value = NULL;
    if (g_tls_keys[index].active && g_tls_keys[index].generation == generation &&
        g_tls_values[index].generation == generation)
    {
        value = g_tls_values[index].value;
    }
    alix_mutex_unlock(&g_tls_keys_lock);
    return value;
}

int alix_tls_set(alix_tls_key_t key, void *value)
{
    uint32_t index, generation;
    if (!libc_tls_key_index(key, &index, &generation))
    {
        return -EINVAL;
    }
    alix_mutex_lock(&g_tls_keys_lock);
    bool valid = g_tls_keys[index].active && g_tls_keys[index].generation == generation;
    if (valid)
    {
        g_tls_values[index].generation = generation;
        g_tls_values[index].value = value;
    }
    alix_mutex_unlock(&g_tls_keys_lock);
    return valid ? 0 : -EINVAL;
}

void alix_thread_run_tls_destructors(void)
{
    extern void __alix_dl_unpin(void *) __attribute__((weak));
    extern void __alix_dl_thread_cleanup(void) __attribute__((weak));
    if (g_tls_cleanup_active || g_tls_cleanup_done)
    {
        return;
    }
    g_tls_cleanup_active = true;
    while (g_thread_destructors)
    {
        libc_thread_destructor_t *item = g_thread_destructors;
        g_thread_destructors = item->next;
        void (*function)(void *) = item->function;
        void *argument = item->argument;
        void *module = item->module;
        free(item);
        function(argument);
        if (module && __alix_dl_unpin) __alix_dl_unpin(module);
    }
    for (unsigned pass = 0; pass < ALIX_TLS_DESTRUCTOR_ITERATIONS; ++pass)
    {
        bool called = false;
        for (unsigned index = 0; index < ALIX_TLS_KEYS; ++index)
        {
            alix_mutex_lock(&g_tls_keys_lock);
            void (*destroy)(void *) = NULL;
            void *value = NULL;
            if (g_tls_keys[index].active &&
                g_tls_values[index].generation == g_tls_keys[index].generation)
            {
                destroy = g_tls_keys[index].destroy;
                value = g_tls_values[index].value;
            }
            g_tls_values[index].value = NULL;
            alix_mutex_unlock(&g_tls_keys_lock);
            if (destroy && value)
            {
                called = true;
                destroy(value);
            }
        }
        if (!called)
        {
            break;
        }
    }
    /* A pthread-key destructor may have instantiated another C++ TLS object. */
    while (g_thread_destructors)
    {
        libc_thread_destructor_t *item = g_thread_destructors;
        g_thread_destructors = item->next;
        void (*function)(void *) = item->function;
        void *argument = item->argument;
        void *module = item->module;
        free(item);
        function(argument);
        if (module && __alix_dl_unpin) __alix_dl_unpin(module);
    }
    if (__alix_dl_thread_cleanup) __alix_dl_thread_cleanup();
    g_tls_cleanup_done = true;
    g_tls_cleanup_active = false;
}

#ifndef TTF_HOST_BUILD
typedef struct libc_exit_handler
{
    struct libc_exit_handler *next;
    void (*plain)(void);
    void (*cxa)(void *);
    void *argument;
    void *dso;
} libc_exit_handler_t;
static libc_exit_handler_t *g_exit_handlers;
static alix_mutex_t g_exit_handlers_lock;

int atexit(void (*function)(void))
{
    if (!function)
    {
        errno = EINVAL;
        return -1;
    }
    libc_exit_handler_t *item = (libc_exit_handler_t *)calloc(1, sizeof(*item));
    if (!item)
    {
        errno = ENOMEM;
        return -1;
    }
    item->plain = function;
    alix_mutex_lock(&g_exit_handlers_lock);
    item->next = g_exit_handlers;
    g_exit_handlers = item;
    alix_mutex_unlock(&g_exit_handlers_lock);
    return 0;
}

int __cxa_atexit(void (*function)(void *), void *argument, void *dso)
{
    if (!function)
    {
        errno = EINVAL;
        return -1;
    }
    libc_exit_handler_t *item = (libc_exit_handler_t *)calloc(1, sizeof(*item));
    if (!item)
    {
        errno = ENOMEM;
        return -1;
    }
    item->cxa = function;
    item->argument = argument;
    item->dso = dso;
    alix_mutex_lock(&g_exit_handlers_lock);
    item->next = g_exit_handlers;
    g_exit_handlers = item;
    alix_mutex_unlock(&g_exit_handlers_lock);
    return 0;
}

void __cxa_finalize(void *dso)
{
    for (;;)
    {
        alix_mutex_lock(&g_exit_handlers_lock);
        libc_exit_handler_t **cursor = &g_exit_handlers;
        while (*cursor && dso && (*cursor)->dso != dso)
        {
            cursor = &(*cursor)->next;
        }
        libc_exit_handler_t *item = *cursor;
        if (item)
        {
            *cursor = item->next;
        }
        alix_mutex_unlock(&g_exit_handlers_lock);
        if (!item)
        {
            break;
        }
        /* Remove before calling: recursive finalize cannot invoke it twice. */
        if (item->cxa)
        {
            item->cxa(item->argument);
        }
        else
        {
            item->plain();
        }
        free(item);
    }
}

void alix_run_exit_handlers(void)
{
    __cxa_finalize(NULL);
}

int __cxa_thread_atexit_impl(void (*function)(void *), void *argument, void *dso)
{
    extern void *__alix_dl_pin(const void *) __attribute__((weak));
    if (!function)
    {
        errno = EINVAL;
        return -1;
    }
    libc_thread_destructor_t *item = (libc_thread_destructor_t *)malloc(sizeof(*item));
    if (!item)
    {
        errno = ENOMEM;
        return -1;
    }
    item->function = function;
    item->argument = argument;
    item->module = __alix_dl_pin ? __alix_dl_pin(dso) : NULL;
    item->next = g_thread_destructors;
    g_thread_destructors = item;
    return 0;
}

void _Exit(int status)
{
    sys_exit(status);
}

void _exit(int status)
{
    _Exit(status);
}

/* Mozilla deliberately defines its own abort hook. Keep ordinary Alix libc's
 * definition strong; only the upstream application profile permits that hook. */
#ifdef ALIX_UPSTREAM_ABORT_HOOK
__attribute__((weak))
#endif
void abort(void)
{
    sigset_t set;
    (void)sigemptyset(&set); (void)sigaddset(&set, SIGABRT);
    (void)sigprocmask(SIG_UNBLOCK, &set, NULL);
    (void)raise(SIGABRT);
    sys_exit(134);
}

void __assert_fail(const char *expression, const char *file, unsigned line, const char *function)
{
    serial_printf("assertion failed: %s:%u %s: %s\n", file, line, function, expression);
    abort();
}

int fegetround(void)
{
    uint32_t mxcsr;
    __asm__ volatile ("stmxcsr %0" : "=m"(mxcsr));
    return (int)((mxcsr >> 3) & 0xC00u);
}

int fesetround(int mode)
{
    if (mode != FE_TONEAREST && mode != FE_DOWNWARD && mode != FE_UPWARD && mode != FE_TOWARDZERO)
        return -1;
    uint16_t control;
    uint32_t mxcsr;
    __asm__ volatile ("fnstcw %0; stmxcsr %1" : "=m"(control), "=m"(mxcsr));
    control = (uint16_t)((control & ~0xC00u) | (unsigned)mode);
    mxcsr = (mxcsr & ~0x6000u) | ((unsigned)mode << 3);
    __asm__ volatile ("fldcw %0; ldmxcsr %1" :: "m"(control), "m"(mxcsr) : "memory");
    return 0;
}

long labs(long value) { return value < 0 ? -value : value; }
long long llabs(long long value) { return value < 0 ? -value : value; }
div_t div(int n, int d) { return (div_t){n / d, n % d}; }
ldiv_t ldiv(long n, long d) { return (ldiv_t){n / d, n % d}; }
lldiv_t lldiv(long long n, long long d) { return (lldiv_t){n / d, n % d}; }

static unsigned libc_integer_digit(unsigned char value)
{
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'z') return value - 'a' + 10u;
    if (value >= 'A' && value <= 'Z') return value - 'A' + 10u;
    return 255u;
}

static uint64_t libc_parse_integer(const char *text, char **end, int base,
                                    bool *negative, bool *overflow)
{
    *negative = false;
    *overflow = false;
    if (end) *end = (char *)text;
    if (!text || (base != 0 && (base < 2 || base > 36)))
    { errno = EINVAL; return 0; }
    const char *cursor = text;
    while (isspace((unsigned char)*cursor)) ++cursor;
    if (*cursor == '+' || *cursor == '-') { *negative = *cursor == '-'; ++cursor; }
    if ((base == 0 || base == 16) && cursor[0] == '0' &&
        (cursor[1] == 'x' || cursor[1] == 'X') && libc_integer_digit((unsigned char)cursor[2]) < 16)
    { base = 16; cursor += 2; }
    if (base == 0) base = *cursor == '0' ? 8 : 10;
    const char *first = cursor;
    uint64_t value = 0;
    uint64_t limit = (uint64_t)-1;
    unsigned digit;
    while ((digit = libc_integer_digit((unsigned char)*cursor)) < (unsigned)base)
    {
        if (value > (limit - digit) / (unsigned)base) *overflow = true;
        else if (!*overflow) value = value * (unsigned)base + digit;
        ++cursor;
    }
    if (cursor != first && end) *end = (char *)cursor;
    return *overflow ? limit : value;
}

unsigned long long strtoull(const char *text, char **end, int base)
{
    bool negative, overflow;
    uint64_t value = libc_parse_integer(text, end, base, &negative, &overflow);
    if (overflow) { errno = ERANGE; return (unsigned long long)-1; }
    return negative ? (uint64_t)0 - value : value;
}

long long strtoll(const char *text, char **end, int base)
{
    bool negative, overflow;
    uint64_t value = libc_parse_integer(text, end, base, &negative, &overflow);
    const uint64_t positive_limit = 0x7FFFFFFFFFFFFFFFULL;
    if (overflow || value > positive_limit + (negative ? 1u : 0u))
    { errno = ERANGE; return negative ? (-0x7FFFFFFFFFFFFFFFLL - 1) : 0x7FFFFFFFFFFFFFFFLL; }
    if (!negative) return (long long)value;
    return value ? -(long long)(value - 1u) - 1 : 0;
}

long strtol(const char *text, char **end, int base) { return (long)strtoll(text, end, base); }
unsigned long strtoul(const char *text, char **end, int base) { return (unsigned long)strtoull(text, end, base); }
long atol(const char *text) { return strtol(text, NULL, 10); }
long long atoll(const char *text) { return strtoll(text, NULL, 10); }

void *bsearch(const void *key, const void *base, size_t count, size_t width,
              int (*compare)(const void *, const void *))
{
    if (!compare || !width || count > SIZE_MAX_VALUE / width)
    {
        errno = EINVAL;
        return NULL;
    }
    const uint8_t *bytes = (const uint8_t *)base;
    while (count)
    {
        size_t middle = count / 2;
        const uint8_t *item = bytes + middle * width;
        int order = compare(key, item);
        if (!order) return (void *)item;
        if (order > 0) { bytes = item + width; count -= middle + 1; }
        else count = middle;
    }
    return NULL;
}

static void libc_sort_swap(uint8_t *a, uint8_t *b, size_t width)
{
    while (width--) { uint8_t value = *a; *a++ = *b; *b++ = value; }
}

static void libc_sort_sift(uint8_t *base, size_t root, size_t count, size_t width,
                           int (*compare)(const void *, const void *))
{
    while (root < count / 2)
    {
        size_t child = root * 2 + 1;
        if (child + 1 < count && compare(base + child * width, base + (child + 1) * width) < 0)
            ++child;
        if (compare(base + root * width, base + child * width) >= 0) return;
        libc_sort_swap(base + root * width, base + child * width, width);
        root = child;
    }
}

void qsort(void *base, size_t count, size_t width, int (*compare)(const void *, const void *))
{
    if (count < 2) return;
    if (!base || !compare || !width || count > SIZE_MAX_VALUE / width)
    { errno = EINVAL; return; }
    uint8_t *bytes = (uint8_t *)base;
    for (size_t root = count / 2; root > 0; ) libc_sort_sift(bytes, --root, count, width, compare);
    for (size_t remaining = count; remaining > 1; )
    {
        libc_sort_swap(bytes, bytes + (--remaining) * width, width);
        libc_sort_sift(bytes, 0, remaining, width, compare);
    }
}

static int libc_cpu_clock(clockid_t clock, syscall_cpu_clock_t *snapshot)
{
    int result = sys_cpu_clock(clock == CLOCK_THREAD_CPUTIME_ID ?
        SYSCALL_USAGE_CLOCK_THREAD : SYSCALL_USAGE_CLOCK_PROCESS, snapshot);
    if (result < 0) { errno = -result; return -1; }
    if (!snapshot->tick_frequency || snapshot->reserved) { errno = EIO; return -1; }
    return 0;
}

int clock_gettime(clockid_t clock, struct timespec *value)
{
    if (clock < CLOCK_REALTIME || clock > CLOCK_THREAD_CPUTIME_ID) { errno = EINVAL; return -1; }
    if (!value) { errno = EFAULT; return -1; }
    if (clock == CLOCK_PROCESS_CPUTIME_ID || clock == CLOCK_THREAD_CPUTIME_ID)
    {
        syscall_cpu_clock_t snapshot = {0};
        if (libc_cpu_clock(clock, &snapshot)) return -1;
        uint64_t seconds = snapshot.ticks / snapshot.tick_frequency;
        if (seconds > INT64_MAX) { errno = EOVERFLOW; return -1; }
        value->tv_sec = (time_t)seconds;
        value->tv_nsec = (long)(((snapshot.ticks % snapshot.tick_frequency) * 1000000000ull) /
                                snapshot.tick_frequency);
        return 0;
    }
    uint64_t milliseconds = clock == CLOCK_MONOTONIC ? sys_monotonic_millis() : sys_time_millis();
    value->tv_sec = (time_t)(milliseconds / 1000u);
    value->tv_nsec = (long)((milliseconds % 1000u) * 1000000u);
    return 0;
}

int clock_getres(clockid_t clock, struct timespec *value)
{
    if (clock < CLOCK_REALTIME || clock > CLOCK_THREAD_CPUTIME_ID) { errno = EINVAL; return -1; }
    if (!value) return 0;
    syscall_cpu_clock_t snapshot = {0};
    if (libc_cpu_clock(clock, &snapshot)) return -1;
    uint64_t nanoseconds = (1000000000ull + snapshot.tick_frequency - 1) / snapshot.tick_frequency;
    if ((clock == CLOCK_REALTIME || clock == CLOCK_MONOTONIC) && nanoseconds < 1000000u)
        nanoseconds = 1000000u;
    value->tv_sec = (time_t)(nanoseconds / 1000000000u);
    value->tv_nsec = (long)(nanoseconds % 1000000000u);
    return 0;
}

int timespec_get(struct timespec *value, int base)
{
    return base == TIME_UTC && clock_gettime(CLOCK_REALTIME, value) == 0 ? TIME_UTC : 0;
}

int gettimeofday(struct timeval *value, void *timezone)
{
    (void)timezone;
    if (!value) { errno = EFAULT; return -1; }
    uint64_t milliseconds = sys_time_millis();
    value->tv_sec = (time_t)(milliseconds / 1000u);
    value->tv_usec = (suseconds_t)((milliseconds % 1000u) * 1000u);
    return 0;
}

int nanosleep(const struct timespec *duration, struct timespec *remaining)
{
    if (!duration || duration->tv_sec < 0 || duration->tv_nsec < 0 || duration->tv_nsec >= 1000000000L)
    { errno = EINVAL; return -1; }
    time_t seconds = duration->tv_sec;
    long nanoseconds = duration->tv_nsec;
    const uint32_t chunk_seconds = 4294967u;
    while (seconds >= chunk_seconds)
    {
        uint32_t left = 0;
        int status = sys_sleep_interruptible(chunk_seconds * 1000u, &left);
        if (status < 0)
        {
            if (status == -EINTR && remaining)
            {
                remaining->tv_sec = seconds - chunk_seconds + left / 1000u;
                remaining->tv_nsec = nanoseconds + (long)(left % 1000u) * 1000000L;
                if (remaining->tv_nsec >= 1000000000L) { ++remaining->tv_sec; remaining->tv_nsec -= 1000000000L; }
            }
            errno = -status; return -1;
        }
        seconds -= chunk_seconds;
    }
    uint32_t milliseconds = (uint32_t)seconds * 1000u + (uint32_t)((nanoseconds + 999999L) / 1000000L);
    uint32_t left = 0;
    int status = sys_sleep_interruptible(milliseconds, &left);
    if (status < 0)
    {
        if (status == -EINTR && remaining)
        {
            remaining->tv_sec = left / 1000u;
            remaining->tv_nsec = (long)(left % 1000u) * 1000000L;
            if (remaining->tv_sec > seconds || (remaining->tv_sec == seconds && remaining->tv_nsec > nanoseconds))
            { remaining->tv_sec = seconds; remaining->tv_nsec = nanoseconds; }
        }
        errno = -status; return -1;
    }
    if (remaining) { remaining->tv_sec = 0; remaining->tv_nsec = 0; }
    return 0;
}

unsigned int sleep(unsigned int seconds)
{
    int saved_errno = errno;
    struct timespec duration = { (time_t)seconds, 0 };
    struct timespec remaining = duration;
    if (nanosleep(&duration, &remaining)) return (unsigned int)remaining.tv_sec;
    errno = saved_errno;
    return 0;
}

#ifndef TTF_HOST_BUILD
int usleep(useconds_t microseconds)
{
    struct timespec duration = { (time_t)(microseconds / 1000000u),
                                (long)(microseconds % 1000000u) * 1000L };
    return nanosleep(&duration, NULL);
}
#endif

time_t time(time_t *result)
{
    time_t value = (time_t)(sys_time_millis() / 1000u);
    if (result) *result = value;
    return value;
}

double difftime(time_t end, time_t beginning)
{
    return end >= beginning ? (double)((uint64_t)end - (uint64_t)beginning)
                            : -(double)((uint64_t)beginning - (uint64_t)end);
}

int getpagesize(void) { return (int)sysconf(_SC_PAGESIZE); }

long sysconf(int name)
{
    if (name == _SC_PAGESIZE) return 4096;
    if (name == _SC_PHYS_PAGES || name == _SC_AVPHYS_PAGES)
    {
        int64_t pages = sys_memory_pages(name == _SC_PHYS_PAGES ?
            SYSCALL_MEMORY_TOTAL_PAGES : SYSCALL_MEMORY_AVAILABLE_PAGES);
        if (pages < 0) { errno = (int)-pages; return -1; }
        return (long)pages;
    }
    if (name != _SC_NPROCESSORS_ONLN && name != _SC_NPROCESSORS_CONF)
    { errno = EINVAL; return -1; }
    syscall_cpu_stats_t *cpus = (syscall_cpu_stats_t *)calloc(SYSCALL_CPU_MAX, sizeof(*cpus));
    if (!cpus) { errno = ENOMEM; return -1; }
    ssize_t count = sys_cpu_snapshot(cpus, SYSCALL_CPU_MAX);
    if (count < 0) { free(cpus); errno = EIO; return -1; }
    if (count > SYSCALL_CPU_MAX) count = SYSCALL_CPU_MAX;
    long result = 0;
    for (ssize_t i = 0; i < count; ++i)
    {
        if (name == _SC_NPROCESSORS_CONF || cpus[i].online) ++result;
    }
    free(cpus);
    return result;
}
#else
void alix_run_exit_handlers(void) { }
#endif
