#include <stdarg.h>

#include "userlib.h"
#include "serial.h"
#include "stdio.h"
#include "errno.h"
#include "unistd.h"

int errno = 0;

#define ALIGNMENT 16UL
#define SIZE_MAX_VALUE ((size_t)-1)

typedef struct heap_block
{
    size_t size;
    struct heap_block *next;
    struct heap_block *prev;
    bool free;
} heap_block_t;

static heap_block_t *g_heap_head = NULL;
static heap_block_t *g_heap_tail = NULL;
static volatile int g_heap_lock = 0;

typedef struct
{
    char *name;
    char *value;
} libc_env_entry_t;

static libc_env_entry_t *g_env_entries = NULL;
static size_t g_env_count = 0;
static size_t g_env_capacity = 0;

static int libc_env_find(const char *name)
{
    if (!name)
    {
        return -1;
    }
    for (size_t i = 0; i < g_env_count; ++i)
    {
        if (strcmp(g_env_entries[i].name, name) == 0)
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
static void user_heap_log(const char *msg, uintptr_t value)
{
    serial_printf("%s", "[uheap] ");
    serial_printf("%s", msg);
    serial_printf("%s", "0x");
    serial_printf("%016llX", (unsigned long long)((uint64_t)value));
    serial_printf("%s", "\r\n");
}
#else
static void user_heap_log(const char *msg, uintptr_t value)
{
    (void)msg;
    (void)value;
}
#endif

static size_t align_size(size_t size)
{
    if (size == 0)
    {
        return 0;
    }
    size_t mask = ALIGNMENT - 1;
    return (size + mask) & ~mask;
}

static void split_block(heap_block_t *block, size_t size)
{
    if (!block || block->size <= size + sizeof(heap_block_t) + ALIGNMENT)
    {
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
        new_block->next->prev = new_block;
    }
    else
    {
        g_heap_tail = new_block;
    }
    block->next = new_block;
    block->size = size;
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
        block->size += sizeof(heap_block_t) + next->size;
        block->next = next->next;
        if (block->next)
        {
            block->next->prev = block;
        }
        else
        {
            g_heap_tail = block;
        }
    }

    if (block->prev && block->prev->free)
    {
        block = block->prev;
        coalesce(block);
    }
}

static heap_block_t *find_free_block(size_t size)
{
    for (heap_block_t *block = g_heap_head; block; block = block->next)
    {
        if (block->free && block->size >= size)
        {
            return block;
        }
    }
    return NULL;
}

static heap_block_t *request_block_unlinked(size_t size)
{
    if (size > SIZE_MAX_VALUE - sizeof(heap_block_t))
    {
        return NULL;
    }
    size_t total = sizeof(heap_block_t) + size;
    void *base = sys_sbrk((int64_t)total);
    user_heap_log("sbrk size=", total);
    user_heap_log("sbrk result=", (uintptr_t)base);
    if (base == (void *)-1 || base == NULL)
    {
        user_heap_log("sbrk failed size=", total);
        return NULL;
    }
    heap_block_t *block = (heap_block_t *)base;
    block->size = size;
    block->next = NULL;
    block->prev = NULL;
    block->free = false;
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
    while (__sync_lock_test_and_set(&g_heap_lock, 1) != 0)
    {
        while (g_heap_lock)
        {
            __asm__ volatile ("pause");
        }
    }
}

static void user_heap_lock_release(void)
{
    __sync_lock_release(&g_heap_lock);
}

static void *malloc_locked(size_t size)
{
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

    /*
     * Grow the heap without holding the spinlock across the syscall, then
     * re-acquire the lock to splice the new block. This keeps list mutation
     * serialized while avoiding blocking in sbrk with the lock held.
     */
    user_heap_lock_release();
    heap_block_t *new_block = request_block_unlinked(size);
    user_heap_lock_acquire();
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

void *memset(void *dst, int value, size_t count)
{
    uint8_t *ptr = (uint8_t *)dst;
    uint8_t byte = (uint8_t)value;
    for (size_t i = 0; i < count; ++i)
    {
        ptr[i] = byte;
    }
    return dst;
}

void *memcpy(void *dst, const void *src, size_t count)
{
    uint8_t *d = (uint8_t *)dst;
    const uint8_t *s = (const uint8_t *)src;
    for (size_t i = 0; i < count; ++i)
    {
        d[i] = s[i];
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
            return (int)va - (int)vb;
        }
    }
    return 0;
}

size_t strlen(const char *str)
{
    size_t len = 0;
    while (str && str[len] != '\0')
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

char *strchr(const char *str, int ch)
{
    if (!str)
    {
        return NULL;
    }
    char target = (char)ch;
    while (*str)
    {
        if (*str == target)
        {
            return (char *)str;
        }
        ++str;
    }
    return (target == '\0') ? (char *)str : NULL;
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
    while (a && b && *a && *b)
    {
        int ca = libc_tolower_char((unsigned char)*a);
        int cb = libc_tolower_char((unsigned char)*b);
        if (ca != cb)
        {
            return ca - cb;
        }
        ++a;
        ++b;
    }
    int ca = a ? libc_tolower_char((unsigned char)*a) : 0;
    int cb = b ? libc_tolower_char((unsigned char)*b) : 0;
    return ca - cb;
}

int strncasecmp(const char *a, const char *b, size_t n)
{
    if (n == 0)
    {
        return 0;
    }
    for (size_t i = 0; i < n; ++i)
    {
        int ca = a ? libc_tolower_char((unsigned char)a[i]) : 0;
        int cb = b ? libc_tolower_char((unsigned char)b[i]) : 0;
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

char *getenv(const char *name)
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
    return g_env_entries[index].value;
}

int setenv(const char *name, const char *value, int overwrite)
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
        g_env_entries[g_env_count].name = name_copy;
        g_env_entries[g_env_count].value = value_copy;
        g_env_count++;
        return 0;
    }

    free(g_env_entries[index].value);
    g_env_entries[index].value = value_copy;
    return 0;
}

int unsetenv(const char *name)
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

char *strerror(int errnum)
{
    switch (errnum)
    {
        case EINVAL: return "Invalid argument";
        case ENOMEM: return "Out of memory";
        case ENOENT: return "No such file or directory";
        case EAGAIN: return "Resource temporarily unavailable";
        case EINTR:  return "Interrupted system call";
        case EEXIST: return "File exists";
        case EIO:    return "I/O error";
        default:     return "Unknown error";
    }
}

typedef struct
{
    int fd;
    char *buffer;
    size_t capacity;
    size_t length;
    bool error;
    bool buffer_mode;
} printf_sink_t;

static void printf_sink_write(printf_sink_t *sink, const char *data, size_t len)
{
    if (!sink || sink->error || !data || len == 0)
    {
        return;
    }

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

    size_t offset = 0;
    while (offset < len)
    {
        ssize_t result = write(sink->fd, data + offset, len - offset);
        if (result <= 0)
        {
            sink->error = true;
            return;
        }
        offset += (size_t)result;
        sink->length += (size_t)result;
    }
}

static void printf_sink_putc(printf_sink_t *sink, char c)
{
    printf_sink_write(sink, &c, 1);
}

static void printf_sink_puts(printf_sink_t *sink, const char *text)
{
    if (!text)
    {
        text = "(null)";
    }
    printf_sink_write(sink, text, strlen(text));
}

static void printf_sink_print_unsigned(printf_sink_t *sink,
                                       uint64_t value,
                                       unsigned base,
                                       bool uppercase,
                                       int width,
                                       bool zero_pad)
{
    if (base < 2 || base > 16)
    {
        return;
    }

    char buffer[32];
    size_t index = 0;
    const char *digits = uppercase ? "0123456789ABCDEF" : "0123456789abcdef";

    do
    {
        buffer[index++] = digits[value % base];
        value /= base;
    } while (value != 0 && index < sizeof(buffer));

    if (!zero_pad)
    {
        width = 0;
    }
    int pad = 0;
    if (width > 0 && (int)index < width)
    {
        pad = width - (int)index;
    }
    while (pad-- > 0)
    {
        printf_sink_putc(sink, '0');
    }

    while (index > 0)
    {
        printf_sink_putc(sink, buffer[--index]);
    }
}

static void printf_sink_print_signed(printf_sink_t *sink, int64_t value, int width, bool zero_pad)
{
    if (value < 0)
    {
        printf_sink_putc(sink, '-');
        if (zero_pad && width > 0)
        {
            width--;
        }
        uint64_t magnitude = (uint64_t)(-(value + 1)) + 1;
        printf_sink_print_unsigned(sink, magnitude, 10, false, width, zero_pad);
        return;
    }
    printf_sink_print_unsigned(sink, (uint64_t)value, 10, false, width, zero_pad);
}

static void printf_format(printf_sink_t *sink, const char *format, va_list args)
{
    while (format && *format && sink && !sink->error)
    {
        if (*format != '%')
        {
            const char *start = format;
            while (*format && *format != '%')
            {
                ++format;
            }
            printf_sink_write(sink, start, (size_t)(format - start));
            continue;
        }

        ++format;
        if (*format == '%')
        {
            printf_sink_putc(sink, '%');
            ++format;
            continue;
        }

        bool zero_pad = false;
        if (*format == '0')
        {
            zero_pad = true;
            ++format;
        }

        int width = 0;
        while (*format >= '0' && *format <= '9')
        {
            width = width * 10 + (*format - '0');
            ++format;
        }
        if (!zero_pad)
        {
            width = 0;
        }

        bool length_z = false;
        bool length_l = false;
        bool length_ll = false;
        while (*format == 'z' || *format == 'l')
        {
            if (*format == 'z')
            {
                length_z = true;
                ++format;
                break;
            }
            if (*format == 'l')
            {
                if (length_l)
                {
                    length_ll = true;
                }
                length_l = true;
                ++format;
            }
        }

        char specifier = *format ? *format++ : '\0';
        switch (specifier)
        {
            case 'c':
            {
                char value = (char)va_arg(args, int);
                printf_sink_putc(sink, value);
                break;
            }
            case 's':
            {
                const char *text = va_arg(args, const char *);
                printf_sink_puts(sink, text);
                break;
            }
            case 'd':
            case 'i':
            {
                if (length_z || length_l)
                {
                    long value = va_arg(args, long);
                    printf_sink_print_signed(sink, (int64_t)value, width, zero_pad);
                }
                else if (length_ll)
                {
                    long long value = va_arg(args, long long);
                    printf_sink_print_signed(sink, (int64_t)value, width, zero_pad);
                }
                else
                {
                    int value = va_arg(args, int);
                    printf_sink_print_signed(sink, (int64_t)value, width, zero_pad);
                }
                break;
            }
            case 'u':
            {
                uint64_t value;
                if (length_z)
                {
                    value = (uint64_t)va_arg(args, size_t);
                }
                else if (length_ll)
                {
                    value = (uint64_t)va_arg(args, unsigned long long);
                }
                else if (length_l)
                {
                    value = (uint64_t)va_arg(args, unsigned long);
                }
                else
                {
                    value = (uint64_t)va_arg(args, unsigned int);
                }
                printf_sink_print_unsigned(sink, value, 10, false, width, zero_pad);
                break;
            }
            case 'x':
            {
                uint64_t value;
                if (length_z)
                {
                    value = (uint64_t)va_arg(args, size_t);
                }
                else if (length_ll)
                {
                    value = (uint64_t)va_arg(args, unsigned long long);
                }
                else if (length_l)
                {
                    value = (uint64_t)va_arg(args, unsigned long);
                }
                else
                {
                    value = (uint64_t)va_arg(args, unsigned int);
                }
                printf_sink_print_unsigned(sink, value, 16, false, width, zero_pad);
                break;
            }
            case 'X':
            {
                uint64_t value;
                if (length_z)
                {
                    value = (uint64_t)va_arg(args, size_t);
                }
                else if (length_ll)
                {
                    value = (uint64_t)va_arg(args, unsigned long long);
                }
                else if (length_l)
                {
                    value = (uint64_t)va_arg(args, unsigned long);
                }
                else
                {
                    value = (uint64_t)va_arg(args, unsigned int);
                }
                printf_sink_print_unsigned(sink, value, 16, true, width, zero_pad);
                break;
            }
            case 'p':
            {
                uintptr_t ptr = (uintptr_t)va_arg(args, void *);
                printf_sink_write(sink, "0x", 2);
                printf_sink_print_unsigned(sink, ptr, 16, false, 0, false);
                break;
            }
            case '\0':
            {
                printf_sink_putc(sink, '%');
                if (length_z)
                {
                    printf_sink_putc(sink, 'z');
                }
                if (length_l)
                {
                    printf_sink_putc(sink, 'l');
                    if (length_ll)
                    {
                        printf_sink_putc(sink, 'l');
                    }
                }
                return;
            }
            default:
            {
                printf_sink_putc(sink, '%');
                if (length_z)
                {
                    printf_sink_putc(sink, 'z');
                }
                if (length_l)
                {
                    printf_sink_putc(sink, 'l');
                    if (length_ll)
                    {
                        printf_sink_putc(sink, 'l');
                    }
                }
                printf_sink_putc(sink, specifier);
                break;
            }
        }
    }
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

static int vprintf_fd(int fd, const char *format, va_list args)
{
    if (!format)
    {
        return -1;
    }

    printf_sink_t sink = {
        .fd = fd,
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
    if (!format)
    {
        return -1;
    }
    printf_sink_t sink = {
        .fd = -1,
        .buffer = buf,
        .capacity = size,
        .length = 0,
        .error = false,
        .buffer_mode = true,
    };
    printf_format(&sink, format, args);
    printf_sink_finalize_buffer(&sink);
    return (int)sink.length;
}

int printf(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    int result = vprintf_fd(1, format, args);
    va_end(args);
    return result;
}

int vfprintf(FILE *stream, const char *format, va_list args)
{
    if (!stream)
    {
        return -1;
    }
    return vprintf_fd(stream->fd, format, args);
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

void *malloc(size_t size)
{
    user_heap_log("malloc req=", size);
    user_heap_lock_acquire();
    void *ptr = malloc_locked(size);
    user_heap_lock_release();
    user_heap_log("malloc ptr=", (uintptr_t)ptr);
    return ptr;
}

void free(void *ptr)
{
    user_heap_log("free ptr=", (uintptr_t)ptr);
    user_heap_lock_acquire();
    free_locked(ptr);
    user_heap_lock_release();
}

void *realloc(void *ptr, size_t size)
{
    user_heap_log("realloc ptr=", (uintptr_t)ptr);
    user_heap_log("realloc size=", size);
    user_heap_lock_acquire();
    void *res = realloc_locked(ptr, size);
    user_heap_lock_release();
    return res;
}

void *calloc(size_t count, size_t size)
{
    user_heap_log("calloc count=", count);
    user_heap_log("calloc size=", size);
    if (count != 0 && size > SIZE_MAX_VALUE / count)
    {
        return NULL;
    }
    size_t total = count * size;
    user_heap_lock_acquire();
    void *ptr = malloc_locked(total);
    user_heap_lock_release();
    if (!ptr)
    {
        return NULL;
    }
    memset(ptr, 0, total);
    return ptr;
}

static FILE g_stdout_obj = { .fd = 1, .error = 0, .eof = 0 };
static FILE g_stderr_obj = { .fd = 2, .error = 0, .eof = 0 };
static FILE g_stdin_obj = { .fd = 0, .error = 0, .eof = 0 };
FILE *stdout = &g_stdout_obj;
FILE *stderr = &g_stderr_obj;
FILE *stdin = &g_stdin_obj;

static FILE *file_alloc(int fd)
{
    FILE *stream = (FILE *)malloc(sizeof(FILE));
    if (!stream)
    {
        return NULL;
    }
    stream->fd = fd;
    stream->error = 0;
    stream->eof = 0;
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
        return SYSCALL_OPEN_READ;
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
            flags = SYSCALL_OPEN_WRITE | SYSCALL_OPEN_CREATE;
            append = true;
            break;
        default:
            flags = SYSCALL_OPEN_READ;
            break;
    }

    for (const char *c = mode; *c; ++c)
    {
        if (*c == '+')
        {
            plus = true;
        }
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
    int fd = open(path, flags);
    if (fd < 0)
    {
        return NULL;
    }
    if (append)
    {
        (void)lseek(fd, 0, SYSCALL_SEEK_END);
    }

    FILE *stream = file_alloc(fd);
    if (!stream)
    {
        close(fd);
        return NULL;
    }
    return stream;
}

int fclose(FILE *stream)
{
    if (!stream)
    {
        return -1;
    }
    int fd = stream->fd;
    int res = (fd >= 0) ? close(fd) : -1;
    if (stream != stdout && stream != stderr && stream != stdin)
    {
        free(stream);
    }
    return res;
}

size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream)
{
    if (!stream || !ptr || size == 0 || nmemb == 0)
    {
        return 0;
    }
    size_t total = size * nmemb;
    size_t read_bytes = 0;
    uint8_t *dst = (uint8_t *)ptr;
    while (read_bytes < total)
    {
        ssize_t got = read(stream->fd, dst + read_bytes, total - read_bytes);
        if (got <= 0)
        {
            if (got == 0)
            {
                stream->eof = 1;
            }
            else
            {
                stream->error = 1;
            }
            break;
        }
        read_bytes += (size_t)got;
    }
    return read_bytes / size;
}

size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream)
{
    if (!stream || !ptr || size == 0 || nmemb == 0)
    {
        return 0;
    }
    size_t total = size * nmemb;
    size_t written = 0;
    const uint8_t *src = (const uint8_t *)ptr;
    while (written < total)
    {
        ssize_t out = write(stream->fd, src + written, total - written);
        if (out <= 0)
        {
            stream->error = 1;
            break;
        }
        written += (size_t)out;
    }
    return written / size;
}

int fflush(FILE *stream)
{
    (void)stream;
    return 0;
}

int fseek(FILE *stream, long offset, int whence)
{
    if (!stream)
    {
        return -1;
    }
    stream->eof = 0;
    int64_t pos = lseek(stream->fd, offset, whence);
    return (pos < 0) ? -1 : 0;
}

long ftell(FILE *stream)
{
    if (!stream)
    {
        return -1;
    }
    return (long)lseek(stream->fd, 0, SYSCALL_SEEK_CUR);
}

int fputc(int ch, FILE *stream)
{
    unsigned char c = (unsigned char)ch;
    return (fwrite(&c, 1, 1, stream) == 1) ? (int)c : -1;
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

void setbuf(FILE *stream, char *buf)
{
    (void)stream;
    (void)buf;
}

int getchar(void)
{
    unsigned char ch = 0;
    ssize_t got = read(0, &ch, 1);
    if (got == 1)
    {
        return (int)ch;
    }
    return -1;
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

int64_t lseek(int fd, int64_t offset, int whence)
{
    return sys_lseek(fd, offset, whence);
}

int fstat(int fd, struct stat *st)
{
    if (!st)
    {
        return -1;
    }
    syscall_stat_t tmp;
    int res = sys_fstat(fd, &tmp);
    if (res != 0)
    {
        return res;
    }
    st->st_size = tmp.size_bytes;
    st->st_mode = 0;
    st->st_type = tmp.type;
    return 0;
}

ssize_t pread(int fd, void *buffer, size_t count, size_t offset)
{
    return sys_pread(fd, buffer, count, offset);
}

int open(const char *path, uint64_t flags, ...)
{
    uint64_t mode_flags = flags;
    if ((mode_flags & (SYSCALL_OPEN_READ | SYSCALL_OPEN_WRITE)) == 0)
    {
        mode_flags |= SYSCALL_OPEN_READ;
    }
    return sys_open(path, mode_flags);
}

int socket_open(const char *iface_name)
{
    return sys_socket_open(iface_name);
}

int socket_connect(int fd, const char *ipv4_text, uint16_t port)
{
    return sys_socket_connect(fd, ipv4_text, port);
}

void *sbrk(int64_t increment)
{
    return sys_sbrk(increment);
}

int access(const char *path, int mode)
{
    uint64_t flags = 0;
    if (mode & W_OK)
    {
        flags |= SYSCALL_OPEN_WRITE;
    }
    if ((mode & W_OK) == 0 || (mode & R_OK))
    {
        flags |= SYSCALL_OPEN_READ;
    }
    int fd = open(path, flags);
    if (fd < 0)
    {
        return -1;
    }
    close(fd);
    return 0;
}

static bool parse_int(const char **cursor, int base, int *out)
{
    const char *s = *cursor;
    while (*s == ' ' || *s == '\t' || *s == '\n' || *s == '\r')
    {
        ++s;
    }
    int sign = 1;
    if (*s == '+' || *s == '-')
    {
        if (*s == '-')
        {
            sign = -1;
        }
        ++s;
    }
    if (base == 10 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
    {
        base = 16;
        s += 2;
    }
    int value = 0;
    bool any = false;
    while (*s)
    {
        int digit;
        if (*s >= '0' && *s <= '9')
        {
            digit = *s - '0';
        }
        else if (base == 16 && *s >= 'a' && *s <= 'f')
        {
            digit = 10 + (*s - 'a');
        }
        else if (base == 16 && *s >= 'A' && *s <= 'F')
        {
            digit = 10 + (*s - 'A');
        }
        else
        {
            break;
        }
        if (digit >= base)
        {
            break;
        }
        value = value * base + digit;
        any = true;
        ++s;
    }
    if (!any)
    {
        return false;
    }
    *cursor = s;
    if (out)
    {
        *out = value * sign;
    }
    return true;
}

int sscanf(const char *str, const char *fmt, ...)
{
    if (!str || !fmt)
    {
        return 0;
    }
    va_list args;
    va_start(args, fmt);
    int assigned = 0;
    const char *s = str;
    const char *f = fmt;

    while (*f)
    {
        if (*f == '%')
        {
            ++f;
            if (*f == '\0')
            {
                break;
            }
            switch (*f)
            {
                case 'c':
                {
                    int *out = va_arg(args, int *);
                    if (!out || *s == '\0')
                    {
                        goto done;
                    }
                    *out = (unsigned char)*s++;
                    assigned++;
                    ++f;
                    break;
                }
                case 'd':
                case 'i':
                {
                    int *out = va_arg(args, int *);
                    if (!parse_int(&s, 10, out))
                    {
                        goto done;
                    }
                    assigned++;
                    ++f;
                    break;
                }
                case 'x':
                {
                    int *out = va_arg(args, int *);
                    if (!parse_int(&s, 16, out))
                    {
                        goto done;
                    }
                    assigned++;
                    ++f;
                    break;
                }
                default:
                    goto done;
            }
        }
        else if (isspace((unsigned char)*f))
        {
            while (isspace((unsigned char)*f))
            {
                ++f;
            }
            while (isspace((unsigned char)*s))
            {
                ++s;
            }
        }
        else
        {
            if (*f != *s)
            {
                goto done;
            }
            ++f;
            ++s;
        }
    }

done:
    va_end(args);
    return assigned;
}

void exit(int status)
{
    sys_exit(status);
    for (;;)
    {
    }
}
