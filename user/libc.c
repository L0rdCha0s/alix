#include <stdarg.h>

#include "userlib.h"
#include "serial.h"

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

static void user_heap_log(const char *msg, uintptr_t value)
{
    serial_write_string("[uheap] ");
    serial_write_string(msg);
    serial_write_string("0x");
    serial_write_hex64((uint64_t)value);
    serial_write_string("\r\n");
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

static heap_block_t *request_block(size_t size)
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
    block->prev = g_heap_tail;
    block->free = false;

    if (g_heap_tail)
    {
        g_heap_tail->next = block;
    }
    else
    {
        g_heap_head = block;
    }
    g_heap_tail = block;
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

typedef struct
{
    int fd;
    int count;
    bool error;
} printf_sink_t;

static void printf_sink_write(printf_sink_t *sink, const char *data, size_t len)
{
    if (!sink || sink->error || !data || len == 0)
    {
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
        sink->count += (int)result;
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

static int vprintf_internal(const char *format, va_list args)
{
    if (!format)
    {
        return -1;
    }

    printf_sink_t sink = {
        .fd = 1,
        .count = 0,
        .error = false
    };

    printf_format(&sink, format, args);
    if (sink.error)
    {
        return -1;
    }
    return sink.count;
}

int printf(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    int result = vprintf_internal(format, args);
    va_end(args);
    return result;
}

void *malloc(size_t size)
{
    user_heap_log("malloc req=", size);
    size = align_size(size);
    if (size == 0)
    {
        return NULL;
    }

    heap_block_t *block = find_free_block(size);
    if (!block)
    {
        block = request_block(size);
        if (!block)
        {
            return NULL;
        }
    }
    else
    {
        block->free = false;
        split_block(block, size);
    }

    void *ptr = (uint8_t *)block + sizeof(heap_block_t);
    user_heap_log("malloc ptr=", (uintptr_t)ptr);
    return ptr;
}

void free(void *ptr)
{
    user_heap_log("free ptr=", (uintptr_t)ptr);
    heap_block_t *block = payload_to_block(ptr);
    if (!block || block->free)
    {
        user_heap_log("free ignored ptr=", (uintptr_t)ptr);
        return;
    }

    block->free = true;
    coalesce(block);
}

void *realloc(void *ptr, size_t size)
{
    user_heap_log("realloc ptr=", (uintptr_t)ptr);
    user_heap_log("realloc size=", size);
    if (!ptr)
    {
        return malloc(size);
    }
    if (size == 0)
    {
        free(ptr);
        return NULL;
    }

    heap_block_t *block = payload_to_block(ptr);
    if (!block)
    {
        user_heap_log("realloc invalid block ptr=", (uintptr_t)ptr);
        return NULL;
    }

    size = align_size(size);
    if (size <= block->size)
    {
        split_block(block, size);
        return ptr;
    }

    void *new_ptr = malloc(size);
    if (!new_ptr)
    {
        user_heap_log("realloc malloc fail size=", size);
        user_heap_log("realloc malloc fail old_size=", block->size);
        user_heap_log("realloc malloc fail block=", (uintptr_t)block);
        return NULL;
    }
    memcpy(new_ptr, ptr, block->size);
    free(ptr);
    return new_ptr;
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
    void *ptr = malloc(total);
    if (!ptr)
    {
        return NULL;
    }
    memset(ptr, 0, total);
    return ptr;
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

int open(const char *path, uint64_t flags)
{
    uint64_t mode_flags = flags;
    if ((mode_flags & (SYSCALL_OPEN_READ | SYSCALL_OPEN_WRITE)) == 0)
    {
        mode_flags |= SYSCALL_OPEN_READ;
    }
    return sys_open(path, mode_flags);
}

void *sbrk(int64_t increment)
{
    return sys_sbrk(increment);
}

void exit(int status)
{
    sys_exit(status);
    for (;;)
    {
    }
}
