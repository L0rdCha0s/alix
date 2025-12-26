#include <stdarg.h>

#include "userlib.h"
#include "serial.h"
#include "stdio.h"
#include "errno.h"
#include "unistd.h"

int errno = 0;

#define ALIGNMENT 16UL
#define SIZE_MAX_VALUE ((size_t)-1)
#define LIBC_MAX_PASSWD_BYTES (64u * 1024u)

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
    serial_printf("[uheap] %s0x%016llX\n",
                  msg ? msg : "",
                  (unsigned long long)((uint64_t)value));
}
#else
static void user_heap_log(const char *msg, uintptr_t value)
{
    (void)msg;
    (void)value;
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
    uintptr_t high = user_heap_current_brk();
    if (low == 0 || high == 0)
    {
        return true;
    }
    return addr >= low && addr < high;
}

static void user_heap_log_corruption(const char *where,
                                     const heap_block_t *block,
                                     size_t request_size,
                                     const heap_block_t *new_block,
                                     const heap_block_t *suspect)
{
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

double atof(const char *str)
{
    if (!str)
    {
        return 0.0;
    }

    const char *s = str;
    while (isspace((unsigned char)*s))
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

    double value = 0.0;
    while (isdigit((unsigned char)*s))
    {
        value = value * 10.0 + (double)(*s - '0');
        ++s;
    }

    if (*s == '.')
    {
        ++s;
        double place = 0.1;
        while (isdigit((unsigned char)*s))
        {
            value += (double)(*s - '0') * place;
            place *= 0.1;
            ++s;
        }
    }

    if (*s == 'e' || *s == 'E')
    {
        ++s;
        int exp_sign = 1;
        if (*s == '+' || *s == '-')
        {
            if (*s == '-')
            {
                exp_sign = -1;
            }
            ++s;
        }
        int exp = 0;
        while (isdigit((unsigned char)*s))
        {
            exp = exp * 10 + (*s - '0');
            ++s;
        }
        exp *= exp_sign;

        double pow10 = 1.0;
        int e = exp < 0 ? -exp : exp;
        double base = 10.0;
        while (e)
        {
            if (e & 1)
            {
                pow10 *= base;
            }
            base *= base;
            e >>= 1;
        }

        if (exp < 0)
        {
            value /= pow10;
        }
        else
        {
            value *= pow10;
        }
    }

    return value * (double)sign;
}

static uint32_t g_rand_state = 1u;

void srand(unsigned int seed)
{
    g_rand_state = seed ? (uint32_t)seed : 1u;
}

int rand(void)
{
    /* ANSI C compatible LCG; returns 0..32767. */
    g_rand_state = g_rand_state * 1103515245u + 12345u;
    return (int)((g_rand_state >> 16) & 0x7FFFu);
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

    int fd = open(path, SYSCALL_OPEN_READ);
    if (fd < 0)
    {
        return NULL;
    }

    struct stat st;
    if (fstat(fd, &st) != 0)
    {
        close(fd);
        return NULL;
    }

    if (st.st_size == 0 || st.st_size > (uint64_t)max_bytes)
    {
        close(fd);
        return NULL;
    }

    size_t size = (size_t)st.st_size;
    char *buf = (char *)malloc(size + 1);
    if (!buf)
    {
        close(fd);
        return NULL;
    }

    size_t offset = 0;
    while (offset < size)
    {
        ssize_t got = read(fd, buf + offset, size - offset);
        if (got <= 0)
        {
            free(buf);
            close(fd);
            return NULL;
        }
        offset += (size_t)got;
    }
    buf[size] = '\0';
    close(fd);

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

int mkdir(const char *path, uint32_t mode)
{
    (void)mode;
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

static void printf_sink_pad(printf_sink_t *sink, char ch, int count)
{
    while (count-- > 0)
    {
        printf_sink_putc(sink, ch);
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
                                             size_t prefix_len)
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
                                            int precision)
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
                                     prefix_len);
}

static size_t printf_uint_to_buffer(char *buffer, size_t capacity, uint64_t value)
{
    if (!buffer || capacity == 0)
    {
        return 0;
    }

    size_t len = 0;
    do
    {
        if (len + 1 >= capacity)
        {
            break;
        }
        buffer[len++] = (char)('0' + (value % 10));
        value /= 10;
    } while (value != 0);

    for (size_t i = 0; i < len / 2; ++i)
    {
        char tmp = buffer[i];
        buffer[i] = buffer[len - 1 - i];
        buffer[len - 1 - i] = tmp;
    }
    buffer[len] = '\0';
    return len;
}

static void printf_sink_print_literal(printf_sink_t *sink,
                                      const char *prefix,
                                      size_t prefix_len,
                                      const char *text,
                                      size_t text_len,
                                      int width,
                                      bool left_align)
{
    size_t total = prefix_len + text_len;
    int pad = 0;
    if (width > (int)total)
    {
        pad = width - (int)total;
    }

    if (!left_align)
    {
        printf_sink_pad(sink, ' ', pad);
    }
    if (prefix_len)
    {
        printf_sink_write(sink, prefix, prefix_len);
    }
    if (text_len)
    {
        printf_sink_write(sink, text, text_len);
    }
    if (left_align)
    {
        printf_sink_pad(sink, ' ', pad);
    }
}

static void printf_sink_print_float_formatted(printf_sink_t *sink,
                                              double value,
                                              int width,
                                              bool left_align,
                                              bool zero_pad,
                                              bool has_precision,
                                              int precision,
                                              bool uppercase)
{
    if (!sink)
    {
        return;
    }

    if (value != value)
    {
        const char *nan_text = uppercase ? "NAN" : "nan";
        printf_sink_print_literal(sink, "", 0, nan_text, 3, width, left_align);
        return;
    }
    if (value > 1.0e308 || value < -1.0e308)
    {
        bool negative = (value < 0.0);
        const char *prefix = negative ? "-" : "";
        size_t prefix_len = negative ? 1 : 0;
        const char *inf_text = uppercase ? "INF" : "inf";
        printf_sink_print_literal(sink, prefix, prefix_len, inf_text, 3, width, left_align);
        return;
    }

    bool negative = (value < 0.0);
    if (value == 0.0 && (1.0 / value) < 0.0)
    {
        negative = true;
    }
    double abs_value = negative ? -value : value;

    int prec = has_precision ? precision : 6;
    if (prec < 0)
    {
        prec = 0;
    }
    if (prec > 9)
    {
        prec = 9;
    }

    uint64_t pow10 = 1;
    for (int i = 0; i < prec; ++i)
    {
        pow10 *= 10;
    }

    uint64_t int_part = 0;
    uint64_t frac_part = 0;
    if (prec == 0)
    {
        int_part = (uint64_t)(abs_value + 0.5);
    }
    else
    {
        double scaled = abs_value * (double)pow10 + 0.5;
        uint64_t rounded = (uint64_t)scaled;
        int_part = rounded / pow10;
        frac_part = rounded % pow10;
    }

    char int_buf[32];
    size_t int_len = printf_uint_to_buffer(int_buf, sizeof(int_buf), int_part);

    char frac_buf[32];
    size_t frac_len = 0;
    if (prec > 0)
    {
        frac_len = (size_t)prec;
        for (size_t i = 0; i < frac_len; ++i)
        {
            frac_buf[frac_len - 1 - i] = (char)('0' + (frac_part % 10));
            frac_part /= 10;
        }
    }

    size_t digits_len = int_len + ((prec > 0) ? (1 + frac_len) : 0);
    const char *prefix = negative ? "-" : "";
    size_t prefix_len = negative ? 1 : 0;
    int pad = 0;
    if (width > (int)(prefix_len + digits_len))
    {
        pad = width - (int)(prefix_len + digits_len);
    }

    if (!left_align)
    {
        if (zero_pad)
        {
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
    else if (prefix_len)
    {
        printf_sink_write(sink, prefix, prefix_len);
    }

    printf_sink_write(sink, int_buf, int_len);
    if (prec > 0)
    {
        printf_sink_putc(sink, '.');
        printf_sink_write(sink, frac_buf, frac_len);
    }

    if (left_align)
    {
        printf_sink_pad(sink, ' ', pad);
    }
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

        bool left_align = false;
        bool zero_pad = false;
        while (*format == '-' || *format == '0')
        {
            if (*format == '-')
            {
                left_align = true;
                ++format;
                continue;
            }
            if (*format == '0')
            {
                zero_pad = true;
                ++format;
                continue;
            }
        }

        int width = 0;
        if (*format == '*')
        {
            width = va_arg(args, int);
            if (width < 0)
            {
                left_align = true;
                width = -width;
            }
            ++format;
        }
        while (*format >= '0' && *format <= '9')
        {
            width = width * 10 + (*format - '0');
            ++format;
        }

        bool has_precision = false;
        int precision = 0;
        if (*format == '.')
        {
            has_precision = true;
            ++format;
            if (*format == '*')
            {
                precision = va_arg(args, int);
                ++format;
            }
            else
            {
                precision = 0;
                while (*format >= '0' && *format <= '9')
                {
                    precision = precision * 10 + (*format - '0');
                    ++format;
                }
            }
        }

        enum
        {
            LENGTH_NONE,
            LENGTH_Z,
            LENGTH_L,
            LENGTH_LL,
        } length = LENGTH_NONE;

        if (*format == 'z')
        {
            length = LENGTH_Z;
            ++format;
        }
        else if (*format == 'l')
        {
            ++format;
            if (*format == 'l')
            {
                length = LENGTH_LL;
                ++format;
            }
            else
            {
                length = LENGTH_L;
            }
        }

        char specifier = *format ? *format++ : '\0';
        switch (specifier)
        {
            case 'c':
            {
                char value = (char)va_arg(args, int);
                if (!left_align && width > 1)
                {
                    printf_sink_pad(sink, ' ', width - 1);
                }
                printf_sink_putc(sink, value);
                if (left_align && width > 1)
                {
                    printf_sink_pad(sink, ' ', width - 1);
                }
                break;
            }
            case 's':
            {
                const char *text = va_arg(args, const char *);
                if (!text)
                {
                    text = "(null)";
                }
                size_t len = strlen(text);
                if (has_precision && precision >= 0 && (size_t)precision < len)
                {
                    len = (size_t)precision;
                }
                int pad = 0;
                if (width > 0 && (size_t)width > len)
                {
                    pad = width - (int)len;
                }
                if (!left_align)
                {
                    printf_sink_pad(sink, ' ', pad);
                }
                printf_sink_write(sink, text, len);
                if (left_align)
                {
                    printf_sink_pad(sink, ' ', pad);
                }
                break;
            }
            case 'd':
            case 'i':
            {
                int64_t value;
                if (length == LENGTH_Z)
                {
                    value = (int64_t)va_arg(args, ssize_t);
                }
                else if (length == LENGTH_LL)
                {
                    value = (int64_t)va_arg(args, long long);
                }
                else if (length == LENGTH_L)
                {
                    value = (int64_t)va_arg(args, long);
                }
                else
                {
                    value = (int64_t)va_arg(args, int);
                }
                printf_sink_print_int_formatted(sink,
                                               value,
                                               width,
                                               left_align,
                                               zero_pad,
                                               has_precision,
                                               precision);
                break;
            }
            case 'u':
            {
                uint64_t value;
                if (length == LENGTH_Z)
                {
                    value = (uint64_t)va_arg(args, size_t);
                }
                else if (length == LENGTH_LL)
                {
                    value = (uint64_t)va_arg(args, unsigned long long);
                }
                else if (length == LENGTH_L)
                {
                    value = (uint64_t)va_arg(args, unsigned long);
                }
                else
                {
                    value = (uint64_t)va_arg(args, unsigned int);
                }
                printf_sink_print_uint_formatted(sink,
                                                 value,
                                                 10,
                                                 false,
                                                 width,
                                                 left_align,
                                                 zero_pad,
                                                 has_precision,
                                                 precision,
                                                 "",
                                                 0);
                break;
            }
            case 'x':
            {
                uint64_t value;
                if (length == LENGTH_Z)
                {
                    value = (uint64_t)va_arg(args, size_t);
                }
                else if (length == LENGTH_LL)
                {
                    value = (uint64_t)va_arg(args, unsigned long long);
                }
                else if (length == LENGTH_L)
                {
                    value = (uint64_t)va_arg(args, unsigned long);
                }
                else
                {
                    value = (uint64_t)va_arg(args, unsigned int);
                }
                printf_sink_print_uint_formatted(sink,
                                                 value,
                                                 16,
                                                 false,
                                                 width,
                                                 left_align,
                                                 zero_pad,
                                                 has_precision,
                                                 precision,
                                                 "",
                                                 0);
                break;
            }
            case 'X':
            {
                uint64_t value;
                if (length == LENGTH_Z)
                {
                    value = (uint64_t)va_arg(args, size_t);
                }
                else if (length == LENGTH_LL)
                {
                    value = (uint64_t)va_arg(args, unsigned long long);
                }
                else if (length == LENGTH_L)
                {
                    value = (uint64_t)va_arg(args, unsigned long);
                }
                else
                {
                    value = (uint64_t)va_arg(args, unsigned int);
                }
                printf_sink_print_uint_formatted(sink,
                                                 value,
                                                 16,
                                                 true,
                                                 width,
                                                 left_align,
                                                 zero_pad,
                                                 has_precision,
                                                 precision,
                                                 "",
                                                 0);
                break;
            }
            case 'p':
            {
                uintptr_t ptr = (uintptr_t)va_arg(args, void *);
                printf_sink_print_uint_formatted(sink,
                                                 (uint64_t)ptr,
                                                 16,
                                                 false,
                                                 width,
                                                 left_align,
                                                 zero_pad,
                                                 false,
                                                 0,
                                                 "0x",
                                                 2);
                break;
            }
            case 'f':
            case 'F':
            {
                double value = va_arg(args, double);
                printf_sink_print_float_formatted(sink,
                                                  value,
                                                  width,
                                                  left_align,
                                                  zero_pad,
                                                  has_precision,
                                                  precision,
                                                  specifier == 'F');
                break;
            }
            case '\0':
            {
                printf_sink_putc(sink, '%');
                if (length == LENGTH_Z)
                {
                    printf_sink_putc(sink, 'z');
                }
                if (length == LENGTH_L)
                {
                    printf_sink_putc(sink, 'l');
                }
                if (length == LENGTH_LL)
                {
                    printf_sink_putc(sink, 'l');
                    printf_sink_putc(sink, 'l');
                }
                return;
            }
            default:
            {
                printf_sink_putc(sink, '%');
                if (length == LENGTH_Z)
                {
                    printf_sink_putc(sink, 'z');
                }
                if (length == LENGTH_L)
                {
                    printf_sink_putc(sink, 'l');
                }
                if (length == LENGTH_LL)
                {
                    printf_sink_putc(sink, 'l');
                    printf_sink_putc(sink, 'l');
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

int fgetc(FILE *stream)
{
    unsigned char ch = 0;
    size_t got = fread(&ch, 1, 1, stream);
    if (got == 1)
    {
        return (int)ch;
    }
    return EOF;
}

int getc(FILE *stream)
{
    return fgetc(stream);
}

char *fgets(char *s, int size, FILE *stream)
{
    if (!s || size <= 0 || !stream)
    {
        return NULL;
    }
    s[0] = '\0';

    int idx = 0;
    while (idx < size - 1)
    {
        int ch = fgetc(stream);
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

    if (idx == 0)
    {
        return NULL;
    }
    s[idx] = '\0';
    return s;
}

int feof(FILE *stream)
{
    if (!stream)
    {
        return 1;
    }
    return stream->eof != 0;
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

int unlink(const char *path)
{
    (void)path;
    errno = ENOSYS;
    return -1;
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

ssize_t socket_available(int fd)
{
    return sys_socket_available(fd);
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

static bool fscanf_read_token(FILE *stream, char *buf, size_t cap)
{
    if (!stream || !buf || cap == 0)
    {
        return false;
    }

    size_t out_len = 0;
    buf[0] = '\0';

    int ch = fgetc(stream);
    while (ch != EOF && isspace((unsigned char)ch))
    {
        ch = fgetc(stream);
    }
    if (ch == EOF)
    {
        return false;
    }

    while (ch != EOF && !isspace((unsigned char)ch))
    {
        if (out_len + 1 < cap)
        {
            buf[out_len++] = (char)ch;
        }
        ch = fgetc(stream);
    }

    buf[out_len] = '\0';
    return out_len > 0;
}

static double fscanf_parse_double(const char *text)
{
    if (!text)
    {
        return 0.0;
    }

    const char *s = text;
    while (isspace((unsigned char)*s))
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

    double value = 0.0;
    while (isdigit((unsigned char)*s))
    {
        value = value * 10.0 + (double)(*s - '0');
        ++s;
    }

    if (*s == '.')
    {
        ++s;
        double place = 0.1;
        while (isdigit((unsigned char)*s))
        {
            value += (double)(*s - '0') * place;
            place *= 0.1;
            ++s;
        }
    }

    if (*s == 'e' || *s == 'E')
    {
        ++s;
        int exp_sign = 1;
        if (*s == '+' || *s == '-')
        {
            if (*s == '-')
            {
                exp_sign = -1;
            }
            ++s;
        }
        int exp = 0;
        while (isdigit((unsigned char)*s))
        {
            exp = exp * 10 + (*s - '0');
            ++s;
        }
        exp *= exp_sign;

        double pow10 = 1.0;
        int e = exp < 0 ? -exp : exp;
        double base = 10.0;
        while (e)
        {
            if (e & 1)
            {
                pow10 *= base;
            }
            base *= base;
            e >>= 1;
        }

        if (exp < 0)
        {
            value /= pow10;
        }
        else
        {
            value *= pow10;
        }
    }

    return value * (double)sign;
}

int fscanf(FILE *stream, const char *fmt, ...)
{
    if (!stream || !fmt)
    {
        return 0;
    }

    va_list args;
    va_start(args, fmt);
    int assigned = 0;

    const char *f = fmt;
    while (*f)
    {
        if (isspace((unsigned char)*f))
        {
            ++f;
            continue;
        }

        if (*f != '%')
        {
            int ch = fgetc(stream);
            if (ch == EOF)
            {
                break;
            }
            ++f;
            continue;
        }

        ++f;
        int width = 0;
        while (isdigit((unsigned char)*f))
        {
            width = width * 10 + (*f - '0');
            ++f;
        }

        char spec = *f ? *f : '\0';
        if (!spec)
        {
            break;
        }

        if (spec == 'i' || spec == 'd')
        {
            int *out = va_arg(args, int *);
            char tok[64];
            if (!out || !fscanf_read_token(stream, tok, sizeof(tok)))
            {
                break;
            }
            *out = atoi(tok);
            assigned++;
        }
        else if (spec == 'f')
        {
            float *out = va_arg(args, float *);
            char tok[128];
            if (!out || !fscanf_read_token(stream, tok, sizeof(tok)))
            {
                break;
            }
            *out = (float)fscanf_parse_double(tok);
            assigned++;
        }
        else if (spec == 's')
        {
            char *out = va_arg(args, char *);
            if (!out)
            {
                break;
            }
            if (width <= 0)
            {
                width = 63;
            }
            if (!fscanf_read_token(stream, out, (size_t)width + 1))
            {
                break;
            }
            assigned++;
        }
        else
        {
            break;
        }

        ++f;
    }

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

    uint32_t spins = 0;
    while (__sync_lock_test_and_set(&mutex->state, 1) != 0)
    {
        while (__atomic_load_n(&mutex->state, __ATOMIC_RELAXED))
        {
            __asm__ volatile ("pause");
            if (((++spins) & 0xFFu) == 0)
            {
                (void)sys_yield();
            }
        }
    }
}

void alix_mutex_unlock(alix_mutex_t *mutex)
{
    if (!mutex)
    {
        return;
    }
    __sync_lock_release(&mutex->state);
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
    sys_thread_exit(status);
    for (;;)
    {
    }
}
