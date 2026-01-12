#include "web/js/internal.h"

#include "libc.h"

typedef struct
{
    uint32_t magic;
    uint16_t class_index;
    uint16_t reserved;
    size_t size;
} js_alloc_header_t;

typedef struct js_pool_block
{
    struct js_pool_block *next;
    size_t capacity;
    unsigned char data[];
} js_pool_block_t;

typedef struct js_pool_free
{
    struct js_pool_free *next;
} js_pool_free_t;

typedef struct
{
    size_t payload_size;
    size_t chunk_size;
    js_pool_free_t *free_list;
    js_pool_block_t *blocks;
} js_pool_class_t;

enum
{
    JS_POOL_CLASS_COUNT = 8,
    JS_POOL_BLOCK_SIZE = 8192,
    JS_ALLOC_MAGIC = 0x4A53414Cu
};

#define JS_ALLOC_ALIGN (sizeof(void *))
#define JS_ALLOC_HEADER_SIZE ((sizeof(js_alloc_header_t) + JS_ALLOC_ALIGN - 1u) & ~(JS_ALLOC_ALIGN - 1u))

static js_pool_class_t js_pool_classes[JS_POOL_CLASS_COUNT];
static const size_t js_pool_sizes[JS_POOL_CLASS_COUNT] = {16u, 32u, 64u, 128u, 256u, 512u, 1024u, 2048u};
static int js_pool_ready = 0;
static int js_pool_lock = 0;

static void js_pool_lock_acquire(void)
{
    while (__atomic_test_and_set(&js_pool_lock, __ATOMIC_ACQUIRE))
    {
    }
}

static void js_pool_lock_release(void)
{
    __atomic_clear(&js_pool_lock, __ATOMIC_RELEASE);
}

static void js_pool_init(void)
{
    if (js_pool_ready)
    {
        return;
    }
    for (size_t i = 0; i < JS_POOL_CLASS_COUNT; ++i)
    {
        size_t payload = js_pool_sizes[i];
        payload = (payload + JS_ALLOC_ALIGN - 1u) & ~(JS_ALLOC_ALIGN - 1u);
        js_pool_classes[i].payload_size = payload;
        js_pool_classes[i].chunk_size = JS_ALLOC_HEADER_SIZE + payload;
        js_pool_classes[i].free_list = NULL;
        js_pool_classes[i].blocks = NULL;
    }
    js_pool_ready = 1;
}

static size_t js_pool_class_for(size_t size)
{
    for (size_t i = 0; i < JS_POOL_CLASS_COUNT; ++i)
    {
        if (size <= js_pool_classes[i].payload_size)
        {
            return i;
        }
    }
    return JS_POOL_CLASS_COUNT;
}

static bool js_pool_grow_class(size_t idx)
{
    js_pool_class_t *cls = &js_pool_classes[idx];
    size_t chunk_size = cls->chunk_size;
    size_t chunk_count = JS_POOL_BLOCK_SIZE / chunk_size;
    if (chunk_count == 0)
    {
        chunk_count = 1;
    }
    size_t bytes = sizeof(*cls->blocks) + (chunk_count * chunk_size);
    js_pool_block_t *block = (js_pool_block_t *)malloc(bytes);
    if (!block)
    {
        return false;
    }
    block->next = cls->blocks;
    block->capacity = chunk_count * chunk_size;
    cls->blocks = block;

    unsigned char *cursor = block->data;
    for (size_t i = 0; i < chunk_count; ++i)
    {
        js_alloc_header_t *hdr = (js_alloc_header_t *)cursor;
        hdr->magic = JS_ALLOC_MAGIC;
        hdr->class_index = (uint16_t)idx;
        hdr->reserved = 0;
        hdr->size = cls->payload_size;
        js_pool_free_t *node = (js_pool_free_t *)(cursor + JS_ALLOC_HEADER_SIZE);
        node->next = cls->free_list;
        cls->free_list = node;
        cursor += chunk_size;
    }
    return true;
}

void *js_malloc(size_t size)
{
    if (size == 0)
    {
        size = 1;
    }
    js_pool_init();
    size_t idx = js_pool_class_for(size);
    if (idx >= JS_POOL_CLASS_COUNT)
    {
        size_t bytes = JS_ALLOC_HEADER_SIZE + size;
        js_alloc_header_t *hdr = (js_alloc_header_t *)malloc(bytes);
        if (!hdr)
        {
            return NULL;
        }
        hdr->magic = JS_ALLOC_MAGIC;
        hdr->class_index = (uint16_t)JS_POOL_CLASS_COUNT;
        hdr->reserved = 0;
        hdr->size = size;
        return (unsigned char *)hdr + JS_ALLOC_HEADER_SIZE;
    }

    js_pool_lock_acquire();
    js_pool_class_t *cls = &js_pool_classes[idx];
    if (!cls->free_list)
    {
        if (!js_pool_grow_class(idx))
        {
            js_pool_lock_release();
            return NULL;
        }
    }
    js_pool_free_t *node = cls->free_list;
    cls->free_list = node->next;
    js_pool_lock_release();

    js_alloc_header_t *hdr = (js_alloc_header_t *)((unsigned char *)node - JS_ALLOC_HEADER_SIZE);
    hdr->magic = JS_ALLOC_MAGIC;
    hdr->class_index = (uint16_t)idx;
    hdr->reserved = 0;
    hdr->size = size;
    return node;
}

void *js_calloc(size_t count, size_t size)
{
    size_t total = 0;
    if (__builtin_mul_overflow(count, size, &total))
    {
        return NULL;
    }
    void *ptr = js_malloc(total);
    if (!ptr)
    {
        return NULL;
    }
    memset(ptr, 0, total);
    return ptr;
}

void *js_realloc(void *ptr, size_t size)
{
    if (!ptr)
    {
        return js_malloc(size);
    }
    if (size == 0)
    {
        js_free(ptr);
        return NULL;
    }
    js_alloc_header_t *hdr = (js_alloc_header_t *)((unsigned char *)ptr - JS_ALLOC_HEADER_SIZE);
    size_t old_size = hdr->size;
    size_t idx = hdr->class_index;
    if (idx < JS_POOL_CLASS_COUNT)
    {
        if (size <= js_pool_classes[idx].payload_size)
        {
            hdr->size = size;
            return ptr;
        }
        void *next = js_malloc(size);
        if (!next)
        {
            return NULL;
        }
        memcpy(next, ptr, (old_size < size) ? old_size : size);
        js_free(ptr);
        return next;
    }

    size_t bytes = JS_ALLOC_HEADER_SIZE + size;
    js_alloc_header_t *next_hdr = (js_alloc_header_t *)realloc(hdr, bytes);
    if (!next_hdr)
    {
        return NULL;
    }
    next_hdr->magic = JS_ALLOC_MAGIC;
    next_hdr->class_index = (uint16_t)JS_POOL_CLASS_COUNT;
    next_hdr->reserved = 0;
    next_hdr->size = size;
    return (unsigned char *)next_hdr + JS_ALLOC_HEADER_SIZE;
}

void js_free(void *ptr)
{
    if (!ptr)
    {
        return;
    }
    js_alloc_header_t *hdr = (js_alloc_header_t *)((unsigned char *)ptr - JS_ALLOC_HEADER_SIZE);
    if (hdr->magic != JS_ALLOC_MAGIC)
    {
        free(ptr);
        return;
    }
    size_t idx = hdr->class_index;
    if (idx < JS_POOL_CLASS_COUNT)
    {
        js_pool_lock_acquire();
        js_pool_free_t *node = (js_pool_free_t *)ptr;
        node->next = js_pool_classes[idx].free_list;
        js_pool_classes[idx].free_list = node;
        js_pool_lock_release();
        return;
    }
    free(hdr);
}

typedef struct js_arena_block
{
    struct js_arena_block *next;
    size_t used;
    size_t capacity;
    unsigned char data[];
} js_arena_block_t;

enum
{
    JS_ARENA_BLOCK_SIZE = 32768
};

void js_arena_init(js_arena_t *arena)
{
    if (!arena)
    {
        return;
    }
    arena->blocks = NULL;
}

void *js_arena_alloc(js_arena_t *arena, size_t size)
{
    if (!arena || size == 0)
    {
        return NULL;
    }
    size_t align = sizeof(void *);
    size_t padded = (size + align - 1u) & ~(align - 1u);

    js_arena_block_t *block = arena->blocks;
    if (!block || block->capacity - block->used < padded)
    {
        size_t capacity = JS_ARENA_BLOCK_SIZE;
        if (padded > capacity)
        {
            capacity = padded;
        }
        js_arena_block_t *next = (js_arena_block_t *)malloc(sizeof(*next) + capacity);
        if (!next)
        {
            return NULL;
        }
        next->next = arena->blocks;
        next->used = 0;
        next->capacity = capacity;
        arena->blocks = next;
        block = next;
    }

    void *ptr = block->data + block->used;
    block->used += padded;
    memset(ptr, 0, size);
    return ptr;
}

char *js_arena_strdup_len(js_arena_t *arena, const char *src, size_t len)
{
    if (!arena)
    {
        return NULL;
    }
    char *out = (char *)js_arena_alloc(arena, len + 1);
    if (!out)
    {
        return NULL;
    }
    if (len && src)
    {
        memcpy(out, src, len);
    }
    out[len] = '\0';
    return out;
}

void js_arena_release(js_arena_t *arena)
{
    if (!arena)
    {
        return;
    }
    js_arena_block_t *block = arena->blocks;
    while (block)
    {
        js_arena_block_t *next = block->next;
        free(block);
        block = next;
    }
    arena->blocks = NULL;
}

void js_parse_error_set(js_parse_error_t *err, size_t offset, const char *message)
{
    if (!err || err->message)
    {
        return;
    }
    err->offset = offset;
    err->message = message;
}

char *js_strdup_len(const char *src, size_t len)
{
    char *out = (char *)js_malloc(len + 1);
    if (!out)
    {
        return NULL;
    }
    if (len)
    {
        memcpy(out, src, len);
    }
    out[len] = '\0';
    return out;
}

char *js_strdup(const char *src)
{
    if (!src)
    {
        return NULL;
    }
    return js_strdup_len(src, strlen(src));
}

int js_hex_value(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
}
