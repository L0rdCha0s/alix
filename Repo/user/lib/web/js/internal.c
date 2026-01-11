#include "web/js/internal.h"

#include "libc.h"

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
    char *out = (char *)malloc(len + 1);
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
