#ifndef WEB_JS_INTERNAL_H
#define WEB_JS_INTERNAL_H

#include "web/js.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct js_arena_block js_arena_block_t;

typedef struct
{
    js_arena_block_t *blocks;
} js_arena_t;

void js_arena_init(js_arena_t *arena);
void *js_arena_alloc(js_arena_t *arena, size_t size);
char *js_arena_strdup_len(js_arena_t *arena, const char *src, size_t len);
void js_arena_release(js_arena_t *arena);

void *js_malloc(size_t size);
void *js_calloc(size_t count, size_t size);
void *js_realloc(void *ptr, size_t size);
void js_free(void *ptr);

void js_parse_error_set(js_parse_error_t *err, size_t offset, const char *message);
char *js_strdup_len(const char *src, size_t len);
char *js_strdup(const char *src);
int js_hex_value(char c);

#define JS_EVAL_NUL_SENTINEL 0xC0

#ifdef __cplusplus
}
#endif

#endif /* WEB_JS_INTERNAL_H */
