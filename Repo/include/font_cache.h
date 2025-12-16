#ifndef FONT_CACHE_H
#define FONT_CACHE_H

#include "types.h"

ssize_t font_cache_copy_to_user(void *user_dst, size_t capacity);
size_t font_cache_size(void);

#endif
