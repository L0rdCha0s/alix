#ifndef USER_COPY_H
#define USER_COPY_H

#include "types.h"
#include "memory_layout.h"

#define USER_POINTER_BASE  (g_mem_layout.user_pointer_base)
#define USER_POINTER_LIMIT (g_mem_layout.user_pointer_limit)

bool user_ptr_range_valid(const void *ptr, size_t len);
bool user_copy_from_user(void *dst, const void *src_user, size_t len);
bool user_copy_to_user(void *dst_user, const void *src, size_t len);
bool user_copy_string_from_user(char *dst,
                                size_t capacity,
                                const char *src_user,
                                size_t *out_len);

#endif /* USER_COPY_H */
