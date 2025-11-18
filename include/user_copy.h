#ifndef USER_COPY_H
#define USER_COPY_H

#include "types.h"

/* User binaries are loaded low (link.ld bases at 0x400000). */
#define USER_POINTER_BASE  0x0000000000400000ULL
/* User virtual space lives in the low 4 GiB; block anything above that. */
#define USER_POINTER_LIMIT 0x00000000FFFFFFFFULL

bool user_ptr_range_valid(const void *ptr, size_t len);
bool user_copy_from_user(void *dst, const void *src_user, size_t len);
bool user_copy_to_user(void *dst_user, const void *src, size_t len);
bool user_copy_string_from_user(char *dst,
                                size_t capacity,
                                const char *src_user,
                                size_t *out_len);

#endif /* USER_COPY_H */
