#ifndef ALIX_SYS_RANDOM_H
#define ALIX_SYS_RANDOM_H

#include <types.h>

#define GRND_NONBLOCK 1u

#ifdef __cplusplus
extern "C" {
#endif

/* Short reads are permitted; each native request returns at most 256 bytes.
 * Flags other than GRND_NONBLOCK are unsupported and fail with EINVAL. */
__attribute__((visibility("default"))) ssize_t getrandom(void *buffer, size_t length, unsigned int flags);
/* Fill at most 256 bytes, returning 0 on success or -1 with errno set. */
__attribute__((visibility("default"))) int getentropy(void *buffer, size_t length);

#ifdef __cplusplus
}
#endif
#endif
