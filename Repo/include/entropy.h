#ifndef ALIX_ENTROPY_H
#define ALIX_ENTROPY_H

#include "types.h"

#define ENTROPY_MAX_BYTES 256u
#define ENTROPY_NONBLOCK 1u

/* Return up to ENTROPY_MAX_BYTES, or a negative errno. The caller supplies a
 * user address; generation and permission-checked copyout happen in kernel. */
ssize_t syscall_do_getrandom(void *user_buffer, size_t length, uint32_t flags);
/* Bounded generation into caller-owned kernel storage; no user address or
 * borrowed stack is retained. Failed generation wipes the requested prefix. */
ssize_t entropy_read_kernel(void *buffer, size_t length, uint32_t flags);

#endif
