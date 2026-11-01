#ifndef ALIX_SYS_UIO_H
#define ALIX_SYS_UIO_H
#ifdef TTF_HOST_BUILD
#include_next <sys/uio.h>
#else
#include "sys/types.h"
struct iovec { void *iov_base; size_t iov_len; };
#define IOV_MAX 1024
#ifdef __cplusplus
extern "C" {
#endif
ssize_t readv(int descriptor, const struct iovec *vectors, int count);
ssize_t writev(int descriptor, const struct iovec *vectors, int count);
#ifdef __cplusplus
}
#endif
#endif
#endif
