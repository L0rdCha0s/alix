#ifndef SYS_TYPES_H
#define SYS_TYPES_H

#ifdef TTF_HOST_BUILD
#include_next <sys/types.h>
#else
#include <stdint.h>
#include "types.h"

typedef int64_t off_t;

#endif
#endif /* SYS_TYPES_H */
