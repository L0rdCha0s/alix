#ifndef WEB_COMMON_BLOOM_H
#define WEB_COMMON_BLOOM_H

#include "types.h"

#define WEB_BLOOM_WORDS 4

typedef struct
{
    uint64_t bits[WEB_BLOOM_WORDS];
} web_bloom_t;

#endif /* WEB_COMMON_BLOOM_H */
