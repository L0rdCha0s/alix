#ifndef ALIX_STDIO_INTERNAL_H
#define ALIX_STDIO_INTERNAL_H

#include "stdio.h"

/* Caller owns stream->mutex for the entire use. These helpers are synchronous
 * and retain no caller buffers. Raw byte operations deliberately do not select
 * orientation: a byte/wide public entry point must select/check it first. */
bool __alix_stdio_orient_unlocked(FILE *stream, int orientation);
size_t __alix_stdio_read_unlocked(FILE *stream, void *buffer, size_t count, bool *failed);
size_t __alix_stdio_write_unlocked(FILE *stream, const void *buffer, size_t count);
int __alix_stdio_pushback_unlocked(FILE *stream, unsigned char byte);

#endif
