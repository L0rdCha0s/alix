#ifndef ALIX_STAT_INTERNAL_H
#define ALIX_STAT_INTERNAL_H
#include "sys/stat.h"
int __alix_stat_decode(const syscall_stat_t *input, struct stat *output);
int __alix_stat_decode_legacy(syscall_stat_t *input, void *output);
#endif
