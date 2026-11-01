#ifndef ALIX_SYS_TIME_H
#define ALIX_SYS_TIME_H

#ifdef TTF_HOST_BUILD
#include_next <sys/time.h>
#else
#include "sys/types.h"
#include <time.h>

struct timeval
{
    time_t tv_sec;
    suseconds_t tv_usec;
};

#ifdef __cplusplus
extern "C" {
#endif
/* timezone is obsolete and ignored; pass NULL. Resolution is milliseconds. */
int gettimeofday(struct timeval *value, void *timezone);
#ifdef __cplusplus
}
#endif
#endif
#endif
