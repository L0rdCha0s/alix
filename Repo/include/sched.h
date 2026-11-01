#ifndef ALIX_SCHED_H
#define ALIX_SCHED_H

#ifdef TTF_HOST_BUILD
#include_next <sched.h>
#else
#include "sys/types.h"

struct sched_param { int sched_priority; };
#define SCHED_OTHER 0
#define SCHED_FIFO 1
#define SCHED_RR 2

#ifdef __cplusplus
extern "C" {
#endif
int sched_yield(void);
int sched_getcpu(void);
#ifdef __cplusplus
}
#endif
#endif
#endif
