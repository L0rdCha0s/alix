#ifndef ALIX_SYS_UCONTEXT_H
#define ALIX_SYS_UCONTEXT_H
#ifdef TTF_HOST_BUILD
#include_next <sys/ucontext.h>
#else
#include "signal.h"
typedef alix_mcontext_t mcontext_t;
typedef alix_ucontext_t ucontext_t;
#endif
#endif
