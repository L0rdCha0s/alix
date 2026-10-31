#ifndef SETJMP_H
#define SETJMP_H

#include "types.h"
#include "signal_abi.h"

typedef struct
{
    uint64_t rbx;
    uint64_t rbp;
    uint64_t r12;
    uint64_t r13;
    uint64_t r14;
    uint64_t r15;
    uint64_t rsp;
    uint64_t rip;
} alix_jmp_buf_t;

typedef alix_jmp_buf_t jmp_buf[1];
typedef alix_sigjmp_state_t sigjmp_buf[1];

#ifdef __cplusplus
extern "C" {
#endif

int sigsetjmp(sigjmp_buf env, int savemask) __attribute__((returns_twice));
void siglongjmp(sigjmp_buf env, int value) __attribute__((noreturn));

int setjmp(jmp_buf env) __attribute__((returns_twice));
void longjmp(jmp_buf env, int value) __attribute__((noreturn));

#ifdef __cplusplus
}
#endif

#endif /* SETJMP_H */
