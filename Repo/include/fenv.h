#ifndef ALIX_FENV_H
#define ALIX_FENV_H
#ifdef TTF_HOST_BUILD
#include_next <fenv.h>
#else
#include "types.h"
#define FE_INVALID 0x01
#define FE_DIVBYZERO 0x04
#define FE_OVERFLOW 0x08
#define FE_UNDERFLOW 0x10
#define FE_INEXACT 0x20
#define FE_ALL_EXCEPT 0x3D
#define FE_TONEAREST 0x000
#define FE_DOWNWARD 0x400
#define FE_UPWARD 0x800
#define FE_TOWARDZERO 0xC00
typedef uint16_t fexcept_t;
typedef struct { uint8_t x87[28]; uint32_t mxcsr; } fenv_t;
#define FE_DFL_ENV ((const fenv_t *)-1)
#ifdef __cplusplus
extern "C" {
#endif
int fegetround(void);
int fesetround(int mode);
int feclearexcept(int excepts);
int fegetexceptflag(fexcept_t *flag, int excepts);
int feraiseexcept(int excepts);
int fesetexceptflag(const fexcept_t *flag, int excepts);
int fetestexcept(int excepts);
int fegetenv(fenv_t *environment);
int feholdexcept(fenv_t *environment);
int fesetenv(const fenv_t *environment);
int feupdateenv(const fenv_t *environment);
#ifdef __cplusplus
}
#endif
#endif
#endif
