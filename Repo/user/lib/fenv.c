#include "fenv.h"
#include "string.h"

/* FXSAVE context switching preserves both units. Never borrow another CPU's
 * environment: each operation changes only the calling thread's registers. */
static uint16_t env_word(const fenv_t *env, unsigned offset)
{
    uint16_t value;
    memcpy(&value, env->x87 + offset, sizeof(value));
    return value;
}

static void env_set_word(fenv_t *env, unsigned offset, uint16_t value)
{
    memcpy(env->x87 + offset, &value, sizeof(value));
}

int fegetenv(fenv_t *env)
{
    __asm__ volatile("fnstenv %0; stmxcsr %1; fldenv %0"
                     : "=m"(env->x87), "=m"(env->mxcsr) : : "memory");
    return 0;
}

int fesetenv(const fenv_t *env)
{
    fenv_t normal;
    if (env == FE_DFL_ENV)
    {
        fegetenv(&normal);
        env_set_word(&normal, 0, 0x037f);
        env_set_word(&normal, 4, 0);
        env_set_word(&normal, 8, 0xffff);
        normal.mxcsr = 0x1f80;
        env = &normal;
    }
    __asm__ volatile("fldenv %0; ldmxcsr %1"
                     : : "m"(env->x87), "m"(env->mxcsr) : "memory");
    return 0;
}

int fetestexcept(int excepts)
{
    uint16_t status;
    uint32_t mxcsr;
    __asm__ volatile("fnstsw %0; stmxcsr %1" : "=am"(status), "=m"(mxcsr));
    return (status | mxcsr) & excepts & FE_ALL_EXCEPT;
}

int feclearexcept(int excepts)
{
    fenv_t env;
    fegetenv(&env);
    unsigned mask = (unsigned)excepts & FE_ALL_EXCEPT;
    uint16_t status = env_word(&env, 4) & ~mask;
    if (!(status & ~env_word(&env, 0) & 0x3f)) status &= ~0x8080u;
    env_set_word(&env, 4, status);
    env.mxcsr &= ~mask;
    return fesetenv(&env);
}

int fegetexceptflag(fexcept_t *flag, int excepts)
{
    *flag = (fexcept_t)fetestexcept(excepts);
    return 0;
}

int fesetexceptflag(const fexcept_t *flag, int excepts)
{
    fenv_t env;
    fegetenv(&env);
    unsigned mask = (unsigned)excepts & FE_ALL_EXCEPT;
    env_set_word(&env, 4, (env_word(&env, 4) & ~mask) | (*flag & mask));
    env.mxcsr = (env.mxcsr & ~mask) | (*flag & mask);
    return fesetenv(&env);
}

int feraiseexcept(int excepts)
{
    fenv_t env;
    fegetenv(&env);
    unsigned flags = (unsigned)excepts & FE_ALL_EXCEPT;
    uint16_t status = env_word(&env, 4) | flags;
    if (status & ~env_word(&env, 0) & 0x3f) status |= 0x8080;
    env_set_word(&env, 4, status);
    env.mxcsr |= flags;
    fesetenv(&env);
    __asm__ volatile("fwait" : : : "memory");
    return 0;
}

int feholdexcept(fenv_t *env)
{
    fenv_t held;
    fegetenv(env);
    held = *env;
    env_set_word(&held, 0, env_word(&held, 0) | 0x3f);
    env_set_word(&held, 4, env_word(&held, 4) & ~0x80ffu);
    held.mxcsr = (held.mxcsr | 0x1f80) & ~0x3fu;
    return fesetenv(&held);
}

int feupdateenv(const fenv_t *env)
{
    int flags = fetestexcept(FE_ALL_EXCEPT);
    fesetenv(env);
    return feraiseexcept(flags);
}
