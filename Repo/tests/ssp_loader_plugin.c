#include "types.h"
#include "string.h"
#include "alix_process.h"
#define EXPORT __attribute__((visibility("default")))
extern uintptr_t __stack_chk_guard __attribute__((visibility("default")));
static int initialized;
EXPORT int ssp_plugin_environment(void)
{
    char **environment=alix_environment_copy();
    if(!environment)return 0;
    int found=0;
    for(size_t i=0;environment[i];++i)
        if(!strcmp(environment[i],"SSP_LOADER_ENV=shared"))found=1;
    alix_environment_free(environment);
    return found;
}
__attribute__((constructor)) static void initialize(void)
{
    char value[32];
    memcpy(value,"initialized",12);
    __asm__ volatile(""::"r"(value):"memory");
    initialized=__stack_chk_guard!=0 && value[0]=='i';
}
EXPORT uintptr_t ssp_plugin_guard(void){return __stack_chk_guard;}
EXPORT int ssp_plugin_ready(void){return initialized;}
/* Deliberately addressable stack storage exercises compiler-generated canary
 * saves/checks. The corrupt-mode fixture passes an oversized copy on purpose. */
EXPORT __attribute__((noinline)) int ssp_plugin_check(const char *text,size_t length)
{
    char bytes[64];
    memcpy(bytes,text,length);
    __asm__ volatile(""::"r"(bytes):"memory");
    return bytes[0]=='s';
}
