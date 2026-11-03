#ifndef ALIX_PROCESS_NATIVE_H
#define ALIX_PROCESS_NATIVE_H
#include "sys/types.h"
#ifdef __cplusplus
extern "C" {
#endif
/* Native argv launch, with a private descriptor/cwd snapshot. This initial
 * interface launches an empty environment; POSIX spawn attributes/file actions
 * are provided separately as their native backends are integrated. */
__attribute__((visibility("default"))) pid_t alix_spawn_argv(const char *path, char *const argv[]);
/* Heap-owned snapshot of the current native getenv/setenv map. */
__attribute__((visibility("default"))) char **alix_environment_copy(void);
__attribute__((visibility("default"))) void alix_environment_free(char **environment);
#ifdef __cplusplus
}
#endif
#endif
