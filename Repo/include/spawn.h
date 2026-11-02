#ifndef ALIX_SPAWN_H
#define ALIX_SPAWN_H
#include "sys/types.h"
#include "signal.h"
#include "syscall_defs.h"

#define POSIX_SPAWN_SETSIGMASK SYSCALL_SPAWN_SETSIGMASK
#define POSIX_SPAWN_SETSIGDEF SYSCALL_SPAWN_SETSIGDEF
#define POSIX_SPAWN_RESETIDS SYSCALL_SPAWN_RESETIDS
#define POSIX_SPAWN_SETPGROUP 8u
#define POSIX_SPAWN_SETSCHEDPARAM 16u
#define POSIX_SPAWN_SETSCHEDULER 32u

typedef struct
{
    uint32_t magic, count, capacity;
    syscall_spawn_action_t *actions;
} posix_spawn_file_actions_t;
typedef struct
{
    uint32_t magic;
    short flags;
    pid_t pgroup;
    sigset_t signal_mask, signal_default;
} posix_spawnattr_t;

#ifdef __cplusplus
extern "C" {
#endif
int posix_spawn(pid_t *pid, const char *path, const posix_spawn_file_actions_t *actions,
                 const posix_spawnattr_t *attributes, char *const argv[], char *const environment[]);
int posix_spawnp(pid_t *pid, const char *file, const posix_spawn_file_actions_t *actions,
                  const posix_spawnattr_t *attributes, char *const argv[], char *const environment[]);
int posix_spawn_file_actions_init(posix_spawn_file_actions_t *actions);
int posix_spawn_file_actions_destroy(posix_spawn_file_actions_t *actions);
int posix_spawn_file_actions_addclose(posix_spawn_file_actions_t *actions, int fd);
int posix_spawn_file_actions_adddup2(posix_spawn_file_actions_t *actions, int source, int destination);
int posix_spawn_file_actions_addopen(posix_spawn_file_actions_t *actions, int fd, const char *path, int flags, mode_t mode);
int posix_spawn_file_actions_addchdir_np(posix_spawn_file_actions_t *actions, const char *path);
int posix_spawnattr_init(posix_spawnattr_t *attributes);
int posix_spawnattr_destroy(posix_spawnattr_t *attributes);
int posix_spawnattr_getflags(const posix_spawnattr_t *attributes, short *flags);
int posix_spawnattr_setflags(posix_spawnattr_t *attributes, short flags);
int posix_spawnattr_getsigmask(const posix_spawnattr_t *attributes, sigset_t *mask);
int posix_spawnattr_setsigmask(posix_spawnattr_t *attributes, const sigset_t *mask);
int posix_spawnattr_getsigdefault(const posix_spawnattr_t *attributes, sigset_t *set);
int posix_spawnattr_setsigdefault(posix_spawnattr_t *attributes, const sigset_t *set);
int posix_spawnattr_getpgroup(const posix_spawnattr_t *attributes, pid_t *group);
int posix_spawnattr_setpgroup(posix_spawnattr_t *attributes, pid_t group);
#ifdef __cplusplus
}
#endif
#endif
