#include "spawn.h"
#include "alix_process.h"
#include "usyscall.h"
#include "stdlib.h"
#include "string.h"
#include "errno.h"
#include "limits.h"

#define ACTIONS_MAGIC 0x53504641u
#define ATTR_MAGIC 0x53504154u
#define ACTION_LIMIT 256u
#define FILE_LIMIT 256

int posix_spawn_file_actions_init(posix_spawn_file_actions_t *actions)
{
    if (!actions) return EINVAL;
    *actions = (posix_spawn_file_actions_t){ .magic = ACTIONS_MAGIC }; return 0;
}

int posix_spawn_file_actions_destroy(posix_spawn_file_actions_t *actions)
{
    if (!actions || actions->magic != ACTIONS_MAGIC || actions->count > actions->capacity) return EINVAL;
    for (uint32_t index = 0; index < actions->count; ++index)
        if (actions->actions[index].operation == SYSCALL_SPAWN_OPEN ||
            actions->actions[index].operation == SYSCALL_SPAWN_CHDIR) free((void *)(uintptr_t)actions->actions[index].path);
    free(actions->actions); memset(actions, 0, sizeof(*actions)); return 0;
}

static int add_action(posix_spawn_file_actions_t *actions, syscall_spawn_action_t action)
{
    if (!actions || actions->magic != ACTIONS_MAGIC || actions->count > actions->capacity) return EINVAL;
    if (actions->count == ACTION_LIMIT) return E2BIG;
    int saved = errno;
    if (actions->count == actions->capacity)
    {
        uint32_t capacity = actions->capacity ? actions->capacity * 2 : 8;
        syscall_spawn_action_t *grown = realloc(actions->actions, (size_t)capacity * sizeof(*grown));
        if (!grown) { errno = saved; return ENOMEM; }
        actions->actions = grown; actions->capacity = capacity;
    }
    actions->actions[actions->count++] = action; errno = saved; return 0;
}

int posix_spawn_file_actions_addclose(posix_spawn_file_actions_t *actions, int fd)
{
    if (fd < 0 || fd >= FILE_LIMIT) return EBADF;
    return add_action(actions, (syscall_spawn_action_t){ .operation = SYSCALL_SPAWN_CLOSE, .fd = fd });
}

int posix_spawn_file_actions_adddup2(posix_spawn_file_actions_t *actions, int source, int destination)
{
    if (source < 0 || source >= FILE_LIMIT || destination < 0 || destination >= FILE_LIMIT) return EBADF;
    return add_action(actions, (syscall_spawn_action_t){ .operation = SYSCALL_SPAWN_DUP2, .fd = source, .destination = destination });
}

int posix_spawn_file_actions_addopen(posix_spawn_file_actions_t *actions, int fd, const char *path, int flags, mode_t mode)
{
    if (fd < 0 || fd >= FILE_LIMIT) return EBADF;
    if (!path) return EINVAL;
    int saved = errno;
    char *copy = strdup(path);
    if (!copy) { errno = saved; return ENOMEM; }
    int result = add_action(actions, (syscall_spawn_action_t){ .operation = SYSCALL_SPAWN_OPEN, .fd = fd,
                                 .path = (uintptr_t)copy, .flags = (uint32_t)flags, .mode = mode });
    if (result) free(copy);
    errno = saved; return result;
}

int posix_spawn_file_actions_addchdir_np(posix_spawn_file_actions_t *actions, const char *path)
{
    if (!path) return EINVAL;
    int saved = errno;
    char *copy = strdup(path);
    if (!copy) { errno = saved; return ENOMEM; }
    int result = add_action(actions, (syscall_spawn_action_t){ .operation = SYSCALL_SPAWN_CHDIR,
                                                              .path = (uintptr_t)copy });
    if (result) free(copy);
    errno = saved; return result;
}

int posix_spawnattr_init(posix_spawnattr_t *attributes)
{
    if (!attributes) return EINVAL;
    *attributes = (posix_spawnattr_t){ .magic = ATTR_MAGIC }; return 0;
}
int posix_spawnattr_destroy(posix_spawnattr_t *attributes)
{
    if (!attributes || attributes->magic != ATTR_MAGIC) return EINVAL;
    memset(attributes, 0, sizeof(*attributes)); return 0;
}
int posix_spawnattr_getflags(const posix_spawnattr_t *attributes, short *flags)
{
    if (!attributes || attributes->magic != ATTR_MAGIC || !flags) return EINVAL;
    *flags = attributes->flags; return 0;
}
int posix_spawnattr_setflags(posix_spawnattr_t *attributes, short flags)
{
    unsigned known = POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_SETSIGDEF | POSIX_SPAWN_RESETIDS |
                     POSIX_SPAWN_SETPGROUP | POSIX_SPAWN_SETSCHEDPARAM | POSIX_SPAWN_SETSCHEDULER |
                     POSIX_SPAWN_CLOEXEC_DEFAULT;
    if (!attributes || attributes->magic != ATTR_MAGIC || ((unsigned short)flags & ~known)) return EINVAL;
    attributes->flags = flags; return 0;
}
int posix_spawnattr_getsigmask(const posix_spawnattr_t *attributes, sigset_t *mask)
{
    if (!attributes || attributes->magic != ATTR_MAGIC || !mask) return EINVAL;
    *mask = attributes->signal_mask; return 0;
}
int posix_spawnattr_setsigmask(posix_spawnattr_t *attributes, const sigset_t *mask)
{
    if (!attributes || attributes->magic != ATTR_MAGIC || !mask || (*mask & ~ALIX_SIGNAL_MASK)) return EINVAL;
    attributes->signal_mask = *mask; return 0;
}
int posix_spawnattr_getsigdefault(const posix_spawnattr_t *attributes, sigset_t *set)
{
    if (!attributes || attributes->magic != ATTR_MAGIC || !set) return EINVAL;
    *set = attributes->signal_default; return 0;
}
int posix_spawnattr_setsigdefault(posix_spawnattr_t *attributes, const sigset_t *set)
{
    if (!attributes || attributes->magic != ATTR_MAGIC || !set || (*set & ~ALIX_SIGNAL_MASK)) return EINVAL;
    attributes->signal_default = *set; return 0;
}
int posix_spawnattr_getpgroup(const posix_spawnattr_t *attributes, pid_t *group)
{
    if (!attributes || attributes->magic != ATTR_MAGIC || !group) return EINVAL;
    *group = attributes->pgroup; return 0;
}
int posix_spawnattr_setpgroup(posix_spawnattr_t *attributes, pid_t group)
{
    if (!attributes || attributes->magic != ATTR_MAGIC || group < 0) return EINVAL;
    attributes->pgroup = group; return 0;
}

static int spawn_request(pid_t *pid, const char *path, const posix_spawn_file_actions_t *actions,
                           const posix_spawnattr_t *attributes, char *const argv[], char *const environment[],
                           const char *search_path)
{
    if (!path || !argv || (actions && (actions->magic != ACTIONS_MAGIC || actions->count > actions->capacity)) ||
        (attributes && attributes->magic != ATTR_MAGIC)) return EINVAL;
    syscall_spawn_t specification = { .version = SYSCALL_SPAWN_VERSION, .size = sizeof(specification),
                                      .path = (uintptr_t)path, .argv = (uintptr_t)argv, .environment = (uintptr_t)environment };
    if (actions) { specification.actions = (uintptr_t)actions->actions; specification.action_count = actions->count; }
    if (attributes)
    {
        specification.flags = (unsigned short)attributes->flags;
        specification.signal_mask = attributes->signal_mask;
        specification.signal_default = attributes->signal_default;
    }
    if (search_path) { specification.flags |= SYSCALL_SPAWN_SEARCH_PATH; specification.search_path = (uintptr_t)search_path; }
    int saved = errno;
    int64_t result = sys_process(SYSCALL_PROCESS_SPAWN_EX, (uintptr_t)&specification, sizeof(specification), 0);
    errno = saved;
    if (result < 0) return (int)-result;
    if (pid) *pid = (pid_t)result;
    return 0;
}

int posix_spawn(pid_t *pid, const char *path, const posix_spawn_file_actions_t *actions,
                 const posix_spawnattr_t *attributes, char *const argv[], char *const environment[])
{
    return spawn_request(pid, path, actions, attributes, argv, environment, NULL);
}

int posix_spawnp(pid_t *pid, const char *file, const posix_spawn_file_actions_t *actions,
                  const posix_spawnattr_t *attributes, char *const argv[], char *const environment[])
{
    if (!file || !*file) return ENOENT;
    if (strchr(file, '/')) return posix_spawn(pid, file, actions, attributes, argv, environment);
    int saved = errno;
    char **snapshot = alix_environment_copy();
    if (!snapshot) { errno = saved; return ENOMEM; }
    const char *path = "/bin:/usr/bin";
    for (size_t index = 0; snapshot[index]; ++index)
        if (!strncmp(snapshot[index], "PATH=", 5)) { path = snapshot[index] + 5; break; }
    int result = spawn_request(pid, file, actions, attributes, argv, environment, path);
    alix_environment_free(snapshot); errno = saved; return result;
}
