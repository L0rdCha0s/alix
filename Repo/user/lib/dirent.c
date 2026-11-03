#include "dirent.h"
#include "usyscall.h"
#include "libc.h"
#include "errno.h"

struct alix_directory
{
    alix_mutex_t mutex;
    int handle;
    syscall_directory_entry_t wire;
    struct dirent entry;
};

DIR *opendir(const char *path)
{
    if (!path) { errno = EFAULT; return NULL; }
    DIR *directory = calloc(1, sizeof(*directory));
    if (!directory) { errno = ENOMEM; return NULL; }
    alix_mutex_init(&directory->mutex);
    int64_t result = sys_directory(SYSCALL_DIRECTORY_OPEN, 0, (void *)path, 0);
    if (result < 0)
    {
        free(directory);
        errno = (int)-result;
        return NULL;
    }
    directory->handle = (int)result;
    return directory;
}

static int directory_read_locked(DIR *directory, struct dirent *entry)
{
    syscall_directory_entry_t *wire = &directory->wire;
    int64_t result = sys_directory(SYSCALL_DIRECTORY_NEXT, directory->handle, wire, sizeof(*wire));
    if (result <= 0)
    {
        return (int)result;
    }
    if (result != 1 || wire->version != SYSCALL_DIRENT_VERSION || wire->size != sizeof(*wire) ||
        !wire->inode || wire->name_length > SYSCALL_DIRENT_NAME_MAX ||
        wire->name[wire->name_length] || strlen(wire->name) != wire->name_length)
    {
        return -EIO;
    }
    entry->d_ino = wire->inode;
    switch (wire->type)
    {
        case 0: entry->d_type = DT_DIR; break;
        case 1: entry->d_type = DT_REG; break;
        case 2: entry->d_type = DT_BLK; break;
        case 3: entry->d_type = DT_LNK; break;
        case 6: entry->d_type = DT_FIFO; break;
        default: entry->d_type = DT_UNKNOWN; break;
    }
    memcpy(entry->d_name, wire->name, wire->name_length + 1u);
    return 1;
}

struct dirent *readdir(DIR *directory)
{
    if (!directory) { errno = EBADF; return NULL; }
    alix_mutex_lock(&directory->mutex);
    int result = directory_read_locked(directory, &directory->entry);
    alix_mutex_unlock(&directory->mutex);
    if (result < 0) errno = -result;
    return result > 0 ? &directory->entry : NULL;
}

int readdir_r(DIR *directory, struct dirent *entry, struct dirent **result)
{
    if (!result) return EINVAL;
    *result = NULL;
    if (!directory) return EBADF;
    if (!entry) return EINVAL;
    int saved = errno;
    alix_mutex_lock(&directory->mutex);
    int status = directory_read_locked(directory, entry);
    alix_mutex_unlock(&directory->mutex);
    if (status > 0) *result = entry;
    errno = saved;
    return status < 0 ? -status : 0;
}

int closedir(DIR *directory)
{
    if (!directory) { errno = EBADF; return -1; }
    /* As with FILE/standard DIR, callers must quiesce other users before close. */
    int64_t result = sys_directory(SYSCALL_DIRECTORY_CLOSE, directory->handle, NULL, 0);
    if (result < 0) { errno = (int)-result; return -1; }
    free(directory);
    return 0;
}

void rewinddir(DIR *directory)
{
    if (!directory) { errno = EBADF; return; }
    alix_mutex_lock(&directory->mutex);
    int64_t result = sys_directory(SYSCALL_DIRECTORY_REWIND, directory->handle, NULL, 0);
    alix_mutex_unlock(&directory->mutex);
    if (result < 0) errno = (int)-result;
}
