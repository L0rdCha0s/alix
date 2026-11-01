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

struct dirent *readdir(DIR *directory)
{
    if (!directory) { errno = EBADF; return NULL; }
    alix_mutex_lock(&directory->mutex);
    syscall_directory_entry_t *wire = &directory->wire;
    int64_t result = sys_directory(SYSCALL_DIRECTORY_NEXT, directory->handle, wire, sizeof(*wire));
    if (result <= 0)
    {
        alix_mutex_unlock(&directory->mutex);
        if (result < 0) errno = (int)-result;
        return NULL; /* EOF preserves errno. */
    }
    if (result != 1 || wire->version != SYSCALL_DIRENT_VERSION || wire->size != sizeof(*wire) ||
        !wire->inode || wire->name_length > SYSCALL_DIRENT_NAME_MAX ||
        wire->name[wire->name_length] || strlen(wire->name) != wire->name_length)
    {
        alix_mutex_unlock(&directory->mutex);
        errno = EIO;
        return NULL;
    }
    directory->entry.d_ino = wire->inode;
    switch (wire->type)
    {
        case 0: directory->entry.d_type = DT_DIR; break;
        case 1: directory->entry.d_type = DT_REG; break;
        case 2: directory->entry.d_type = DT_BLK; break;
        case 3: directory->entry.d_type = DT_LNK; break;
        default: directory->entry.d_type = DT_UNKNOWN; break;
    }
    memcpy(directory->entry.d_name, wire->name, wire->name_length + 1u);
    alix_mutex_unlock(&directory->mutex);
    return &directory->entry;
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
