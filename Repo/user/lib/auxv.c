#include "alix_image.h"
#include "alix_mutex.h"
#include "alix_process.h"
#include "errno.h"
#include "stdlib.h"
#include "sys/auxv.h"
#include "unistd.h"
#include "usyscall.h"

static alix_mutex_t image_lock;
static syscall_elf_info_t *image_info;
static char *image_path;
static unsigned char image_random[16] __attribute__((aligned(16)));
static int image_random_ready;

const syscall_elf_info_t *__alix_main_image(void)
{
    alix_mutex_lock(&image_lock);
    if (!image_info)
    {
        int64_t bytes = sys_process(SYSCALL_PROCESS_ELF_INFO, 0, 0, 0);
        if (bytes < (int64_t)sizeof(syscall_elf_info_t) ||
            bytes > (int64_t)(sizeof(syscall_elf_info_t) + UINT16_MAX * SYSCALL_ELF_PHENT))
        { errno = bytes < 0 ? (int)-bytes : EIO; alix_mutex_unlock(&image_lock); return NULL; }
        syscall_elf_info_t *info = malloc((size_t)bytes);
        if (!info) { errno = ENOMEM; alix_mutex_unlock(&image_lock); return NULL; }
        int64_t result = sys_process(SYSCALL_PROCESS_ELF_INFO, (uintptr_t)info, (size_t)bytes, 0);
        if (result != bytes || info->version != SYSCALL_ELF_INFO_VERSION || info->size != bytes ||
            info->phent != SYSCALL_ELF_PHENT || !info->phnum || info->phnum > UINT16_MAX ||
            sizeof(*info) + (size_t)info->phnum * info->phent != (size_t)bytes || info->reserved)
        {
            free(info); errno = result < 0 ? (int)-result : EIO;
            alix_mutex_unlock(&image_lock); return NULL;
        }
        image_info = info;
    }
    const syscall_elf_info_t *result = image_info;
    alix_mutex_unlock(&image_lock);
    return result;
}

unsigned long getauxval(unsigned long type)
{
    int saved = errno;
    const syscall_elf_info_t *info;
    unsigned long value;
    switch (type)
    {
        case AT_PAGESZ: value = 4096; break;
        case AT_BASE: case AT_FLAGS: case AT_SECURE: value = 0; break;
        case AT_PLATFORM: case AT_BASE_PLATFORM: value = (uintptr_t)"x86_64"; break;
        case AT_UID: case AT_EUID: value = getuid(); break;
        case AT_GID: case AT_EGID: value = getgid(); break;
        case AT_PHDR: case AT_PHENT: case AT_PHNUM: case AT_ENTRY:
            info = __alix_main_image(); if (!info) return 0;
            value = type == AT_PHDR ? (uintptr_t)(info + 1) : type == AT_PHENT ? info->phent :
                    type == AT_PHNUM ? info->phnum : info->entry;
            break;
        case AT_RANDOM:
            alix_mutex_lock(&image_lock);
            if (!image_random_ready)
            {
                if (getentropy(image_random, sizeof(image_random))) { alix_mutex_unlock(&image_lock); return 0; }
                image_random_ready = 1;
            }
            value = (uintptr_t)image_random;
            alix_mutex_unlock(&image_lock);
            break;
        case AT_EXECFN:
            alix_mutex_lock(&image_lock);
            if (!image_path)
            {
                char *path = malloc(SYSCALL_EXECUTABLE_PATH_MAX);
                if (!path) { errno = ENOMEM; alix_mutex_unlock(&image_lock); return 0; }
                if (alix_get_executable_path(path, SYSCALL_EXECUTABLE_PATH_MAX) < 0)
                { free(path); alix_mutex_unlock(&image_lock); return 0; }
                image_path = path;
            }
            value = (uintptr_t)image_path;
            alix_mutex_unlock(&image_lock);
            break;
        case AT_CLKTCK:
        {
            syscall_resource_usage_t usage = {0};
            int result = sys_resource_usage(SYSCALL_USAGE_SELF, &usage, sizeof(usage));
            if (result < 0) { errno = -result; return 0; }
            if (!usage.tick_frequency) { errno = EIO; return 0; }
            value = usage.tick_frequency; break;
        }
        default: errno = ENOENT; return 0;
    }
    errno = saved;
    return value;
}
