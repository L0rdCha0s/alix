#ifndef ALIX_SYS_MMAN_H
#define ALIX_SYS_MMAN_H

#ifdef TTF_HOST_BUILD
#include_next <sys/mman.h>
#else
#include "types.h"
#include "sys/types.h"
#include "syscall_defs.h"

#define PROT_NONE SYSCALL_VM_PROT_NONE
#define PROT_READ SYSCALL_VM_PROT_READ
#define PROT_WRITE SYSCALL_VM_PROT_WRITE
#define PROT_EXEC SYSCALL_VM_PROT_EXEC
#define MAP_PRIVATE SYSCALL_VM_MAP_PRIVATE
#define MAP_ANONYMOUS SYSCALL_VM_MAP_ANONYMOUS
#define MAP_ANON MAP_ANONYMOUS
#define MAP_FIXED SYSCALL_VM_MAP_FIXED
#define MAP_FIXED_NOREPLACE SYSCALL_VM_MAP_FIXED_NOREPLACE
#define MAP_FAILED ((void *)-1)

#define MADV_DONTNEED SYSCALL_VM_ADVICE_DONTNEED
#define POSIX_MADV_NORMAL 0
#define POSIX_MADV_RANDOM 1
#define POSIX_MADV_SEQUENTIAL 2
#define POSIX_MADV_WILLNEED 3
#define POSIX_MADV_DONTNEED 4

#ifdef __cplusplus
extern "C" {
#endif

/* Anonymous, process-private pages. PROT_NONE reservations do not allocate
 * physical backing; protection can commit them or temporarily hide contents.
 * File-backed/shared mappings are unsupported. x86 write/execute permission
 * implies read permission; all defined PROT combinations, including RWX, work. */
void *mmap(void *address, size_t length, int protection, int flags, int fd, off_t offset);
int mprotect(void *address, size_t length, int protection);
int munmap(void *address, size_t length);
/* Anonymous discard releases backing after TLB acknowledgement. The address
 * and permissions remain; the next permitted access allocates a zeroed page. */
int madvise(void *address, size_t length, int advice);
/* POSIX advice validates the complete mapping and preserves contents/errno.
 * The performance hint is accepted without changing paging policy. */
int posix_madvise(void *address, size_t length, int advice);

#ifdef __cplusplus
}
#endif
#endif
#endif
