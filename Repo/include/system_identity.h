#ifndef ALIX_SYSTEM_IDENTITY_H
#define ALIX_SYSTEM_IDENTITY_H
#include "vfs.h"
#include "syscall_defs.h"
/* Protected storage worker; cwd/reply are registered-request owned. */
int system_identity_snapshot(vfs_node_t *cwd, uint32_t uid, uint32_t gid, syscall_utsname_t *reply);
#endif
