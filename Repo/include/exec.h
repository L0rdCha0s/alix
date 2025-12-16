#ifndef EXEC_H
#define EXEC_H

#include "types.h"
#include "vfs.h"
#include "process.h"

process_t *exec_spawn_elf(const char *name,
                          vfs_node_t *file,
                          const char *const *argv,
                          size_t argc,
                          int stdout_fd,
                          process_t *parent,
                          const char **error_out);

#endif
