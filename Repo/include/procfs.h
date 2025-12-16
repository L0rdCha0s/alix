#ifndef PROCFS_H
#define PROCFS_H

#include "vfs.h"

void procfs_init(void);
vfs_node_t *procfs_root(void);
vfs_node_t *procfs_mkdir(const char *path);
vfs_node_t *procfs_create_file(const char *name,
                               vfs_read_cb_t read_cb,
                               vfs_write_cb_t write_cb,
                               void *context);
vfs_node_t *procfs_create_file_at(const char *path,
                                  vfs_read_cb_t read_cb,
                                  vfs_write_cb_t write_cb,
                                  void *context);

#endif /* PROCFS_H */
