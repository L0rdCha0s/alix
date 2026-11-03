#ifndef IO_LOCAL_H
#define IO_LOCAL_H
#include "io_tcp.h"

#define IO_LOCAL_RIGHTS_MAX FD_TABLE_MAX_ENTRIES
#define IO_LOCAL_CONTROL_BYTES (16u + 4u * IO_LOCAL_RIGHTS_MAX)
typedef struct io_local_control io_local_control_t;

int io_local_create_pair(fd_retirement_queue_t *retirement, uint32_t flags,
                          fd_description_t **first, fd_description_t **second);
bool io_local_description_valid(const fd_description_t *description);
bool io_local_execute(io_request_t *request, io_service_result_t *result);
int io_local_shutdown(fd_description_t *description, unsigned direction);
int io_local_control_create(fd_retirement_queue_t *retirement, fd_description_t **owner);
int io_local_control_capture(io_local_control_t *control, fd_table_t *table,
                              const void *bytes, size_t length);
int io_local_control_install(io_local_control_t *control, fd_table_t *table,
                              size_t capacity, bool cloexec);
const void *io_local_control_output(io_local_control_t *control, size_t *bytes, uint32_t *flags);
void io_local_control_commit(io_local_control_t *control);
#endif
