#ifndef IO_STREAM_H
#define IO_STREAM_H

#include "io_vfs.h"

/* Copy callbacks by value. Context is kernel-static or kept alive by the
 * supplied owner. That owner transfers on success only. Callbacks must be
 * independent of the executing worker's process/credentials and must not retain
 * caller buffers. Constructor requires a protected worker or preparation guard;
 * data/close callbacks run only on protected workers, without caller locks. */
fd_description_t *io_stream_create(const fd_ops_t *ops, void *context,
                                   fd_description_t *owner, fd_retirement_queue_t *retirement);
bool io_stream_description_valid(const fd_description_t *description);
void io_stream_execute(io_request_t *request, io_service_result_t *result);
fd_description_t *io_console_import_owned(void *unused);
fd_description_t *io_null_input_create(fd_retirement_queue_t *retirement);

#endif
