#ifndef IO_POLL_H
#define IO_POLL_H
#include "io_event_service.h"

/* Heap-owned set pins the original descriptions, independent of later FD
 * close/reuse. Constructors and population run in the syscall preparation
 * guard; final destruction runs on the protected retirement worker. */
int io_poll_create(fd_retirement_queue_t *retirement, size_t count, int timeout,
                     fd_description_t **output);
/* Select readiness excludes unrequested errors/hangups and supports signed
 * 64-bit millisecond intervals. -1 alone selects an indefinite wait. */
int io_select_create(fd_retirement_queue_t *retirement, size_t count, int64_t timeout,
                       fd_description_t **output);
syscall_pollfd_t *io_poll_entries(fd_description_t *description);
int io_poll_pin(fd_description_t *description, fd_table_t *table);
bool io_poll_description_valid(const fd_description_t *description);
bool io_poll_execute(io_request_t *request, io_service_result_t *result);
#endif
