#ifndef IO_RECORD_LOCK_H
#define IO_RECORD_LOCK_H
#include "io_event_service.h"

/* Consume target_owned on every return. Caller holds a bounded preparation
 * guard. The lease retains the table until cleanup, never a process/stack/user
 * address. Held records retain only target descriptions: retaining the table
 * there would prevent its final shutdown and create a reference cycle. */
int io_record_lock_create(fd_retirement_queue_t *retirement, fd_table_t *table,
    fd_description_t *target_owned, uint64_t pid, uint32_t command, fd_description_t **output);
syscall_record_lock_t *io_record_lock_query(fd_description_t *lease);
int io_record_lock_validate(fd_description_t *lease);
bool io_record_lock_resolved(fd_description_t *lease);
bool io_record_lock_is_query(fd_description_t *lease);
/* Protected storage worker only, for SEEK_CUR/END offset/size resolution. */
int io_record_lock_resolve(fd_description_t *lease);
bool io_record_lock_description_valid(const fd_description_t *lease);
bool io_record_lock_execute(io_request_t *request, io_service_result_t *result);
/* Only the live guarded caller commits; failure/cancellation retains its old
 * locks. Close observers revoke reservations without running destructors. */
int io_record_lock_commit(fd_description_t *lease);
void io_record_lock_abort(fd_description_t *lease);
size_t io_record_lock_drain(size_t budget);
#endif
