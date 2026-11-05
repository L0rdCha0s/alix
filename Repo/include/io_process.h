#ifndef IO_PROCESS_H
#define IO_PROCESS_H
#include "types.h"
bool io_process_services_start(void);
int64_t io_process_dispatch(uint32_t operation, uint64_t first, uint64_t second, uint64_t third);
struct syscall_frame;
int64_t io_process_fork(const struct syscall_frame *frame);
int64_t io_process_exec(struct syscall_frame *frame);
#endif
