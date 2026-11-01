#ifndef IO_PROCESS_H
#define IO_PROCESS_H
#include "types.h"
bool io_process_services_start(void);
int64_t io_process_dispatch(uint32_t operation, uint64_t first, uint64_t second, uint64_t third);
#endif
