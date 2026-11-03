#ifndef IO_USER_FILE_H
#define IO_USER_FILE_H
#include "types.h"
bool io_user_file_services_start(void);
int64_t io_user_file_map(uintptr_t address, size_t length, uint32_t protection,
                         uint32_t flags, int fd, int64_t offset);
int io_user_file_msync(uintptr_t address, size_t length, uint32_t flags);
int64_t io_user_file_dispatch(uint32_t operation, uint64_t first, uint64_t second,
                               uint64_t third, uint64_t fourth);
#endif
