#ifndef IO_USER_FILE_H
#define IO_USER_FILE_H
#include "types.h"
bool io_user_file_services_start(void);
int64_t io_user_file_dispatch(uint32_t operation, uint64_t first, uint64_t second,
                               uint64_t third, uint64_t fourth);
#endif
