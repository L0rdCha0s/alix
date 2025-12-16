#ifndef LOGGER_H
#define LOGGER_H

#include "types.h"

#define LOGGER_FILE_PATH "/var/log/console.log"

bool logger_init(void);
bool logger_write(const char *text);
bool logger_write_len(const char *text, size_t len);
bool logger_log(const char *line);
bool logger_is_ready(void);

#endif
