#ifndef SERIAL_H
#define SERIAL_H

#include "types.h"

void serial_init(void);
void serial_printf(const char *format, ...);
void serial_output_bytes(const char *data, size_t length);
void serial_early_write_string(const char *s);
char serial_read_char(void);
bool serial_has_char(void);
bool serial_is_ready(void);
void serial_start_async_worker(void);

#endif
