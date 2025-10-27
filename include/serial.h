#ifndef SERIAL_H
#define SERIAL_H

#include "types.h"

void serial_init(void);
void serial_write_char(char c);
void serial_write_string(const char *s);
char serial_read_char(void);
bool serial_has_char(void);

#endif
