#ifndef CONSOLE_H
#define CONSOLE_H

#include "types.h"

void console_init(void);
void console_clear(void);
void console_putc(char c);
void console_write(const char *s);
void console_backspace(void);
void console_set_vga_enabled(bool enabled);

#endif
