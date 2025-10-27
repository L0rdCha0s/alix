#ifndef KEYBOARD_H
#define KEYBOARD_H

#include "types.h"

void keyboard_init(void);
bool keyboard_try_read(char *out_char);

#endif
