#ifndef KEYBOARD_H
#define KEYBOARD_H

#include "types.h"

void keyboard_init(void);
bool keyboard_try_read(char *out_char);
typedef struct
{
    uint8_t scancode;
    bool extended;
    bool released;
    bool repeat;
    char ch;
} keyboard_event_t;
bool keyboard_try_read_event(keyboard_event_t *event);
void keyboard_buffer_push(uint8_t scancode);
void keyboard_unread_char(char ch);
void keyboard_disable_ps2(void);
bool keyboard_ps2_enabled(void);

#endif
