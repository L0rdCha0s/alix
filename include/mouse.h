#ifndef MOUSE_H
#define MOUSE_H

#include "types.h"

typedef void (*mouse_listener_t)(int dx, int dy, bool left_pressed);

void mouse_init(void);
void mouse_on_irq(uint8_t byte);
void mouse_register_listener(mouse_listener_t listener);
void mouse_reset_debug_counter(void);
void mouse_poll(void);
/* Drain queued mouse events (FIFO) and dispatch to the registered listener. */
void mouse_dispatch_events(void);

#endif
