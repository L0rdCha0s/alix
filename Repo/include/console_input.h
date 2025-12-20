#ifndef CONSOLE_INPUT_H
#define CONSOLE_INPUT_H

#include "process.h"

void console_input_init(void);
void console_input_wake(void);
void console_input_wait(wait_queue_predicate_t predicate, void *context);
bool console_input_wait_timeout(wait_queue_predicate_t predicate,
                                void *context,
                                uint64_t timeout_ticks);

#endif /* CONSOLE_INPUT_H */
