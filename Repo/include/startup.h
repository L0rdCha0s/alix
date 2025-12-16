#ifndef STARTUP_H
#define STARTUP_H

#include "types.h"

/* Initializes the startup script system and ensures default assets exist. */
void startup_init(void);

/* Schedules the background process that executes startup scripts. */
bool startup_schedule(void);

#endif
