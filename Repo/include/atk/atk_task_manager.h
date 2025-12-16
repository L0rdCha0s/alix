#ifndef ATK_TASK_MANAGER_H
#define ATK_TASK_MANAGER_H

#include "types.h"

struct atk_state;

/*
 * Open the ATK Task Manager window.
 *
 * Returns true on success. This is typically used by desktop/menu actions.
 */
bool atk_task_manager_open(struct atk_state *state);

#endif
