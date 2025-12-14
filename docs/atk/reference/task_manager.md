# Task Manager (`atk_task_manager_open`)

Header: `include/atk/atk_task_manager.h`

The Task Manager is a kernel-managed ATK window that shows process and system information.

## Key function

- `atk_task_manager_open(state)` – opens the task manager window; returns true on success.

This is typically invoked from desktop/menu actions.
