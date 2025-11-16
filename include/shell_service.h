#ifndef SHELL_SERVICE_H
#define SHELL_SERVICE_H

#include "types.h"

struct process;

int shell_service_open_session(void);
int shell_service_exec(uint32_t handle,
                       const char *command,
                       size_t command_len);
ssize_t shell_service_poll(uint32_t handle,
                           char *output,
                           size_t output_capacity,
                           int *status_out,
                           int *running_out);
int shell_service_interrupt(uint32_t handle);
bool shell_service_close_session(uint32_t handle);
void shell_service_cleanup_process(struct process *process);

#endif
