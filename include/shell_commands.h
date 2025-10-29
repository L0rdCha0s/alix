#ifndef SHELL_COMMANDS_H
#define SHELL_COMMANDS_H

#include "shell.h"

bool shell_cmd_echo(shell_state_t *shell, shell_output_t *out, const char *args);
bool shell_cmd_cat(shell_state_t *shell, shell_output_t *out, const char *args);
bool shell_cmd_mkdir(shell_state_t *shell, shell_output_t *out, const char *args);
bool shell_cmd_ls(shell_state_t *shell, shell_output_t *out, const char *args);
bool shell_cmd_ip(shell_state_t *shell, shell_output_t *out, const char *args);
bool shell_cmd_start_video(shell_state_t *shell, shell_output_t *out, const char *args);
bool shell_cmd_net_mac(shell_state_t *shell, shell_output_t *out, const char *args);
bool shell_cmd_dhclient(shell_state_t *shell, shell_output_t *out, const char *args);
bool shell_cmd_ping(shell_state_t *shell, shell_output_t *out, const char *args);

#endif
