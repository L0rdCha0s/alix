#ifndef SHELL_COMMANDS_H
#define SHELL_COMMANDS_H

#include "shell.h"

bool shell_cmd_echo(shell_state_t *shell, shell_output_t *out, const char *args);
bool shell_cmd_cat(shell_state_t *shell, shell_output_t *out, const char *args);
bool shell_cmd_mkdir(shell_state_t *shell, shell_output_t *out, const char *args);
bool shell_cmd_cd(shell_state_t *shell, shell_output_t *out, const char *args);
bool shell_cmd_rm(shell_state_t *shell, shell_output_t *out, const char *args);
bool shell_cmd_ls(shell_state_t *shell, shell_output_t *out, const char *args);
bool shell_cmd_ip(shell_state_t *shell, shell_output_t *out, const char *args);
bool shell_cmd_shutdown(shell_state_t *shell, shell_output_t *out, const char *args);
bool shell_cmd_start_video(shell_state_t *shell, shell_output_t *out, const char *args);
bool shell_cmd_net_mac(shell_state_t *shell, shell_output_t *out, const char *args);
bool shell_cmd_dnsdebug(shell_state_t *shell, shell_output_t *out, const char *args);
bool shell_cmd_dhclient(shell_state_t *shell, shell_output_t *out, const char *args);
bool shell_cmd_ping(shell_state_t *shell, shell_output_t *out, const char *args);
bool shell_cmd_nslookup(shell_state_t *shell, shell_output_t *out, const char *args);
bool shell_cmd_wget(shell_state_t *shell, shell_output_t *out, const char *args);
bool shell_cmd_alloc1m(shell_state_t *shell, shell_output_t *out, const char *args);
bool shell_cmd_free(shell_state_t *shell, shell_output_t *out, const char *args);
bool shell_cmd_imgview(shell_state_t *shell, shell_output_t *out, const char *args);
bool shell_cmd_logcat(shell_state_t *shell, shell_output_t *out, const char *args);
bool shell_cmd_sha1sum(shell_state_t *shell, shell_output_t *out, const char *args);
bool shell_cmd_mkfs(shell_state_t *shell, shell_output_t *out, const char *args);
bool shell_cmd_mount(shell_state_t *shell, shell_output_t *out, const char *args);
bool shell_cmd_ntpdate(shell_state_t *shell, shell_output_t *out, const char *args);
bool shell_cmd_tzset(shell_state_t *shell, shell_output_t *out, const char *args);
bool shell_cmd_tzstatus(shell_state_t *shell, shell_output_t *out, const char *args);
bool shell_cmd_tzsync(shell_state_t *shell, shell_output_t *out, const char *args);
bool shell_cmd_loop1(shell_state_t *shell, shell_output_t *out, const char *args);
bool shell_cmd_loop2(shell_state_t *shell, shell_output_t *out, const char *args);
bool shell_cmd_letters(shell_state_t *shell, shell_output_t *out, const char *args);
bool shell_cmd_top(shell_state_t *shell, shell_output_t *out, const char *args);
bool shell_cmd_userdemo(shell_state_t *shell, shell_output_t *out, const char *args);
bool shell_cmd_userdemo2(shell_state_t *shell, shell_output_t *out, const char *args);
bool shell_cmd_useratk(shell_state_t *shell, shell_output_t *out, const char *args);
bool shell_cmd_wolf3d(shell_state_t *shell, shell_output_t *out, const char *args);
bool shell_cmd_doom(shell_state_t *shell, shell_output_t *out, const char *args);
bool shell_cmd_runelf(shell_state_t *shell, shell_output_t *out, const char *args);
bool shell_cmd_atkshell(shell_state_t *shell, shell_output_t *out, const char *args);
bool shell_cmd_atktaskmgr(shell_state_t *shell, shell_output_t *out, const char *args);
bool shell_cmd_bgset(shell_state_t *shell, shell_output_t *out, const char *args);

#endif
