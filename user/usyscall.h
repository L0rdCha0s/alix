#ifndef USER_USYSCALL_H
#define USER_USYSCALL_H

#include "types.h"
#include "syscall_defs.h"
#include "user_atk_defs.h"

ssize_t sys_write(int fd, const void *buffer, size_t count);
ssize_t sys_read(int fd, void *buffer, size_t count);
int sys_close(int fd);
int sys_open(const char *path, uint64_t flags);
void *sys_sbrk(int64_t increment);
void sys_exit(int status) __attribute__((noreturn));
int sys_ui_create(const user_atk_window_desc_t *desc);
int sys_ui_present(uint32_t handle, const void *pixels, size_t byte_len);
int sys_ui_poll_event(uint32_t handle, user_atk_event_t *event, uint32_t flags);
int sys_ui_close(uint32_t handle);
int sys_yield(void);
int sys_serial_write(const char *buffer, size_t length);
int sys_shell_open(void);
int sys_shell_exec(int handle,
                   const char *command,
                   size_t command_len);
ssize_t sys_shell_poll(int handle,
                       char *output,
                       size_t output_len,
                       int *status_out,
                       int *running_out);
int sys_shell_interrupt(int handle);
int sys_shell_close(int handle);
ssize_t sys_proc_snapshot(syscall_process_info_t *buffer, size_t capacity);
ssize_t sys_net_snapshot(syscall_net_stats_t *buffer, size_t capacity);
ssize_t sys_cpu_snapshot(syscall_cpu_stats_t *buffer, size_t capacity);
uint64_t sys_time_millis(void);
int sys_time_info(syscall_time_info_t *info);
ssize_t sys_font_cache(void *buffer, size_t capacity);
int64_t sys_lseek(int fd, int64_t offset, int whence);
int sys_fstat(int fd, syscall_stat_t *st);
ssize_t sys_pread(int fd, void *buffer, size_t count, size_t offset);

#endif
