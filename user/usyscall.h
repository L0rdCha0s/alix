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

#endif
