#ifndef USER_USYSCALL_H
#define USER_USYSCALL_H

#include "types.h"
#include "signal_abi.h"
#include "syscall_defs.h"
#include "user_atk_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

ssize_t sys_write(int fd, const void *buffer, size_t count);
ssize_t sys_read(int fd, void *buffer, size_t count);
int sys_close(int fd);
int sys_open(const char *path, uint64_t flags);
int sys_open_mode(const char *path, uint64_t flags, uint32_t mode);
int64_t sys_file_io(uint32_t operation, uint64_t first, uint64_t second, uint64_t third, uint64_t fourth);
int64_t sys_shm_open(const char *name, uint32_t flags, uint32_t mode);
int sys_shm_unlink(const char *name);
int64_t sys_directory(uint32_t operation, int handle, void *argument, size_t bytes);
int64_t sys_process(uint32_t operation, uint64_t first, uint64_t second, uint64_t third);
void *sys_sbrk(int64_t increment);
void sys_exit(int status) __attribute__((__noreturn__));
int sys_ui_create(const user_atk_window_desc_t *desc);
int sys_ui_present(uint32_t handle, const void *pixels, size_t byte_len);
int sys_ui_poll_event(uint32_t handle, user_atk_event_t *event, uint32_t flags);
int sys_ui_poll_event_timeout(uint32_t handle, user_atk_event_t *event, uint32_t timeout_ms);
int sys_ui_close(uint32_t handle);
int sys_ui_capture(uint32_t handle, uint32_t flags);
int sys_ui_control(uint32_t handle, uint32_t operation, user_atk_window_control_t *control);
int sys_yield(void);
int sys_sleep_ms(uint32_t ms);
int sys_sigaction(int number, const alix_sigaction_t *action, alix_sigaction_t *old, size_t size);
int sys_sigprocmask(int how, const alix_sigset_t *set, alix_sigset_t *old);
int sys_sigwait(const alix_sigset_t *set, int *number, size_t size, uint64_t flags);
int sys_sigaltstack(const alix_stack_t *stack, alix_stack_t *old, size_t size);
int sys_sigreturn(uintptr_t frame);
int sys_signal_jump(uint32_t operation, alix_sigjmp_state_t *environment, size_t size, int argument);
int sys_raise(int number, uint64_t thread);
int sys_kill(int32_t pid, int number);
int sys_sleep_interruptible(uint32_t milliseconds, uint32_t *remaining);

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
ssize_t sys_shell_get_cwd(int handle, char *buffer, size_t capacity);
ssize_t sys_shell_prompt(int handle, char *buffer, size_t capacity);
int sys_shell_interrupt(int handle);
int sys_shell_close(int handle);
ssize_t sys_proc_snapshot(syscall_process_info_t *buffer, size_t capacity);
ssize_t sys_net_snapshot(syscall_net_stats_t *buffer, size_t capacity);
ssize_t sys_cpu_snapshot(syscall_cpu_stats_t *buffer, size_t capacity);
int64_t sys_memory_pages(uint32_t selector);
uint64_t sys_time_millis(void);
uint64_t sys_monotonic_millis(void);
uint64_t sys_process_uptime_ns(void);
int sys_resource_usage(int which, syscall_resource_usage_t *output, size_t bytes);
int sys_cpu_clock(int which, syscall_cpu_clock_t *output);
int sys_time_info(syscall_time_info_t *info);
int sys_timezone_info(syscall_timezone_info_t *info, size_t size);
ssize_t sys_font_cache(void *buffer, size_t capacity);
int64_t sys_lseek(int fd, int64_t offset, int whence);
int sys_fstat(int fd, syscall_stat_t *st);
ssize_t sys_pread(int fd, void *buffer, size_t count, size_t offset);
ssize_t sys_readlink(const char *path, char *buffer, size_t capacity);
int sys_socket_open(const char *iface_name);
int sys_socket_connect(int fd, const char *ipv4_text, uint16_t port);
ssize_t sys_socket_available(int fd);
uint64_t sys_thread_self(void);
/* Raw TLS thread-pointer facility; it does not initialize ELF PT_TLS data. */
int sys_thread_set_tls(uintptr_t base);
uintptr_t sys_thread_get_tls(void);
/* UINT32_MAX clears explicit affinity; other values must name an online CPU. */
int sys_thread_set_affinity(uint32_t cpu_index);
uint32_t sys_thread_cpu(void);
int sys_futex_wait(volatile uint32_t *address, uint32_t expected, uint32_t timeout_ms);
int sys_futex_wake(volatile uint32_t *address, uint32_t max_waiters);
int64_t sys_vm_map(uintptr_t hint, size_t length, uint32_t protection, uint32_t flags);
int64_t sys_vm_file_map(uintptr_t hint, size_t length, uint32_t protection, uint32_t flags, int fd, int64_t offset);
int sys_vm_sync(uintptr_t address, size_t length, uint32_t flags);
ssize_t sys_file_writev(int fd, const void *vectors, int count);
int sys_vm_protect(uintptr_t address, size_t length, uint32_t protection);
int sys_vm_unmap(uintptr_t address, size_t length);
int sys_vm_advise(uintptr_t address, size_t length, uint32_t advice);
int sys_thread_detach(uint64_t tid);
ssize_t sys_getrandom(void *buffer, size_t length, uint32_t flags);
int sys_thread_info(uint64_t tid, syscall_thread_info_t *info);
int sys_thread_set_name(uint64_t tid, const char *name);
int sys_thread_prepare_exit(void);
int32_t sys_getpid(void);
int64_t sys_thread_create(uintptr_t entry,
                          uintptr_t arg,
                          size_t stack_size,
                          const char *name);
int sys_thread_join(uint64_t tid, int *status_out);
void sys_thread_exit(int status) __attribute__((__noreturn__));
ssize_t sys_list_dir(const char *path, syscall_dirent_t *entries, size_t capacity);
uint32_t sys_getuid(void);
int sys_mkdir(const char *path);

#ifdef __cplusplus
}
#endif

#endif
