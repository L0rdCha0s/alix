#ifndef ALIX_PROCESS_SIGNAL_H
#define ALIX_PROCESS_SIGNAL_H
#include "interrupts.h"
#include "signal_abi.h"
#include "syscall.h"
#include "types.h"
typedef struct thread thread_t;
typedef struct process process_t;
bool process_signal_fault(exception_frame_t *, uintptr_t);
void process_signal_syscall_return(syscall_frame_t *, uint64_t);
int process_signal_return(syscall_frame_t *, uintptr_t);
int process_signal_sigaction(int, uintptr_t, uintptr_t, size_t);
int process_signal_sigprocmask(int, uintptr_t, uintptr_t);
int process_signal_sigaltstack(uintptr_t, uintptr_t, size_t, uintptr_t);
int process_signal_raise(int, uint64_t);
int process_signal_kill(int32_t, int);
int process_signal_sleep(uint32_t, uintptr_t);
bool process_signal_pending_locked(thread_t *);
void process_signal_thread_cleanup(thread_t *);
bool process_signal_address_mapped(process_t *, uintptr_t);
bool process_signal_prepare_user_frame(process_t *, uintptr_t, size_t);
#endif
