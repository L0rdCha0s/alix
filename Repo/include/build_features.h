#ifndef BUILD_FEATURES_H
#define BUILD_FEATURES_H

/* Build-time subsystem and diagnostic switches. */
#define ENABLE_STARTUP_SCRIPT 1
#define ENABLE_FSTAB_MOUNT    1
#define ENABLE_FLUSHD         1
#define ENABLE_INIT_HWINFO        1
#define ENABLE_INIT_USER_ATK      1
#define ENABLE_INIT_BLOCK         1
#define ENABLE_INIT_VFS           1
#define ENABLE_INIT_KEYBOARD      1
#define ENABLE_INIT_NET           1
#define ENABLE_INIT_HDA           1
#define ENABLE_INIT_PROC_DEVICES  1
#define ENABLE_INIT_SERIAL_ASYNC  1
#define ENABLE_INIT_TCP_TIMER     1
#define ENABLE_INIT_WARMUP        1
#ifndef ENABLE_USB
#define ENABLE_USB 1
#endif
/* Stack-debug enforcement disabled by request for normal performance runs. */
#define ENABLE_STACK_WRITE_DEBUG      0
#define ENABLE_STACK_WRITE_DEBUG_LOGS 0
#define ENABLE_STACK_GUARD_PROTECT    0
#define ENABLE_CONTEXT_GUARD          0
#define ENABLE_STACK_CANARY_CHECKS    0
#define ENABLE_SMP_BOOT_STACK_SCAN    0
#define ENABLE_STACK_SCAN_LOGS        0
#define ENABLE_SCHEDULER_STACK_DUMP   0

#endif /* BUILD_FEATURES_H */
