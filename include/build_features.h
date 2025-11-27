#ifndef BUILD_FEATURES_H
#define BUILD_FEATURES_H

/*
 * Temporary build-time feature toggles used while debugging SMP stack
 * corruption. Flip these back to 1 once the underlying issue is resolved.
 */
#define ENABLE_STARTUP_SCRIPT 0
#define ENABLE_FSTAB_MOUNT    0
#define ENABLE_FLUSHD         0
#define ENABLE_INIT_HWINFO        0
#define ENABLE_INIT_USER_ATK      0
#define ENABLE_INIT_BLOCK         0
#define ENABLE_INIT_VFS           0
#define ENABLE_INIT_KEYBOARD      0
#define ENABLE_INIT_NET           0
#define ENABLE_INIT_PROC_DEVICES  0
#define ENABLE_INIT_SERIAL_ASYNC  0
#define ENABLE_INIT_TCP_TIMER     0
#define ENABLE_INIT_WARMUP        0
#ifndef ENABLE_USB
#define ENABLE_USB 0
#endif
/* Keep stack scribble detection enabled while we chase corruption. */
#define ENABLE_STACK_WRITE_DEBUG      1
#define ENABLE_STACK_WRITE_DEBUG_LOGS 1
#define ENABLE_STACK_GUARD_PROTECT    1

#endif /* BUILD_FEATURES_H */
