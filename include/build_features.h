#ifndef BUILD_FEATURES_H
#define BUILD_FEATURES_H

/*
 * Temporary build-time feature toggles used while debugging SMP stack
 * corruption. Flip these back to 1 once the underlying issue is resolved.
 */
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
#define ENABLE_INIT_SERIAL_ASYNC  0
#define ENABLE_INIT_TCP_TIMER     1
#define ENABLE_INIT_WARMUP        1
#ifndef ENABLE_USB
#define ENABLE_USB 1
#endif
/* Keep stack scribble detection enabled while we chase corruption. */
#define ENABLE_STACK_WRITE_DEBUG      1
#define ENABLE_STACK_WRITE_DEBUG_LOGS 1
#define ENABLE_STACK_GUARD_PROTECT    1

#endif /* BUILD_FEATURES_H */
