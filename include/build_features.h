#ifndef BUILD_FEATURES_H
#define BUILD_FEATURES_H

/*
 * Temporary build-time feature toggles used while debugging SMP stack
 * corruption. Flip these back to 1 once the underlying issue is resolved.
 */
#define ENABLE_STARTUP_SCRIPT 0
#define ENABLE_FSTAB_MOUNT    0
#define ENABLE_FLUSHD         1
#ifndef ENABLE_USB
#define ENABLE_USB 1
#endif
/* Keep stack scribble detection enabled while we chase corruption. */
#define ENABLE_STACK_WRITE_DEBUG      1
#define ENABLE_STACK_WRITE_DEBUG_LOGS 1
#define ENABLE_STACK_GUARD_PROTECT    1

#endif /* BUILD_FEATURES_H */
