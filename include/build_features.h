#ifndef BUILD_FEATURES_H
#define BUILD_FEATURES_H

/*
 * Temporary build-time feature toggles used while debugging SMP stack
 * corruption. Flip these back to 1 once the underlying issue is resolved.
 */
#define ENABLE_STARTUP_SCRIPT 0
#define ENABLE_FSTAB_MOUNT    0
#define ENABLE_FLUSHD         0

#endif /* BUILD_FEATURES_H */
