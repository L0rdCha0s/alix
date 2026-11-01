#ifndef ALIX_MUSL_PRIVATE_H
#define ALIX_MUSL_PRIVATE_H
#define hidden __attribute__((visibility("hidden")))
#define weak_alias(old, new) extern __typeof(old) new __attribute__((weak, alias(#old)));
#define strong_alias(old, new) extern __typeof(old) new __attribute__((alias(#old)));
#endif
