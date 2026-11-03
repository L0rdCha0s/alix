/* Each shared object owns its C++ finalization identity. */
__attribute__((visibility("hidden"))) void *__dso_handle = &__dso_handle;
extern void __cxa_finalize(void *);
static void alix_dso_finalize(void) { __cxa_finalize(__dso_handle); }
__attribute__((section(".fini_array"),
               used)) static void (*const alix_dso_fini_entry)(void) = alix_dso_finalize;
