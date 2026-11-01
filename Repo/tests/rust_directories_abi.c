#include <pwd.h>
#include <stddef.h>
size_t alix_rust_passwd_size(void) { return sizeof(struct passwd); }
size_t alix_rust_passwd_directory_offset(void) { return offsetof(struct passwd, pw_dir); }
