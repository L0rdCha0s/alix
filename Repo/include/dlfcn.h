#ifndef ALIX_DLFCN_H
#define ALIX_DLFCN_H
#ifdef TTF_HOST_BUILD
#include_next <dlfcn.h>
#else
#define RTLD_LAZY 1
#define RTLD_NOW 2
#define RTLD_NOLOAD 4
#define RTLD_DEEPBIND 8
#define RTLD_LOCAL 0
#define RTLD_GLOBAL 0x100
#define RTLD_NODELETE 0x1000
#define RTLD_DEFAULT ((void *)0)
#define RTLD_NEXT ((void *)-1)
typedef struct { const char *dli_fname; void *dli_fbase; const char *dli_sname; void *dli_saddr; } Dl_info;
#ifdef __cplusplus
extern "C" {
#endif
void *dlopen(const char *path, int flags);
int dlclose(void *handle);
void *dlsym(void *handle, const char *name);
void *dlvsym(void *handle, const char *name, const char *version);
char *dlerror(void);
int dladdr(const void *address, Dl_info *information);
#ifdef __cplusplus
}
#endif
#endif
#endif
