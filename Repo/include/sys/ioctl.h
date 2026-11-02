#ifndef ALIX_SYS_IOCTL_H
#define ALIX_SYS_IOCTL_H
#ifdef TTF_HOST_BUILD
#include_next <sys/ioctl.h>
#else
#include "../syscall_defs.h"
#define FIONREAD SYSCALL_IOCTL_FIONREAD
#define FIONBIO SYSCALL_IOCTL_FIONBIO
#define FIONCLEX SYSCALL_IOCTL_FIONCLEX
#define FIOCLEX SYSCALL_IOCTL_FIOCLEX
/* The native runtime has no TTY backend. These queries return ENOTTY. */
struct winsize { uint16_t ws_row, ws_col, ws_xpixel, ws_ypixel; };
#define TIOCGWINSZ 0x5413u
#define TIOCSWINSZ 0x5414u
#ifdef __cplusplus
extern "C" {
#endif
int ioctl(int fd, unsigned long request, ...);
#ifdef __cplusplus
}
#endif
#endif
#endif
