#ifndef ALIX_SYS_WAIT_H
#define ALIX_SYS_WAIT_H
#include "sys/types.h"

/* Encoded child status. Normal exit uses bits 8..15; a terminating signal uses
 * bits 0..6. Stopped/continued encodings are reserved for future job control. */
#define WNOHANG 1
#define WUNTRACED 2
#define WCONTINUED 8
#define WIFEXITED(status) (((status) & 0x7f) == 0)
#define WEXITSTATUS(status) (((unsigned)(status) >> 8) & 0xff)
#define WTERMSIG(status) ((status) & 0x7f)
#define WIFSIGNALED(status) ((unsigned)(((status) & 0x7f) - 1) < 0x7eu)
#define WIFSTOPPED(status) (((status) & 0xff) == 0x7f)
#define WSTOPSIG(status) WEXITSTATUS(status)
#define WIFCONTINUED(status) ((status) == 0xffff)
#define WCOREDUMP(status) ((status) & 0x80)

#ifdef __cplusplus
extern "C" {
#endif
/* Declarations establish the ABI; native spawn/wait implementation is pending.
 * Linking a caller still requires that implementation, never a success stub. */
pid_t wait(int *status);
pid_t waitpid(pid_t pid, int *status, int options);
#ifdef __cplusplus
}
#endif
#endif
