/* Compare Rust declarations with Alix's actual public C headers. */
#include <errno.h>
#include <signal.h>
#include <stddef.h>

int alix_rust_os_check_abi(const int *values, size_t count)
{
    static const int expected[] = {
        EAGAIN, EWOULDBLOCK, EINVAL, ENOENT, EBADF, ESRCH, ERANGE,
        ENOSYS, ENOTSUP, EOPNOTSUPP, EOVERFLOW, ECANCELED,
        EOWNERDEAD, ENOTRECOVERABLE, SIGABRT, SIGKILL, SIGPIPE, SIGSEGV
    };
    if (count != sizeof(expected) / sizeof(expected[0])) return -1;
    for (size_t index = 0; index < count; ++index)
        if (values[index] != expected[index]) return (int)index + 1;
    return 0;
}

int *alix_rust_os_errno_address(void) { return &errno; }
void alix_rust_os_set_errno(int value) { errno = value; }
