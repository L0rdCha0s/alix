#include "fcntl.h"
#include "errno.h"
int alix_rust_net_flags(int fd)
{
    int slots=fcntl(fd,F_GETFD);if(slots<0)return -errno;
    int status=fcntl(fd,F_GETFL);if(status<0)return -errno;
    return ((slots&FD_CLOEXEC)?1:0)|((status&O_NONBLOCK)?2:0);
}
