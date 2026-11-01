#include "termios.h"
#include "unistd.h"
#include "usyscall.h"
#include "errno.h"

/* The owned runtime currently exposes EOF input, console/capture output, VFS
 * files and sockets, but no TTY description or line discipline. Validate the
 * actual private slot, never the matching legacy global integer. Once Alix
 * gains a TTY backend, replace this query with its capability/state operation;
 * character-device metadata alone does not imply terminal support. */
static int terminal_required(int fd)
{
    int64_t result = sys_file_io(SYSCALL_FILE_GETFD, (uint64_t)(int64_t)fd, 0, 0, 0);
    errno = result < 0 ? (int)-result : ENOTTY;
    return -1;
}

int isatty(int fd)
{
    (void)terminal_required(fd);
    return 0;
}

int tcgetattr(int fd, struct termios *attributes)
{
    (void)attributes;
    return terminal_required(fd);
}

int tcsetattr(int fd, int action, const struct termios *attributes)
{
    (void)attributes;
    if (action != TCSANOW && action != TCSADRAIN && action != TCSAFLUSH)
    { errno = EINVAL; return -1; }
    return terminal_required(fd);
}

int tcdrain(int fd) { return terminal_required(fd); }

int tcflush(int fd, int queue)
{
    if (queue != TCIFLUSH && queue != TCOFLUSH && queue != TCIOFLUSH)
    { errno = EINVAL; return -1; }
    return terminal_required(fd);
}

int tcflow(int fd, int action)
{
    if (action != TCOOFF && action != TCOON && action != TCIOFF && action != TCION)
    { errno = EINVAL; return -1; }
    return terminal_required(fd);
}

int tcsendbreak(int fd, int duration)
{
    (void)duration;
    return terminal_required(fd);
}

speed_t cfgetispeed(const struct termios *attributes) { return attributes->c_ispeed; }
speed_t cfgetospeed(const struct termios *attributes) { return attributes->c_ospeed; }

int cfsetispeed(struct termios *attributes, speed_t speed)
{
    if (speed > B230400) { errno = EINVAL; return -1; }
    attributes->c_ispeed = speed ? speed : attributes->c_ospeed;
    return 0;
}

int cfsetospeed(struct termios *attributes, speed_t speed)
{
    if (speed > B230400) { errno = EINVAL; return -1; }
    attributes->c_ospeed = speed;
    return 0;
}
