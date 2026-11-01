#include "termios.h"
#include "unistd.h"
#include "fcntl.h"
#include "errno.h"
#include "stdlib.h"
#include "string.h"
#include "serial.h"

#define CHECK(c, label) do { if (!(c)) { serial_printf("TERMINAL_TEST: FAIL %s errno=%d\n", label, errno); return 1; } } while (0)

int main(void)
{
    struct termios *attributes = malloc(sizeof(*attributes));
    struct termios *before = malloc(sizeof(*before));
    CHECK(attributes && before, "heap state");
    memset(attributes, 0xa5, sizeof(*attributes));
    memcpy(before, attributes, sizeof(*before));
    for (int fd = 0; fd < 3; ++fd)
    {
        CHECK(!isatty(fd) && errno == ENOTTY, "stdio streams are not TTYs");
        CHECK(tcgetattr(fd, attributes) == -1 && errno == ENOTTY, "no invented terminal attributes");
        CHECK(!memcmp(attributes, before, sizeof(*before)), "failed query preserves destination");
        CHECK(tcsetattr(fd, TCSADRAIN, attributes) == -1 && errno == ENOTTY, "no successful terminal mode change");
        CHECK(tcdrain(fd) == -1 && errno == ENOTTY, "no terminal drain");
        CHECK(tcflush(fd, TCIOFLUSH) == -1 && errno == ENOTTY, "no terminal flush");
        CHECK(tcflow(fd, TCOOFF) == -1 && errno == ENOTTY, "no terminal flow");
        CHECK(tcsendbreak(fd, 0) == -1 && errno == ENOTTY, "no terminal break");
    }
    int fd = open("/tmp/terminal-test", O_RDWR | O_CREAT | O_TRUNC);
    CHECK(fd >= 3 && !isatty(fd) && errno == ENOTTY, "regular file classification");
    CHECK(tcgetattr(fd, attributes) == -1 && errno == ENOTTY, "regular file terminal query");
    int alias = dup(fd);
    CHECK(alias >= 3 && close(fd) == 0, "close original description slot");
    CHECK(!isatty(fd) && errno == EBADF, "closed slot is EBADF");
    CHECK(!isatty(alias) && errno == ENOTTY, "live alias is not TTY");
    CHECK(close(alias) == 0 && tcgetattr(alias, attributes) == -1 && errno == EBADF, "closed alias");
    CHECK(tcsetattr(-1, TCSANOW, attributes) == -1 && errno == EBADF, "invalid descriptor");
    CHECK(tcgetattr(0x7fffffff, attributes) == -1 && errno == EBADF, "out of range descriptor");
    CHECK(tcsetattr(1, 99, attributes) == -1 && errno == EINVAL, "invalid action");
    CHECK(tcflow(1, 99) == -1 && errno == EINVAL, "invalid flow action");
    CHECK(tcflush(1, 99) == -1 && errno == EINVAL, "invalid queue");
    memset(attributes, 0, sizeof(*attributes));
    errno = EDOM;
    CHECK(cfsetospeed(attributes, B115200) == 0 && cfgetospeed(attributes) == B115200 && errno == EDOM, "output speed and errno");
    CHECK(cfsetispeed(attributes, B9600) == 0 && cfgetispeed(attributes) == B9600, "independent input speed");
    CHECK(cfsetispeed(attributes, B0) == 0 && cfgetispeed(attributes) == B115200, "zero input speed follows output");
    memcpy(before, attributes, sizeof(*before));
    CHECK(cfsetospeed(attributes, 0xffffffffu) == -1 && errno == EINVAL &&
          !memcmp(attributes, before, sizeof(*before)), "invalid output speed preserves attributes");
    CHECK(cfsetispeed(attributes, 0xffffffffu) == -1 && errno == EINVAL &&
          !memcmp(attributes, before, sizeof(*before)), "invalid input speed preserves attributes");
    free(before); free(attributes);
    serial_printf("TERMINAL_TEST: PASS private_fds=1 non_tty=1 closed=1 unchanged=1 speeds=1\n");
    return 0;
}
