#ifndef ALIX_TERMIOS_H
#define ALIX_TERMIOS_H

#include <stdint.h>

/* Native Alix layout and constants, independent of Linux ioctl encodings. */
typedef uint32_t tcflag_t;
typedef uint32_t speed_t;
typedef unsigned char cc_t;
#define NCCS 20
struct termios
{
    tcflag_t c_iflag, c_oflag, c_cflag, c_lflag;
    cc_t c_cc[NCCS];
    speed_t c_ispeed, c_ospeed;
};

#define VINTR 0
#define VQUIT 1
#define VERASE 2
#define VKILL 3
#define VEOF 4
#define VTIME 5
#define VMIN 6
#define VSTART 7
#define VSTOP 8
#define VSUSP 9
#define VEOL 10
#define VREPRINT 11
#define VDISCARD 12
#define VWERASE 13
#define VLNEXT 14
#define VEOL2 15

#define IGNBRK (1u << 0)
#define BRKINT (1u << 1)
#define IGNPAR (1u << 2)
#define PARMRK (1u << 3)
#define INPCK (1u << 4)
#define ISTRIP (1u << 5)
#define INLCR (1u << 6)
#define IGNCR (1u << 7)
#define ICRNL (1u << 8)
#define IXON (1u << 9)
#define IXOFF (1u << 10)
#define IXANY (1u << 11)
#define OPOST (1u << 0)
#define ONLCR (1u << 1)
#define OCRNL (1u << 2)
#define ONOCR (1u << 3)
#define ONLRET (1u << 4)
#define CSIZE (3u << 0)
#define CS5 (0u << 0)
#define CS6 (1u << 0)
#define CS7 (2u << 0)
#define CS8 (3u << 0)
#define CSTOPB (1u << 2)
#define CREAD (1u << 3)
#define PARENB (1u << 4)
#define PARODD (1u << 5)
#define HUPCL (1u << 6)
#define CLOCAL (1u << 7)
#define ECHO (1u << 0)
#define ECHOE (1u << 1)
#define ECHOK (1u << 2)
#define ECHONL (1u << 3)
#define ICANON (1u << 4)
#define IEXTEN (1u << 5)
#define ISIG (1u << 6)
#define NOFLSH (1u << 7)
#define TOSTOP (1u << 8)

#define B0 0u
#define B50 1u
#define B75 2u
#define B110 3u
#define B134 4u
#define B150 5u
#define B200 6u
#define B300 7u
#define B600 8u
#define B1200 9u
#define B1800 10u
#define B2400 11u
#define B4800 12u
#define B9600 13u
#define B19200 14u
#define B38400 15u
#define B57600 16u
#define B115200 17u
#define B230400 18u

#define TCSANOW 0
#define TCSADRAIN 1
#define TCSAFLUSH 2
#define TCIFLUSH 0
#define TCOFLUSH 1
#define TCIOFLUSH 2
#define TCOOFF 0
#define TCOON 1
#define TCIOFF 2
#define TCION 3

#ifdef __cplusplus
extern "C" {
#endif
int tcgetattr(int fd, struct termios *attributes);
int tcsetattr(int fd, int action, const struct termios *attributes);
int tcdrain(int fd);
int tcflush(int fd, int queue);
int tcflow(int fd, int action);
int tcsendbreak(int fd, int duration);
speed_t cfgetispeed(const struct termios *attributes);
speed_t cfgetospeed(const struct termios *attributes);
int cfsetispeed(struct termios *attributes, speed_t speed);
int cfsetospeed(struct termios *attributes, speed_t speed);
#ifdef __cplusplus
}
#endif
#endif
