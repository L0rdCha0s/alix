#ifndef ERRNO_H
#define ERRNO_H

#define EAGAIN 11
#define EWOULDBLOCK EAGAIN
#define EINTR 4
#define EINVAL 22
#define ENOENT 2
#define EIO 5
#define ENOMEM 12
#define EEXIST 17
#define ENOSYS 38

extern int errno;

#endif /* ERRNO_H */
