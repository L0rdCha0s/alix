#include "sys/uio.h"
#include "usyscall.h"
#include "errno.h"
#include "stddef.h"

_Static_assert(sizeof(struct iovec)==sizeof(syscall_iovec_t) &&
               offsetof(struct iovec,iov_base)==offsetof(syscall_iovec_t,base) &&
               offsetof(struct iovec,iov_len)==offsetof(syscall_iovec_t,length) &&
               IOV_MAX==SYSCALL_IOV_MAX,"native vector I/O ABI");
ssize_t writev(int descriptor,const struct iovec *vectors,int count)
{
    ssize_t result=sys_file_writev(descriptor,vectors,count);
    if(result<0){errno=(int)-result;return -1;}
    return result;
}
