#include "sys/ioctl.h"
#include "usyscall.h"
#include "errno.h"
#include "serial.h"
int main(void)
{
    int64_t before=sys_file_io(SYSCALL_FILE_GETFD,1,0,0,0);
    if(before<0 || ioctl(1,FIOCLEX)!=-1 || errno!=ENOTSUP ||
        ioctl(1,FIONREAD,(void *)1)!=-1 || errno!=ENOTSUP ||
        sys_file_io(SYSCALL_FILE_GETFD,1,0,0,0)!=before) return 1;
    serial_printf("IOCTL_LEGACY_TEST: PASS unsupported=1 namespace_preserved=1\n");return 0;
}
