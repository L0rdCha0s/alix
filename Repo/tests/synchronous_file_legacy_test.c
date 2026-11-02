#include "fcntl.h"
#include "unistd.h"
#include "usyscall.h"
#include "serial.h"
#include "errno.h"
#include "string.h"
#include "stdlib.h"
int main(void)
{
    const char *path="/tmp/synchronous-legacy";
    int fd=open(path,O_CREAT|O_TRUNC|O_RDWR);
    if(fd<0 || write(fd,"persist",7)!=7 || close(fd))return 1;
    if(open(path,O_TRUNC|O_RDWR|O_SYNC)!=-1 || errno!=ENOTSUP)return 2;
    long raw;
    __asm__ volatile("int $0x80" : "=a"(raw) : "a"((long)SYSCALL_OPEN),"D"(path),"S"((long)(O_TRUNC|O_RDWR|O_SYNC)) : "rcx","r11","memory");
    if(raw!=-ENOTSUP)return 3;
    char *bytes=calloc(1,8);if(!bytes)return 4;
    fd=open(path,O_RDONLY);
    if(fd<0 || read(fd,bytes,8)!=7 || memcmp(bytes,"persist",7) || close(fd))return 5;
    free(bytes);serial_printf("SYNCHRONOUS_FILE_LEGACY_TEST: PASS unsupported=1 truncate_preserved=1 raw_kernel=1\n");return 0;
}
