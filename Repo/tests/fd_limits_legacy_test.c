#include "sys/resource.h"
#include "usyscall.h"
#include "serial.h"
#include "stdlib.h"
#include "string.h"
#include "errno.h"
int main(void)
{
    struct rlimit *limits=calloc(3,sizeof(*limits));if(!limits)return 1;
    if(sys_file_io(SYSCALL_FILE_GET_LIMIT,RLIMIT_NOFILE,(uintptr_t)&limits[0],sizeof(*limits),0))return 2;
    limits[1]=(struct rlimit){0,0};
    if(getrlimit(RLIMIT_NOFILE,&limits[1])!=-1 || errno!=ENOTSUP || limits[1].rlim_cur || limits[1].rlim_max ||
        setrlimit(RLIMIT_NOFILE,&limits[1])!=-1 || errno!=ENOTSUP)return 3;
    if(sys_file_io(SYSCALL_FILE_GET_LIMIT,RLIMIT_NOFILE,(uintptr_t)&limits[2],sizeof(*limits),0) || memcmp(&limits[0],&limits[2],sizeof(*limits)))return 4;
    if(getrlimit(RLIMIT_AS,&limits[1]) || limits[1].rlim_cur!=RLIM_INFINITY || limits[1].rlim_max!=RLIM_INFINITY)return 5;
    free(limits);serial_printf("FD_LIMITS_LEGACY_TEST: PASS unsupported=1 private_preserved=1 as_query=1\n");return 0;
}
