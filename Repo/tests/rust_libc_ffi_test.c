#include "stddef.h"
#include "serial.h"
#include "netdb.h"
#include "sys/select.h"
#include "sys/ioctl.h"
#include "sys/utsname.h"
#include "unistd.h"
#include "fcntl.h"
#include "sys/resource.h"
#include "netinet/in.h"
_Static_assert(sizeof(long) == 8 && sizeof(void *) == 8 && sizeof(wchar_t) == 2, "native Rust FFI ABI");
_Static_assert(sizeof(struct addrinfo) == 48 && offsetof(struct addrinfo, ai_addr) == 24, "native netdb ABI");
_Static_assert(sizeof(fd_set) == 32 && sizeof(struct timeval) == 16 && FD_SETSIZE == 256, "native select ABI");
_Static_assert(sizeof(struct winsize) == 8, "native winsize ABI");
int alix_rust_ioctl_abi(unsigned long readable,unsigned long nonblock,unsigned long set_close,
                        unsigned long clear_close,size_t win_size)
{ return readable==FIONREAD && nonblock==FIONBIO && set_close==FIOCLEX && clear_close==FIONCLEX && win_size==sizeof(struct winsize); }
int alix_rust_identity_abi(size_t size, size_t machine_offset, uint32_t uid, uint32_t gid)
{ return size==sizeof(struct utsname) && machine_offset==offsetof(struct utsname,machine) && uid==getuid() && gid==getgid(); }
int alix_rust_sync_abi(uint64_t flags) { return flags==(O_RDWR|O_CREAT|O_TRUNC|O_SYNC); }
int alix_rust_limit_abi(size_t bytes,int nofile,int address,uint64_t infinity,size_t multicast)
{ return bytes==sizeof(struct rlimit) && nofile==RLIMIT_NOFILE && address==RLIMIT_AS && infinity==RLIM_INFINITY && multicast==sizeof(struct ip_mreq); }
extern int alix_rust_libc_ffi_test(char, long, unsigned long, float, double, unsigned short, size_t);
int main(void)
{
    int result = alix_rust_libc_ffi_test(-7, (1L << 42) + 99, (1UL << 63) + 17,
                                          1.25f, -2.5, 0xd83d, (size_t)0x100000007ULL);
    if (result) { serial_printf("RUST_LIBC_FFI_TEST: FAIL stage=%d\n", result); return 1; }
    serial_printf("RUST_LIBC_FFI_TEST: PASS lp64=1 wchar16=1 heap=1 env=1 files=1 offset64=1 pipes=1 sockets=1 netdb=1 fsync=1 memory_pages=1 select=1 resize=1 realpath=1 rmdir=1 ioctl=1 identity=1 sync_open=1 fd_limits=1\n");
    return 0;
}
