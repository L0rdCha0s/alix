#include "stddef.h"
#include "serial.h"
#include "netdb.h"
#include "sys/select.h"
_Static_assert(sizeof(long) == 8 && sizeof(void *) == 8 && sizeof(wchar_t) == 2, "native Rust FFI ABI");
_Static_assert(sizeof(struct addrinfo) == 48 && offsetof(struct addrinfo, ai_addr) == 24, "native netdb ABI");
_Static_assert(sizeof(fd_set) == 32 && sizeof(struct timeval) == 16 && FD_SETSIZE == 256, "native select ABI");
extern int alix_rust_libc_ffi_test(char, long, unsigned long, float, double, unsigned short, size_t);
int main(void)
{
    int result = alix_rust_libc_ffi_test(-7, (1L << 42) + 99, (1UL << 63) + 17,
                                          1.25f, -2.5, 0xd83d, (size_t)0x100000007ULL);
    if (result) { serial_printf("RUST_LIBC_FFI_TEST: FAIL stage=%d\n", result); return 1; }
    serial_printf("RUST_LIBC_FFI_TEST: PASS lp64=1 wchar16=1 heap=1 env=1 files=1 offset64=1 pipes=1 sockets=1 netdb=1 fsync=1 memory_pages=1 select=1 resize=1 realpath=1 rmdir=1\n");
    return 0;
}
