#include "alix_network.h"
#include "syscall_defs.h"
#include "usyscall.h"
#include "stddef.h"
#include "stdlib.h"
#include "stdio.h"
#include "string.h"
#include "errno.h"
#include "sys/mman.h"

_Static_assert(sizeof(alix_net_route_info_t) == 24, "native route size");
_Static_assert(offsetof(alix_net_route_info_t, interface_name) == 16, "native route name");
static long raw_route(uint64_t destination, void *output, size_t bytes)
{
    long result;
    __asm__ volatile("int $0x80" : "=a"(result) : "a"((long)SYSCALL_NET_ROUTE),
                     "D"(destination), "S"(output), "d"(bytes) : "rcx", "r11", "memory");
    return result;
}
#define CHECK(c) do { if (!(c)) return __LINE__; } while (0)
int alix_route_api_test(void)
{
    alix_net_route_info_t *info = calloc(1, sizeof(*info));
    syscall_net_stats_t *interfaces = calloc(8, sizeof(*interfaces));
    CHECK(info && interfaces);
    CHECK(alix_net_route_ipv4(0x0a000202, info) == 0 && info->version == 1 && info->mtu == 1500);
    ssize_t count = sys_net_snapshot(interfaces, 8);
    CHECK(count > 0 && count <= 8);
    bool found = false;
    for (ssize_t i = 0; i < count; ++i)
        if (!strcmp(interfaces[i].name, info->interface_name))
        {
            CHECK(interfaces[i].present && interfaces[i].link_up &&
                  interfaces[i].ipv4_addr == info->source_ipv4);
            found = true;
        }
    CHECK(found && info->next_hop_ipv4 == 0x0a000202);
    printf("NATIVE_ROUTE_INFO: interface=%s source=0x%08x mtu=%u\n",
           info->interface_name, info->source_ipv4, info->mtu);
    CHECK(alix_net_route_ipv4(0x08080808, info) == 0 && info->next_hop_ipv4 == 0x0a000202);
    memset(info, 0xa5, sizeof(*info));
    CHECK(alix_net_route_ipv4(0x7f000001, info) == -1 && errno == ENETUNREACH);
    for (size_t i = 0; i < sizeof(*info); ++i) CHECK(((unsigned char *)info)[i] == 0xa5);
    CHECK(raw_route(0x100000000ull, info, sizeof(*info)) == -EINVAL);
    CHECK(raw_route(0x0a000202, info, sizeof(*info) - 1) == -EINVAL);
    CHECK(alix_net_route_ipv4(0x0a000202, NULL) == -1 && errno == EFAULT);
    CHECK(alix_net_route_ipv4(0x0a000202, (void *)1) == -1 && errno == EFAULT);
    unsigned char *pages = mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(pages != MAP_FAILED);
    memset(pages, 0xa5, 8192);
    alix_net_route_info_t *cross = (void *)(pages + 4096 - 12);
    CHECK(alix_net_route_ipv4(0x0a000202, cross) == 0 && cross->mtu == 1500);
    CHECK(mprotect(pages + 4096, 4096, PROT_READ) == 0);
    CHECK(alix_net_route_ipv4(0x0a000202, (void *)(pages + 4096)) == -1 && errno == EFAULT);
    CHECK(pages[4096 + 32] == 0xa5);
    CHECK(munmap(pages, 8192) == 0);
    free(interfaces); free(info);
    return 0;
}
