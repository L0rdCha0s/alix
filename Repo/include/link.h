#ifndef ALIX_LINK_H
#define ALIX_LINK_H
#include "elf.h"
#include <stddef.h>
#define ElfW(type) Elf64_##type
struct dl_phdr_info
{
    Elf64_Addr dlpi_addr;
    const char *dlpi_name;
    const Elf64_Phdr *dlpi_phdr;
    Elf64_Half dlpi_phnum;
};
#ifdef __cplusplus
extern "C" {
#endif
int dl_iterate_phdr(int (*callback)(struct dl_phdr_info *, size_t, void *), void *context);
#ifdef __cplusplus
}
#endif
#endif
