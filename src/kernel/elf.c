#include "elf.h"

#include "libc.h"
#include "serial.h"

#define ELF_MAGIC 0x464C457FU
#define ELF_CLASS_64 2U
#define ELF_DATA_LSB 1U
#define ELF_TYPE_EXEC 2U
#define ELF_MACHINE_X86_64 0x3E
#define ELF_PH_TYPE_LOAD 1U
#define ELF_FLAG_EXEC 0x1U
#define ELF_FLAG_WRITE 0x2U

#define ELF_PAGE_SIZE 4096ULL

typedef struct
{
    uint32_t magic;
    uint8_t class_id;
    uint8_t data;
    uint8_t version;
    uint8_t os_abi;
    uint8_t abi_version;
    uint8_t pad[7];
    uint16_t type;
    uint16_t machine;
    uint32_t version2;
    uint64_t entry;
    uint64_t phoff;
    uint64_t shoff;
    uint32_t flags;
    uint16_t ehsize;
    uint16_t phentsize;
    uint16_t phnum;
    uint16_t shentsize;
    uint16_t shnum;
    uint16_t shstrndx;
} __attribute__((packed)) elf64_ehdr_t;

typedef struct
{
    uint32_t type;
    uint32_t flags;
    uint64_t offset;
    uint64_t vaddr;
    uint64_t paddr;
    uint64_t filesz;
    uint64_t memsz;
    uint64_t align;
} __attribute__((packed)) elf64_phdr_t;

static inline uintptr_t elf_align_down(uintptr_t value)
{
    return value & ~(ELF_PAGE_SIZE - 1ULL);
}

static inline size_t elf_align_up_size(size_t value)
{
    size_t mask = (size_t)(ELF_PAGE_SIZE - 1ULL);
    return (value + mask) & ~mask;
}

bool elf_load_process(process_t *process, const uint8_t *image, size_t size, uintptr_t *entry_out)
{
    if (!process || !image || size < sizeof(elf64_ehdr_t))
    {
        return false;
    }

    const elf64_ehdr_t *ehdr = (const elf64_ehdr_t *)image;
    if (ehdr->magic != ELF_MAGIC ||
        ehdr->class_id != ELF_CLASS_64 ||
        ehdr->data != ELF_DATA_LSB ||
        ehdr->type != ELF_TYPE_EXEC ||
        ehdr->machine != ELF_MACHINE_X86_64)
    {
        return false;
    }

    if (ehdr->phoff == 0 || ehdr->phentsize != sizeof(elf64_phdr_t))
    {
        return false;
    }

    if ((size_t)ehdr->phoff + (size_t)ehdr->phnum * sizeof(elf64_phdr_t) > size)
    {
        return false;
    }

    const elf64_phdr_t *phdr = (const elf64_phdr_t *)(image + ehdr->phoff);
    for (uint16_t i = 0; i < ehdr->phnum; ++i)
    {
        const elf64_phdr_t *ph = &phdr[i];
        if (ph->type != ELF_PH_TYPE_LOAD || ph->memsz == 0)
        {
            continue;
        }

        if (ph->offset + ph->filesz > size)
        {
            return false;
        }

        uintptr_t seg_start = (uintptr_t)ph->vaddr;
        uintptr_t seg_base = elf_align_down(seg_start);
        size_t seg_offset = (size_t)(seg_start - seg_base);
        size_t seg_size = elf_align_up_size((size_t)ph->memsz + seg_offset);

        bool writable = (ph->flags & ELF_FLAG_WRITE) != 0;
        bool executable = (ph->flags & ELF_FLAG_EXEC) != 0;

        void *host_ptr = NULL;
        if (!process_map_user_segment(process,
                                      seg_base,
                                      seg_size,
                                      writable,
                                      executable,
                                      &host_ptr))
        {
            return false;
        }

        uint8_t *dest = (uint8_t *)host_ptr + seg_offset;
        size_t file_bytes = (size_t)ph->filesz;
        if (file_bytes > 0)
        {
            memcpy(dest, image + ph->offset, file_bytes);
        }

        size_t remaining = (size_t)ph->memsz;
        if (file_bytes < remaining)
        {
            memset(dest + file_bytes, 0, remaining - file_bytes);
        }
    }

    if (entry_out)
    {
        *entry_out = (uintptr_t)ehdr->entry;
    }
    return true;
}
