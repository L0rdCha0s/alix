#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "memory_layout.h"

typedef struct process process_t;

bool elf_validate_image(const uint8_t *image, size_t size, uintptr_t *entry_out);

uint64_t process_get_pid(const process_t *process)
{
    (void)process;
    return 0;
}

/* Link stubs for the loading half of src/kernel/elf.c. Validation never calls
 * either function. */
bool process_map_user_segment(process_t *process,
                              uintptr_t user_base,
                              size_t bytes,
                              bool writable,
                              bool executable,
                              void **host_ptr_out)
{
    (void)process;
    (void)user_base;
    (void)bytes;
    (void)writable;
    (void)executable;
    (void)host_ptr_out;
    return false;
}

void serial_printf(const char *format, ...)
{
    (void)format;
}

memory_layout_t g_mem_layout = {
    .user_pointer_base = USER_DEFAULT_POINTER_BASE,
    .user_pointer_limit = USER_DEFAULT_POINTER_LIMIT,
};

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
} __attribute__((packed)) test_ehdr_t;

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
} __attribute__((packed)) test_phdr_t;

typedef struct
{
    test_ehdr_t ehdr;
    test_phdr_t phdr;
    uint8_t payload[32];
} test_image_t;

static test_image_t valid_image(void)
{
    test_image_t image;
    memset(&image, 0, sizeof(image));
    image.ehdr.magic = 0x464C457FU;
    image.ehdr.class_id = 2;
    image.ehdr.data = 1;
    image.ehdr.type = 2;
    image.ehdr.machine = 0x3E;
    image.ehdr.entry = USER_DEFAULT_POINTER_BASE + 0x1000;
    image.ehdr.phoff = sizeof(test_ehdr_t);
    image.ehdr.phentsize = sizeof(test_phdr_t);
    image.ehdr.phnum = 1;
    image.phdr.type = 1;
    image.phdr.flags = 0x5;
    image.phdr.offset = sizeof(test_ehdr_t) + sizeof(test_phdr_t);
    image.phdr.vaddr = USER_DEFAULT_POINTER_BASE + 0x1000;
    image.phdr.filesz = sizeof(image.payload);
    image.phdr.memsz = 0x1000;
    return image;
}

static int expect(bool condition, const char *name)
{
    if (!condition)
    {
        fprintf(stderr, "FAIL: %s\n", name);
        return 1;
    }
    return 0;
}

int main(void)
{
    int failures = 0;
    uintptr_t entry = 0;
    test_image_t image = valid_image();
    failures += expect(elf_validate_image((const uint8_t *)&image, sizeof(image), &entry),
                       "valid executable");
    failures += expect(entry == image.ehdr.entry, "validated entry");

    image = valid_image();
    image.phdr.filesz = image.phdr.memsz + 1;
    failures += expect(!elf_validate_image((const uint8_t *)&image, sizeof(image), NULL),
                       "filesz exceeds memsz");

    image = valid_image();
    image.phdr.offset = UINT64_MAX - 4;
    failures += expect(!elf_validate_image((const uint8_t *)&image, sizeof(image), NULL),
                       "file range overflow");

    image = valid_image();
    image.phdr.vaddr = UINT64_MAX - 0x100;
    image.phdr.memsz = 0x1000;
    image.ehdr.entry = image.phdr.vaddr;
    failures += expect(!elf_validate_image((const uint8_t *)&image, sizeof(image), NULL),
                       "virtual range overflow");

    image = valid_image();
    image.phdr.vaddr = USER_DEFAULT_POINTER_BASE - 0x1000;
    image.ehdr.entry = image.phdr.vaddr;
    failures += expect(!elf_validate_image((const uint8_t *)&image, sizeof(image), NULL),
                       "below user range");

    image = valid_image();
    image.phdr.flags = 0x4;
    failures += expect(!elf_validate_image((const uint8_t *)&image, sizeof(image), NULL),
                       "entry requires executable segment");

    image = valid_image();
    image.ehdr.entry = image.phdr.vaddr + image.phdr.memsz;
    failures += expect(!elf_validate_image((const uint8_t *)&image, sizeof(image), NULL),
                       "entry at segment end");

    image = valid_image();
    image.ehdr.phoff = UINT64_MAX;
    failures += expect(!elf_validate_image((const uint8_t *)&image, sizeof(image), NULL),
                       "program header range overflow");

    image = valid_image();
    image.phdr.vaddr = USER_DEFAULT_POINTER_LIMIT - 0xFFF;
    image.phdr.memsz = 0x1000;
    image.phdr.filesz = sizeof(image.payload);
    image.ehdr.entry = image.phdr.vaddr;
    failures += expect(elf_validate_image((const uint8_t *)&image, sizeof(image), NULL),
                       "segment may end one byte beyond inclusive limit");

    if (failures == 0)
    {
        puts("elf validation tests passed");
    }
    return failures ? 1 : 0;
}
