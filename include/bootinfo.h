#ifndef BOOTINFO_H
#define BOOTINFO_H

#include <stdint.h>

#define BOOTINFO_MAGIC 0x414C4958U
#define BOOTINFO_VERSION 2U
#define BOOTINFO_MAX_E820_ENTRIES 128U

typedef struct
{
    uint64_t base;
    uint64_t length;
    uint32_t type;
    uint32_t attr;
} bootinfo_e820_entry_t;

typedef struct
{
    uint32_t magic;
    uint32_t version;
    uint32_t e820_entry_count;
    bootinfo_e820_entry_t e820[BOOTINFO_MAX_E820_ENTRIES];

    uint8_t framebuffer_enabled;
    uint8_t framebuffer_reserved[3];
    uint32_t framebuffer_width;
    uint32_t framebuffer_height;
    uint32_t framebuffer_pitch;
    uint32_t framebuffer_bpp;
    uint64_t framebuffer_base;
    uint64_t framebuffer_size;

    uint64_t acpi_rsdp;
    uint32_t acpi_rsdp_length;
    uint8_t  acpi_rsdp_data[64];
} bootinfo_t;

extern bootinfo_t boot_info;

#endif /* BOOTINFO_H */
