#include "arch/x86/bootlayout.h"
#include "bootinfo.h"
#include "uefi.h"

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define EFI_PAGE_SIZE 4096ULL
#define EFI_SIZE_TO_PAGES(x) (((x) + EFI_PAGE_SIZE - 1) / EFI_PAGE_SIZE)

#define KERNEL_PATH L"\\alix.elf"

#define PT_LOAD 1U

typedef struct __attribute__((packed))
{
    uint8_t  e_ident[16];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint64_t e_entry;
    uint64_t e_phoff;
    uint64_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
} elf64_ehdr_t;

typedef struct __attribute__((packed))
{
    uint32_t p_type;
    uint32_t p_flags;
    uint64_t p_offset;
    uint64_t p_vaddr;
    uint64_t p_paddr;
    uint64_t p_filesz;
    uint64_t p_memsz;
    uint64_t p_align;
} elf64_phdr_t;

static EFI_SYSTEM_TABLE *g_st = NULL;
static EFI_BOOT_SERVICES *g_bs = NULL;

typedef void (*kernel_entry_t)(bootinfo_t *) __attribute__((sysv_abi));

typedef struct __attribute__((packed))
{
    char     signature[8];
    uint8_t  checksum;
    char     oem_id[6];
    uint8_t  revision;
    uint32_t rsdt_address;
} loader_acpi_rsdp_v1_t;

typedef struct __attribute__((packed))
{
    loader_acpi_rsdp_v1_t first;
    uint32_t length;
    uint64_t xsdt_address;
    uint8_t  extended_checksum;
    uint8_t  reserved[3];
} loader_acpi_rsdp_v2_t;

static EFI_GUID g_loaded_image_guid = EFI_LOADED_IMAGE_PROTOCOL_GUID;
static EFI_GUID g_simple_fs_guid = EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID;
static EFI_GUID g_file_info_guid = EFI_FILE_INFO_ID_GUID;
static EFI_GUID g_gop_guid = EFI_GRAPHICS_OUTPUT_PROTOCOL_GUID;
static EFI_GUID g_acpi20_guid = EFI_ACPI_20_TABLE_GUID;
static EFI_GUID g_acpi10_guid = EFI_ACPI_TABLE_GUID;

static void console_write(const CHAR16 *message)
{
    if (!g_st || !g_st->ConOut || !message)
    {
        return;
    }
    g_st->ConOut->OutputString(g_st->ConOut, message);
}

static void console_write_hex(uint64_t value)
{
    CHAR16 digits[17];
    for (int i = 15; i >= 0; --i)
    {
        uint8_t nibble = (uint8_t)(value & 0xF);
        digits[i] = (CHAR16)((nibble < 10) ? (L'0' + nibble) : (L'A' + (nibble - 10)));
        value >>= 4;
    }
    digits[16] = L'\0';
    console_write(digits);
}

static void panic(const CHAR16 *message) __attribute__((noreturn));
static void panic(const CHAR16 *message)
{
    console_write(L"[alix] loader panic: ");
    console_write(message);
    console_write(L"\r\n");
    for (;;)
    {
        __asm__ volatile ("hlt");
    }
}

static inline bool efi_error(EFI_STATUS status)
{
    return (status & EFIERR(0)) != 0;
}

static void zero_memory(void *ptr, size_t len)
{
    uint8_t *p = (uint8_t *)ptr;
    while (len--)
    {
        *p++ = 0;
    }
}

static void copy_memory(void *dst, const void *src, size_t len)
{
    uint8_t *d = (uint8_t *)dst;
    const uint8_t *s = (const uint8_t *)src;
    while (len--)
    {
        *d++ = *s++;
    }
}

static inline void outb(uint16_t port, uint8_t value)
{
    __asm__ volatile ("outb %0, %1" :: "a"(value), "Nd"(port));
}

static inline uint8_t inb(uint16_t port)
{
    uint8_t value;
    __asm__ volatile ("inb %1, %0" : "=a"(value) : "Nd"(port));
    return value;
}

static void serial_early_write_char(char c);

static void serial_early_init(void)
{
    static bool initialized = false;
    if (initialized)
    {
        return;
    }
    const uint16_t com1 = 0x3F8;
    outb(com1 + 1, 0x00);
    outb(com1 + 3, 0x80);
    outb(com1 + 0, 0x01);
    outb(com1 + 1, 0x00);
    outb(com1 + 3, 0x03);
    outb(com1 + 2, 0xC7);
    outb(com1 + 4, 0x0B);
    initialized = true;
}

static void serial_early_write_char(char c)
{
    const uint16_t com1 = 0x3F8;
    while ((inb(com1 + 5) & 0x20) == 0)
    {
    }
    outb(com1, (uint8_t)c);
}

static void serial_early_write_string(const char *s)
{
    if (!s)
    {
        return;
    }
    while (*s)
    {
        if (*s == '\n')
        {
            serial_early_write_char('\r');
        }
        serial_early_write_char(*s++);
    }
}

static void serial_early_write_hex64(uint64_t value)
{
    for (int shift = 60; shift >= 0; shift -= 4)
    {
        uint8_t nibble = (uint8_t)((value >> shift) & 0xF);
        char hex_char = (char)(nibble < 10 ? ('0' + nibble) : ('A' + (nibble - 10)));
        serial_early_write_char(hex_char);
    }
}

static EFI_STATUS try_open_volume(EFI_HANDLE handle, EFI_FILE_PROTOCOL **root)
{
    EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *fs = NULL;
    EFI_STATUS status = g_bs->HandleProtocol(handle, &g_simple_fs_guid, (void **)&fs);
    if (efi_error(status) || !fs)
    {
        return status;
    }
    status = fs->OpenVolume(fs, root);
    return status;
}

static void panic_status(const CHAR16 *message, EFI_STATUS status) __attribute__((noreturn));
static void panic_status(const CHAR16 *message, EFI_STATUS status)
{
    console_write(message);
    console_write(L": 0x");
    console_write_hex(status);
    console_write(L"\r\n");
    panic(L"(see above)");
}

static void log_line(const CHAR16 *message)
{
    console_write(message);
    console_write(L"\r\n");
}

static void log_hex(const CHAR16 *prefix, uint64_t value)
{
    console_write(prefix);
    console_write(L"0x");
    console_write_hex(value);
    console_write(L"\r\n");
}


static EFI_STATUS locate_fs_handles(EFI_HANDLE **handles, UINTN *handle_count)
{
    const UINTN max_attempts = 64;
    for (UINTN attempt = 0; attempt < max_attempts; ++attempt)
    {
        EFI_STATUS status = g_bs->LocateHandleBuffer(ByProtocol,
                                                     &g_simple_fs_guid,
                                                     NULL,
                                                     handle_count,
                                                     handles);
        if (!efi_error(status))
        {
            console_write(L"LocateHandle success, count=0x");
            console_write_hex(*handle_count);
            console_write(L"\r\n");
            if (*handle_count > 0)
            {
                return EFI_SUCCESS;
            }
            status = EFI_NOT_FOUND;
        }

        console_write(L"LocateHandle attempt ");
        console_write_hex(attempt);
        console_write(L" status 0x");
        console_write_hex(status);
        console_write(L"\r\n");

        if (status != EFI_NOT_READY && status != EFI_NOT_FOUND && status != EFI_TIMEOUT)
        {
            return status;
        }

        if (g_bs->Stall)
        {
            g_bs->Stall(5000);
        }
        else
        {
            for (volatile UINTN spin = 0; spin < 100000; ++spin)
            {
            }
        }
    }
    return EFI_NOT_READY;
}

static EFI_STATUS open_root_volume(EFI_HANDLE image_handle, EFI_FILE_PROTOCOL **root)
{
    EFI_LOADED_IMAGE_PROTOCOL *loaded = NULL;
    EFI_STATUS status = g_bs->HandleProtocol(image_handle, &g_loaded_image_guid, (void **)&loaded);
    if (efi_error(status) || !loaded)
    {
        panic_status(L"HandleProtocol(LIP) failed", status);
    }

    if (g_bs->ConnectController)
    {
        console_write(L"Connecting controller...\r\n");
        status = g_bs->ConnectController(loaded->DeviceHandle, NULL, NULL, 1);
        if (efi_error(status))
        {
            console_write(L"ConnectController failed: 0x");
            console_write_hex(status);
            console_write(L"\r\n");
        }
    }

    status = try_open_volume(loaded->DeviceHandle, root);
    if (!efi_error(status) && *root)
    {
        return EFI_SUCCESS;
    }

    EFI_HANDLE *handles = NULL;
    UINTN handle_count = 0;
    status = locate_fs_handles(&handles, &handle_count);
    if (efi_error(status) || !handles)
    {
        panic_status(L"LocateHandleBuffer(SFS) failed", status);
    }

    for (UINTN i = 0; i < handle_count; ++i)
    {
        EFI_FILE_PROTOCOL *volume = NULL;
        console_write(L"Trying FS handle 0x");
        console_write_hex((uint64_t)(uintptr_t)handles[i]);
        console_write(L"\r\n");
        status = try_open_volume(handles[i], &volume);
        if (!efi_error(status) && volume)
        {
            *root = volume;
            g_bs->FreePool(handles);
            return EFI_SUCCESS;
        }
        console_write(L"  Open failed: 0x");
        console_write_hex(status);
        console_write(L"\r\n");
    }

    g_bs->FreePool(handles);
    panic_status(L"No filesystem handles opened", status);
    return status;
}

static EFI_STATUS read_entire_file(EFI_FILE_PROTOCOL *file, void **buffer, UINTN *size)
{
    if (!file || !buffer || !size)
    {
        return EFI_INVALID_PARAMETER;
    }

    UINTN info_size = 0;
    EFI_STATUS status = file->GetInfo(file, &g_file_info_guid, &info_size, NULL);
    if (status != EFI_BUFFER_TOO_SMALL)
    {
        return status;
    }

    EFI_FILE_INFO *info = NULL;
    status = g_bs->AllocatePool(EfiLoaderData, info_size, (void **)&info);
    if (efi_error(status) || !info)
    {
        return status;
    }

    status = file->GetInfo(file, &g_file_info_guid, &info_size, info);
    if (efi_error(status))
    {
        g_bs->FreePool(info);
        return status;
    }

    UINTN file_size = (UINTN)info->FileSize;
    g_bs->FreePool(info);

    void *file_buffer = NULL;
    status = g_bs->AllocatePool(EfiLoaderData, file_size, &file_buffer);
    if (efi_error(status) || !file_buffer)
    {
        return status;
    }

    status = file->Read(file, &file_size, file_buffer);
    if (efi_error(status))
    {
        g_bs->FreePool(file_buffer);
        return status;
    }

    *buffer = file_buffer;
    *size = file_size;
    return EFI_SUCCESS;
}

static EFI_STATUS load_kernel_segments(const uint8_t *image,
                                       UINTN image_size,
                                       kernel_entry_t *entry_out)
{
    if (image_size < sizeof(elf64_ehdr_t))
    {
        return EFI_LOAD_ERROR;
    }

    const elf64_ehdr_t *eh = (const elf64_ehdr_t *)image;
    if (eh->e_ident[0] != 0x7F || eh->e_ident[1] != 'E' ||
        eh->e_ident[2] != 'L' || eh->e_ident[3] != 'F')
    {
        return EFI_LOAD_ERROR;
    }
    if (eh->e_ident[4] != 2 || eh->e_ident[5] != 1)
    {
        return EFI_UNSUPPORTED;
    }
    if (eh->e_phoff == 0 || eh->e_phentsize != sizeof(elf64_phdr_t))
    {
        return EFI_LOAD_ERROR;
    }

    const elf64_phdr_t *ph = (const elf64_phdr_t *)(image + eh->e_phoff);
    for (uint16_t i = 0; i < eh->e_phnum; ++i, ++ph)
    {
        if (ph->p_type != PT_LOAD)
        {
            continue;
        }
        if (ph->p_offset + ph->p_filesz > image_size)
        {
            return EFI_LOAD_ERROR;
        }

        EFI_PHYSICAL_ADDRESS segment_start = ph->p_paddr & ~(EFI_PAGE_SIZE - 1);
        UINTN segment_pages = EFI_SIZE_TO_PAGES(ph->p_memsz + (ph->p_paddr - segment_start));
        EFI_STATUS status = g_bs->AllocatePages(EfiAllocateAddress, EfiLoaderData, segment_pages, &segment_start);
        if (efi_error(status))
        {
            return status;
        }

        uint8_t *dest = (uint8_t *)(uintptr_t)(ph->p_paddr);
        const uint8_t *src = image + ph->p_offset;
        copy_memory(dest, src, (size_t)ph->p_filesz);
        if (ph->p_memsz > ph->p_filesz)
        {
            zero_memory(dest + ph->p_filesz, (size_t)(ph->p_memsz - ph->p_filesz));
        }
    }

    if (entry_out)
    {
        *entry_out = (kernel_entry_t)(uintptr_t)(eh->e_entry);
    }
    return EFI_SUCCESS;
}

static uint32_t efi_type_to_e820(uint32_t type)
{
    switch (type)
    {
        case EfiConventionalMemory:
        case EfiLoaderCode:
        case EfiLoaderData:
        case EfiBootServicesCode:
        case EfiBootServicesData:
            return 1;
        case EfiACPIReclaimMemory:
            return 3;
        case EfiACPIMemoryNVS:
            return 4;
        default:
            return 2;
    }
}

static bool guid_equal(const EFI_GUID *a, const EFI_GUID *b)
{
    if (!a || !b)
    {
        return false;
    }
    if (a->Data1 != b->Data1 || a->Data2 != b->Data2 || a->Data3 != b->Data3)
    {
        return false;
    }
    for (size_t i = 0; i < sizeof(a->Data4); ++i)
    {
        if (a->Data4[i] != b->Data4[i])
        {
            return false;
        }
    }
    return true;
}

static void capture_acpi_rsdp(bootinfo_t *info)
{
    if (!g_st || !info)
    {
        return;
    }
    for (UINTN i = 0; i < g_st->NumberOfTableEntries; ++i)
    {
        EFI_CONFIGURATION_TABLE *entry = &g_st->ConfigurationTable[i];
        if (!entry->VendorTable)
        {
            continue;
        }
        if (guid_equal(&entry->VendorGuid, &g_acpi20_guid) ||
            guid_equal(&entry->VendorGuid, &g_acpi10_guid))
        {
            info->acpi_rsdp = (uint64_t)(uintptr_t)entry->VendorTable;
            if (entry->VendorTable)
            {
                size_t copy_len = sizeof(info->acpi_rsdp_data);
                loader_acpi_rsdp_v1_t *rsdp1 = (loader_acpi_rsdp_v1_t *)entry->VendorTable;
                if (rsdp1->revision >= 2)
                {
                    loader_acpi_rsdp_v2_t *rsdp2 = (loader_acpi_rsdp_v2_t *)entry->VendorTable;
                    if (rsdp2->length != 0 && rsdp2->length < copy_len)
                    {
                        copy_len = rsdp2->length;
                    }
                }
                else
                {
                    if (sizeof(loader_acpi_rsdp_v1_t) < copy_len)
                    {
                        copy_len = sizeof(loader_acpi_rsdp_v1_t);
                    }
                }
                copy_memory(info->acpi_rsdp_data, entry->VendorTable, copy_len);
                info->acpi_rsdp_length = (uint32_t)copy_len;
            }
            return;
        }
    }
}

static void capture_framebuffer(bootinfo_t *info)
{
    if (!info)
    {
        return;
    }
    EFI_GRAPHICS_OUTPUT_PROTOCOL *gop = NULL;
    EFI_STATUS status = g_bs->LocateProtocol(&g_gop_guid, NULL, (void **)&gop);
    if (efi_error(status) || !gop || !gop->Mode || !gop->Mode->Info)
    {
        info->framebuffer_enabled = 0;
        return;
    }

    info->framebuffer_enabled = 1;
    info->framebuffer_base = (uint64_t)gop->Mode->FrameBufferBase;
    info->framebuffer_size = (uint64_t)gop->Mode->FrameBufferSize;
    info->framebuffer_width = gop->Mode->Info->HorizontalResolution;
    info->framebuffer_height = gop->Mode->Info->VerticalResolution;
    info->framebuffer_pitch = gop->Mode->Info->PixelsPerScanLine;
    switch (gop->Mode->Info->PixelFormat)
    {
        case PixelBlueGreenRedReserved8BitPerColor:
        case PixelRedGreenBlueReserved8BitPerColor:
        case PixelBitMask:
            info->framebuffer_bpp = 32;
            break;
        default:
            info->framebuffer_bpp = 0;
            break;
    }
}

static void reserve_region(EFI_PHYSICAL_ADDRESS base, uint64_t size)
{
    UINTN pages = EFI_SIZE_TO_PAGES(size);
    EFI_PHYSICAL_ADDRESS address = base & ~(EFI_PAGE_SIZE - 1);
    g_bs->AllocatePages(EfiAllocateAddress, EfiLoaderData, pages, &address);
}

static void reserve_kernel_regions(void)
{
    reserve_region(PAGE_TABLE_BASE, PAGE_TABLE_PAGES * EFI_PAGE_SIZE);
    reserve_region(STACK_TOP - STACK_SIZE, STACK_SIZE);
}


static void convert_to_e820(bootinfo_t *info,
                            EFI_MEMORY_DESCRIPTOR *map,
                            UINTN map_size,
                            UINTN descriptor_size)
{
    info->e820_entry_count = 0;
    UINTN entry_count = map_size / descriptor_size;
    uint8_t *cursor = (uint8_t *)map;
    for (UINTN i = 0; i < entry_count; ++i)
    {
        if (info->e820_entry_count >= BOOTINFO_MAX_E820_ENTRIES)
        {
            break;
        }
        EFI_MEMORY_DESCRIPTOR *desc = (EFI_MEMORY_DESCRIPTOR *)(cursor + (i * descriptor_size));
        bootinfo_e820_entry_t *entry = &info->e820[info->e820_entry_count++];
        entry->base = desc->PhysicalStart;
        entry->length = desc->NumberOfPages * EFI_PAGE_SIZE;
        entry->type = efi_type_to_e820(desc->Type);
        entry->attr = (uint32_t)(desc->Attribute & 0xFFFFFFFFULL);
    }
}

static EFI_STATUS exit_boot_services(EFI_HANDLE image_handle, bootinfo_t *info)
{
    if (!g_bs)
    {
        return EFI_LOAD_ERROR;
    }

    serial_early_init();
    serial_early_write_string("[alix-serial] exit boot services begin\n");

    if (g_bs->SetWatchdogTimer)
    {
        g_bs->SetWatchdogTimer(0, 0, 0, NULL);
    }

    EFI_MEMORY_DESCRIPTOR *map = NULL;
    UINTN map_size = 0;
    UINTN map_key = 0;
    UINTN descriptor_size = 0;
    uint32_t descriptor_version = 0;

    for (UINTN attempt = 1; attempt <= 64; ++attempt)
    {
        serial_early_write_string("[alix-serial] EBS attempt ");
        serial_early_write_hex64(attempt);
        serial_early_write_string("\n");

        UINTN size = map_size;
        EFI_STATUS status = g_bs->GetMemoryMap(&size, map, &map_key, &descriptor_size, &descriptor_version);
        if (status == EFI_BUFFER_TOO_SMALL)
        {
            size += descriptor_size * 2;
            serial_early_write_string("[alix-serial]  resizing map buffer to 0x");
            serial_early_write_hex64(size);
            serial_early_write_string("\n");

            if (map)
            {
                g_bs->FreePool(map);
                map = NULL;
            }
            map_size = size;
            status = g_bs->AllocatePool(EfiLoaderData, map_size, (void **)&map);
            if (efi_error(status) || !map)
            {
                serial_early_write_string("[alix-serial]  AllocatePool failed 0x");
                serial_early_write_hex64(status);
                serial_early_write_string("\n");
                return status;
            }
            continue;
        }
        else if (efi_error(status))
        {
            serial_early_write_string("[alix-serial]  GetMemoryMap error 0x");
            serial_early_write_hex64(status);
            serial_early_write_string("\n");
            if (map)
            {
                g_bs->FreePool(map);
            }
            return status;
        }

        map_size = size;
        convert_to_e820(info, map, map_size, descriptor_size);

        serial_early_write_string("[alix-serial]  calling ExitBootServices map_key 0x");
        serial_early_write_hex64(map_key);
        serial_early_write_string("\n");
        status = g_bs->ExitBootServices(image_handle, map_key);
        if (status == EFI_SUCCESS)
        {
            serial_early_write_string("[alix-serial] ExitBootServices success\n");
            return EFI_SUCCESS;
        }

        serial_early_write_string("[alix-serial] ExitBootServices retry status 0x");
        serial_early_write_hex64(status);
        serial_early_write_string("\n");

        if (status != EFI_INVALID_PARAMETER)
        {
            if (map)
            {
                g_bs->FreePool(map);
            }
            return status;
        }
    }

    if (map)
    {
        g_bs->FreePool(map);
    }
    return EFI_INVALID_PARAMETER;
}



EFI_STATUS EFIAPI efi_main(EFI_HANDLE image_handle, EFI_SYSTEM_TABLE *system_table)
{
    g_st = system_table;
    g_bs = system_table ? system_table->BootServices : NULL;
    if (!g_bs)
    {
        panic(L"Boot services unavailable");
    }

    serial_early_init();
    serial_early_write_string("[alix-serial] loader init\n");

    log_line(L"[alix] loader start");

    bootinfo_t boot_info;
    zero_memory(&boot_info, sizeof(boot_info));
    boot_info.magic = BOOTINFO_MAGIC;
    boot_info.version = BOOTINFO_VERSION;

    EFI_FILE_PROTOCOL *root = NULL;
    EFI_STATUS status = open_root_volume(image_handle, &root);
    if (efi_error(status) || !root)
    {
        panic(L"Failed to open root volume");
    }
    log_line(L"Root volume opened");

    EFI_FILE_PROTOCOL *kernel_file = NULL;
    status = root->Open(root, &kernel_file, KERNEL_PATH, EFI_FILE_MODE_READ, EFI_FILE_READ_ONLY);
    if (efi_error(status) || !kernel_file)
    {
        panic(L"Cannot open \\alix.elf");
    }
    log_line(L"Kernel file opened");

    void *kernel_buffer = NULL;
    UINTN kernel_size = 0;
    status = read_entire_file(kernel_file, &kernel_buffer, &kernel_size);
    kernel_file->Close(kernel_file);
    root->Close(root);
    if (efi_error(status) || !kernel_buffer)
    {
        panic(L"Kernel read failed");
    }
    log_hex(L"Kernel size: ", kernel_size);

    kernel_entry_t kernel_entry = NULL;
    log_line(L"Loading kernel segments");
    status = load_kernel_segments((const uint8_t *)kernel_buffer, kernel_size, &kernel_entry);
    g_bs->FreePool(kernel_buffer);
    if (efi_error(status) || !kernel_entry)
    {
        panic_status(L"Kernel image invalid", status);
    }
    log_line(L"Kernel segments loaded");

    capture_framebuffer(&boot_info);
    capture_acpi_rsdp(&boot_info);
    reserve_kernel_regions();
    log_line(L"System info captured");

    EFI_PHYSICAL_ADDRESS boot_info_phys = 0;
    status = g_bs->AllocatePages(EfiAllocateAnyPages,
                                 EfiLoaderData,
                                 EFI_SIZE_TO_PAGES(sizeof(bootinfo_t)),
                                 &boot_info_phys);
    if (efi_error(status))
    {
        panic(L"Failed to allocate bootinfo");
    }
    copy_memory((void *)(uintptr_t)boot_info_phys, &boot_info, sizeof(bootinfo_t));
    log_hex(L"Bootinfo at: ", boot_info_phys);

    log_line(L"Exiting boot services");
    status = exit_boot_services(image_handle, (bootinfo_t *)(uintptr_t)boot_info_phys);
    if (efi_error(status))
    {
        panic(L"ExitBootServices failed");
    }

    serial_early_write_string("[alix] about to init serial services\n");
    serial_early_init();
    serial_early_write_string("[alix] boot services exited\n");
    serial_early_write_string("[alix] kernel entry @ ");
    for (int shift = 60; shift >= 0; shift -= 4)
    {
        const uint64_t nibble = (((uint64_t)(uintptr_t)kernel_entry) >> shift) & 0xF;
        const char hex_char = (char)(nibble < 10 ? ('0' + nibble) : ('A' + (nibble - 10)));
        serial_early_write_char(hex_char);
    }
    serial_early_write_string(" bootinfo @ ");
    for (int shift = 60; shift >= 0; shift -= 4)
    {
        uint64_t nibble = (boot_info_phys >> shift) & 0xF;
        char hex_char = (char)(nibble < 10 ? ('0' + nibble) : ('A' + (nibble - 10)));
        serial_early_write_char(hex_char);
    }
    serial_early_write_string("\n");

    kernel_entry((bootinfo_t *)(uintptr_t)boot_info_phys);
    panic(L"Kernel returned");
}
