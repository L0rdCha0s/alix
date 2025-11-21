#include "idt.h"
#include "libc.h"
#include "heap.h"
#include "serial.h"
#include <stddef.h>

struct idt_entry
{
    uint16_t offset_low;
    uint16_t selector;
    uint8_t ist;
    uint8_t type_attr;
    uint16_t offset_mid;
    uint32_t offset_high;
    uint32_t zero;
} __attribute__((packed));

struct idt_ptr
{
    uint16_t limit;
    uint64_t base;
} __attribute__((packed));

static struct idt_entry *idt = NULL;

uintptr_t idt_current_base(void)
{
    return (uintptr_t)idt;
}
void idt_init(void)
{
    size_t idt_bytes = sizeof(struct idt_entry) * 256;
    if (!idt)
    {
        serial_printf("%s", "IDT alloc request\r\n");
        idt = malloc(idt_bytes);
        serial_printf("IDT alloc ptr=%016llX\r\n", (unsigned long long)((uint64_t)idt));
        if (!idt)
        {
            serial_printf("%s", "IDT allocation failed\r\n");
            for (;;)
            {
                __asm__ volatile ("hlt");
            }
        }
    }
    serial_printf("IDT memset ptr=%016llX\r\n", (unsigned long long)((uint64_t)idt));
    memset(idt, 0, idt_bytes);
}

void idt_set_gate_dpl(uint8_t vector, void (*handler)(void), uint8_t dpl)
{
    uint64_t addr = (uint64_t)handler;
    struct idt_entry *entry = &idt[vector];
    entry->offset_low = (uint16_t)(addr & 0xFFFF);
    entry->selector = 0x18;  /* 64-bit code segment */
    entry->ist = 0;
    uint8_t attr = 0x8E;
    attr &= (uint8_t)~0x60;
    attr |= (uint8_t)((dpl & 0x3u) << 5);
    entry->type_attr = attr;
    entry->offset_mid = (uint16_t)((addr >> 16) & 0xFFFF);
    entry->offset_high = (uint32_t)((addr >> 32) & 0xFFFFFFFF);
    entry->zero = 0;
}

void idt_set_gate(uint8_t vector, void (*handler)(void))
{
    idt_set_gate_dpl(vector, handler, 0);
}

void idt_load(void)
{
    struct idt_ptr descriptor;
    descriptor.limit = (uint16_t)(sizeof(struct idt_entry) * 256 - 1);
    descriptor.base = (uint64_t)idt;
    __asm__ volatile ("lidt %0" : : "m"(descriptor));
}
