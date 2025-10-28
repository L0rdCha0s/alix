#include "idt.h"
#include "libc.h"

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

static struct idt_entry idt[256];

void idt_init(void)
{
    memset(idt, 0, sizeof(idt));
}

void idt_set_gate(uint8_t vector, void (*handler)(void))
{
    uint64_t addr = (uint64_t)handler;
    struct idt_entry *entry = &idt[vector];
    entry->offset_low = (uint16_t)(addr & 0xFFFF);
    entry->selector = 0x18;  /* 64-bit code segment */
    entry->ist = 0;
    entry->type_attr = 0x8E;
    entry->offset_mid = (uint16_t)((addr >> 16) & 0xFFFF);
    entry->offset_high = (uint32_t)((addr >> 32) & 0xFFFFFFFF);
    entry->zero = 0;
}

void idt_load(void)
{
    struct idt_ptr descriptor;
    descriptor.limit = sizeof(idt) - 1;
    descriptor.base = (uint64_t)&idt[0];
    __asm__ volatile ("lidt %0" : : "m"(descriptor));
}
