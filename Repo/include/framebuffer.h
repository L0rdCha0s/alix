#ifndef FRAMEBUFFER_H
#define FRAMEBUFFER_H
#include "bootinfo.h"
#include <stdbool.h>
#include <stdint.h>

bool framebuffer_valid(const bootinfo_t *info);
volatile uint32_t *framebuffer_map(void); /* after paging/ioremap initialization */
static inline uint32_t framebuffer_channel(uint8_t channel, uint32_t mask)
{
    if (!mask) return 0;
    unsigned shift = __builtin_ctz(mask);
    uint32_t maximum = mask >> shift;
    return (uint32_t)(((uint64_t)channel * maximum + 127) / 255) << shift;
}
static inline uint32_t framebuffer_pack(uint32_t rgb)
{
    return framebuffer_channel(rgb >> 16, boot_info.framebuffer_red_mask) |
           framebuffer_channel(rgb >> 8, boot_info.framebuffer_green_mask) |
           framebuffer_channel(rgb, boot_info.framebuffer_blue_mask);
}
#endif
