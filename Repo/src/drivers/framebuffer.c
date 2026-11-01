#include "framebuffer.h"
#include "ioremap.h"

static volatile uint32_t *g_mapping;

static bool channel_valid(uint32_t mask)
{
    if (!mask) return false;
    uint32_t bits = mask >> __builtin_ctz(mask);
    return !(bits & (bits + 1));
}

bool framebuffer_valid(const bootinfo_t *info)
{
    if (!info || !info->framebuffer_enabled || info->framebuffer_bpp != 32 ||
        !info->framebuffer_base || !info->framebuffer_width || !info->framebuffer_height ||
        info->framebuffer_width > 8192 || info->framebuffer_height > 8192 ||
        info->framebuffer_pitch < info->framebuffer_width || info->framebuffer_pitch > 16384 ||
        (uint64_t)info->framebuffer_width * info->framebuffer_height > 16 * 1024 * 1024 ||
        (uint64_t)info->framebuffer_pitch * info->framebuffer_height * 4 > info->framebuffer_size ||
        info->framebuffer_base + info->framebuffer_size < info->framebuffer_base)
        return false;
    uint32_t r = info->framebuffer_red_mask, g = info->framebuffer_green_mask, b = info->framebuffer_blue_mask;
    return channel_valid(r) && channel_valid(g) && channel_valid(b) && !(r & g) && !(r & b) && !(g & b);
}

volatile uint32_t *framebuffer_map(void)
{
    if (!framebuffer_valid(&boot_info)) return 0;
    if (!g_mapping) g_mapping = ioremap(boot_info.framebuffer_base,
        (size_t)boot_info.framebuffer_pitch * boot_info.framebuffer_height * 4);
    return g_mapping;
}
