#include "atk_internal.h"
#ifdef KERNEL_BUILD
#include "serial.h"
#include "spinlock.h"
#endif

static void atk_guard_log(const char *label, uint64_t front, uint64_t back)
{
#ifdef KERNEL_BUILD
    serial_write_string("atk_guard violation: ");
    serial_write_string(label ? label : "unknown");
    serial_write_string(" front=0x");
    serial_write_hex64(front);
    serial_write_string(" back=0x");
    serial_write_hex64(back);
    serial_write_string("\r\n");
#else
    (void)label;
    (void)front;
    (void)back;
#endif
}

void atk_guard_reset(uint64_t *front, uint64_t *back)
{
    if (front)
    {
        *front = ATK_GUARD_MAGIC;
    }
    if (back)
    {
        *back = ATK_GUARD_MAGIC;
    }
}

void atk_guard_check(uint64_t *front, uint64_t *back, const char *label)
{
    if (!front || !back)
    {
        return;
    }
    if (*front == ATK_GUARD_MAGIC && *back == ATK_GUARD_MAGIC)
    {
        return;
    }
    atk_guard_log(label, *front, *back);
    atk_guard_reset(front, back);
}

void atk_state_guard_init(atk_state_t *state)
{
    if (!state)
    {
        return;
    }
    atk_guard_reset(&state->windows_guard_front, &state->windows_guard_back);
    atk_guard_reset(&state->desktop_guard_front, &state->desktop_guard_back);
    atk_guard_reset(&state->menu_guard_front, &state->menu_guard_back);
    atk_guard_reset(&state->theme_guard_front, &state->theme_guard_back);
    state->theme_crc = 0;
}

static uint64_t atk_theme_checksum(const atk_theme_t *theme)
{
    if (!theme)
    {
        return 0;
    }
    const uint8_t *bytes = (const uint8_t *)theme;
    size_t count = sizeof(*theme);
    uint64_t hash = 0xCBF29CE484222325ULL;
    for (size_t i = 0; i < count; ++i)
    {
        hash ^= bytes[i];
        hash *= 0x100000001B3ULL;
    }
    return hash;
}

#if ATK_DEBUG && defined(KERNEL_BUILD)
static void atk_theme_log_values(const atk_theme_t *theme, const char *label)
{
    if (!theme)
    {
        return;
    }
    serial_write_string("[atk][theme] ");
    serial_write_string(label ? label : "values");
    serial_write_string(" bg=0x");
    serial_write_hex64(theme->background);
    serial_write_string(" icon_face=0x");
    serial_write_hex64(theme->desktop_icon_face);
    serial_write_string(" icon_text=0x");
    serial_write_hex64(theme->desktop_icon_text);
    serial_write_string(" title=0x");
    serial_write_hex64(theme->window_title);
    serial_write_string(" body=0x");
    serial_write_hex64(theme->window_body);
    serial_write_string(" menu_face=0x");
    serial_write_hex64(theme->menu_bar_face);
    serial_write_string(" menu_text=0x");
    serial_write_hex64(theme->menu_bar_text);
    serial_write_string("\r\n");
}
#endif /* ATK_DEBUG && KERNEL_BUILD */

#if ATK_DEBUG
void atk_state_theme_log(const atk_state_t *state, const char *label)
{
#if defined(KERNEL_BUILD)
    if (state)
    {
        atk_theme_log_values(&state->theme, label);
    }
#else
    (void)state;
    (void)label;
#endif
}
#endif /* ATK_DEBUG */

void atk_state_theme_commit(atk_state_t *state)
{
    if (!state)
    {
        return;
    }
    state->theme_crc = atk_theme_checksum(&state->theme);
    atk_guard_reset(&state->theme_guard_front, &state->theme_guard_back);
}

bool atk_state_theme_validate(const atk_state_t *state, const char *label)
{
    if (!state)
    {
        return false;
    }

    atk_guard_check((uint64_t *)&state->theme_guard_front, (uint64_t *)&state->theme_guard_back, label ? label : "state->theme");

    if (state->theme_crc == 0)
    {
        return true;
    }

    uint64_t actual = atk_theme_checksum(&state->theme);
    if (actual == state->theme_crc)
    {
        return true;
    }

#if ATK_DEBUG && defined(KERNEL_BUILD)
    serial_write_string("[atk][theme] checksum mismatch");
    if (label)
    {
        serial_write_string(" label=");
        serial_write_string(label);
    }
    serial_write_string(" expected=0x");
    serial_write_hex64(state->theme_crc);
    serial_write_string(" actual=0x");
    serial_write_hex64(actual);
    serial_write_string("\r\n");
    atk_theme_log_values(&state->theme, "current");
#else
    (void)label;
#endif
    return false;
}
atk_state_t *atk_state_get(void)
{
    static atk_state_t state;
    return &state;
}

atk_widget_t *atk_state_mouse_capture(const atk_state_t *state)
{
    return state ? state->mouse_capture_widget : NULL;
}

void atk_state_set_mouse_capture(atk_state_t *state, atk_widget_t *widget)
{
    if (!state)
    {
        return;
    }
    state->mouse_capture_widget = widget;
}

void atk_state_release_mouse_capture(atk_state_t *state, const atk_widget_t *widget)
{
    if (!state)
    {
        return;
    }
    if (!widget || state->mouse_capture_widget == widget)
    {
        state->mouse_capture_widget = NULL;
    }
}

atk_widget_t *atk_state_focus_widget(const atk_state_t *state)
{
    return state ? state->focus_widget : NULL;
}

void atk_state_set_focus_widget(atk_state_t *state, atk_widget_t *widget)
{
    if (!state)
    {
        return;
    }
    state->focus_widget = widget;
}
#ifdef KERNEL_BUILD
static spinlock_t g_atk_lock;
static bool g_atk_lock_ready = false;

static inline void atk_global_lock_ensure(void)
{
    if (!g_atk_lock_ready)
    {
        spinlock_init(&g_atk_lock);
        g_atk_lock_ready = true;
    }
}

void atk_state_lock_init(void)
{
    atk_global_lock_ensure();
}

uint64_t atk_state_lock_acquire(void)
{
    atk_global_lock_ensure();
    uint64_t flags;
    __asm__ volatile ("pushfq; pop %0" : "=r"(flags));
    __asm__ volatile ("cli" ::: "memory");
    spinlock_lock(&g_atk_lock);
    return flags;
}

void atk_state_lock_release(uint64_t flags)
{
    spinlock_unlock(&g_atk_lock);
    __asm__ volatile ("push %0; popfq" :: "r"(flags) : "cc");
}
#else
void atk_state_lock_init(void)
{
}

uint64_t atk_state_lock_acquire(void)
{
    return 0;
}

void atk_state_lock_release(uint64_t flags)
{
    (void)flags;
}
#endif
