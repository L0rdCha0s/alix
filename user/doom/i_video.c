// AlixOS usermode video glue for DOOM.

#include "i_video.h"

#include "atk_user.h"
#include "doomdef.h"
#include "doomstat.h"
#include "d_main.h"
#include "m_argv.h"
#include "i_system.h"
#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "serial.h"
#include "types.h"
#include "usyscall.h"
#include "v_video.h"
#include "video_surface.h"
#include "video.h"

#define DOOM_DEFAULT_SCALE 2
#define DOOM_WINDOW_WIDTH  640
#define DOOM_WINDOW_HEIGHT 480

static atk_user_window_t g_window;
static bool g_window_ready = false;
static int g_scale = DOOM_DEFAULT_SCALE;
static video_color_t g_palette_rgba[256];
static video_color_t *g_frame_rgba = NULL;
static int g_last_mouse_x = -1;
static int g_last_mouse_y = -1;
static int g_mouse_buttons = 0;
static int g_target_fps = 30;
static uint64_t g_next_frame_ms = 0;

static void doom_video_pick_scale(void)
{
    if (M_CheckParm("-4"))
    {
        g_scale = 4;
    }
    else if (M_CheckParm("-3"))
    {
        g_scale = 3;
    }
    else if (M_CheckParm("-2"))
    {
        g_scale = 2;
    }
    if (g_scale < 1)
    {
        g_scale = 1;
    }
}

static void doom_video_pick_fps(void)
{
    if (M_CheckParm("-uncapped"))
    {
        g_target_fps = 0;
        return;
    }

    int idx = M_CheckParm("-fps");
    if (idx && idx + 1 < myargc)
    {
        int fps = atoi(myargv[idx + 1]);
        if (fps > 0 && fps <= 240)
        {
            g_target_fps = fps;
        }
    }

    if (g_target_fps < 0)
    {
        g_target_fps = 0;
    }
}

static void doom_frame_limiter_tick(void)
{
    if (g_target_fps <= 0)
    {
        return;
    }

    uint64_t frame_ms = (uint64_t)(1000 / g_target_fps);
    if (frame_ms == 0)
    {
        frame_ms = 1;
    }

    uint64_t now = sys_time_millis();
    if (g_next_frame_ms == 0)
    {
        g_next_frame_ms = now + frame_ms;
        return;
    }

    while (now < g_next_frame_ms)
    {
        sys_yield();
        now = sys_time_millis();
    }

    g_next_frame_ms += frame_ms;
    if (g_next_frame_ms < now)
    {
        g_next_frame_ms = now + frame_ms;
    }
}

static int doom_translate_scancode(uint32_t scancode)
{
    switch (scancode)
    {
        case 0x48: return KEY_UPARROW;
        case 0x50: return KEY_DOWNARROW;
        case 0x4B: return KEY_LEFTARROW;
        case 0x4D: return KEY_RIGHTARROW;
        case 0x01: return KEY_ESCAPE;
        case 0x0F: return KEY_TAB;
        case 0x1C: return KEY_ENTER;
        case 0x0E: return KEY_BACKSPACE;
        case 0x3B: return KEY_F1;
        case 0x3C: return KEY_F2;
        case 0x3D: return KEY_F3;
        case 0x3E: return KEY_F4;
        case 0x3F: return KEY_F5;
        case 0x40: return KEY_F6;
        case 0x41: return KEY_F7;
        case 0x42: return KEY_F8;
        case 0x43: return KEY_F9;
        case 0x44: return KEY_F10;
        case 0x57: return KEY_F11;
        case 0x58: return KEY_F12;
        case 0x1D: return KEY_RCTRL;
        case 0x38: return KEY_RALT;
        case 0x2A:
        case 0x36: return KEY_RSHIFT;
        default:
            break;
    }
    return 0;
}

static int doom_translate_key(const user_atk_event_t *ev)
{
    if (!ev)
    {
        return 0;
    }

    int key = doom_translate_scancode(ev->data1);
    if (key)
    {
        return key;
    }

    unsigned char ch = (unsigned char)ev->data0;
    if (ch == 0)
    {
        // ATK key events sometimes arrive without a translated ASCII char.
        // Provide a minimal scancode->ASCII fallback for common DOOM binds.
        switch (ev->data1)
        {
            case 0x39: return ' '; // Space (default "use" key)

            // Number row 1..0 (weapon selection, etc.)
            case 0x02: return '1';
            case 0x03: return '2';
            case 0x04: return '3';
            case 0x05: return '4';
            case 0x06: return '5';
            case 0x07: return '6';
            case 0x08: return '7';
            case 0x09: return '8';
            case 0x0A: return '9';
            case 0x0B: return '0';

            // Unshifted punctuation on the number row.
            case 0x0C: return '-';
            case 0x0D: return '=';
            default:
                break;
        }
    }

    if (ch >= 'A' && ch <= 'Z')
    {
        ch = (unsigned char)(ch - 'A' + 'a');
    }

    switch (ch)
    {
        case 0: return 0;
        case 27: return KEY_ESCAPE;
        case 9:  return KEY_TAB;
        case 13: return KEY_ENTER;
        case 8:
        case 127: return KEY_BACKSPACE;
        case '-': return KEY_MINUS;
        case '=': return KEY_EQUALS;
        default:  return (int)ch;
    }
}

static void doom_handle_key_event(const user_atk_event_t *event)
{
    int key = doom_translate_key(event);
    if (key == 0)
    {
        return;
    }

    event_t doom_event;
    doom_event.type = (event->flags & USER_ATK_KEY_FLAG_RELEASE) ? ev_keyup : ev_keydown;
    doom_event.data1 = key;
    doom_event.data2 = 0;
    doom_event.data3 = 0;
    D_PostEvent(&doom_event);
}

static void doom_handle_mouse_event(const user_atk_event_t *event)
{
    if (!event)
    {
        return;
    }

    if (event->flags & USER_ATK_MOUSE_FLAG_PRESS)
    {
        g_mouse_buttons |= 1;
    }
    if (event->flags & USER_ATK_MOUSE_FLAG_RELEASE)
    {
        g_mouse_buttons &= ~1;
    }

    int dx = 0;
    int dy = 0;
    if (g_last_mouse_x >= 0 && g_last_mouse_y >= 0)
    {
        dx = (event->x - g_last_mouse_x) << 2;
        dy = (g_last_mouse_y - event->y) << 2;
    }
    g_last_mouse_x = event->x;
    g_last_mouse_y = event->y;

    if ((dx == 0 && dy == 0) &&
        (event->flags & (USER_ATK_MOUSE_FLAG_PRESS | USER_ATK_MOUSE_FLAG_RELEASE)) == 0)
    {
        return;
    }

    event_t doom_event;
    doom_event.type = ev_mouse;
    doom_event.data1 = g_mouse_buttons;
    doom_event.data2 = dx;
    doom_event.data3 = dy;
    D_PostEvent(&doom_event);
}

static void doom_blit_scaled(void)
{
    if (!g_window.buffer || !g_frame_rgba)
    {
        return;
    }

    int win_w = (int)g_window.width;
    int win_h = (int)g_window.height;
    if (win_w <= 0 || win_h <= 0)
    {
        return;
    }

    int fit_x = win_w / SCREENWIDTH;
    int fit_y = win_h / SCREENHEIGHT;
    int scale = g_scale;
    if (fit_x > 0 && fit_y > 0)
    {
        int fit = fit_x < fit_y ? fit_x : fit_y;
        if (fit < scale)
        {
            scale = fit;
        }
    }
    if (scale < 1)
    {
        scale = 1;
    }
    if (scale * SCREENWIDTH > win_w)
    {
        scale = win_w / SCREENWIDTH;
        if (scale < 1)
        {
            scale = 1;
        }
    }
    if (scale * SCREENHEIGHT > win_h)
    {
        scale = win_h / SCREENHEIGHT;
        if (scale < 1)
        {
            scale = 1;
        }
    }

    int dst_w = SCREENWIDTH * scale;
    int dst_h = SCREENHEIGHT * scale;
    int offset_x = (win_w - dst_w) / 2;
    int offset_y = (win_h - dst_h) / 2;
    if (offset_x < 0) offset_x = 0;
    if (offset_y < 0) offset_y = 0;

    for (int y = 0; y < SCREENHEIGHT; ++y)
    {
        const video_color_t *src_row = g_frame_rgba + (size_t)y * SCREENWIDTH;
        for (int sy = 0; sy < scale; ++sy)
        {
            int dst_y = offset_y + y * scale + sy;
            if (dst_y < 0 || dst_y >= win_h)
            {
                continue;
            }
            video_color_t *dst_row =
                g_window.buffer + (size_t)dst_y * (size_t)win_w + (size_t)offset_x;
            for (int x = 0; x < SCREENWIDTH; ++x)
            {
                video_color_t color = src_row[x];
                for (int sx = 0; sx < scale; ++sx)
                {
                    int dst_x = x * scale + sx;
                    if (dst_x + offset_x >= win_w)
                    {
                        break;
                    }
                    dst_row[dst_x] = color;
                }
            }
        }
    }
}

void I_InitGraphics(void)
{
    if (g_window_ready)
    {
        return;
    }

    serial_printf("[doom][video] I_InitGraphics begin\n");
    doom_video_pick_scale();
    doom_video_pick_fps();
    serial_printf("[doom][video] scale=%d fps=%d win=%dx%d\n", g_scale, g_target_fps, DOOM_WINDOW_WIDTH, DOOM_WINDOW_HEIGHT);

    /* Keep the window at a predictable size so the present byte_len matches the
     * window buffer size the kernel expects. */
    int width = DOOM_WINDOW_WIDTH;
    int height = DOOM_WINDOW_HEIGHT;
    if (!atk_user_window_open(&g_window, "DOOM", (uint32_t)width, (uint32_t)height))
    {
        I_Error("I_InitGraphics: failed to open window");
    }
    serial_printf("[doom][video] window_open ok handle=%u buffer=0x%016llX bytes=%llu\n",
                  (unsigned)g_window.handle,
                  (unsigned long long)(uintptr_t)g_window.buffer,
                  (unsigned long long)g_window.buffer_bytes);
    atk_user_enable_dirty_tracking(&g_window, false);

    size_t total_pixels = g_window.buffer_bytes / sizeof(video_color_t);
    video_color_t clear = video_make_color(0, 0, 0);
    for (size_t i = 0; i < total_pixels; ++i)
    {
        g_window.buffer[i] = clear;
    }

    size_t pixels = (size_t)SCREENWIDTH * (size_t)SCREENHEIGHT;
    g_frame_rgba = (video_color_t *)malloc(pixels * sizeof(video_color_t));
    if (!g_frame_rgba)
    {
        I_Error("I_InitGraphics: failed to allocate frame buffer");
    }
    serial_printf("[doom][video] framebuf=0x%016llX pixels=%llu\n",
                  (unsigned long long)(uintptr_t)g_frame_rgba,
                  (unsigned long long)pixels);

    g_window_ready = true;
    g_last_mouse_x = -1;
    g_last_mouse_y = -1;
    g_mouse_buttons = 0;
    g_next_frame_ms = 0;

    serial_printf("[doom][video] I_InitGraphics done\n");
}

void I_ShutdownGraphics(void)
{
    if (g_window_ready)
    {
        atk_user_close(&g_window);
        g_window_ready = false;
    }
    if (g_frame_rgba)
    {
        free(g_frame_rgba);
        g_frame_rgba = NULL;
    }
    g_last_mouse_x = -1;
    g_last_mouse_y = -1;
    g_mouse_buttons = 0;
    g_next_frame_ms = 0;
}

void I_SetPalette(byte *palette)
{
    if (!palette)
    {
        return;
    }

    for (int i = 0; i < 256; ++i)
    {
        byte r = gammatable[usegamma][palette[0]];
        byte g = gammatable[usegamma][palette[1]];
        byte b = gammatable[usegamma][palette[2]];
        g_palette_rgba[i] = video_make_color(r, g, b);
        palette += 3;
    }
}

void I_UpdateNoBlit(void) {}

void I_FinishUpdate(void)
{
    if (!g_window_ready || !g_frame_rgba || !screens[0])
    {
        return;
    }
    size_t pixel_count = (size_t)SCREENWIDTH * (size_t)SCREENHEIGHT;
    video_surface_convert8_to_rgba32(screens[0], g_palette_rgba, g_frame_rgba, pixel_count);
    doom_blit_scaled();
    video_surface_force_dirty();
    atk_user_present(&g_window);
    doom_frame_limiter_tick();
}

void I_ReadScreen(byte *scr)
{
    if (!scr || !screens[0])
    {
        return;
    }
    memcpy(scr, screens[0], SCREENWIDTH * SCREENHEIGHT);
}

void I_StartTic(void)
{
    if (!g_window_ready)
    {
        return;
    }

    user_atk_event_t ev;
    while (atk_user_poll_event(&g_window, &ev))
    {
        switch (ev.type)
        {
            case USER_ATK_EVENT_KEY:
                doom_handle_key_event(&ev);
                break;
            case USER_ATK_EVENT_MOUSE:
                doom_handle_mouse_event(&ev);
                break;
            case USER_ATK_EVENT_CLOSE:
                I_Quit();
                break;
            default:
                break;
        }
    }
}
