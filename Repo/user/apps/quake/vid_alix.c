// AlixOS usermode ATK-window video/input driver for Quake (WinQuake software renderer).

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "atk_user.h"
#include "quakedef.h"
#include "d_local.h"
#include "serial.h"
#include "usyscall.h"
#include "video.h"
#include "video_surface.h"

unsigned short d_8to16table[256];
unsigned d_8to24table[256];

enum
{
    QUAKE_BASE_WIDTH = 320,
    QUAKE_BASE_HEIGHT = 200,
    QUAKE_WINDOW_WIDTH = 960,
    QUAKE_WINDOW_HEIGHT = 600,
    QUAKE_SURFCACHE_BYTES = 4 * 1024 * 1024,
};

static atk_user_window_t g_window;
static bool g_window_ready = false;

static byte *g_vid_buffer = NULL;
static short *g_zbuffer = NULL;
static byte *g_surfcache = NULL;
static video_color_t g_palette_rgba[256];
static video_color_t *g_frame_rgba = NULL;

static int g_last_mouse_x = -1;
static int g_last_mouse_y = -1;
static int g_mouse_dx = 0;
static int g_mouse_dy = 0;
static bool g_mouse_btn_down = false;
static bool g_mouse_captured = false;

static unsigned char quake_scancode_to_ascii(uint32_t scancode)
{
    static const unsigned char map[128] = {
        0,   27, '1','2','3','4','5','6','7','8','9','0','-','=', '\b','\t',
        'q','w','e','r','t','y','u','i','o','p','[',']','\n', 0, 'a','s',
        'd','f','g','h','j','k','l',';','\'','`', 0,'\\','z','x','c','v',
        'b','n','m',',','.','/', 0,'*', 0,' ', 0,  0,   0,   0,   0,   0,
        0,   0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
        0,   0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
        0,   0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
        0,   0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0
    };

    if (scancode < 128)
    {
        return map[scancode];
    }
    return 0;
}

static void quake_reset_mouse_tracking(void)
{
    g_last_mouse_x = -1;
    g_last_mouse_y = -1;
    g_mouse_dx = 0;
    g_mouse_dy = 0;
}

static void quake_set_mouse_capture(bool enable)
{
    if (!g_window_ready || g_mouse_captured == enable)
    {
        return;
    }
    atk_user_set_mouse_capture(&g_window, enable, true);
    g_mouse_captured = enable;
    quake_reset_mouse_tracking();
}

static void quake_blit_scaled(void)
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

    int src_w = (int)vid.width;
    int src_h = (int)vid.height;
    if (src_w <= 0 || src_h <= 0)
    {
        return;
    }

    int scale_x = win_w / src_w;
    int scale_y = win_h / src_h;
    int scale = scale_x < scale_y ? scale_x : scale_y;
    if (scale < 1)
    {
        scale = 1;
    }

    int dst_w = src_w * scale;
    int dst_h = src_h * scale;
    int offset_x = (win_w - dst_w) / 2;
    int offset_y = (win_h - dst_h) / 2;
    if (offset_x < 0) offset_x = 0;
    if (offset_y < 0) offset_y = 0;

    for (int y = 0; y < src_h; ++y)
    {
        const video_color_t *src_row = g_frame_rgba + (size_t)y * (size_t)src_w;
        for (int sy = 0; sy < scale; ++sy)
        {
            int dst_y = offset_y + y * scale + sy;
            if (dst_y < 0 || dst_y >= win_h)
            {
                continue;
            }
            video_color_t *dst_row =
                g_window.buffer + (size_t)dst_y * (size_t)win_w + (size_t)offset_x;
            for (int x = 0; x < src_w; ++x)
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

static int quake_translate_scancode(uint32_t scancode)
{
    switch (scancode)
    {
        case 0x01: return K_ESCAPE;
        case 0x0F: return K_TAB;
        case 0x1C: return K_ENTER;
        case 0x0E: return K_BACKSPACE;
        case 0x3B: return K_F1;
        case 0x3C: return K_F2;
        case 0x3D: return K_F3;
        case 0x3E: return K_F4;
        case 0x3F: return K_F5;
        case 0x40: return K_F6;
        case 0x41: return K_F7;
        case 0x42: return K_F8;
        case 0x43: return K_F9;
        case 0x44: return K_F10;
        case 0x57: return K_F11;
        case 0x58: return K_F12;
        case 0x1D: return K_CTRL;
        case 0x38: return K_ALT;
        case 0x2A:
        case 0x36: return K_SHIFT;
        default:
            break;
    }
    return 0;
}

static int quake_translate_key(const user_atk_event_t *ev)
{
    if (!ev)
    {
        return 0;
    }

    if ((ev->flags & USER_ATK_KEY_FLAG_EXTENDED) != 0)
    {
        switch (ev->data1)
        {
            case 0x48: /* Up */
            case 0x50: /* Down */
            case 0x4B: /* Left */
            case 0x4D: /* Right */
                return 0;
            default:
                break;
        }
    }

    int key = quake_translate_scancode(ev->data1);
    if (key)
    {
        return key;
    }

    unsigned char ch = (unsigned char)ev->data0;
    if (ch == 0)
    {
        ch = quake_scancode_to_ascii(ev->data1);
    }

    if (ch >= 'A' && ch <= 'Z')
    {
        ch = (unsigned char)(ch - 'A' + 'a');
    }

    switch (ch)
    {
        case 0: return 0;
        case 27: return K_ESCAPE;
        case 9: return K_TAB;
        case 13: return K_ENTER;
        case 8:
        case 127: return K_BACKSPACE;
        default: return (int)ch;
    }
}

void Sys_SendKeyEvents(void)
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
            {
                bool down = (ev.flags & USER_ATK_KEY_FLAG_RELEASE) == 0;
                int key = quake_translate_key(&ev);
                if (key)
                {
                    if (down && key == K_ESCAPE && g_mouse_captured)
                    {
                        quake_set_mouse_capture(false);
                    }
                    Key_Event(key, down);
                }
                break;
            }
            case USER_ATK_EVENT_MOUSE:
            {
                if (!g_mouse_captured &&
                    (ev.flags & (USER_ATK_MOUSE_FLAG_PRESS | USER_ATK_MOUSE_FLAG_LEFT)))
                {
                    quake_set_mouse_capture(true);
                }
                if (ev.flags & USER_ATK_MOUSE_FLAG_RELATIVE)
                {
                    if (!g_mouse_captured)
                    {
                        g_mouse_captured = true;
                    }
                }
                else if (g_mouse_captured)
                {
                    g_mouse_captured = false;
                    quake_reset_mouse_tracking();
                }

                if (ev.flags & USER_ATK_MOUSE_FLAG_PRESS)
                {
                    if (!g_mouse_btn_down)
                    {
                        g_mouse_btn_down = true;
                        Key_Event(K_MOUSE1, true);
                    }
                }
                if (ev.flags & USER_ATK_MOUSE_FLAG_RELEASE)
                {
                    if (g_mouse_btn_down)
                    {
                        g_mouse_btn_down = false;
                        Key_Event(K_MOUSE1, false);
                    }
                }

                if (ev.flags & USER_ATK_MOUSE_FLAG_RELATIVE)
                {
                    g_mouse_dx += (int32_t)ev.data0;
                    g_mouse_dy += (int32_t)ev.data1;
                    g_last_mouse_x = ev.x;
                    g_last_mouse_y = ev.y;
                }
                else
                {
                    if (g_last_mouse_x >= 0 && g_last_mouse_y >= 0)
                    {
                        g_mouse_dx += ev.x - g_last_mouse_x;
                        g_mouse_dy += ev.y - g_last_mouse_y;
                    }
                    g_last_mouse_x = ev.x;
                    g_last_mouse_y = ev.y;
                }
                break;
            }
            case USER_ATK_EVENT_CLOSE:
                Sys_Quit();
                break;
            default:
                break;
        }
    }
}

void IN_Init(void) {}
void IN_Shutdown(void) {}
void IN_Commands(void) {}

void IN_Move(usercmd_t *cmd)
{
    if (!cmd)
    {
        return;
    }

    int dx = g_mouse_dx;
    int dy = g_mouse_dy;
    g_mouse_dx = 0;
    g_mouse_dy = 0;
    if (dx == 0 && dy == 0)
    {
        if (g_mouse_captured || (in_mlook.state & 1))
        {
            V_StopPitchDrift();
        }
        return;
    }

    qboolean mlook = g_mouse_captured || (in_mlook.state & 1);
    if (!g_mouse_captured && !mlook)
    {
        return;
    }

    float mx = (float)dx * sensitivity.value;
    float my = (float)dy * sensitivity.value;

    if ((in_strafe.state & 1) || (lookstrafe.value && mlook))
    {
        cmd->sidemove += m_side.value * mx;
    }
    else
    {
        cl.viewangles[YAW] -= m_yaw.value * mx;
    }

    if (mlook)
    {
        V_StopPitchDrift();
    }

    if (mlook && !(in_strafe.state & 1))
    {
        cl.viewangles[PITCH] += m_pitch.value * my;
        if (cl.viewangles[PITCH] > 80)
        {
            cl.viewangles[PITCH] = 80;
        }
        if (cl.viewangles[PITCH] < -70)
        {
            cl.viewangles[PITCH] = -70;
        }
    }
    else
    {
        if ((in_strafe.state & 1) && noclip_anglehack)
        {
            cmd->upmove -= m_forward.value * my;
        }
        else
        {
            cmd->forwardmove -= m_forward.value * my;
        }
    }
}

void VID_HandlePause(qboolean pause)
{
    (void)pause;
}

void VID_SetPalette(unsigned char *palette)
{
    if (!palette)
    {
        return;
    }

    for (int i = 0; i < 256; ++i)
    {
        uint8_t r = palette[0];
        uint8_t g = palette[1];
        uint8_t b = palette[2];
        g_palette_rgba[i] = video_make_color(r, g, b);
        d_8to24table[i] = (unsigned)((r << 16) | (g << 8) | b);
        palette += 3;
    }
}

void VID_ShiftPalette(unsigned char *palette)
{
    VID_SetPalette(palette);
}

void VID_Init(unsigned char *palette)
{
    serial_printf("[quake][video] VID_Init begin\n");

    if (!atk_user_window_open(&g_window, "Quake", QUAKE_WINDOW_WIDTH, QUAKE_WINDOW_HEIGHT))
    {
        Sys_Error("VID_Init: failed to open window");
    }
    atk_user_enable_dirty_tracking(&g_window, false);

    size_t win_pixels = g_window.buffer_bytes / sizeof(video_color_t);
    video_color_t clear = video_make_color(0, 0, 0);
    for (size_t i = 0; i < win_pixels; ++i)
    {
        g_window.buffer[i] = clear;
    }

    vid.maxwarpwidth = vid.width = vid.conwidth = QUAKE_BASE_WIDTH;
    vid.maxwarpheight = vid.height = vid.conheight = QUAKE_BASE_HEIGHT;
    vid.aspect = 1.0f;
    vid.numpages = 1;
    vid.colormap = host_colormap;
    vid.fullbright = 256 - LittleLong(*((int *)vid.colormap + 2048));
    vid.rowbytes = vid.conrowbytes = QUAKE_BASE_WIDTH;
    vid.direct = NULL;

    size_t vid_pixels = (size_t)vid.width * (size_t)vid.height;
    g_vid_buffer = (byte *)malloc(vid_pixels);
    g_zbuffer = (short *)malloc(vid_pixels * sizeof(short));
    g_surfcache = (byte *)malloc(QUAKE_SURFCACHE_BYTES);
    g_frame_rgba = (video_color_t *)malloc(vid_pixels * sizeof(video_color_t));

    if (!g_vid_buffer || !g_zbuffer || !g_surfcache || !g_frame_rgba)
    {
        Sys_Error("VID_Init: out of memory");
    }
    memset(g_vid_buffer, 0, vid_pixels);
    memset(g_zbuffer, 0, vid_pixels * sizeof(short));

    vid.buffer = vid.conbuffer = g_vid_buffer;
    d_pzbuffer = g_zbuffer;
    D_InitCaches(g_surfcache, QUAKE_SURFCACHE_BYTES);

    VID_SetPalette(palette);

    g_window_ready = true;
    quake_reset_mouse_tracking();
    g_mouse_btn_down = false;
    g_mouse_captured = false;

    serial_printf("[quake][video] VID_Init done\n");
}

void VID_Shutdown(void)
{
    if (g_window_ready)
    {
        quake_set_mouse_capture(false);
        atk_user_close(&g_window);
        g_window_ready = false;
    }

    free(g_vid_buffer);
    g_vid_buffer = NULL;
    free(g_zbuffer);
    g_zbuffer = NULL;
    free(g_surfcache);
    g_surfcache = NULL;
    free(g_frame_rgba);
    g_frame_rgba = NULL;

    quake_reset_mouse_tracking();
    g_mouse_btn_down = false;
    g_mouse_captured = false;
}

void VID_Update(vrect_t *rects)
{
    (void)rects;
    if (!g_window_ready || !vid.buffer || !g_frame_rgba)
    {
        return;
    }

    size_t pixel_count = (size_t)vid.width * (size_t)vid.height;
    video_surface_convert8_to_rgba32(vid.buffer, g_palette_rgba, g_frame_rgba, pixel_count);
    quake_blit_scaled();
    video_surface_force_dirty();
    atk_user_present(&g_window);
}

void D_BeginDirectRect(int x, int y, byte *pbitmap, int width, int height)
{
    (void)x;
    (void)y;
    (void)pbitmap;
    (void)width;
    (void)height;
}

void D_EndDirectRect(int x, int y, int width, int height)
{
    (void)x;
    (void)y;
    (void)width;
    (void)height;
}
