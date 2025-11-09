#include "atk_user.h"

#include "libc.h"
#include "syscall_defs.h"
#include "types.h"
#include "video.h"

#define MAP_WIDTH 16
#define MAP_HEIGHT 16
#define FOV_PLANE 0.66
#define MOVE_SPEED 0.15
#define STRAFE_SPEED 0.12
#define ROTATE_SPEED 0.08
#define MAX_RAY_STEPS 64
#define PROC_REPEAT_INITIAL "/proc/keyboard/repeat/initial"
#define PROC_REPEAT_INTERVAL "/proc/keyboard/repeat/repeat"
#define PROC_REPEAT_MULTI "/proc/keyboard/repeat/multi_mode"

#define WOLF_ABS(value) ((value) < 0.0 ? -(value) : (value))

typedef struct
{
    double x;
    double y;
    double angle;
    double dir_x;
    double dir_y;
    double plane_x;
    double plane_y;
} wolf_player_t;

typedef struct
{
    uint32_t initial_ms;
    uint32_t repeat_ms;
    bool multi_enabled;
    bool valid;
} keyboard_repeat_backup_t;

static const uint8_t g_world_map[MAP_HEIGHT][MAP_WIDTH] = {
    { 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1 },
    { 1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1 },
    { 1,0,2,2,2,0,0,0,3,3,3,0,4,4,0,1 },
    { 1,0,2,0,0,0,0,0,0,0,3,0,0,4,0,1 },
    { 1,0,2,0,5,5,0,0,0,0,3,0,0,4,0,1 },
    { 1,0,2,0,5,0,0,0,0,0,3,0,0,4,0,1 },
    { 1,0,2,0,5,0,0,0,0,0,3,0,0,4,0,1 },
    { 1,0,0,0,5,0,0,6,6,6,3,0,0,0,0,1 },
    { 1,0,0,0,5,0,0,6,0,6,0,0,0,0,0,1 },
    { 1,0,0,0,5,0,0,6,0,6,0,0,0,0,0,1 },
    { 1,0,0,0,5,0,0,6,0,6,0,0,0,0,0,1 },
    { 1,0,0,0,5,0,0,6,0,6,0,0,0,0,0,1 },
    { 1,0,0,0,5,0,0,6,6,6,0,0,0,0,0,1 },
    { 1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1 },
    { 1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1 },
    { 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1 },
};

static atk_user_window_t g_window;
static wolf_player_t g_player = {
    .x = 3.5f,
    .y = 3.5f,
    .angle = 0.0f,
    .dir_x = 1.0f,
    .dir_y = 0.0f,
    .plane_x = 0.0f,
    .plane_y = FOV_PLANE,
};

static bool wolf3d_parse_uint32(const char *text, uint32_t *value_out);
static uint32_t wolf3d_read_repeat_value(const char *path, uint32_t fallback);
static bool wolf3d_write_repeat_value(const char *path, uint32_t value);
static bool wolf3d_override_keyboard_repeat(keyboard_repeat_backup_t *backup);
static void wolf3d_restore_keyboard_repeat(const keyboard_repeat_backup_t *backup);

static void wolf_wrap_angle(double *angle)
{
    if (!angle)
    {
        return;
    }
    const double PI = 3.141592653589793;
    const double TWO_PI = 6.283185307179586;
    while (*angle < -PI)
    {
        *angle += TWO_PI;
    }
    while (*angle > PI)
    {
        *angle -= TWO_PI;
    }
}

static void wolf_fast_sin_cos(double angle, double *out_sin, double *out_cos)
{
    const double B = 4.0 / 3.141592653589793;
    const double C = -4.0 / (3.141592653589793 * 3.141592653589793);
    const double P = 0.225;

    wolf_wrap_angle(&angle);
    double y = B * angle + C * angle * WOLF_ABS(angle);
    double sine = P * (y * WOLF_ABS(y) - y) + y;

    double shifted = angle + 1.5707963267948966;
    wolf_wrap_angle(&shifted);
    double y2 = B * shifted + C * shifted * WOLF_ABS(shifted);
    double cosine = P * (y2 * WOLF_ABS(y2) - y2) + y2;

    if (out_sin)
    {
        *out_sin = sine;
    }
    if (out_cos)
    {
        *out_cos = cosine;
    }
}

static void wolf_set_angle(double angle)
{
    double normalized = angle;
    wolf_wrap_angle(&normalized);
    g_player.angle = normalized;

    double sine = 0.0;
    double cosine = 0.0;
    wolf_fast_sin_cos(normalized, &sine, &cosine);
    g_player.dir_x = cosine;
    g_player.dir_y = sine;
    g_player.plane_x = -g_player.dir_y * FOV_PLANE;
    g_player.plane_y = g_player.dir_x * FOV_PLANE;
}

static bool wolf3d_parse_uint32(const char *text, uint32_t *value_out)
{
    if (!text || !value_out)
    {
        return false;
    }
    const char *cursor = text;
    while (*cursor == ' ' || *cursor == '\t' || *cursor == '\n' || *cursor == '\r')
    {
        ++cursor;
    }
    if (*cursor == '\0')
    {
        return false;
    }
    uint64_t value = 0;
    bool any = false;
    while (*cursor >= '0' && *cursor <= '9')
    {
        any = true;
        value = value * 10ULL + (uint64_t)(*cursor - '0');
        ++cursor;
    }
    while (*cursor == ' ' || *cursor == '\t' || *cursor == '\n' || *cursor == '\r')
    {
        ++cursor;
    }
    if (*cursor != '\0')
    {
        return false;
    }
    if (!any)
    {
        return false;
    }
    *value_out = (uint32_t)value;
    return true;
}

static int wolf3d_format_uint32(char *buffer, size_t capacity, uint32_t value)
{
    if (!buffer || capacity == 0)
    {
        return 0;
    }
    char digits[16];
    size_t len = 0;
    if (value == 0)
    {
        digits[len++] = '0';
    }
    else
    {
        while (value > 0 && len < sizeof(digits))
        {
            digits[len++] = (char)('0' + (value % 10U));
            value /= 10U;
        }
    }
    int written = 0;
    while (len > 0 && (size_t)written + 1 < capacity)
    {
        buffer[written++] = digits[--len];
    }
    if ((size_t)written < capacity)
    {
        buffer[written++] = '\n';
    }
    return written;
}

static uint32_t wolf3d_read_repeat_value(const char *path, uint32_t fallback)
{
    if (!path)
    {
        return fallback;
    }

    int fd = open(path, SYSCALL_OPEN_READ);
    if (fd < 0)
    {
        return fallback;
    }
    char buffer[48];
    ssize_t len = read(fd, buffer, sizeof(buffer) - 1);
    close(fd);
    if (len <= 0)
    {
        return fallback;
    }
    buffer[len] = '\0';
    uint32_t parsed = fallback;
    if (!wolf3d_parse_uint32(buffer, &parsed))
    {
        return fallback;
    }
    return parsed;
}

static bool wolf3d_write_repeat_value(const char *path, uint32_t value)
{
    if (!path)
    {
        return false;
    }
    char buffer[32];
    int len = wolf3d_format_uint32(buffer, sizeof(buffer), value);
    if (len <= 0)
    {
        return false;
    }
    int fd = open(path, SYSCALL_OPEN_WRITE | SYSCALL_OPEN_TRUNCATE);
    if (fd < 0)
    {
        return false;
    }
    ssize_t written = write(fd, buffer, (size_t)len);
    close(fd);
    return written == len;
}

static bool wolf3d_read_bool(const char *path, bool fallback)
{
    uint32_t value = wolf3d_read_repeat_value(path, fallback ? 1U : 0U);
    return value != 0;
}

static bool wolf3d_write_bool(const char *path, bool value)
{
    char buffer[8];
    int len = 0;
    buffer[len++] = value ? '1' : '0';
    buffer[len++] = '\n';
    int fd = open(path, SYSCALL_OPEN_WRITE | SYSCALL_OPEN_TRUNCATE);
    if (fd < 0)
    {
        return false;
    }
    ssize_t written = write(fd, buffer, (size_t)len);
    close(fd);
    return written == len;
}

static bool wolf3d_override_keyboard_repeat(keyboard_repeat_backup_t *backup)
{
    if (!backup)
    {
        return false;
    }
    backup->initial_ms = wolf3d_read_repeat_value(PROC_REPEAT_INITIAL, 500);
    backup->repeat_ms = wolf3d_read_repeat_value(PROC_REPEAT_INTERVAL, 200);
    backup->multi_enabled = wolf3d_read_bool(PROC_REPEAT_MULTI, false);
    backup->valid = true;

    bool initial_ok = wolf3d_write_repeat_value(PROC_REPEAT_INITIAL, 0);
    bool repeat_ok = wolf3d_write_repeat_value(PROC_REPEAT_INTERVAL, 100);
    bool multi_ok = wolf3d_write_bool(PROC_REPEAT_MULTI, true);
    return initial_ok || repeat_ok || multi_ok;
}

static void wolf3d_restore_keyboard_repeat(const keyboard_repeat_backup_t *backup)
{
    if (!backup || !backup->valid)
    {
        return;
    }
    wolf3d_write_repeat_value(PROC_REPEAT_INITIAL, backup->initial_ms);
    wolf3d_write_repeat_value(PROC_REPEAT_INTERVAL, backup->repeat_ms);
    wolf3d_write_bool(PROC_REPEAT_MULTI, backup->multi_enabled);
}

static bool wolf_cell_blocked(int x, int y)
{
    if (x < 0 || y < 0 || x >= MAP_WIDTH || y >= MAP_HEIGHT)
    {
        return true;
    }
    return g_world_map[y][x] != 0;
}

static bool wolf_position_blocked(double x, double y)
{
    int cell_x = (int)x;
    int cell_y = (int)y;
    return wolf_cell_blocked(cell_x, cell_y);
}

static bool wolf_try_move(double dx, double dy)
{
    bool moved = false;
    double next_x = g_player.x + dx;
    double next_y = g_player.y + dy;

    if (!wolf_position_blocked(next_x, g_player.y))
    {
        g_player.x = next_x;
        moved = true;
    }
    if (!wolf_position_blocked(g_player.x, next_y))
    {
        g_player.y = next_y;
        moved = true;
    }
    return moved;
}

static bool wolf_move_forward(void)
{
    return wolf_try_move(g_player.dir_x * MOVE_SPEED, g_player.dir_y * MOVE_SPEED);
}

static bool wolf_move_backward(void)
{
    return wolf_try_move(-g_player.dir_x * MOVE_SPEED, -g_player.dir_y * MOVE_SPEED);
}

static bool wolf_strafe_left(void)
{
    return wolf_try_move(-g_player.dir_y * STRAFE_SPEED, g_player.dir_x * STRAFE_SPEED);
}

static bool wolf_strafe_right(void)
{
    return wolf_try_move(g_player.dir_y * STRAFE_SPEED, -g_player.dir_x * STRAFE_SPEED);
}

static bool wolf_rotate(double delta)
{
    if (delta == 0.0)
    {
        return false;
    }
    wolf_set_angle(g_player.angle + delta);
    return true;
}

static uint16_t wolf_color_shade(uint8_t r, uint8_t g, uint8_t b, double shade)
{
    if (shade < 0.0)
    {
        shade = 0.0;
    }
    if (shade > 1.0)
    {
        shade = 1.0;
    }
    uint8_t sr = (uint8_t)(r * shade);
    uint8_t sg = (uint8_t)(g * shade);
    uint8_t sb = (uint8_t)(b * shade);
    return video_make_color(sr, sg, sb);
}

static uint16_t wolf_wall_color(int tile, int side)
{
    static const struct
    {
        uint8_t r, g, b;
    } palette[] = {
        { 200, 200, 200 },
        { 220, 120, 80 },
        { 80, 160, 220 },
        { 160, 100, 190 },
        { 90, 180, 90 },
        { 220, 210, 120 },
    };

    if (tile <= 0)
    {
        tile = 1;
    }
    size_t index = (size_t)(tile - 1) % (sizeof(palette) / sizeof(palette[0]));
    double shade = (side == 0) ? 0.9 : 0.6;
    return wolf_color_shade(palette[index].r, palette[index].g, palette[index].b, shade);
}

static void wolf_fill_background(uint16_t *buffer, int width, int height)
{
    int half = height / 2;
    for (int y = 0; y < height; ++y)
    {
        double t;
        uint8_t r;
        uint8_t g;
        uint8_t b;

        if (y < half)
        {
            t = (double)y / (double)(half ? half : 1);
            double inv = 1.0 - t;
            r = (uint8_t)(20.0 + 40.0 * inv);
            g = (uint8_t)(60.0 + 60.0 * inv);
            b = (uint8_t)(120.0 + 100.0 * inv);
        }
        else
        {
            int rel = y - half;
            int denom = height - half;
            if (denom <= 0)
            {
                denom = 1;
            }
            t = (double)rel / (double)denom;
            r = (uint8_t)(40.0 + 100.0 * t);
            g = (uint8_t)(30.0 + 80.0 * t);
            b = (uint8_t)(20.0 + 60.0 * t);
        }

        uint16_t color = video_make_color(r, g, b);
        uint16_t *row = buffer + (size_t)y * (size_t)width;
        for (int x = 0; x < width; ++x)
        {
            row[x] = color;
        }
    }
}

static void wolf_draw_column(uint16_t *buffer, int width, int height, int x)
{
    double camera_x = 2.0 * (double)x / (double)width - 1.0;
    double ray_dir_x = g_player.dir_x + g_player.plane_x * camera_x;
    double ray_dir_y = g_player.dir_y + g_player.plane_y * camera_x;

    int map_x = (int)g_player.x;
    int map_y = (int)g_player.y;

    double delta_dist_x = (ray_dir_x == 0.0) ? 1e30 : WOLF_ABS(1.0 / ray_dir_x);
    double delta_dist_y = (ray_dir_y == 0.0) ? 1e30 : WOLF_ABS(1.0 / ray_dir_y);

    double side_dist_x;
    double side_dist_y;
    int step_x;
    int step_y;

    if (ray_dir_x < 0.0)
    {
        step_x = -1;
        side_dist_x = (g_player.x - map_x) * delta_dist_x;
    }
    else
    {
        step_x = 1;
        side_dist_x = (map_x + 1.0 - g_player.x) * delta_dist_x;
    }

    if (ray_dir_y < 0.0)
    {
        step_y = -1;
        side_dist_y = (g_player.y - map_y) * delta_dist_y;
    }
    else
    {
        step_y = 1;
        side_dist_y = (map_y + 1.0 - g_player.y) * delta_dist_y;
    }

    int tile = 0;
    int side = 0;
    for (int i = 0; i < MAX_RAY_STEPS; ++i)
    {
        if (side_dist_x < side_dist_y)
        {
            side_dist_x += delta_dist_x;
            map_x += step_x;
            side = 0;
        }
        else
        {
            side_dist_y += delta_dist_y;
            map_y += step_y;
            side = 1;
        }

        if (map_x < 0 || map_y < 0 || map_x >= MAP_WIDTH || map_y >= MAP_HEIGHT)
        {
            tile = 1;
            break;
        }

        tile = g_world_map[map_y][map_x];
        if (tile != 0)
        {
            break;
        }
    }

    if (tile == 0)
    {
        return;
    }

    double perp_wall_dist = (side == 0) ? (side_dist_x - delta_dist_x) : (side_dist_y - delta_dist_y);
    if (perp_wall_dist <= 0.0001)
    {
        perp_wall_dist = 0.0001;
    }

    int line_height = (int)((double)height / perp_wall_dist);
    int draw_start = (height / 2) - (line_height / 2);
    int draw_end = (height / 2) + (line_height / 2);

    if (draw_start < 0)
    {
        draw_start = 0;
    }
    if (draw_end >= height)
    {
        draw_end = height - 1;
    }

    uint16_t color = wolf_wall_color(tile, side);
    for (int y = draw_start; y <= draw_end; ++y)
    {
        buffer[(size_t)y * (size_t)width + (size_t)x] = color;
    }
}

static void wolf_render_scene(void)
{
    if (!g_window.buffer || g_window.width == 0 || g_window.height == 0)
    {
        return;
    }

    int width = (int)g_window.width;
    int height = (int)g_window.height;
    wolf_fill_background(g_window.buffer, width, height);

    for (int x = 0; x < width; ++x)
    {
        wolf_draw_column(g_window.buffer, width, height, x);
    }

    atk_user_present(&g_window);
}

static bool wolf_handle_key(char ch, bool *running)
{
    bool updated = false;
    if (ch >= 'A' && ch <= 'Z')
    {
        ch = (char)(ch - 'A' + 'a');
    }

    switch (ch)
    {
        case 'w':
            updated = wolf_move_forward();
            break;
        case 's':
            updated = wolf_move_backward();
            break;
        case 'a':
            updated = wolf_rotate(-ROTATE_SPEED);
            break;
        case 'd':
            updated = wolf_rotate(ROTATE_SPEED);
            break;
        case 'q':
            updated = wolf_strafe_left();
            break;
        case 'e':
            updated = wolf_strafe_right();
            break;
        case 27:
            *running = false;
            break;
        default:
            break;
    }
    return updated;
}

int main(void)
{
    keyboard_repeat_backup_t repeat_backup = { 0 };
    bool repeat_override_active = wolf3d_override_keyboard_repeat(&repeat_backup);

    if (!atk_user_window_open(&g_window, "Wolf3D (user)", VIDEO_WIDTH, VIDEO_HEIGHT))
    {
        printf("wolf3d: failed to open window\n");
        if (repeat_override_active)
        {
            wolf3d_restore_keyboard_repeat(&repeat_backup);
        }
        return 1;
    }

    wolf_set_angle(0.0f);
    wolf_render_scene();

    bool running = true;
    while (running)
    {
        user_atk_event_t event;
        if (!atk_user_wait_event(&g_window, &event))
        {
            continue;
        }

        bool needs_redraw = false;
        switch (event.type)
        {
            case USER_ATK_EVENT_KEY:
                needs_redraw = wolf_handle_key((char)event.data0, &running);
                break;
            case USER_ATK_EVENT_CLOSE:
                running = false;
                break;
            default:
                break;
        }

        if (needs_redraw)
        {
            wolf_render_scene();
        }
    }

    atk_user_close(&g_window);
    if (repeat_override_active)
    {
        wolf3d_restore_keyboard_repeat(&repeat_backup);
    }
    return 0;
}
