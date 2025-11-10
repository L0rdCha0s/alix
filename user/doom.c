#include "atk_user.h"

#include "libc.h"
#include "syscall_defs.h"
#include "types.h"
#include "video.h"

#define DOOM_PI 3.14159265358979323846f
#define DOOM_TWO_PI (DOOM_PI * 2.0f)
#define DOOM_ARRAY_LEN(x) (sizeof(x) / sizeof((x)[0]))
#define DOOM_VIDEO_WIDTH ((int)VIDEO_WIDTH)
#define DOOM_VIDEO_HEIGHT ((int)VIDEO_HEIGHT)

#define DOOM_MOVE_SPEED 0.18f
#define DOOM_STRAFE_SPEED 0.16f
#define DOOM_TURN_SPEED 0.045f
#define DOOM_EYE_HEIGHT 1.6f
#define DOOM_MIN_HEADROOM 1.9f
#define DOOM_NEAR_CLIP 0.05f
#define DOOM_FOV_DEG 90.0f

#define PROC_REPEAT_INITIAL "/proc/keyboard/repeat/initial"
#define PROC_REPEAT_INTERVAL "/proc/keyboard/repeat/repeat"
#define PROC_REPEAT_MULTI "/proc/keyboard/repeat/multi_mode"

typedef struct
{
    float x;
    float y;
} doom_vec2_t;

typedef struct
{
    uint8_t r;
    uint8_t g;
    uint8_t b;
} doom_color_t;

typedef struct
{
    const int *indices;
    size_t count;
} doom_polygon_t;

typedef struct
{
    float min_x;
    float min_y;
    float max_x;
    float max_y;
} doom_bbox_t;

typedef struct
{
    float floor_height;
    float ceiling_height;
    doom_color_t wall_color;
    doom_color_t floor_color;
    doom_color_t ceiling_color;
    doom_polygon_t polygon;
} doom_sector_t;

typedef struct
{
    int v0;
    int v1;
    int back_sector;
    doom_color_t color;
} doom_wall_t;

typedef struct
{
    int sector;
    const doom_wall_t *walls;
    size_t wall_count;
} doom_subsector_t;

typedef struct
{
    doom_vec2_t origin;
    doom_vec2_t direction;
    int16_t front_child;
    int16_t back_child;
    doom_bbox_t front_bbox;
    doom_bbox_t back_bbox;
} doom_bsp_node_t;

typedef struct
{
    float depth;
    float side;
    float screen_x;
    doom_vec2_t world;
} doom_projected_point_t;

typedef struct
{
    float plane_distance;
    float vertical_scale;
    float horizontal_tan;
    float center_x;
    float center_y;
    int screen_width;
    int screen_height;
} doom_projection_t;

typedef struct
{
    float x;
    float y;
    float z;
    float angle;
    float dir_x;
    float dir_y;
    float left_x;
    float left_y;
    int sector;
} doom_player_t;

typedef struct
{
    uint32_t initial_ms;
    uint32_t repeat_ms;
    bool multi_enabled;
    bool valid;
} doom_keyboard_repeat_t;

#define DOOM_COLOR(r, g, b) { (uint8_t)(r), (uint8_t)(g), (uint8_t)(b) }
#define DOOM_LEAF(index) ((int16_t)(-1 - (index)))

static atk_user_window_t g_window;
static doom_projection_t g_projection;
static doom_player_t g_player = {
    .x = 4.0f,
    .y = 4.0f,
    .z = 0.0f,
    .angle = 0.0f,
    .dir_x = 1.0f,
    .dir_y = 0.0f,
    .left_x = 0.0f,
    .left_y = 1.0f,
    .sector = 0,
};
static doom_keyboard_repeat_t g_repeat_backup = { 0 };

static float doom_fast_sin(float angle);
static void doom_fast_sin_cos(float angle, float *out_sin, float *out_cos);
static float doom_fast_tan(float angle);
static void doom_wrap_angle(float *angle);
static void doom_set_angle(float angle);
static void doom_update_player_height(void);
static bool doom_move_forward(void);
static bool doom_move_backward(void);
static bool doom_strafe_left(void);
static bool doom_strafe_right(void);
static bool doom_rotate(float delta);
static bool doom_point_in_sector(const doom_sector_t *sector, float x, float y);
static int doom_find_sector(float x, float y);
static bool doom_sector_has_space(const doom_sector_t *sector);
static bool doom_move_component(float dx, float dy);
static void doom_render_scene(void);
static void doom_render_bsp(int16_t node_index);
static void doom_render_subsector(int subsector_index);
static bool doom_clip_to_near(doom_projected_point_t *a, doom_projected_point_t *b);
static void doom_transform_vertex(const doom_vec2_t *v, doom_projected_point_t *out);
static void doom_draw_wall(const doom_sector_t *front, const doom_wall_t *wall);
static void doom_draw_span(int x, int y0, int y1, doom_color_t color, float depth);
static void doom_clear_background(void);
static bool doom_point_on_front(const doom_bsp_node_t *node, float x, float y);
static bool doom_bbox_visible(const doom_bbox_t *bbox);
static bool doom_read_uint32(const char *path, uint32_t *value_out);
static bool doom_write_uint32(const char *path, uint32_t value);
static bool doom_read_bool(const char *path, bool *value_out);
static bool doom_write_bool(const char *path, bool value);
static bool doom_override_repeat(doom_keyboard_repeat_t *backup);
static void doom_restore_repeat(const doom_keyboard_repeat_t *backup);
static bool doom_handle_key(char ch, bool *running);

static inline float doom_fabs(float value)
{
    return (value < 0.0f) ? -value : value;
}

static inline int doom_fast_floor(float value)
{
    int i = (int)value;
    if ((float)i > value)
    {
        --i;
    }
    return i;
}

static inline int doom_fast_ceil(float value)
{
    int i = (int)value;
    if ((float)i < value)
    {
        ++i;
    }
    return i;
}

static inline uint16_t doom_pack_color(doom_color_t color, float shade)
{
    if (shade < 0.0f)
    {
        shade = 0.0f;
    }
    if (shade > 1.0f)
    {
        shade = 1.0f;
    }
    uint8_t r = (uint8_t)(color.r * shade);
    uint8_t g = (uint8_t)(color.g * shade);
    uint8_t b = (uint8_t)(color.b * shade);
    return video_make_color(r, g, b);
}

static inline uint16_t doom_color_from_depth(doom_color_t color, float depth)
{
    if (depth < 0.01f)
    {
        depth = 0.01f;
    }
    float falloff = 1.0f / (1.0f + depth * 0.08f);
    return doom_pack_color(color, falloff);
}

static inline bool doom_is_leaf(int16_t value)
{
    return (value < 0);
}

static inline int doom_leaf_index(int16_t value)
{
    return -value - 1;
}

static const doom_vec2_t g_vertices[] = {
    { 0.0f, 0.0f },  // 0
    { 8.0f, 0.0f },  // 1
    { 8.0f, 2.0f },  // 2
    { 8.0f, 6.0f },  // 3
    { 8.0f, 8.0f },  // 4
    { 6.0f, 8.0f },  // 5
    { 2.0f, 8.0f },  // 6
    { 0.0f, 8.0f },  // 7
    { 10.0f, 2.0f }, // 8
    { 10.0f, 6.0f }, // 9
    { 12.0f, 2.0f }, // 10
    { 12.0f, 6.0f }, // 11
    { 14.0f, 2.0f }, // 12
    { 14.0f, 6.0f }, // 13
    { 16.0f, 2.0f }, // 14
    { 16.0f, 6.0f }, // 15
    { 16.0f, 0.0f }, // 16
    { 26.0f, 0.0f }, // 17
    { 26.0f, 10.0f },// 18
    { 16.0f, 10.0f },// 19
    { 6.0f, 14.0f }, // 20
    { 2.0f, 14.0f }, // 21
};

static const int g_sector0_indices[] = { 0, 1, 2, 3, 4, 5, 6, 7 };
static const int g_sector1_indices[] = { 2, 8, 9, 3 };
static const int g_sector2_indices[] = { 8, 10, 11, 9 };
static const int g_sector3_indices[] = { 10, 12, 13, 11 };
static const int g_sector4_indices[] = { 12, 13, 15, 19, 18, 17, 16, 14 };
static const int g_sector5_indices[] = { 6, 5, 20, 21 };

static const doom_sector_t g_sectors[] = {
    {
        .floor_height = 0.0f,
        .ceiling_height = 8.0f,
        .wall_color = DOOM_COLOR(170, 160, 150),
        .floor_color = DOOM_COLOR(70, 60, 50),
        .ceiling_color = DOOM_COLOR(40, 50, 70),
        .polygon = { g_sector0_indices, DOOM_ARRAY_LEN(g_sector0_indices) },
    },
    {
        .floor_height = 0.4f,
        .ceiling_height = 8.0f,
        .wall_color = DOOM_COLOR(200, 150, 90),
        .floor_color = DOOM_COLOR(80, 60, 40),
        .ceiling_color = DOOM_COLOR(45, 55, 80),
        .polygon = { g_sector1_indices, DOOM_ARRAY_LEN(g_sector1_indices) },
    },
    {
        .floor_height = 0.8f,
        .ceiling_height = 8.0f,
        .wall_color = DOOM_COLOR(210, 170, 100),
        .floor_color = DOOM_COLOR(85, 65, 45),
        .ceiling_color = DOOM_COLOR(45, 55, 80),
        .polygon = { g_sector2_indices, DOOM_ARRAY_LEN(g_sector2_indices) },
    },
    {
        .floor_height = 1.4f,
        .ceiling_height = 8.0f,
        .wall_color = DOOM_COLOR(220, 190, 110),
        .floor_color = DOOM_COLOR(90, 70, 50),
        .ceiling_color = DOOM_COLOR(50, 70, 95),
        .polygon = { g_sector3_indices, DOOM_ARRAY_LEN(g_sector3_indices) },
    },
    {
        .floor_height = 2.2f,
        .ceiling_height = 9.5f,
        .wall_color = DOOM_COLOR(90, 140, 190),
        .floor_color = DOOM_COLOR(50, 70, 90),
        .ceiling_color = DOOM_COLOR(30, 40, 60),
        .polygon = { g_sector4_indices, DOOM_ARRAY_LEN(g_sector4_indices) },
    },
    {
        .floor_height = -0.8f,
        .ceiling_height = 7.5f,
        .wall_color = DOOM_COLOR(150, 60, 60),
        .floor_color = DOOM_COLOR(60, 30, 24),
        .ceiling_color = DOOM_COLOR(30, 30, 40),
        .polygon = { g_sector5_indices, DOOM_ARRAY_LEN(g_sector5_indices) },
    },
};

static const doom_wall_t g_sector0_walls[] = {
    { 0, 1, -1, DOOM_COLOR(90, 90, 120) },
    { 1, 2, -1, DOOM_COLOR(110, 110, 140) },
    { 2, 3, 1,  DOOM_COLOR(200, 160, 100) },
    { 3, 4, -1, DOOM_COLOR(92, 92, 122) },
    { 4, 5, -1, DOOM_COLOR(92, 92, 122) },
    { 5, 6, 5,  DOOM_COLOR(160, 80, 60) },
    { 6, 7, -1, DOOM_COLOR(92, 92, 122) },
    { 7, 0, -1, DOOM_COLOR(90, 90, 120) },
};

static const doom_wall_t g_sector1_walls[] = {
    { 2, 8, -1, DOOM_COLOR(140, 110, 80) },
    { 8, 9, 2,  DOOM_COLOR(190, 150, 90) },
    { 9, 3, -1, DOOM_COLOR(140, 110, 80) },
    { 3, 2, 0,  DOOM_COLOR(200, 160, 100) },
};

static const doom_wall_t g_sector2_walls[] = {
    { 8, 10, -1, DOOM_COLOR(150, 120, 90) },
    { 10, 11, 3, DOOM_COLOR(210, 170, 100) },
    { 11, 9, -1, DOOM_COLOR(150, 120, 90) },
    { 9, 8, 1,  DOOM_COLOR(190, 150, 90) },
};

static const doom_wall_t g_sector3_walls[] = {
    { 10, 12, -1, DOOM_COLOR(160, 130, 95) },
    { 12, 13, 4,  DOOM_COLOR(90, 140, 190) },
    { 13, 11, -1, DOOM_COLOR(160, 130, 95) },
    { 11, 10, 2,  DOOM_COLOR(210, 170, 100) },
};

static const doom_wall_t g_sector4_walls[] = {
    { 12, 13, 3,  DOOM_COLOR(90, 140, 190) },
    { 13, 15, -1, DOOM_COLOR(80, 110, 160) },
    { 15, 19, -1, DOOM_COLOR(80, 110, 160) },
    { 19, 18, -1, DOOM_COLOR(70, 100, 150) },
    { 18, 17, -1, DOOM_COLOR(70, 100, 150) },
    { 17, 16, -1, DOOM_COLOR(80, 120, 170) },
    { 16, 14, -1, DOOM_COLOR(90, 130, 180) },
    { 14, 12, -1, DOOM_COLOR(90, 130, 180) },
};

static const doom_wall_t g_sector5_walls[] = {
    { 6, 5, 0,  DOOM_COLOR(160, 80, 60) },
    { 5, 20, -1, DOOM_COLOR(120, 50, 40) },
    { 20, 21, -1, DOOM_COLOR(120, 50, 40) },
    { 21, 6, -1, DOOM_COLOR(140, 60, 50) },
};

static const doom_subsector_t g_subsectors[] = {
    { 0, g_sector0_walls, DOOM_ARRAY_LEN(g_sector0_walls) },
    { 1, g_sector1_walls, DOOM_ARRAY_LEN(g_sector1_walls) },
    { 2, g_sector2_walls, DOOM_ARRAY_LEN(g_sector2_walls) },
    { 3, g_sector3_walls, DOOM_ARRAY_LEN(g_sector3_walls) },
    { 4, g_sector4_walls, DOOM_ARRAY_LEN(g_sector4_walls) },
    { 5, g_sector5_walls, DOOM_ARRAY_LEN(g_sector5_walls) },
};

static const doom_bsp_node_t g_bsp_nodes[] = {
    {
        .origin = { 12.0f, 0.0f },
        .direction = { 0.0f, 1.0f },
        .front_child = 1,
        .back_child = 2,
        .front_bbox = { 12.0f, 0.0f, 26.0f, 10.0f },
        .back_bbox = { 0.0f, 0.0f, 12.0f, 14.0f },
    },
    {
        .origin = { 14.0f, 0.0f },
        .direction = { 0.0f, 1.0f },
        .front_child = DOOM_LEAF(4),
        .back_child = DOOM_LEAF(3),
        .front_bbox = { 14.0f, 0.0f, 26.0f, 10.0f },
        .back_bbox = { 12.0f, 2.0f, 14.0f, 6.0f },
    },
    {
        .origin = { 0.0f, 8.0f },
        .direction = { 1.0f, 0.0f },
        .front_child = 3,
        .back_child = DOOM_LEAF(5),
        .front_bbox = { 0.0f, 0.0f, 12.0f, 8.0f },
        .back_bbox = { 2.0f, 8.0f, 6.0f, 14.0f },
    },
    {
        .origin = { 8.0f, 0.0f },
        .direction = { 0.0f, 1.0f },
        .front_child = 4,
        .back_child = DOOM_LEAF(0),
        .front_bbox = { 8.0f, 2.0f, 12.0f, 6.0f },
        .back_bbox = { 0.0f, 0.0f, 8.0f, 8.0f },
    },
    {
        .origin = { 10.0f, 0.0f },
        .direction = { 0.0f, 1.0f },
        .front_child = DOOM_LEAF(2),
        .back_child = DOOM_LEAF(1),
        .front_bbox = { 10.0f, 2.0f, 12.0f, 6.0f },
        .back_bbox = { 8.0f, 2.0f, 10.0f, 6.0f },
    },
};

#define DOOM_BSP_ROOT 0

static float doom_fast_sin(float angle)
{
    const float B = 4.0f / DOOM_PI;
    const float C = -4.0f / (DOOM_PI * DOOM_PI);
    const float P = 0.225f;

    while (angle < -DOOM_PI)
    {
        angle += DOOM_TWO_PI;
    }
    while (angle > DOOM_PI)
    {
        angle -= DOOM_TWO_PI;
    }

    float y = B * angle + C * angle * doom_fabs(angle);
    return P * (y * doom_fabs(y) - y) + y;
}

static void doom_fast_sin_cos(float angle, float *out_sin, float *out_cos)
{
    float sine = doom_fast_sin(angle);
    float cosine = doom_fast_sin(angle + DOOM_PI * 0.5f);
    if (out_sin)
    {
        *out_sin = sine;
    }
    if (out_cos)
    {
        *out_cos = cosine;
    }
}

static float doom_fast_tan(float angle)
{
    float s = 0.0f;
    float c = 1.0f;
    doom_fast_sin_cos(angle, &s, &c);
    if (doom_fabs(c) < 0.0001f)
    {
        return (s >= 0.0f) ? 10000.0f : -10000.0f;
    }
    return s / c;
}

static void doom_wrap_angle(float *angle)
{
    if (!angle)
    {
        return;
    }
    while (*angle < -DOOM_PI)
    {
        *angle += DOOM_TWO_PI;
    }
    while (*angle > DOOM_PI)
    {
        *angle -= DOOM_TWO_PI;
    }
}

static void doom_set_angle(float angle)
{
    doom_wrap_angle(&angle);
    g_player.angle = angle;

    float s = 0.0f;
    float c = 1.0f;
    doom_fast_sin_cos(angle, &s, &c);
    g_player.dir_x = c;
    g_player.dir_y = s;
    g_player.left_x = -g_player.dir_y;
    g_player.left_y = g_player.dir_x;
}

static void doom_update_projection(void)
{
    g_projection.screen_width = (g_window.width > 0) ? (int)g_window.width : DOOM_VIDEO_WIDTH;
    g_projection.screen_height = (g_window.height > 0) ? (int)g_window.height : DOOM_VIDEO_HEIGHT;
    g_projection.center_x = (float)g_projection.screen_width * 0.5f;
    g_projection.center_y = (float)g_projection.screen_height * 0.5f;
    float half_fov_rad = (DOOM_FOV_DEG * 0.5f) * (DOOM_PI / 180.0f);
    g_projection.horizontal_tan = doom_fast_tan(half_fov_rad);
    if (g_projection.horizontal_tan < 0.001f)
    {
        g_projection.horizontal_tan = 0.001f;
    }
    g_projection.plane_distance = g_projection.center_x / g_projection.horizontal_tan;
    g_projection.vertical_scale = g_projection.center_y;
}

static void doom_update_player_height(void)
{
    if (g_player.sector < 0 || g_player.sector >= (int)DOOM_ARRAY_LEN(g_sectors))
    {
        g_player.sector = 0;
    }
    g_player.z = g_sectors[g_player.sector].floor_height + DOOM_EYE_HEIGHT;
}

static bool doom_sector_has_space(const doom_sector_t *sector)
{
    if (!sector)
    {
        return false;
    }
    float span = sector->ceiling_height - sector->floor_height;
    return (span >= DOOM_MIN_HEADROOM);
}

static bool doom_point_in_sector(const doom_sector_t *sector, float x, float y)
{
    if (!sector || !sector->polygon.indices || sector->polygon.count < 3)
    {
        return false;
    }
    const int *indices = sector->polygon.indices;
    size_t count = sector->polygon.count;
    for (size_t i = 0; i < count; ++i)
    {
        const doom_vec2_t *a = &g_vertices[indices[i]];
        const doom_vec2_t *b = &g_vertices[indices[(i + 1) % count]];
        float cross = (b->x - a->x) * (y - a->y) - (b->y - a->y) * (x - a->x);
        if (cross < -0.0001f)
        {
            return false;
        }
    }
    return true;
}

static int doom_find_sector(float x, float y)
{
    for (size_t i = 0; i < DOOM_ARRAY_LEN(g_sectors); ++i)
    {
        if (doom_point_in_sector(&g_sectors[i], x, y))
        {
            return (int)i;
        }
    }
    return -1;
}

static bool doom_move_component(float dx, float dy)
{
    float next_x = g_player.x + dx;
    float next_y = g_player.y + dy;
    int sector = doom_find_sector(next_x, next_y);
    if (sector < 0)
    {
        return false;
    }
    const doom_sector_t *target = &g_sectors[sector];
    if (!doom_sector_has_space(target))
    {
        return false;
    }
    g_player.x = next_x;
    g_player.y = next_y;
    if (sector != g_player.sector)
    {
        g_player.sector = sector;
        doom_update_player_height();
    }
    return true;
}

static bool doom_move_forward(void)
{
    bool moved = false;
    moved |= doom_move_component(g_player.dir_x * DOOM_MOVE_SPEED, 0.0f);
    moved |= doom_move_component(0.0f, g_player.dir_y * DOOM_MOVE_SPEED);
    return moved;
}

static bool doom_move_backward(void)
{
    bool moved = false;
    moved |= doom_move_component(-g_player.dir_x * DOOM_MOVE_SPEED, 0.0f);
    moved |= doom_move_component(0.0f, -g_player.dir_y * DOOM_MOVE_SPEED);
    return moved;
}

static bool doom_strafe_left(void)
{
    bool moved = false;
    moved |= doom_move_component(g_player.left_x * DOOM_STRAFE_SPEED, 0.0f);
    moved |= doom_move_component(0.0f, g_player.left_y * DOOM_STRAFE_SPEED);
    return moved;
}

static bool doom_strafe_right(void)
{
    bool moved = false;
    moved |= doom_move_component(-g_player.left_x * DOOM_STRAFE_SPEED, 0.0f);
    moved |= doom_move_component(0.0f, -g_player.left_y * DOOM_STRAFE_SPEED);
    return moved;
}

static bool doom_rotate(float delta)
{
    if (delta == 0.0f)
    {
        return false;
    }
    doom_set_angle(g_player.angle + delta);
    return true;
}

static void doom_transform_vertex(const doom_vec2_t *v, doom_projected_point_t *out)
{
    float rel_x = v->x - g_player.x;
    float rel_y = v->y - g_player.y;
    out->world = *v;
    out->depth = rel_x * g_player.dir_x + rel_y * g_player.dir_y;
    out->side = rel_x * g_player.left_x + rel_y * g_player.left_y;
    if (out->depth == 0.0f)
    {
        out->depth = 0.0001f;
    }
    out->screen_x = g_projection.center_x - (out->side * g_projection.plane_distance) / out->depth;
}

static bool doom_clip_to_near(doom_projected_point_t *a, doom_projected_point_t *b)
{
    bool a_inside = (a->depth >= DOOM_NEAR_CLIP);
    bool b_inside = (b->depth >= DOOM_NEAR_CLIP);
    if (a_inside && b_inside)
    {
        return true;
    }
    if (!a_inside && !b_inside)
    {
        return false;
    }

    float t = (DOOM_NEAR_CLIP - a->depth) / (b->depth - a->depth);
    if (t < 0.0f)
    {
        t = 0.0f;
    }
    if (t > 1.0f)
    {
        t = 1.0f;
    }

    doom_vec2_t clipped = {
        a->world.x + (b->world.x - a->world.x) * t,
        a->world.y + (b->world.y - a->world.y) * t,
    };

    if (!a_inside)
    {
        doom_transform_vertex(&clipped, a);
    }
    else
    {
        doom_transform_vertex(&clipped, b);
    }
    return true;
}

static void doom_clear_background(void)
{
    if (!g_window.buffer)
    {
        return;
    }
    const doom_sector_t *sector = &g_sectors[g_player.sector];
    int width = g_projection.screen_width;
    int height = g_projection.screen_height;
    int half = height / 2;
    for (int y = 0; y < height; ++y)
    {
        float shade = 1.0f;
        doom_color_t base = sector->floor_color;
        if (y < half)
        {
            float t = (half > 0) ? ((float)(half - y) / (float)half) : 0.0f;
            shade = 0.4f + 0.6f * t;
            base = sector->ceiling_color;
        }
        else
        {
            int span = height - half;
            float t = (span > 0) ? ((float)(y - half) / (float)span) : 0.0f;
            shade = 0.5f + 0.5f * (1.0f - t);
        }
        uint16_t packed = doom_pack_color(base, shade);
        uint16_t *row = g_window.buffer + (size_t)y * (size_t)width;
        for (int x = 0; x < width; ++x)
        {
            row[x] = packed;
        }
    }
}

static void doom_draw_span(int x, int y0, int y1, doom_color_t color, float depth)
{
    if (!g_window.buffer)
    {
        return;
    }
    if (x < 0 || x >= g_projection.screen_width)
    {
        return;
    }
    if (y0 < 0)
    {
        y0 = 0;
    }
    if (y1 > g_projection.screen_height)
    {
        y1 = g_projection.screen_height;
    }
    if (y1 <= y0)
    {
        return;
    }

    uint16_t color16 = doom_color_from_depth(color, depth);
    uint16_t *buffer = g_window.buffer;
    int stride = g_projection.screen_width;
    for (int y = y0; y < y1; ++y)
    {
        buffer[(size_t)y * (size_t)stride + (size_t)x] = color16;
    }
}

static int doom_project_height(float height, float depth)
{
    float relative = height - g_player.z;
    float projected = g_projection.center_y - (relative * g_projection.vertical_scale) / depth;
    return doom_fast_floor(projected);
}

static void doom_draw_wall(const doom_sector_t *front, const doom_wall_t *wall)
{
    if (!front || !wall)
    {
        return;
    }
    const doom_vec2_t *v0 = &g_vertices[wall->v0];
    const doom_vec2_t *v1 = &g_vertices[wall->v1];

    doom_projected_point_t p0;
    doom_projected_point_t p1;
    doom_transform_vertex(v0, &p0);
    doom_transform_vertex(v1, &p1);

    if (!doom_clip_to_near(&p0, &p1))
    {
        return;
    }

    if (p1.screen_x < p0.screen_x)
    {
        doom_projected_point_t tmp = p0;
        p0 = p1;
        p1 = tmp;
    }

    float screen_delta = p1.screen_x - p0.screen_x;
    if (screen_delta == 0.0f)
    {
        return;
    }

    float inv_depth0 = 1.0f / (p0.depth <= 0.0001f ? 0.0001f : p0.depth);
    float inv_depth1 = 1.0f / (p1.depth <= 0.0001f ? 0.0001f : p1.depth);

    int x_start = doom_fast_floor(p0.screen_x);
    int x_end = doom_fast_floor(p1.screen_x) + 1;
    if (x_start < 0)
    {
        x_start = 0;
    }
    if (x_end > g_projection.screen_width)
    {
        x_end = g_projection.screen_width;
    }

    const doom_sector_t *back = (wall->back_sector >= 0 &&
                                 wall->back_sector < (int)DOOM_ARRAY_LEN(g_sectors))
                              ? &g_sectors[wall->back_sector]
                              : NULL;

    for (int x = x_start; x < x_end; ++x)
    {
        float center = (float)x + 0.5f;
        float t = (center - p0.screen_x) / screen_delta;
        if (t < 0.0f)
        {
            t = 0.0f;
        }
        if (t > 1.0f)
        {
            t = 1.0f;
        }

        float inv_depth = inv_depth0 + (inv_depth1 - inv_depth0) * t;
        if (inv_depth <= 0.00001f)
        {
            continue;
        }
        float depth = 1.0f / inv_depth;

        int front_top = doom_project_height(front->ceiling_height, depth);
        int front_bottom = doom_project_height(front->floor_height, depth) + 1;

        if (!back)
        {
            doom_draw_span(x, front_top, front_bottom, wall->color, depth);
            continue;
        }

        int back_top = doom_project_height(back->ceiling_height, depth);
        int back_bottom = doom_project_height(back->floor_height, depth) + 1;

        if (back_top < front_top)
        {
            doom_draw_span(x, back_top, front_top, wall->color, depth);
        }
        if (back_bottom > front_bottom)
        {
            doom_draw_span(x, front_bottom, back_bottom, wall->color, depth);
        }
    }
}

static bool doom_point_on_front(const doom_bsp_node_t *node, float x, float y)
{
    float dx = x - node->origin.x;
    float dy = y - node->origin.y;
    float cross = dx * node->direction.y - dy * node->direction.x;
    return (cross >= 0.0f);
}

static bool doom_bbox_visible(const doom_bbox_t *bbox)
{
    if (!bbox)
    {
        return true;
    }

    if (g_player.x >= bbox->min_x && g_player.x <= bbox->max_x &&
        g_player.y >= bbox->min_y && g_player.y <= bbox->max_y)
    {
        return true;
    }

    doom_vec2_t corners[4] = {
        { bbox->min_x, bbox->min_y },
        { bbox->max_x, bbox->min_y },
        { bbox->max_x, bbox->max_y },
        { bbox->min_x, bbox->max_y },
    };

    for (size_t i = 0; i < 4; ++i)
    {
        float rel_x = corners[i].x - g_player.x;
        float rel_y = corners[i].y - g_player.y;
        float depth = rel_x * g_player.dir_x + rel_y * g_player.dir_y;
        if (depth <= DOOM_NEAR_CLIP)
        {
            continue;
        }
        float side = rel_x * g_player.left_x + rel_y * g_player.left_y;
        float limit = depth * g_projection.horizontal_tan;
        if (side >= -limit && side <= limit)
        {
            return true;
        }
    }
    return false;
}

static void doom_render_subsector(int subsector_index)
{
    if (subsector_index < 0 || subsector_index >= (int)DOOM_ARRAY_LEN(g_subsectors))
    {
        return;
    }
    const doom_subsector_t *sub = &g_subsectors[subsector_index];
    if (sub->sector < 0 || sub->sector >= (int)DOOM_ARRAY_LEN(g_sectors))
    {
        return;
    }
    const doom_sector_t *sector = &g_sectors[sub->sector];
    for (size_t i = 0; i < sub->wall_count; ++i)
    {
        doom_draw_wall(sector, &sub->walls[i]);
    }
}

static void doom_render_bsp(int16_t node_index)
{
    if (doom_is_leaf(node_index))
    {
        doom_render_subsector(doom_leaf_index(node_index));
        return;
    }
    if (node_index < 0 || node_index >= (int16_t)DOOM_ARRAY_LEN(g_bsp_nodes))
    {
        return;
    }
    const doom_bsp_node_t *node = &g_bsp_nodes[node_index];
    bool player_front = doom_point_on_front(node, g_player.x, g_player.y);

    int16_t first_child = player_front ? node->back_child : node->front_child;
    int16_t second_child = player_front ? node->front_child : node->back_child;
    const doom_bbox_t *first_bbox = player_front ? &node->back_bbox : &node->front_bbox;
    const doom_bbox_t *second_bbox = player_front ? &node->front_bbox : &node->back_bbox;

    if (doom_bbox_visible(first_bbox))
    {
        doom_render_bsp(first_child);
    }
    if (doom_bbox_visible(second_bbox))
    {
        doom_render_bsp(second_child);
    }
}

static bool doom_read_uint32(const char *path, uint32_t *value_out)
{
    if (!path || !value_out)
    {
        return false;
    }
    char buffer[32];
    int fd = open(path, SYSCALL_OPEN_READ);
    if (fd < 0)
    {
        return false;
    }
    ssize_t bytes = read(fd, buffer, sizeof(buffer) - 1);
    close(fd);
    if (bytes <= 0)
    {
        return false;
    }
    buffer[bytes] = '\0';

    uint32_t value = 0;
    const char *cursor = buffer;
    while (*cursor == ' ' || *cursor == '\n' || *cursor == '\r' || *cursor == '\t')
    {
        ++cursor;
    }
    bool any = false;
    while (*cursor >= '0' && *cursor <= '9')
    {
        any = true;
        value = value * 10u + (uint32_t)(*cursor - '0');
        ++cursor;
    }
    if (!any)
    {
        return false;
    }
    *value_out = value;
    return true;
}

static bool doom_write_uint32(const char *path, uint32_t value)
{
    if (!path)
    {
        return false;
    }
    char buffer[32];
    int len = 0;
    if (value == 0)
    {
        buffer[len++] = '0';
    }
    else
    {
        char temp[32];
        int t = 0;
        while (value > 0 && t < (int)sizeof(temp))
        {
            temp[t++] = (char)('0' + (value % 10u));
            value /= 10u;
        }
        while (t > 0 && len < (int)sizeof(buffer) - 1)
        {
            buffer[len++] = temp[--t];
        }
    }
    buffer[len] = '\0';

    int fd = open(path, SYSCALL_OPEN_WRITE | SYSCALL_OPEN_TRUNCATE);
    if (fd < 0)
    {
        return false;
    }
    bool ok = (write(fd, buffer, (size_t)len) == len);
    close(fd);
    return ok;
}

static bool doom_read_bool(const char *path, bool *value_out)
{
    uint32_t value = 0;
    if (!doom_read_uint32(path, &value))
    {
        return false;
    }
    if (value_out)
    {
        *value_out = (value != 0);
    }
    return true;
}

static bool doom_write_bool(const char *path, bool value)
{
    return doom_write_uint32(path, value ? 1u : 0u);
}

static bool doom_override_repeat(doom_keyboard_repeat_t *backup)
{
    if (!backup)
    {
        return false;
    }
    backup->valid = doom_read_uint32(PROC_REPEAT_INITIAL, &backup->initial_ms) &&
                    doom_read_uint32(PROC_REPEAT_INTERVAL, &backup->repeat_ms) &&
                    doom_read_bool(PROC_REPEAT_MULTI, &backup->multi_enabled);
    bool initial_ok = doom_write_uint32(PROC_REPEAT_INITIAL, 0);
    bool repeat_ok = doom_write_uint32(PROC_REPEAT_INTERVAL, 60);
    bool multi_ok = doom_write_bool(PROC_REPEAT_MULTI, true);
    return (initial_ok && repeat_ok && multi_ok);
}

static void doom_restore_repeat(const doom_keyboard_repeat_t *backup)
{
    if (!backup || !backup->valid)
    {
        return;
    }
    doom_write_uint32(PROC_REPEAT_INITIAL, backup->initial_ms);
    doom_write_uint32(PROC_REPEAT_INTERVAL, backup->repeat_ms);
    doom_write_bool(PROC_REPEAT_MULTI, backup->multi_enabled);
}

static void doom_render_scene(void)
{
    if (!g_window.buffer || g_window.width == 0 || g_window.height == 0)
    {
        return;
    }
    doom_clear_background();
    doom_render_bsp(DOOM_BSP_ROOT);
    atk_user_present(&g_window);
}

static bool doom_handle_key(char ch, bool *running)
{
    if (ch >= 'A' && ch <= 'Z')
    {
        ch = (char)(ch - 'A' + 'a');
    }
    bool updated = false;
    switch (ch)
    {
        case 'w':
            updated = doom_move_forward();
            break;
        case 's':
            updated = doom_move_backward();
            break;
        case 'a':
            updated = doom_strafe_left();
            break;
        case 'd':
            updated = doom_strafe_right();
            break;
        case 'q':
            updated = doom_rotate(-DOOM_TURN_SPEED);
            break;
        case 'e':
            updated = doom_rotate(DOOM_TURN_SPEED);
            break;
        case 27:
            if (running)
            {
                *running = false;
            }
            break;
        default:
            break;
    }
    return updated;
}

int main(void)
{
    if (!atk_user_window_open(&g_window, "Doom-ish (user)", VIDEO_WIDTH, VIDEO_HEIGHT))
    {
        printf("doom: failed to open window\n");
        return 1;
    }

    if (doom_override_repeat(&g_repeat_backup))
    {
        g_repeat_backup.valid = true;
    }

    doom_update_projection();
    g_player.sector = doom_find_sector(g_player.x, g_player.y);
    if (g_player.sector < 0)
    {
        g_player.sector = 0;
    }
    doom_update_player_height();
    doom_set_angle(0.0f);
    doom_render_scene();

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
                needs_redraw = doom_handle_key((char)event.data0, &running);
                break;
            case USER_ATK_EVENT_CLOSE:
                running = false;
                break;
            default:
                break;
        }

        if (needs_redraw)
        {
            doom_render_scene();
        }
    }

    atk_user_close(&g_window);
    doom_restore_repeat(&g_repeat_backup);
    return 0;
}
