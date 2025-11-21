#include "atk_user.h"

#include "libc.h"
#include "syscall_defs.h"
#include "types.h"
#include "usyscall.h"
#include "video.h"

#define DOOM_PI 3.14159265358979323846f
#define DOOM_TWO_PI (DOOM_PI * 2.0f)
#define DOOM_ARRAY_LEN(x) (sizeof(x) / sizeof((x)[0]))
#define DOOM_VIDEO_WIDTH ((int)VIDEO_WIDTH)
#define DOOM_VIDEO_HEIGHT ((int)VIDEO_HEIGHT)

#define DOOM_MOVE_SPEED 0.18f
#define DOOM_STRAFE_SPEED 0.16f
#define DOOM_TURN_SPEED 0.045f
#define DOOM_EYE_HEIGHT 4.0f
#define DOOM_MIN_HEADROOM 4.5f
#define DOOM_NEAR_CLIP 0.05f
#define DOOM_FOV_DEG 90.0f
#define DOOM_JUMP_SPEED 5.0f
#define DOOM_GRAVITY 12.0f
#define DOOM_PHYSICS_DT 0.05f
#define DOOM_CEILING_MARGIN 0.1f
#define DOOM_JUMP_EPSILON 0.0001f

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
    const doom_vec2_t *points;
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
    doom_vec2_t v0;
    doom_vec2_t v1;
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
    float z_offset;
    float vertical_velocity;
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
    .z_offset = 0.0f,
    .vertical_velocity = 0.0f,
};
static doom_keyboard_repeat_t g_repeat_backup = { 0 };

#define DOOM_EVENT_CACHE_MAX 4
static user_atk_event_t g_event_cache[DOOM_EVENT_CACHE_MAX];
static size_t g_event_cache_count = 0;

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
static bool doom_poll_event(user_atk_event_t *event, bool block);
static void doom_unread_event(const user_atk_event_t *event);
static bool doom_try_consume_arrow(char *code_out);
static bool doom_handle_escape(bool *running);
static bool doom_player_on_ground(void);
static bool doom_jump_active(void);
static bool doom_trigger_jump(void);
static bool doom_step_physics(float dt);
static const doom_sector_t *doom_current_sector(void);
static float doom_max_jump_offset(const doom_sector_t *sector);
static bool doom_read_uint32(const char *path, uint32_t *value_out);
static bool doom_write_uint32(const char *path, uint32_t value);
static bool doom_read_bool(const char *path, bool *value_out);
static bool doom_write_bool(const char *path, bool value);
static bool doom_override_repeat(doom_keyboard_repeat_t *backup);
static void doom_restore_repeat(const doom_keyboard_repeat_t *backup);
static bool doom_handle_resize(uint32_t width, uint32_t height);
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

static inline video_color_t doom_pack_color(doom_color_t color, float shade)
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

static inline video_color_t doom_color_from_depth(doom_color_t color, float depth)
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

static bool doom_event_cache_push(const user_atk_event_t *event)
{
    if (!event || g_event_cache_count >= DOOM_EVENT_CACHE_MAX)
    {
        return false;
    }
    g_event_cache[g_event_cache_count++] = *event;
    return true;
}

static bool doom_event_cache_pop(user_atk_event_t *event)
{
    if (!event || g_event_cache_count == 0)
    {
        return false;
    }
    *event = g_event_cache[--g_event_cache_count];
    return true;
}

static bool doom_poll_event(user_atk_event_t *event, bool block)
{
    if (!event)
    {
        return false;
    }
    if (doom_event_cache_pop(event))
    {
        return true;
    }
    if (g_window.handle == 0)
    {
        return false;
    }
    uint32_t flags = block ? USER_ATK_POLL_FLAG_BLOCK : 0;
    int rc = sys_ui_poll_event(g_window.handle, event, flags);
    return (rc == 1);
}

static void doom_unread_event(const user_atk_event_t *event)
{
    (void)doom_event_cache_push(event);
}

static bool doom_try_consume_arrow(char *code_out)
{
    user_atk_event_t next;
    if (!doom_poll_event(&next, false))
    {
        return false;
    }
    if (next.type != USER_ATK_EVENT_KEY || (char)next.data0 != '[')
    {
        doom_unread_event(&next);
        return false;
    }

    user_atk_event_t final;
    if (!doom_poll_event(&final, false))
    {
        doom_unread_event(&next);
        return false;
    }
    if (final.type != USER_ATK_EVENT_KEY)
    {
        doom_unread_event(&final);
        doom_unread_event(&next);
        return false;
    }

    char code = (char)final.data0;
    if (code == 'A' || code == 'B' || code == 'C' || code == 'D')
    {
        if (code_out)
        {
            *code_out = code;
        }
        return true;
    }

    doom_unread_event(&final);
    doom_unread_event(&next);
    return false;
}

static bool doom_handle_escape(bool *running)
{
    char code = 0;
    if (doom_try_consume_arrow(&code))
    {
        switch (code)
        {
            case 'C':
                return doom_rotate(-DOOM_TURN_SPEED);
            case 'D':
                return doom_rotate(DOOM_TURN_SPEED);
            case 'A':
                return doom_move_forward();
            case 'B':
                return doom_move_backward();
            default:
                return false;
        }
    }

    if (running)
    {
        *running = false;
    }
    return false;
}

typedef struct
{
    float x0, y0, x1, y1;
    float floor_height;
    float ceiling_height;
    doom_color_t wall_color;
    doom_color_t floor_color;
    doom_color_t ceiling_color;
} doom_sector_desc_t;

static const doom_sector_desc_t g_sector_descs[] = {
    {   0.0f,   0.0f,  12.0f,  12.0f,  0.0f, 14.0f,
        DOOM_COLOR(170, 160, 150), DOOM_COLOR(70, 60, 50), DOOM_COLOR(40, 55, 90) },
    { -12.0f,   0.0f,   0.0f,  12.0f,  0.5f, 14.2f,
        DOOM_COLOR(190, 140, 90), DOOM_COLOR(65, 55, 40), DOOM_COLOR(45, 60, 110) },
    { -24.0f,   0.0f, -12.0f,  12.0f,  1.0f, 14.5f,
        DOOM_COLOR(150, 110, 80), DOOM_COLOR(60, 45, 35), DOOM_COLOR(35, 50, 90) },
    {   0.0f, -10.0f,  12.0f,   0.0f, -0.5f, 13.2f,
        DOOM_COLOR(160, 120, 70), DOOM_COLOR(55, 40, 25), DOOM_COLOR(30, 40, 70) },
    { -12.0f, -10.0f,   0.0f,   0.0f, -0.8f, 13.0f,
        DOOM_COLOR(140, 90, 60), DOOM_COLOR(50, 30, 25), DOOM_COLOR(25, 35, 60) },
    {  12.0f,   0.0f,  24.0f,  12.0f,  0.8f, 14.5f,
        DOOM_COLOR(200, 150, 100), DOOM_COLOR(90, 70, 40), DOOM_COLOR(55, 65, 100) },
    {  24.0f,   0.0f,  36.0f,  12.0f,  1.2f, 14.8f,
        DOOM_COLOR(120, 160, 200), DOOM_COLOR(45, 60, 85), DOOM_COLOR(50, 70, 110) },
    {  36.0f,   0.0f,  48.0f,  12.0f,  2.0f, 15.0f,
        DOOM_COLOR(90, 140, 200), DOOM_COLOR(40, 55, 85), DOOM_COLOR(35, 50, 95) },
    {   0.0f,  12.0f,  12.0f,  20.0f,  0.4f, 14.3f,
        DOOM_COLOR(200, 180, 120), DOOM_COLOR(75, 65, 45), DOOM_COLOR(60, 75, 110) },
    {   0.0f,  20.0f,  12.0f,  32.0f,  0.9f, 15.0f,
        DOOM_COLOR(160, 190, 140), DOOM_COLOR(70, 85, 60), DOOM_COLOR(80, 100, 140) },
    {  12.0f,  12.0f,  24.0f,  20.0f,  1.1f, 14.6f,
        DOOM_COLOR(210, 140, 120), DOOM_COLOR(95, 60, 50), DOOM_COLOR(65, 60, 90) },
    {  12.0f,  20.0f,  24.0f,  32.0f,  1.6f, 15.4f,
        DOOM_COLOR(150, 110, 200), DOOM_COLOR(60, 50, 95), DOOM_COLOR(90, 90, 150) },
    {  24.0f,  20.0f,  36.0f,  32.0f,  2.2f, 15.7f,
        DOOM_COLOR(120, 150, 210), DOOM_COLOR(55, 75, 105), DOOM_COLOR(70, 95, 140) },
    {  36.0f,  20.0f,  48.0f,  32.0f,  3.0f, 16.2f,
        DOOM_COLOR(220, 200, 120), DOOM_COLOR(105, 90, 45), DOOM_COLOR(120, 110, 70) },
    { -12.0f,  12.0f,   0.0f,  20.0f,  0.6f, 14.2f,
        DOOM_COLOR(180, 120, 150), DOOM_COLOR(75, 50, 65), DOOM_COLOR(95, 80, 120) },
    { -12.0f,  20.0f,   0.0f,  32.0f,  1.3f, 15.1f,
        DOOM_COLOR(150, 170, 120), DOOM_COLOR(60, 80, 55), DOOM_COLOR(85, 110, 100) },
    { -24.0f,  12.0f, -12.0f,  24.0f,  1.8f, 15.6f,
        DOOM_COLOR(100, 150, 170), DOOM_COLOR(40, 70, 80), DOOM_COLOR(65, 105, 125) },
    {  12.0f,  20.0f,  24.0f,  28.0f,  2.0f, 15.8f,
        DOOM_COLOR(210, 110, 140), DOOM_COLOR(110, 55, 75), DOOM_COLOR(140, 90, 130) },
    {  12.0f, -10.0f,  24.0f,   0.0f, -0.2f, 13.6f,
        DOOM_COLOR(200, 100, 80), DOOM_COLOR(85, 40, 35), DOOM_COLOR(55, 45, 80) },
    {  24.0f, -10.0f,  36.0f,   0.0f,  0.0f, 13.9f,
        DOOM_COLOR(140, 100, 200), DOOM_COLOR(60, 45, 95), DOOM_COLOR(80, 70, 130) },
    {  36.0f, -10.0f,  48.0f,   0.0f,  0.4f, 14.1f,
        DOOM_COLOR(90, 120, 200), DOOM_COLOR(35, 55, 90), DOOM_COLOR(60, 80, 120) },
};

#define DOOM_SECTOR_COUNT ((int)DOOM_ARRAY_LEN(g_sector_descs))
#define DOOM_MAX_SECTOR_POINTS 4
#define DOOM_MAX_WALLS_PER_SECTOR 8
#define DOOM_MAX_BSP_NODES (DOOM_SECTOR_COUNT * 2)

static doom_vec2_t g_sector_points[DOOM_SECTOR_COUNT][DOOM_MAX_SECTOR_POINTS];
static doom_polygon_t g_sector_polygons_meta[DOOM_SECTOR_COUNT];
static doom_sector_t g_sectors[DOOM_SECTOR_COUNT];
static doom_wall_t g_sector_walls[DOOM_SECTOR_COUNT][DOOM_MAX_WALLS_PER_SECTOR];
static doom_subsector_t g_subsectors[DOOM_SECTOR_COUNT];
static doom_bbox_t g_subsector_bboxes[DOOM_SECTOR_COUNT];
static doom_bsp_node_t g_bsp_nodes[DOOM_MAX_BSP_NODES];
static doom_bbox_t g_bsp_node_bounds[DOOM_MAX_BSP_NODES];
static size_t g_bsp_node_count = 0;
static int16_t g_bsp_root = DOOM_LEAF(0);
static bool g_level_initialized = false;

static void doom_init_sector_geometry(void)
{
    for (int i = 0; i < DOOM_SECTOR_COUNT; ++i)
    {
        const doom_sector_desc_t *desc = &g_sector_descs[i];
        doom_vec2_t *points = g_sector_points[i];
        points[0] = (doom_vec2_t){ desc->x0, desc->y0 };
        points[1] = (doom_vec2_t){ desc->x1, desc->y0 };
        points[2] = (doom_vec2_t){ desc->x1, desc->y1 };
        points[3] = (doom_vec2_t){ desc->x0, desc->y1 };

        g_sector_polygons_meta[i].points = points;
        g_sector_polygons_meta[i].count = 4;

        g_sectors[i].floor_height = desc->floor_height;
        g_sectors[i].ceiling_height = desc->ceiling_height;
        g_sectors[i].wall_color = desc->wall_color;
        g_sectors[i].floor_color = desc->floor_color;
        g_sectors[i].ceiling_color = desc->ceiling_color;
        g_sectors[i].polygon = g_sector_polygons_meta[i];
    }
}

static bool doom_points_equal(const doom_vec2_t *a, const doom_vec2_t *b)
{
    const float EPS = 0.0001f;
    return (doom_fabs(a->x - b->x) < EPS) && (doom_fabs(a->y - b->y) < EPS);
}

static doom_bbox_t doom_compute_polygon_bbox(const doom_polygon_t *poly)
{
    doom_bbox_t bbox = { .min_x = 1e9f, .min_y = 1e9f, .max_x = -1e9f, .max_y = -1e9f };
    for (size_t i = 0; i < poly->count; ++i)
    {
        const doom_vec2_t *p = &poly->points[i];
        if (p->x < bbox.min_x) bbox.min_x = p->x;
        if (p->y < bbox.min_y) bbox.min_y = p->y;
        if (p->x > bbox.max_x) bbox.max_x = p->x;
        if (p->y > bbox.max_y) bbox.max_y = p->y;
    }
    return bbox;
}

static doom_bbox_t doom_bbox_union(const doom_bbox_t *a, const doom_bbox_t *b)
{
    doom_bbox_t result = {
        .min_x = (a->min_x < b->min_x) ? a->min_x : b->min_x,
        .min_y = (a->min_y < b->min_y) ? a->min_y : b->min_y,
        .max_x = (a->max_x > b->max_x) ? a->max_x : b->max_x,
        .max_y = (a->max_y > b->max_y) ? a->max_y : b->max_y,
    };
    return result;
}

static int doom_find_neighbor_edge(const doom_vec2_t *start,
                                   const doom_vec2_t *end,
                                   int current_sector)
{
    for (int s = 0; s < DOOM_SECTOR_COUNT; ++s)
    {
        if (s == current_sector)
        {
            continue;
        }
        const doom_polygon_t *poly = &g_sectors[s].polygon;
        for (size_t i = 0; i < poly->count; ++i)
        {
            const doom_vec2_t *b0 = &poly->points[i];
            const doom_vec2_t *b1 = &poly->points[(i + 1) % poly->count];
            if (doom_points_equal(end, b0) && doom_points_equal(start, b1))
            {
                return s;
            }
        }
    }
    return -1;
}

static void doom_build_walls(void)
{
    for (int i = 0; i < DOOM_SECTOR_COUNT; ++i)
    {
        const doom_polygon_t *poly = &g_sectors[i].polygon;
        size_t edge_count = poly->count;
        if (edge_count > DOOM_MAX_WALLS_PER_SECTOR)
        {
            edge_count = DOOM_MAX_WALLS_PER_SECTOR;
        }
        for (size_t e = 0; e < edge_count; ++e)
        {
            const doom_vec2_t *p0 = &poly->points[e];
            const doom_vec2_t *p1 = &poly->points[(e + 1) % poly->count];
            int neighbor = doom_find_neighbor_edge(p0, p1, i);
            g_sector_walls[i][e].v0 = *p0;
            g_sector_walls[i][e].v1 = *p1;
            g_sector_walls[i][e].back_sector = neighbor;
            g_sector_walls[i][e].color = g_sectors[i].wall_color;
        }
        g_subsectors[i].sector = i;
        g_subsectors[i].walls = g_sector_walls[i];
        g_subsectors[i].wall_count = edge_count;
        g_subsector_bboxes[i] = doom_compute_polygon_bbox(poly);
    }
}

static const doom_bbox_t *doom_bbox_for_index(int16_t index)
{
    if (doom_is_leaf(index))
    {
        return &g_subsector_bboxes[doom_leaf_index(index)];
    }
    return &g_bsp_node_bounds[index];
}

static doom_bbox_t doom_bbox_of_indices(const int *indices, size_t count)
{
    doom_bbox_t bbox = { .min_x = 1e9f, .min_y = 1e9f, .max_x = -1e9f, .max_y = -1e9f };
    for (size_t i = 0; i < count; ++i)
    {
        doom_bbox_t bb = g_subsector_bboxes[indices[i]];
        if (bb.min_x < bbox.min_x) bbox.min_x = bb.min_x;
        if (bb.min_y < bbox.min_y) bbox.min_y = bb.min_y;
        if (bb.max_x > bbox.max_x) bbox.max_x = bb.max_x;
        if (bb.max_y > bbox.max_y) bbox.max_y = bb.max_y;
    }
    return bbox;
}

static int16_t doom_build_bsp_recursive(const int *indices, size_t count, int depth)
{
    if (count == 0)
    {
        return DOOM_LEAF(0);
    }
    if (count == 1)
    {
        return DOOM_LEAF(indices[0]);
    }

    doom_bbox_t bounds = doom_bbox_of_indices(indices, count);
    float span_x = bounds.max_x - bounds.min_x;
    float span_y = bounds.max_y - bounds.min_y;
    bool split_on_x = (span_x >= span_y);
    float split = split_on_x ? (bounds.min_x + bounds.max_x) * 0.5f
                             : (bounds.min_y + bounds.max_y) * 0.5f;

    int front_list[DOOM_SECTOR_COUNT];
    int back_list[DOOM_SECTOR_COUNT];
    size_t front_count = 0;
    size_t back_count = 0;

    for (size_t i = 0; i < count; ++i)
    {
        doom_bbox_t bb = g_subsector_bboxes[indices[i]];
        float center = split_on_x
                     ? (bb.min_x + bb.max_x) * 0.5f
                     : (bb.min_y + bb.max_y) * 0.5f;
        if (center >= split)
        {
            front_list[front_count++] = indices[i];
        }
        else
        {
            back_list[back_count++] = indices[i];
        }
    }

    if (front_count == 0)
    {
        front_list[front_count++] = back_list[--back_count];
    }
    else if (back_count == 0)
    {
        back_list[back_count++] = front_list[--front_count];
    }

    int16_t front_child = doom_build_bsp_recursive(front_list, front_count, depth + 1);
    int16_t back_child = doom_build_bsp_recursive(back_list, back_count, depth + 1);

    if (g_bsp_node_count >= DOOM_MAX_BSP_NODES)
    {
        return front_child;
    }

    size_t node_index = g_bsp_node_count++;
    doom_bsp_node_t *node = &g_bsp_nodes[node_index];
    node->origin = split_on_x
                 ? (doom_vec2_t){ split, 0.0f }
                 : (doom_vec2_t){ 0.0f, split };
    node->direction = split_on_x
                    ? (doom_vec2_t){ 0.0f, 1.0f }
                    : (doom_vec2_t){ 1.0f, 0.0f };
    node->front_child = front_child;
    node->back_child = back_child;
    node->front_bbox = *doom_bbox_for_index(front_child);
    node->back_bbox = *doom_bbox_for_index(back_child);
    g_bsp_node_bounds[node_index] = doom_bbox_union(&node->front_bbox, &node->back_bbox);
    return (int16_t)node_index;
}

static void doom_level_init(void)
{
    if (g_level_initialized)
    {
        return;
    }
    doom_init_sector_geometry();
    doom_build_walls();
    int indices[DOOM_SECTOR_COUNT];
    for (int i = 0; i < DOOM_SECTOR_COUNT; ++i)
    {
        indices[i] = i;
    }
    g_bsp_node_count = 0;
    g_bsp_root = doom_build_bsp_recursive(indices, DOOM_SECTOR_COUNT, 0);
    g_level_initialized = true;
}

static const doom_sector_t *doom_current_sector(void)
{
    if (g_player.sector < 0 || g_player.sector >= DOOM_SECTOR_COUNT)
    {
        return NULL;
    }
    return &g_sectors[g_player.sector];
}

static float doom_max_jump_offset(const doom_sector_t *sector)
{
    if (!sector)
    {
        return 0.0f;
    }
    float span = sector->ceiling_height - sector->floor_height - DOOM_EYE_HEIGHT - DOOM_CEILING_MARGIN;
    if (span < 0.0f)
    {
        span = 0.0f;
    }
    return span;
}

static bool doom_player_on_ground(void)
{
    return (g_player.z_offset <= DOOM_JUMP_EPSILON && g_player.vertical_velocity <= 0.0f);
}

static bool doom_jump_active(void)
{
    return !doom_player_on_ground();
}

static bool doom_trigger_jump(void)
{
    const doom_sector_t *sector = doom_current_sector();
    if (!sector || doom_max_jump_offset(sector) <= DOOM_JUMP_EPSILON)
    {
        return false;
    }
    if (!doom_player_on_ground())
    {
        return false;
    }
    g_player.vertical_velocity = DOOM_JUMP_SPEED;
    return true;
}

static bool doom_step_physics(float dt)
{
    if (!doom_jump_active())
    {
        return false;
    }

    if (dt <= 0.0f)
    {
        dt = DOOM_PHYSICS_DT;
    }

    g_player.vertical_velocity -= DOOM_GRAVITY * dt;
    g_player.z_offset += g_player.vertical_velocity * dt;
    if (g_player.z_offset <= 0.0f)
    {
        g_player.z_offset = 0.0f;
        g_player.vertical_velocity = 0.0f;
    }
    doom_update_player_height();
    return true;
}

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
    if (g_player.sector < 0 || g_player.sector >= DOOM_SECTOR_COUNT)
    {
        g_player.sector = 0;
    }
    const doom_sector_t *sector = doom_current_sector();
    if (!sector)
    {
        return;
    }
    float max_offset = doom_max_jump_offset(sector);
    if (g_player.z_offset > max_offset)
    {
        g_player.z_offset = max_offset;
        if (g_player.vertical_velocity > 0.0f)
        {
            g_player.vertical_velocity = 0.0f;
        }
    }
    if (g_player.z_offset < 0.0f)
    {
        g_player.z_offset = 0.0f;
    }
    g_player.z = sector->floor_height + DOOM_EYE_HEIGHT + g_player.z_offset;
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
    if (!sector || !sector->polygon.points || sector->polygon.count < 3)
    {
        return false;
    }
    const doom_vec2_t *points = sector->polygon.points;
    size_t count = sector->polygon.count;
    for (size_t i = 0; i < count; ++i)
    {
        const doom_vec2_t *a = &points[i];
        const doom_vec2_t *b = &points[(i + 1) % count];
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
    for (size_t i = 0; i < DOOM_SECTOR_COUNT; ++i)
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
        video_color_t packed = doom_pack_color(base, shade);
        video_color_t *row = g_window.buffer + (size_t)y * (size_t)width;
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

    video_color_t color16 = doom_color_from_depth(color, depth);
    video_color_t *buffer = g_window.buffer;
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
    doom_projected_point_t p0;
    doom_projected_point_t p1;
    doom_transform_vertex(&wall->v0, &p0);
    doom_transform_vertex(&wall->v1, &p1);

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
                                 wall->back_sector < DOOM_SECTOR_COUNT)
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
    if (subsector_index < 0 || subsector_index >= DOOM_SECTOR_COUNT)
    {
        return;
    }
    const doom_subsector_t *sub = &g_subsectors[subsector_index];
    if (sub->sector < 0 || sub->sector >= DOOM_SECTOR_COUNT)
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
    if (node_index < 0 || node_index >= (int16_t)g_bsp_node_count)
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
    if (!g_level_initialized)
    {
        doom_level_init();
    }

    if (!g_window.buffer || g_window.width == 0 || g_window.height == 0)
    {
        return;
    }
    doom_clear_background();
    doom_render_bsp(g_bsp_root);
    atk_user_present(&g_window);
}

static bool doom_handle_resize(uint32_t width, uint32_t height)
{
    (void)width;
    (void)height;
    if (!g_window.buffer)
    {
        return false;
    }
    doom_update_projection();
    return true;
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
        case ' ':
            updated = doom_trigger_jump();
            break;
        case 27:
            updated = doom_handle_escape(running);
            break;
        default:
            break;
    }
    return updated;
}

int main(void)
{
    if (!atk_user_window_open(&g_window, "Doom", VIDEO_WIDTH, VIDEO_HEIGHT))
    {
        printf("doom: failed to open window\n");
        return 1;
    }

    if (doom_override_repeat(&g_repeat_backup))
    {
        g_repeat_backup.valid = true;
    }

    doom_level_init();
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
        bool airborne = doom_jump_active();
        user_atk_event_t event;
        bool have_event = doom_poll_event(&event, !airborne);
        bool needs_redraw = doom_step_physics(DOOM_PHYSICS_DT);

        if (!have_event)
        {
            if (!airborne)
            {
                break;
            }
            if (needs_redraw)
            {
                doom_render_scene();
            }
            sys_yield();
            continue;
        }

        switch (event.type)
        {
            case USER_ATK_EVENT_KEY:
                needs_redraw |= doom_handle_key((char)event.data0, &running);
                break;
            case USER_ATK_EVENT_RESIZE:
                needs_redraw = doom_handle_resize((uint32_t)event.data0, (uint32_t)event.data1) || needs_redraw;
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
