#include "atk_user.h"

#include "atk.h"
#include "atk_app.h"
#include "atk_internal.h"
#include "atk_menu_bar.h"
#include "atk_window.h"
#include "atk/atk_menu.h"
#include "atk/atk_label.h"
#include "atk/atk_list_view.h"
#include "atk/atk_dropdown.h"
#include "atk/atk_iconbox.h"
#include "atk/atk_tree_view.h"
#include "atk/util/jpeg.h"
#include "atk/util/png.h"
#include "crypto/sha1.h"
#include "ctype.h"
#include "libc.h"
#include "stdio.h"
#include "video.h"
#include "usyscall.h"
#include "user_atk_defs.h"

#define ATK_COL(chars) ((chars) * ATK_FONT_WIDTH)

#define FILEMAN_WINDOW_WIDTH  960
#define FILEMAN_WINDOW_HEIGHT 640
#define FILEMAN_MARGIN 12
#define FILEMAN_TREE_MIN_WIDTH 200
#define FILEMAN_TREE_MAX_WIDTH 320
#define FILEMAN_PATH_MAX 512
#define FILEMAN_MAX_ENTRIES 256
#define FILEMAN_DBLCLICK_MS 500
#define FILEMAN_CLICK_DEBOUNCE_MS 150
#define FILEMAN_VIEW_BUTTON_HEIGHT 24
#define FILEMAN_VIEW_BUTTON_WIDTH 80
#define FILEMAN_VIEW_BUTTON_GAP 8
#define FILEMAN_VIEW_BUTTON_SPACING 8
#define FILEMAN_SORT_DROPDOWN_WIDTH 140
#define FILEMAN_SORT_DROPDOWN_GAP 8
#define FILEMAN_ICON_BASE "/usr/share/icons/48x48"
#define FILEMAN_ICON_MIMETYPE_DIR FILEMAN_ICON_BASE "/mimetypes"
#define FILEMAN_PREVIEW_ELF "/usr/bin/atk_preview.elf"
#define FILEMAN_TTF_DEMO_ELF "/usr/bin/ttf_demo.elf"
#define FILEMAN_DEFAULT_APPS_PATH "/etc/default_apps"
#define FILEMAN_DEFAULT_APPS_LINE_MAX 512
#define FILEMAN_PROPERTIES_WIDTH 360
#define FILEMAN_PROPERTIES_HEIGHT 220
#define FILEMAN_THUMB_DIR_SUFFIX "/.fileman/thumbnails"
#define FILEMAN_THUMB_SIZE 48
#define FILEMAN_THUMB_MAX_BYTES (16u * 1024u * 1024u)
#define FILEMAN_THUMB_MAGIC 0x54484D42u
#define FILEMAN_THUMB_VERSION 1u
#define FILEMAN_THUMB_POLL_MS 50u

typedef struct fileman_app fileman_app_t;

typedef struct
{
    fileman_app_t *app;
    char name[SYSCALL_DIR_NAME_MAX];
    char path[FILEMAN_PATH_MAX];
    uint64_t size_bytes;
    atk_iconbox_image_t icon;
    bool is_dir;
    bool is_elf;
    bool is_image;
    bool is_font;
} fileman_entry_t;

typedef struct
{
    char *path;
    video_color_t *pixels;
    atk_iconbox_image_t image;
} fileman_icon_cache_entry_t;

typedef struct
{
    fileman_icon_cache_entry_t *entries;
    size_t count;
    size_t capacity;
} fileman_icon_cache_t;

typedef struct
{
    char *extension;
    char *program;
} fileman_default_app_t;

typedef struct
{
    fileman_default_app_t *entries;
    size_t count;
    size_t capacity;
} fileman_default_apps_t;

typedef struct __attribute__((packed))
{
    uint32_t magic;
    uint16_t version;
    uint16_t width;
    uint16_t height;
    uint16_t reserved;
    uint32_t stride_bytes;
} fileman_thumb_header_t;

typedef struct fileman_thumb_task
{
    struct fileman_thumb_task *next;
    char *src_path;
    char *thumb_path;
} fileman_thumb_task_t;

typedef struct fileman_thumb_msg
{
    struct fileman_thumb_msg *next;
    char *src_path;
    char *thumb_path;
} fileman_thumb_msg_t;

struct fileman_app
{
    atk_user_window_t remote;
    atk_widget_t *window;
    atk_widget_t *tree;
    atk_widget_t *list_button;
    atk_widget_t *icon_button;
    atk_widget_t *sort_dropdown;
    atk_widget_t *list_view;
    atk_widget_t *iconbox;
    int shell_handle;
    char current_path[FILEMAN_PATH_MAX];
    fileman_entry_t *entries;
    size_t entry_count;
    fileman_icon_cache_t icon_cache;
    const fileman_entry_t *last_click_entry;
    uint64_t last_click_ms;
    size_t view_mode;
    size_t sort_mode;
    fileman_default_apps_t default_apps;
    atk_widget_t *context_menu;
    const fileman_entry_t *context_entry;
    atk_widget_t *properties_window;
    atk_widget_t *properties_label;
    alix_thread_t thumb_thread;
    alix_mutex_t thumb_task_lock;
    fileman_thumb_task_t *thumb_task_head;
    fileman_thumb_task_t *thumb_task_tail;
    alix_mutex_t thumb_msg_lock;
    fileman_thumb_msg_t *thumb_msg_head;
    fileman_thumb_msg_t *thumb_msg_tail;
    char *thumb_dir;
    bool thumbs_enabled;
    bool running;
};

enum
{
    FILEMAN_VIEW_LIST = 0,
    FILEMAN_VIEW_ICONS = 1
};

enum
{
    FILEMAN_SORT_NAME = 0,
    FILEMAN_SORT_SIZE = 1
};

static void fileman_tree_on_select(atk_widget_t *tree, void *context, atk_tree_node_t *node);
static void fileman_icon_action(atk_widget_t *button, void *context);
static void fileman_set_view_mode(fileman_app_t *app, size_t mode);
static void fileman_set_sort_mode(fileman_app_t *app, size_t mode);
static bool fileman_on_mouse_event(const user_atk_event_t *event, void *context);
static bool fileman_on_tick(void *context);
static void fileman_sort_on_select(atk_widget_t *dropdown, void *context, size_t index, uintptr_t value);

static char *fileman_strdup(const char *src)
{
    if (!src)
    {
        return NULL;
    }
    size_t len = strlen(src);
    char *dst = (char *)malloc(len + 1);
    if (!dst)
    {
        return NULL;
    }
    memcpy(dst, src, len);
    dst[len] = '\0';
    return dst;
}

static bool fileman_file_exists(const char *path)
{
    if (!path || path[0] == '\0')
    {
        return false;
    }
    int fd = open(path, SYSCALL_OPEN_READ);
    if (fd < 0)
    {
        return false;
    }
    close(fd);
    return true;
}

static bool fileman_thumb_hash_path(const char *path, char out[41])
{
    if (!path || !out)
    {
        return false;
    }

    uint8_t digest[20];
    sha1_ctx_t ctx;
    sha1_init(&ctx);
    sha1_update(&ctx, path, strlen(path));
    sha1_final(&ctx, digest);

    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < sizeof(digest); ++i)
    {
        out[i * 2] = hex[(digest[i] >> 4) & 0x0F];
        out[i * 2 + 1] = hex[digest[i] & 0x0F];
    }
    out[40] = '\0';
    return true;
}

static bool fileman_thumb_dir_init(fileman_app_t *app)
{
    if (!app)
    {
        return false;
    }
    if (app->thumb_dir)
    {
        return true;
    }

    char *home = alix_home_dir();
    if (!home || home[0] == '\0')
    {
        free(home);
        return false;
    }

    size_t home_len = strlen(home);
    while (home_len > 1 && home[home_len - 1] == '/')
    {
        home_len--;
    }
    home[home_len] = '\0';

    if (!alix_ensure_dir_path(home))
    {
        free(home);
        return false;
    }

    const char suffix[] = FILEMAN_THUMB_DIR_SUFFIX;
    size_t suffix_len = sizeof(suffix) - 1;
    size_t dir_len = home_len + suffix_len;
    char *dir = (char *)malloc(dir_len + 1);
    if (!dir)
    {
        free(home);
        return false;
    }

    memcpy(dir, home, home_len);
    memcpy(dir + home_len, suffix, suffix_len);
    dir[dir_len] = '\0';
    free(home);

    if (!alix_ensure_dir_path(dir))
    {
        free(dir);
        return false;
    }

    app->thumb_dir = dir;
    return true;
}

static char *fileman_thumb_path_for_file(fileman_app_t *app, const char *path)
{
    if (!app || !path || !app->thumb_dir)
    {
        return NULL;
    }

    char hash[41];
    if (!fileman_thumb_hash_path(path, hash))
    {
        return NULL;
    }

    size_t dir_len = strlen(app->thumb_dir);
    size_t path_len = dir_len + 1 + sizeof(hash) - 1;
    char *out = (char *)malloc(path_len + 1);
    if (!out)
    {
        return NULL;
    }

    memcpy(out, app->thumb_dir, dir_len);
    out[dir_len] = '/';
    memcpy(out + dir_len + 1, hash, sizeof(hash));
    out[path_len] = '\0';
    return out;
}

static void fileman_thumb_task_free(fileman_thumb_task_t *task)
{
    if (!task)
    {
        return;
    }
    free(task->src_path);
    free(task->thumb_path);
    free(task);
}

static void fileman_thumb_msg_free(fileman_thumb_msg_t *msg)
{
    if (!msg)
    {
        return;
    }
    free(msg->src_path);
    free(msg->thumb_path);
    free(msg);
}

static bool fileman_thumb_task_is_queued_locked(fileman_app_t *app, const char *src_path)
{
    if (!app || !src_path)
    {
        return false;
    }
    for (fileman_thumb_task_t *cur = app->thumb_task_head; cur; cur = cur->next)
    {
        if (cur->src_path && strcmp(cur->src_path, src_path) == 0)
        {
            return true;
        }
    }
    return false;
}

static bool fileman_thumb_task_enqueue(fileman_app_t *app, const char *src_path, const char *thumb_path)
{
    if (!app || !src_path || !thumb_path || !app->thumbs_enabled)
    {
        return false;
    }

    alix_mutex_lock(&app->thumb_task_lock);
    if (fileman_thumb_task_is_queued_locked(app, src_path))
    {
        alix_mutex_unlock(&app->thumb_task_lock);
        return false;
    }

    fileman_thumb_task_t *task = (fileman_thumb_task_t *)calloc(1, sizeof(*task));
    if (!task)
    {
        alix_mutex_unlock(&app->thumb_task_lock);
        return false;
    }
    task->src_path = fileman_strdup(src_path);
    task->thumb_path = fileman_strdup(thumb_path);
    if (!task->src_path || !task->thumb_path)
    {
        fileman_thumb_task_free(task);
        alix_mutex_unlock(&app->thumb_task_lock);
        return false;
    }

    if (!app->thumb_task_tail)
    {
        app->thumb_task_head = task;
    }
    else
    {
        app->thumb_task_tail->next = task;
    }
    app->thumb_task_tail = task;
    alix_mutex_unlock(&app->thumb_task_lock);
    return true;
}

static fileman_thumb_task_t *fileman_thumb_task_dequeue(fileman_app_t *app)
{
    if (!app)
    {
        return NULL;
    }

    alix_mutex_lock(&app->thumb_task_lock);
    fileman_thumb_task_t *task = app->thumb_task_head;
    if (task)
    {
        app->thumb_task_head = task->next;
        if (!app->thumb_task_head)
        {
            app->thumb_task_tail = NULL;
        }
        task->next = NULL;
    }
    alix_mutex_unlock(&app->thumb_task_lock);
    return task;
}

static void fileman_thumb_msg_enqueue(fileman_app_t *app, const char *src_path, const char *thumb_path)
{
    if (!app || !src_path || !thumb_path)
    {
        return;
    }

    fileman_thumb_msg_t *msg = (fileman_thumb_msg_t *)calloc(1, sizeof(*msg));
    if (!msg)
    {
        return;
    }
    msg->src_path = fileman_strdup(src_path);
    msg->thumb_path = fileman_strdup(thumb_path);
    if (!msg->src_path || !msg->thumb_path)
    {
        fileman_thumb_msg_free(msg);
        return;
    }

    alix_mutex_lock(&app->thumb_msg_lock);
    if (!app->thumb_msg_tail)
    {
        app->thumb_msg_head = msg;
    }
    else
    {
        app->thumb_msg_tail->next = msg;
    }
    app->thumb_msg_tail = msg;
    alix_mutex_unlock(&app->thumb_msg_lock);
}

static fileman_thumb_msg_t *fileman_thumb_msg_dequeue(fileman_app_t *app)
{
    if (!app)
    {
        return NULL;
    }

    alix_mutex_lock(&app->thumb_msg_lock);
    fileman_thumb_msg_t *msg = app->thumb_msg_head;
    if (msg)
    {
        app->thumb_msg_head = msg->next;
        if (!app->thumb_msg_head)
        {
            app->thumb_msg_tail = NULL;
        }
        msg->next = NULL;
    }
    alix_mutex_unlock(&app->thumb_msg_lock);
    return msg;
}

static void fileman_thumb_queue_clear(fileman_app_t *app)
{
    if (!app)
    {
        return;
    }

    alix_mutex_lock(&app->thumb_task_lock);
    fileman_thumb_task_t *task = app->thumb_task_head;
    app->thumb_task_head = NULL;
    app->thumb_task_tail = NULL;
    alix_mutex_unlock(&app->thumb_task_lock);
    while (task)
    {
        fileman_thumb_task_t *next = task->next;
        fileman_thumb_task_free(task);
        task = next;
    }

    alix_mutex_lock(&app->thumb_msg_lock);
    fileman_thumb_msg_t *msg = app->thumb_msg_head;
    app->thumb_msg_head = NULL;
    app->thumb_msg_tail = NULL;
    alix_mutex_unlock(&app->thumb_msg_lock);
    while (msg)
    {
        fileman_thumb_msg_t *next = msg->next;
        fileman_thumb_msg_free(msg);
        msg = next;
    }
}

static bool fileman_is_dot_entry(const char *name)
{
    if (!name)
    {
        return true;
    }
    return (strcmp(name, ".") == 0 || strcmp(name, "..") == 0);
}

static bool fileman_has_extension(const char *name, const char *ext)
{
    if (!name || !ext)
    {
        return false;
    }
    const char *dot = strrchr(name, '.');
    if (!dot)
    {
        return false;
    }
    return strcasecmp(dot, ext) == 0;
}

static bool fileman_is_image_name(const char *name)
{
    return fileman_has_extension(name, ".png") ||
           fileman_has_extension(name, ".jpg") ||
           fileman_has_extension(name, ".jpeg");
}

static bool fileman_is_font_name(const char *name)
{
    return fileman_has_extension(name, ".ttf") ||
           fileman_has_extension(name, ".otf") ||
           fileman_has_extension(name, ".ttc");
}

static bool fileman_has_suffix(const char *name, const char *suffix)
{
    if (!name || !suffix)
    {
        return false;
    }
    size_t name_len = strlen(name);
    size_t suffix_len = strlen(suffix);
    if (suffix_len == 0 || suffix_len > name_len)
    {
        return false;
    }
    return strcasecmp(name + (name_len - suffix_len), suffix) == 0;
}

static uint8_t *fileman_read_file_all(const char *path, size_t *len_out, size_t max_bytes)
{
    if (len_out)
    {
        *len_out = 0;
    }
    if (!path || path[0] == '\0')
    {
        return NULL;
    }

    int fd = open(path, SYSCALL_OPEN_READ);
    if (fd < 0)
    {
        return NULL;
    }

    struct stat st;
    if (fstat(fd, &st) != 0)
    {
        close(fd);
        return NULL;
    }

    if (st.st_size == 0 || st.st_size > (uint64_t)max_bytes)
    {
        close(fd);
        return NULL;
    }

    size_t size = (size_t)st.st_size;
    uint8_t *buf = (uint8_t *)malloc(size);
    if (!buf)
    {
        close(fd);
        return NULL;
    }

    size_t offset = 0;
    while (offset < size)
    {
        ssize_t got = read(fd, buf + offset, size - offset);
        if (got <= 0)
        {
            free(buf);
            close(fd);
            return NULL;
        }
        offset += (size_t)got;
    }
    close(fd);

    if (len_out)
    {
        *len_out = size;
    }
    return buf;
}

static bool fileman_is_png_data(const uint8_t *data, size_t size)
{
    static const uint8_t signature[] = { 0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A };
    return data && size >= sizeof(signature) && memcmp(data, signature, sizeof(signature)) == 0;
}

static bool fileman_is_jpeg_data(const uint8_t *data, size_t size)
{
    return data && size >= 2 && data[0] == 0xFF && data[1] == 0xD8;
}

static bool fileman_decode_image(const uint8_t *data,
                                 size_t size,
                                 video_color_t **pixels_out,
                                 int *width_out,
                                 int *height_out,
                                 int *stride_out)
{
    if (!data || !pixels_out || !width_out || !height_out || !stride_out)
    {
        return false;
    }

    video_color_t *pixels = NULL;
    int width = 0;
    int height = 0;
    int stride = 0;
    int rc = -1;
    if (fileman_is_png_data(data, size))
    {
        rc = png_decode_rgba32(data, size, &pixels, &width, &height, &stride);
    }
    else if (fileman_is_jpeg_data(data, size))
    {
        rc = jpeg_decode_rgba32(data, size, &pixels, &width, &height, &stride);
    }
    else
    {
        return false;
    }

    if (rc != 0 || !pixels || width <= 0 || height <= 0)
    {
        free(pixels);
        return false;
    }

    *pixels_out = pixels;
    *width_out = width;
    *height_out = height;
    *stride_out = stride;
    return true;
}

static video_color_t *fileman_scale_thumbnail(const video_color_t *pixels,
                                              int width,
                                              int height,
                                              int stride_bytes,
                                              int *stride_out)
{
    if (!pixels || width <= 0 || height <= 0)
    {
        return NULL;
    }

    const int target = FILEMAN_THUMB_SIZE;
    size_t total = (size_t)target * (size_t)target;
    video_color_t *thumb = (video_color_t *)calloc(total, sizeof(video_color_t));
    if (!thumb)
    {
        return NULL;
    }

    int max_dim = width > height ? width : height;
    int draw_w = width;
    int draw_h = height;
    if (max_dim > target)
    {
        draw_w = (width * target) / max_dim;
        draw_h = (height * target) / max_dim;
        if (draw_w < 1)
        {
            draw_w = 1;
        }
        if (draw_h < 1)
        {
            draw_h = 1;
        }
    }

    int x_off = (target - draw_w) / 2;
    int y_off = (target - draw_h) / 2;
    int src_stride = stride_bytes > 0 ? stride_bytes : width * (int)sizeof(video_color_t);
    const uint8_t *src_bytes = (const uint8_t *)pixels;

    for (int y = 0; y < draw_h; ++y)
    {
        int src_y = (y * height) / draw_h;
        const video_color_t *src_row = (const video_color_t *)(src_bytes + (size_t)src_y * (size_t)src_stride);
        video_color_t *dst_row = thumb + (size_t)(y + y_off) * target + (size_t)x_off;
        for (int x = 0; x < draw_w; ++x)
        {
            int src_x = (x * width) / draw_w;
            dst_row[x] = src_row[src_x];
        }
    }

    if (stride_out)
    {
        *stride_out = target * (int)sizeof(video_color_t);
    }
    return thumb;
}

static bool fileman_write_thumbnail(const char *path,
                                    const video_color_t *pixels,
                                    int width,
                                    int height,
                                    int stride_bytes)
{
    if (!path || !pixels || width <= 0 || height <= 0 || stride_bytes <= 0)
    {
        return false;
    }

    FILE *fp = fopen(path, "wb");
    if (!fp)
    {
        return false;
    }

    fileman_thumb_header_t header = {
        .magic = FILEMAN_THUMB_MAGIC,
        .version = FILEMAN_THUMB_VERSION,
        .width = (uint16_t)width,
        .height = (uint16_t)height,
        .reserved = 0,
        .stride_bytes = (uint32_t)stride_bytes
    };

    size_t header_written = fwrite(&header, 1, sizeof(header), fp);
    if (header_written != sizeof(header))
    {
        fclose(fp);
        return false;
    }

    size_t bytes = (size_t)height * (size_t)stride_bytes;
    size_t wrote = fwrite(pixels, 1, bytes, fp);
    fclose(fp);
    return wrote == bytes;
}

static bool fileman_generate_thumbnail(const char *src_path, const char *thumb_path)
{
    if (!src_path || !thumb_path)
    {
        return false;
    }

    size_t data_len = 0;
    uint8_t *data = fileman_read_file_all(src_path, &data_len, FILEMAN_THUMB_MAX_BYTES);
    if (!data)
    {
        return false;
    }

    video_color_t *pixels = NULL;
    int width = 0;
    int height = 0;
    int stride = 0;
    bool ok = fileman_decode_image(data, data_len, &pixels, &width, &height, &stride);
    free(data);
    if (!ok)
    {
        free(pixels);
        return false;
    }

    int thumb_stride = 0;
    video_color_t *thumb = fileman_scale_thumbnail(pixels, width, height, stride, &thumb_stride);
    free(pixels);
    if (!thumb)
    {
        return false;
    }

    ok = fileman_write_thumbnail(thumb_path,
                                 thumb,
                                 FILEMAN_THUMB_SIZE,
                                 FILEMAN_THUMB_SIZE,
                                 thumb_stride);
    free(thumb);
    return ok;
}

static void fileman_thumb_thread(void *arg)
{
    fileman_app_t *app = (fileman_app_t *)arg;
    if (!app)
    {
        alix_thread_exit(0);
    }

    while (__atomic_load_n(&app->running, __ATOMIC_ACQUIRE))
    {
        fileman_thumb_task_t *task = fileman_thumb_task_dequeue(app);
        if (!task)
        {
            (void)sys_sleep_ms(FILEMAN_THUMB_POLL_MS);
            continue;
        }

        bool have_thumb = fileman_file_exists(task->thumb_path);
        if (!have_thumb)
        {
            have_thumb = fileman_generate_thumbnail(task->src_path, task->thumb_path);
        }
        if (have_thumb)
        {
            fileman_thumb_msg_enqueue(app, task->src_path, task->thumb_path);
        }

        fileman_thumb_task_free(task);
    }

    alix_thread_exit(0);
}

static char *fileman_trim_whitespace(char *text)
{
    if (!text)
    {
        return NULL;
    }
    while (*text && isspace((unsigned char)*text))
    {
        text++;
    }
    char *end = text + strlen(text);
    while (end > text && isspace((unsigned char)end[-1]))
    {
        end--;
    }
    *end = '\0';
    return text;
}

static char *fileman_normalize_extension(const char *ext)
{
    if (!ext)
    {
        return NULL;
    }
    const char *start = ext;
    while (*start && isspace((unsigned char)*start))
    {
        start++;
    }
    const char *end = start + strlen(start);
    while (end > start && isspace((unsigned char)end[-1]))
    {
        end--;
    }
    size_t len = (size_t)(end - start);
    if (len == 0)
    {
        return NULL;
    }
    bool has_dot = (start[0] == '.');
    size_t out_len = len + (has_dot ? 0 : 1);
    char *out = (char *)malloc(out_len + 1);
    if (!out)
    {
        return NULL;
    }
    size_t idx = 0;
    if (!has_dot)
    {
        out[idx++] = '.';
    }
    for (size_t i = 0; i < len; ++i)
    {
        out[idx++] = (char)tolower((unsigned char)start[i]);
    }
    out[idx] = '\0';
    return out;
}

static void fileman_join_path(char *dst, size_t cap, const char *base, const char *name)
{
    if (!dst || cap == 0)
    {
        return;
    }
    const char *root = (base && base[0]) ? base : "/";
    if (strcmp(root, "/") == 0)
    {
        snprintf(dst, cap, "/%s", name ? name : "");
    }
    else
    {
        snprintf(dst, cap, "%s/%s", root, name ? name : "");
    }
    dst[cap - 1] = '\0';
}

static void fileman_normalize_path(char *path)
{
    if (!path || path[0] == '\0')
    {
        return;
    }
    size_t len = strlen(path);
    while (len > 1 && path[len - 1] == '/')
    {
        path[len - 1] = '\0';
        len--;
    }
}

static void fileman_default_apps_clear(fileman_app_t *app)
{
    if (!app)
    {
        return;
    }
    for (size_t i = 0; i < app->default_apps.count; ++i)
    {
        free(app->default_apps.entries[i].extension);
        free(app->default_apps.entries[i].program);
    }
    free(app->default_apps.entries);
    app->default_apps.entries = NULL;
    app->default_apps.count = 0;
    app->default_apps.capacity = 0;
}

static bool fileman_default_apps_add(fileman_app_t *app, char *extension, char *program)
{
    if (!app || !extension || !program)
    {
        free(extension);
        free(program);
        return false;
    }
    for (size_t i = 0; i < app->default_apps.count; ++i)
    {
        if (strcasecmp(app->default_apps.entries[i].extension, extension) == 0)
        {
            free(app->default_apps.entries[i].program);
            app->default_apps.entries[i].program = program;
            free(extension);
            return true;
        }
    }
    if (app->default_apps.count == app->default_apps.capacity)
    {
        size_t next_capacity = app->default_apps.capacity ? app->default_apps.capacity * 2 : 8;
        fileman_default_app_t *next_entries = (fileman_default_app_t *)realloc(app->default_apps.entries,
                                                                               next_capacity * sizeof(fileman_default_app_t));
        if (!next_entries)
        {
            free(extension);
            free(program);
            return false;
        }
        app->default_apps.entries = next_entries;
        app->default_apps.capacity = next_capacity;
    }
    fileman_default_app_t *dst = &app->default_apps.entries[app->default_apps.count++];
    dst->extension = extension;
    dst->program = program;
    return true;
}

static bool fileman_default_apps_write_default(void)
{
    FILE *fp = fopen(FILEMAN_DEFAULT_APPS_PATH, "wb");
    if (!fp)
    {
        return false;
    }
    const char *lines[] = {
        "# extension=program\n",
        ".png=/usr/bin/atk_preview.elf\n",
        ".jpg=/usr/bin/atk_preview.elf\n",
        ".jpeg=/usr/bin/atk_preview.elf\n",
        ".ttf=/usr/bin/ttf_demo.elf\n",
        ".otf=/usr/bin/ttf_demo.elf\n",
        ".ttc=/usr/bin/ttf_demo.elf\n"
    };
    for (size_t i = 0; i < sizeof(lines) / sizeof(lines[0]); ++i)
    {
        if (fputs(lines[i], fp) < 0)
        {
            fclose(fp);
            return false;
        }
    }
    fclose(fp);
    return true;
}

static bool fileman_default_apps_load(fileman_app_t *app)
{
    if (!app)
    {
        return false;
    }

    fileman_default_apps_clear(app);

    FILE *fp = fopen(FILEMAN_DEFAULT_APPS_PATH, "rb");
    if (!fp)
    {
        (void)fileman_default_apps_write_default();
        fp = fopen(FILEMAN_DEFAULT_APPS_PATH, "rb");
        if (!fp)
        {
            return false;
        }
    }

    char *line = (char *)malloc(FILEMAN_DEFAULT_APPS_LINE_MAX);
    if (!line)
    {
        fclose(fp);
        return false;
    }

    while (fgets(line, (int)FILEMAN_DEFAULT_APPS_LINE_MAX, fp))
    {
        size_t len = strlen(line);
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
        {
            line[len - 1] = '\0';
            len--;
        }

        char *trim = fileman_trim_whitespace(line);
        if (!trim || trim[0] == '\0' || trim[0] == '#')
        {
            continue;
        }

        char *equals = strchr(trim, '=');
        if (!equals)
        {
            continue;
        }
        *equals = '\0';
        char *ext_raw = fileman_trim_whitespace(trim);
        char *prog_raw = fileman_trim_whitespace(equals + 1);
        if (!ext_raw || ext_raw[0] == '\0' || !prog_raw || prog_raw[0] == '\0')
        {
            continue;
        }

        char *ext = fileman_normalize_extension(ext_raw);
        char *program = fileman_strdup(prog_raw);
        if (!ext || !program)
        {
            free(ext);
            free(program);
            continue;
        }
        (void)fileman_default_apps_add(app, ext, program);
    }

    free(line);
    fclose(fp);
    return true;
}

static const char *fileman_default_app_for_name(fileman_app_t *app, const char *name)
{
    if (!app || !name)
    {
        return NULL;
    }
    const char *best = NULL;
    size_t best_len = 0;
    for (size_t i = 0; i < app->default_apps.count; ++i)
    {
        fileman_default_app_t *entry = &app->default_apps.entries[i];
        if (!entry->extension || !entry->program)
        {
            continue;
        }
        if (fileman_has_suffix(name, entry->extension))
        {
            size_t len = strlen(entry->extension);
            if (len > best_len)
            {
                best = entry->program;
                best_len = len;
            }
        }
    }
    return best;
}

typedef struct
{
    const char *suffix;
    const char *icon_name;
} fileman_icon_map_t;

static const fileman_icon_map_t FILEMAN_ICON_MAP[] = {
    { ".tar.gz", "application-x-compressed-tar.png" },
    { ".tgz", "application-x-compressed-tar.png" },
    { ".tar.bz2", "application-x-bzip-compressed-tar.png" },
    { ".tbz2", "application-x-bzip-compressed-tar.png" },
    { ".tbz", "application-x-bzip-compressed-tar.png" },
    { ".tar.xz", "application-x-lzma-compressed-tar.png" },
    { ".txz", "application-x-lzma-compressed-tar.png" },
    { ".7z", "application-x-7z-compressed.png" },
    { ".zip", "application-zip.png" },
    { ".rar", "application-x-rar.png" },
    { ".tar", "application-x-tar.png" },
    { ".gz", "application-x-gzip.png" },
    { ".bz2", "application-x-bzip.png" },
    { ".xz", "application-x-lzma-compressed-tar.png" },
    { ".epub", "application-epub+zip.png" },
    { ".pdf", "application-pdf.png" },
    { ".ps", "application-postscript.png" },
    { ".rtf", "application-rtf.png" },
    { ".doc", "application-msword.png" },
    { ".docx", "application-vnd.openxmlformats-officedocument.wordprocessingml.document.png" },
    { ".odt", "application-vnd.oasis.opendocument.text.png" },
    { ".xls", "application-vnd.ms-excel.png" },
    { ".xlsx", "application-vnd.ms-excel.png" },
    { ".ods", "application-vnd.oasis.opendocument.spreadsheet.png" },
    { ".ppt", "application-vnd.ms-powerpoint.png" },
    { ".pptx", "application-vnd.ms-powerpoint.png" },
    { ".odp", "application-vnd.oasis.opendocument.presentation.png" },
    { ".ttf", "application-x-font-afm.png" },
    { ".otf", "application-x-font-afm.png" },
    { ".ttc", "application-x-font-afm.png" },
    { ".iso", "application-x-cd-image.png" },
    { ".c", "text-x-csrc.png" },
    { ".h", "text-x-chdr.png" },
    { ".cc", "text-x-c++src.png" },
    { ".cpp", "text-x-c++src.png" },
    { ".hh", "text-x-c++hdr.png" },
    { ".hpp", "text-x-c++hdr.png" },
    { ".py", "text-x-python.png" },
    { ".js", "application-javascript.png" },
    { ".css", "text-css.png" },
    { ".html", "text-html.png" },
    { ".htm", "text-html.png" },
    { ".xml", "text-xml.png" },
    { ".csv", "text-csv.png" },
    { ".md", "text-x-readme.png" },
    { ".txt", "text-plain.png" },
    { ".log", "text-x-log.png" },
    { ".sh", "application-x-shellscript.png" },
    { ".bash", "application-x-shellscript.png" },
    { ".exe", "application-x-ms-dos-executable.png" },
    { ".elf", "application-x-executable.png" },
    { ".png", "image-x-generic.png" },
    { ".jpg", "image-x-generic.png" },
    { ".jpeg", "image-x-generic.png" },
    { ".gif", "image-x-generic.png" },
    { ".bmp", "image-x-generic.png" },
    { ".svg", "image-svg+xml.png" },
    { ".mp3", "audio-x-generic.png" },
    { ".wav", "audio-x-wav.png" },
    { ".flac", "audio-x-flac.png" },
    { ".ogg", "audio-x-generic.png" },
    { ".mp4", "video-x-generic.png" },
    { ".mkv", "video-x-generic.png" },
    { ".avi", "video-x-generic.png" },
    { ".mov", "video-x-generic.png" },
};

static bool fileman_path_is_dir(const char *path)
{
    if (!path || !path[0])
    {
        return false;
    }
    syscall_dirent_t *scratch = (syscall_dirent_t *)malloc(sizeof(syscall_dirent_t));
    if (!scratch)
    {
        return false;
    }
    ssize_t count = sys_list_dir(path, scratch, 1);
    free(scratch);
    return count >= 0;
}

static bool fileman_dirent_is_dir(const syscall_dirent_t *ent, const char *path)
{
    if (!ent || !path)
    {
        return false;
    }
    if (ent->type == SYSCALL_NODE_TYPE_DIR)
    {
        return true;
    }
    if (ent->type != SYSCALL_NODE_TYPE_SYMLINK)
    {
        return false;
    }
    return fileman_path_is_dir(path);
}

static fileman_icon_cache_entry_t *fileman_icon_cache_alloc(fileman_app_t *app)
{
    if (!app)
    {
        return NULL;
    }
    if (app->icon_cache.count == app->icon_cache.capacity)
    {
        size_t next_capacity = app->icon_cache.capacity ? app->icon_cache.capacity * 2 : 8;
        fileman_icon_cache_entry_t *next_entries = (fileman_icon_cache_entry_t *)realloc(app->icon_cache.entries,
                                                                                          next_capacity * sizeof(fileman_icon_cache_entry_t));
        if (!next_entries)
        {
            return NULL;
        }
        app->icon_cache.entries = next_entries;
        app->icon_cache.capacity = next_capacity;
    }
    fileman_icon_cache_entry_t *entry = &app->icon_cache.entries[app->icon_cache.count];
    memset(entry, 0, sizeof(*entry));
    app->icon_cache.count++;
    return entry;
}

static const atk_iconbox_image_t *fileman_icon_cache_load(fileman_app_t *app, const char *path)
{
    if (!app || !path || !path[0])
    {
        return NULL;
    }
    for (size_t i = 0; i < app->icon_cache.count; ++i)
    {
        fileman_icon_cache_entry_t *entry = &app->icon_cache.entries[i];
        if (entry->path && strcmp(entry->path, path) == 0)
        {
            return entry->pixels ? &entry->image : NULL;
        }
    }

    FILE *fp = fopen(path, "rb");
    if (!fp)
    {
        return NULL;
    }
    if (fseek(fp, 0, SEEK_END) != 0)
    {
        fclose(fp);
        return NULL;
    }
    long size_long = ftell(fp);
    if (size_long <= 0)
    {
        fclose(fp);
        return NULL;
    }
    if (fseek(fp, 0, SEEK_SET) != 0)
    {
        fclose(fp);
        return NULL;
    }

    size_t size = (size_t)size_long;
    uint8_t *data = (uint8_t *)malloc(size);
    if (!data)
    {
        fclose(fp);
        return NULL;
    }
    size_t read = fread(data, 1, size, fp);
    fclose(fp);
    if (read != size)
    {
        free(data);
        return NULL;
    }

    video_color_t *pixels = NULL;
    int width = 0;
    int height = 0;
    int stride_bytes = 0;

    if (size >= sizeof(fileman_thumb_header_t))
    {
        const fileman_thumb_header_t *header = (const fileman_thumb_header_t *)data;
        if (header->magic == FILEMAN_THUMB_MAGIC && header->version == FILEMAN_THUMB_VERSION)
        {
            width = (int)header->width;
            height = (int)header->height;
            stride_bytes = (int)header->stride_bytes;
            if (width > 0 && height > 0 && stride_bytes >= width * (int)sizeof(video_color_t))
            {
                size_t pixel_bytes = (size_t)height * (size_t)stride_bytes;
                size_t needed = sizeof(fileman_thumb_header_t) + pixel_bytes;
                if (needed <= size)
                {
                    pixels = (video_color_t *)malloc(pixel_bytes);
                    if (pixels)
                    {
                        memcpy(pixels, data + sizeof(fileman_thumb_header_t), pixel_bytes);
                    }
                }
            }
        }
    }

    if (!pixels)
    {
        int rc = png_decode_rgba32(data, size, &pixels, &width, &height, &stride_bytes);
        if (rc != 0 || !pixels)
        {
            free(data);
            return NULL;
        }
    }
    free(data);

    fileman_icon_cache_entry_t *entry = fileman_icon_cache_alloc(app);
    if (!entry)
    {
        free(pixels);
        return NULL;
    }
    entry->path = fileman_strdup(path);
    if (!entry->path)
    {
        app->icon_cache.count--;
        free(pixels);
        return NULL;
    }
    entry->pixels = pixels;
    entry->image.pixels = pixels;
    entry->image.width = width;
    entry->image.height = height;
    entry->image.stride_bytes = stride_bytes;
    entry->image.use_alpha = true;
    return &entry->image;
}

static void fileman_icon_cache_clear(fileman_app_t *app)
{
    if (!app)
    {
        return;
    }
    for (size_t i = 0; i < app->icon_cache.count; ++i)
    {
        fileman_icon_cache_entry_t *entry = &app->icon_cache.entries[i];
        free(entry->pixels);
        free(entry->path);
    }
    free(app->icon_cache.entries);
    app->icon_cache.entries = NULL;
    app->icon_cache.count = 0;
    app->icon_cache.capacity = 0;
}

static fileman_entry_t *fileman_find_entry_by_path(fileman_app_t *app, const char *path)
{
    if (!app || !path || !app->entries)
    {
        return NULL;
    }
    for (size_t i = 0; i < app->entry_count; ++i)
    {
        fileman_entry_t *entry = &app->entries[i];
        if (strcmp(entry->path, path) == 0)
        {
            return entry;
        }
    }
    return NULL;
}

static void fileman_entry_set_icon(fileman_entry_t *entry, const atk_iconbox_image_t *image)
{
    if (!entry)
    {
        return;
    }
    if (image)
    {
        entry->icon = *image;
    }
    else
    {
        memset(&entry->icon, 0, sizeof(entry->icon));
    }
}

static bool fileman_process_thumb_messages(fileman_app_t *app)
{
    if (!app)
    {
        return false;
    }

    bool redraw = false;
    while (true)
    {
        fileman_thumb_msg_t *msg = fileman_thumb_msg_dequeue(app);
        if (!msg)
        {
            break;
        }

        fileman_entry_t *entry = fileman_find_entry_by_path(app, msg->src_path);
        if (entry)
        {
            const atk_iconbox_image_t *thumb = fileman_icon_cache_load(app, msg->thumb_path);
            if (thumb)
            {
                fileman_entry_set_icon(entry, thumb);
                if (app->iconbox)
                {
                    if (atk_iconbox_set_icon_image(app->iconbox, entry, &entry->icon))
                    {
                        redraw = true;
                    }
                }
            }
        }

        fileman_thumb_msg_free(msg);
    }

    return redraw;
}

static const char *fileman_icon_name_for_file(const char *name)
{
    if (!name)
    {
        return "unknown.png";
    }
    for (size_t i = 0; i < sizeof(FILEMAN_ICON_MAP) / sizeof(FILEMAN_ICON_MAP[0]); ++i)
    {
        if (fileman_has_suffix(name, FILEMAN_ICON_MAP[i].suffix))
        {
            return FILEMAN_ICON_MAP[i].icon_name;
        }
    }
    return "unknown.png";
}

static const atk_iconbox_image_t *fileman_icon_for_entry(fileman_app_t *app, const fileman_entry_t *entry)
{
    if (!app || !entry)
    {
        return NULL;
    }
    if (entry->is_image && app->thumb_dir)
    {
        char *thumb_path = fileman_thumb_path_for_file(app, entry->path);
        if (thumb_path)
        {
            const atk_iconbox_image_t *thumb = fileman_icon_cache_load(app, thumb_path);
            if (thumb)
            {
                free(thumb_path);
                return thumb;
            }
            if (app->thumbs_enabled && !fileman_file_exists(thumb_path))
            {
                (void)fileman_thumb_task_enqueue(app, entry->path, thumb_path);
            }
            free(thumb_path);
        }
    }
    const char *icon_name = NULL;
    if (entry->is_dir)
    {
        icon_name = "inode-directory.png";
    }
    else if (entry->is_elf)
    {
        icon_name = "application-x-executable.png";
    }
    else
    {
        icon_name = fileman_icon_name_for_file(entry->name);
    }

    char path[FILEMAN_PATH_MAX];
    snprintf(path, sizeof(path), "%s/%s", FILEMAN_ICON_MIMETYPE_DIR, icon_name);
    path[sizeof(path) - 1] = '\0';
    const atk_iconbox_image_t *icon = fileman_icon_cache_load(app, path);
    if (icon)
    {
        return icon;
    }

    snprintf(path, sizeof(path), "%s/unknown.png", FILEMAN_ICON_MIMETYPE_DIR);
    path[sizeof(path) - 1] = '\0';
    return fileman_icon_cache_load(app, path);
}

static void fileman_entries_clear(fileman_app_t *app)
{
    if (!app)
    {
        return;
    }
    free(app->entries);
    app->entries = NULL;
    app->entry_count = 0;
}

static int fileman_compare_entries(const fileman_entry_t *a, const fileman_entry_t *b, size_t sort_mode)
{
    if (!a || !b)
    {
        return 0;
    }
    if (a->is_dir != b->is_dir)
    {
        return a->is_dir ? -1 : 1;
    }
    if (sort_mode == FILEMAN_SORT_SIZE && !a->is_dir && !b->is_dir)
    {
        if (a->size_bytes < b->size_bytes)
        {
            return -1;
        }
        if (a->size_bytes > b->size_bytes)
        {
            return 1;
        }
    }
    return strcmp(a->name, b->name);
}

static void fileman_sort_entries(fileman_entry_t *entries, size_t count, size_t sort_mode)
{
    if (!entries || count < 2)
    {
        return;
    }
    for (size_t i = 0; i + 1 < count; ++i)
    {
        for (size_t j = i + 1; j < count; ++j)
        {
            fileman_entry_t *a = &entries[i];
            fileman_entry_t *b = &entries[j];
            if (fileman_compare_entries(a, b, sort_mode) > 0)
            {
                fileman_entry_t tmp = *a;
                *a = *b;
                *b = tmp;
            }
        }
    }
}

static void fileman_format_size_bytes(char *dst, size_t cap, const fileman_entry_t *entry)
{
    if (!dst || cap == 0)
    {
        return;
    }
    if (!entry)
    {
        dst[0] = '\0';
        return;
    }
    if (entry->is_dir)
    {
        snprintf(dst, cap, "<DIR>");
    }
    else
    {
        snprintf(dst, cap, "%llu", (unsigned long long)entry->size_bytes);
    }
    dst[cap - 1] = '\0';
}

static void fileman_format_size_human(char *dst, size_t cap, const fileman_entry_t *entry)
{
    if (!dst || cap == 0)
    {
        return;
    }
    if (!entry)
    {
        dst[0] = '\0';
        return;
    }
    if (entry->is_dir)
    {
        snprintf(dst, cap, "<DIR>");
        dst[cap - 1] = '\0';
        return;
    }

    static const char *k_units[] = { "B", "KB", "MB", "GB", "TB" };
    const size_t unit_count = sizeof(k_units) / sizeof(k_units[0]);
    uint64_t size = entry->size_bytes;
    size_t unit = 0;
    uint64_t divisor = 1;
    while (unit + 1 < unit_count && (size / divisor) >= 1024)
    {
        divisor *= 1024;
        unit++;
    }

    if (unit == 0)
    {
        snprintf(dst, cap, "%llu B", (unsigned long long)size);
        dst[cap - 1] = '\0';
        return;
    }

    uint64_t whole = size / divisor;
    uint64_t rem = size % divisor;
    uint64_t frac = (rem * 10 + divisor / 2) / divisor;
    if (frac >= 10)
    {
        whole += 1;
        frac = 0;
    }
    if (frac == 0)
    {
        snprintf(dst, cap, "%llu %s", (unsigned long long)whole, k_units[unit]);
    }
    else
    {
        snprintf(dst, cap, "%llu.%llu %s", (unsigned long long)whole, (unsigned long long)frac, k_units[unit]);
    }
    dst[cap - 1] = '\0';
}

static void fileman_update_title(fileman_app_t *app)
{
    if (!app || !app->window)
    {
        return;
    }
    char title[128];
    const char *path = app->current_path[0] ? app->current_path : "/";
    snprintf(title, sizeof(title), "File Manager - %s", path);
    title[sizeof(title) - 1] = '\0';
    atk_window_set_title_text(app->window, title);
}

static void fileman_properties_on_destroy(void *context)
{
    fileman_app_t *app = (fileman_app_t *)context;
    if (!app)
    {
        return;
    }
    app->properties_window = NULL;
    app->properties_label = NULL;
}

static void fileman_properties_open(fileman_app_t *app, const fileman_entry_t *entry)
{
    if (!app || !entry)
    {
        return;
    }
    atk_state_t *state = atk_state_get();
    if (!state)
    {
        return;
    }

    if (!app->properties_window)
    {
        int center_x = app->window ? app->window->width / 2 : FILEMAN_WINDOW_WIDTH / 2;
        int center_y = app->window ? app->window->height / 2 : FILEMAN_WINDOW_HEIGHT / 2;
        atk_widget_t *window = atk_window_create_at(state, center_x, center_y);
        if (!window)
        {
            return;
        }
        atk_window_set_chrome_visible(window, true);
        window->width = FILEMAN_PROPERTIES_WIDTH;
        window->height = FILEMAN_PROPERTIES_HEIGHT;
        atk_window_set_title_text(window, "Properties");
        atk_window_set_context(window, app, fileman_properties_on_destroy);
        atk_window_ensure_inside(window);
        atk_window_request_layout(window);

        int content_x = FILEMAN_MARGIN;
        int content_y = ATK_WINDOW_TITLE_HEIGHT + FILEMAN_MARGIN;
        int content_w = window->width - FILEMAN_MARGIN * 2;
        int content_h = window->height - ATK_WINDOW_TITLE_HEIGHT - FILEMAN_MARGIN * 2;
        if (content_w < 0)
        {
            content_w = 0;
        }
        if (content_h < 0)
        {
            content_h = 0;
        }
        atk_widget_t *label = atk_window_add_label(window, content_x, content_y, content_w, content_h);
        if (!label)
        {
            atk_window_close(state, window);
            return;
        }
        app->properties_window = window;
        app->properties_label = label;
    }

    const char *type = "File";
    if (entry->is_dir)
    {
        type = "Directory";
    }
    else if (entry->is_font)
    {
        type = "Font";
    }
    else if (entry->is_image)
    {
        type = "Image";
    }
    else if (entry->is_elf)
    {
        type = "Executable";
    }

    char size_buf[32];
    fileman_format_size_bytes(size_buf, sizeof(size_buf), entry);
    const char *size_suffix = entry->is_dir ? "" : " bytes";

    size_t cap = strlen(entry->name) + strlen(entry->path) + 128;
    char *text = (char *)malloc(cap);
    if (!text)
    {
        return;
    }
    snprintf(text,
             cap,
             "Name: %s\nPath: %s\nType: %s\nSize: %s%s",
             entry->name,
             entry->path,
             type,
             size_buf,
             size_suffix);
    text[cap - 1] = '\0';
    if (app->properties_label)
    {
        atk_label_set_text(app->properties_label, text);
    }
    free(text);

    char title[128];
    snprintf(title, sizeof(title), "Properties - %s", entry->name);
    title[sizeof(title) - 1] = '\0';
    atk_window_set_title_text(app->properties_window, title);
    atk_window_bring_to_front(state, app->properties_window);
    atk_window_mark_dirty(app->properties_window);
}

static void fileman_context_menu_close(fileman_app_t *app)
{
    if (!app || !app->context_menu)
    {
        return;
    }
    if (atk_menu_is_visible(app->context_menu))
    {
        atk_menu_hide(app->context_menu);
        if (app->window)
        {
            atk_window_mark_dirty(app->window);
        }
    }
    app->context_entry = NULL;
}

static void fileman_context_menu_action_properties(void *context)
{
    fileman_app_t *app = (fileman_app_t *)context;
    if (!app || !app->context_entry)
    {
        return;
    }
    const fileman_entry_t *entry = app->context_entry;
    fileman_context_menu_close(app);
    fileman_properties_open(app, entry);
}

static void fileman_context_menu_open(fileman_app_t *app, const fileman_entry_t *entry, int x, int y)
{
    if (!app || !entry || !app->context_menu || !app->window)
    {
        return;
    }

    fileman_context_menu_close(app);
    app->context_entry = entry;

    atk_window_priv_t *wpriv = (atk_window_priv_t *)atk_widget_priv(app->window, &ATK_WINDOW_CLASS);
    if (wpriv)
    {
        atk_list_node_t *node = atk_list_find(&wpriv->children, app->context_menu);
        if (node)
        {
            atk_list_move_to_back(&wpriv->children, node);
        }
    }

    atk_menu_show(app->context_menu, x, y);
    if (app->context_menu->width > app->window->width)
    {
        app->context_menu->width = app->window->width;
    }
    if (app->context_menu->x + app->context_menu->width > app->window->width - 2)
    {
        app->context_menu->x = app->window->width - app->context_menu->width - 2;
    }
    if (app->context_menu->x < 0)
    {
        app->context_menu->x = 0;
    }
    if (app->context_menu->y + app->context_menu->height > app->window->height - 2)
    {
        app->context_menu->y = app->window->height - app->context_menu->height - 2;
    }
    if (app->context_menu->y < 0)
    {
        app->context_menu->y = 0;
    }
    atk_window_mark_dirty(app->window);
}

static void fileman_apply_view_state(fileman_app_t *app)
{
    if (!app)
    {
        return;
    }
    bool list_active = (app->view_mode == FILEMAN_VIEW_LIST);
    if (app->list_view)
    {
        atk_list_view_set_active(app->list_view, list_active);
    }
    if (app->iconbox)
    {
        atk_iconbox_set_active(app->iconbox, !list_active);
    }
}

static fileman_entry_t *fileman_entry_at_list(fileman_app_t *app, int px, int py)
{
    if (!app || !app->list_view || !app->list_view->used)
    {
        return NULL;
    }
    int origin_x = 0;
    int origin_y = 0;
    atk_widget_absolute_position(app->list_view, &origin_x, &origin_y);
    int local_x = px - origin_x;
    int local_y = py - origin_y;
    if (local_x < 0 || local_y < 0 ||
        local_x >= app->list_view->width || local_y >= app->list_view->height)
    {
        return NULL;
    }
    size_t row = atk_list_view_row_at(app->list_view, local_x, local_y);
    if (row == ATK_LIST_VIEW_NO_SELECTION || row >= app->entry_count)
    {
        return NULL;
    }
    return &app->entries[row];
}

static fileman_entry_t *fileman_entry_at_icon(fileman_app_t *app, int px, int py)
{
    if (!app || !app->iconbox || !app->iconbox->used)
    {
        return NULL;
    }
    return (fileman_entry_t *)atk_iconbox_context_at(app->iconbox, px, py);
}

static fileman_entry_t *fileman_entry_at_point(fileman_app_t *app, int px, int py)
{
    if (!app)
    {
        return NULL;
    }
    if (app->view_mode == FILEMAN_VIEW_LIST)
    {
        return fileman_entry_at_list(app, px, py);
    }
    return fileman_entry_at_icon(app, px, py);
}

static bool fileman_on_mouse_event(const user_atk_event_t *event, void *context)
{
    fileman_app_t *app = (fileman_app_t *)context;
    if (!app || !event)
    {
        return false;
    }

    bool left = (event->flags & USER_ATK_MOUSE_FLAG_LEFT) != 0;
    bool press = (event->flags & USER_ATK_MOUSE_FLAG_PRESS) != 0;
    bool right_press = (event->flags & USER_ATK_MOUSE_FLAG_RIGHT_PRESS) != 0;
    bool redraw = false;

    if (left && press && app->context_menu && atk_menu_is_visible(app->context_menu))
    {
        bool inside_menu = atk_menu_contains(app->context_menu, event->x, event->y);
        if (!inside_menu)
        {
            fileman_context_menu_close(app);
            redraw = true;
        }
    }

    if (right_press)
    {
        fileman_entry_t *entry = fileman_entry_at_point(app, event->x, event->y);
        if (entry)
        {
            fileman_context_menu_open(app, entry, event->x, event->y);
            redraw = true;
        }
        else if (app->context_menu && atk_menu_is_visible(app->context_menu))
        {
            fileman_context_menu_close(app);
            redraw = true;
        }
    }

    return redraw;
}

static bool fileman_on_tick(void *context)
{
    fileman_app_t *app = (fileman_app_t *)context;
    return fileman_process_thumb_messages(app);
}

static void fileman_refresh_right_view(fileman_app_t *app)
{
    if (!app || !app->list_view || !app->iconbox)
    {
        return;
    }

    atk_list_view_clear(app->list_view);
    atk_iconbox_clear(app->iconbox);
    fileman_context_menu_close(app);
    fileman_entries_clear(app);
    app->last_click_entry = NULL;
    app->last_click_ms = 0;

    syscall_dirent_t entries[FILEMAN_MAX_ENTRIES];
    const char *path = app->current_path[0] ? app->current_path : "/";
    ssize_t count = sys_list_dir(path, entries, FILEMAN_MAX_ENTRIES);
    if (count <= 0)
    {
        atk_list_view_set_row_count(app->list_view, 0);
        atk_list_view_relayout(app->list_view);
        atk_iconbox_relayout(app->iconbox);
        fileman_apply_view_state(app);
        if (app->window)
        {
            atk_window_mark_dirty(app->window);
        }
        return;
    }

    size_t visible = 0;
    for (ssize_t i = 0; i < count; ++i)
    {
        if (!fileman_is_dot_entry(entries[i].name))
        {
            visible++;
        }
    }

    if (visible == 0)
    {
        atk_list_view_set_row_count(app->list_view, 0);
        atk_list_view_relayout(app->list_view);
        atk_iconbox_relayout(app->iconbox);
        fileman_apply_view_state(app);
        if (app->window)
        {
            atk_window_mark_dirty(app->window);
        }
        return;
    }

    app->entries = (fileman_entry_t *)calloc(visible, sizeof(fileman_entry_t));
    if (!app->entries)
    {
        atk_list_view_set_row_count(app->list_view, 0);
        atk_list_view_relayout(app->list_view);
        atk_iconbox_relayout(app->iconbox);
        fileman_apply_view_state(app);
        if (app->window)
        {
            atk_window_mark_dirty(app->window);
        }
        return;
    }

    size_t out = 0;
    for (ssize_t i = 0; i < count && out < visible; ++i)
    {
        syscall_dirent_t *ent = &entries[i];
        if (fileman_is_dot_entry(ent->name))
        {
            continue;
        }
        fileman_entry_t *dst = &app->entries[out++];
        dst->app = app;
        size_t name_len = strlen(ent->name);
        if (name_len >= sizeof(dst->name))
        {
            name_len = sizeof(dst->name) - 1;
        }
        memcpy(dst->name, ent->name, name_len);
        dst->name[name_len] = '\0';
        fileman_join_path(dst->path, sizeof(dst->path), path, dst->name);
        dst->size_bytes = ent->size_bytes;
        dst->is_dir = fileman_dirent_is_dir(ent, dst->path);
        dst->is_elf = (!dst->is_dir && fileman_has_extension(dst->name, ".elf"));
        dst->is_image = (!dst->is_dir && fileman_is_image_name(dst->name));
        dst->is_font = (!dst->is_dir && fileman_is_font_name(dst->name));
        fileman_entry_set_icon(dst, fileman_icon_for_entry(app, dst));
    }

    app->entry_count = out;
    fileman_sort_entries(app->entries, app->entry_count, app->sort_mode);

    atk_list_view_set_row_count(app->list_view, app->entry_count);
    for (size_t i = 0; i < app->entry_count; ++i)
    {
        fileman_entry_t *entry = &app->entries[i];
        atk_list_view_set_cell_text(app->list_view, i, 0, entry->name);
        char size_human[32];
        char size_bytes[32];
        fileman_format_size_human(size_human, sizeof(size_human), entry);
        fileman_format_size_bytes(size_bytes, sizeof(size_bytes), entry);
        atk_list_view_set_cell_text(app->list_view, i, 1, size_human);
        atk_list_view_set_cell_text(app->list_view, i, 2, size_bytes);
    }
    atk_list_view_set_selected(app->list_view, ATK_LIST_VIEW_NO_SELECTION);
    atk_list_view_relayout(app->list_view);

    for (size_t i = 0; i < app->entry_count; ++i)
    {
        fileman_entry_t *entry = &app->entries[i];
        atk_iconbox_add_icon_with_image(app->iconbox, entry->name, &entry->icon, fileman_icon_action, entry);
    }
    atk_iconbox_relayout(app->iconbox);

    fileman_apply_view_state(app);
    if (app->window)
    {
        atk_window_mark_dirty(app->window);
    }
}

static void fileman_set_current_path(fileman_app_t *app, const char *path)
{
    if (!app || !path)
    {
        return;
    }
    size_t len = strlen(path);
    if (len >= sizeof(app->current_path))
    {
        len = sizeof(app->current_path) - 1;
    }
    memcpy(app->current_path, path, len);
    app->current_path[len] = '\0';
    fileman_normalize_path(app->current_path);
    fileman_update_title(app);
    fileman_refresh_right_view(app);
}

static bool fileman_is_double_click(fileman_app_t *app, const fileman_entry_t *entry)
{
    if (!app || !entry)
    {
        return false;
    }
    uint64_t now = sys_time_millis();
    uint64_t delta = (app->last_click_ms > 0) ? (now - app->last_click_ms) : (uint64_t)-1;
    if (delta < FILEMAN_CLICK_DEBOUNCE_MS)
    {
        return false;
    }
    bool is_double = (app->last_click_entry == entry) && (delta <= FILEMAN_DBLCLICK_MS);
    app->last_click_entry = entry;
    app->last_click_ms = now;
    return is_double;
}

static void fileman_run_elf(fileman_app_t *app, const char *path)
{
    if (!app || !path || !path[0])
    {
        return;
    }
    if (app->shell_handle < 0)
    {
        return;
    }
    char command[FILEMAN_PATH_MAX + 16];
    snprintf(command, sizeof(command), "runelf %s", path);
    command[sizeof(command) - 1] = '\0';
    sys_shell_exec(app->shell_handle, command, 0);
}

static void fileman_run_with_app(fileman_app_t *app, const char *program, const char *path)
{
    if (!app || !program || !program[0] || !path || !path[0])
    {
        return;
    }
    if (app->shell_handle < 0)
    {
        return;
    }
    size_t len = strlen(program) + strlen(path) + 16;
    char *command = (char *)malloc(len);
    if (!command)
    {
        return;
    }
    snprintf(command, len, "runelf %s %s", program, path);
    command[len - 1] = '\0';
    sys_shell_exec(app->shell_handle, command, 0);
    free(command);
}

static void fileman_run_preview(fileman_app_t *app, const char *path)
{
    fileman_run_with_app(app, FILEMAN_PREVIEW_ELF, path);
}

static void fileman_open_entry(fileman_app_t *app, fileman_entry_t *entry)
{
    if (!app || !entry)
    {
        return;
    }
    if (entry->is_dir)
    {
        atk_tree_node_t *current = atk_tree_view_selected(app->tree);
        atk_tree_node_t *child = current ? atk_tree_view_node_find_child(current, entry->name) : NULL;
        if (child)
        {
            atk_tree_view_set_selected(app->tree, child);
            fileman_tree_on_select(app->tree, app, child);
        }
        else
        {
            fileman_set_current_path(app, entry->path);
        }
        return;
    }
    if (entry->is_elf)
    {
        fileman_run_elf(app, entry->path);
        return;
    }

    const char *default_app = fileman_default_app_for_name(app, entry->name);
    if (default_app)
    {
        fileman_run_with_app(app, default_app, entry->path);
        return;
    }

    if (entry->is_image)
    {
        fileman_run_preview(app, entry->path);
        return;
    }
    if (entry->is_font)
    {
        fileman_run_with_app(app, FILEMAN_TTF_DEMO_ELF, entry->path);
    }
}

static bool fileman_tree_lazy_load(atk_widget_t *tree, void *context, atk_tree_node_t *node)
{
    (void)context;
    if (!tree || !node)
    {
        return true;
    }
    const char *path = (const char *)atk_tree_view_node_user(node);
    if (!path || !path[0])
    {
        return true;
    }

    syscall_dirent_t entries[FILEMAN_MAX_ENTRIES];
    ssize_t count = sys_list_dir(path, entries, FILEMAN_MAX_ENTRIES);
    if (count <= 0)
    {
        atk_tree_view_set_node_expandable(node, false);
        return true;
    }

    bool added = false;
    for (ssize_t i = 0; i < count; ++i)
    {
        syscall_dirent_t *ent = &entries[i];
        if (fileman_is_dot_entry(ent->name))
        {
            continue;
        }
        char child_path[FILEMAN_PATH_MAX];
        fileman_join_path(child_path, sizeof(child_path), path, ent->name);
        if (!fileman_dirent_is_dir(ent, child_path))
        {
            continue;
        }
        char *path_copy = fileman_strdup(child_path);
        if (!path_copy)
        {
            continue;
        }
        atk_tree_node_t *child = atk_tree_view_add_child(tree, node, ent->name, path_copy);
        if (!child)
        {
            free(path_copy);
            continue;
        }
        atk_tree_view_set_node_expandable(child, true);
        added = true;
    }
    if (!added)
    {
        atk_tree_view_set_node_expandable(node, false);
    }
    return true;
}

static void fileman_tree_destroy_node(atk_widget_t *tree, void *context, atk_tree_node_t *node)
{
    (void)tree;
    (void)context;
    if (!node)
    {
        return;
    }
    char *path = (char *)atk_tree_view_node_user(node);
    free(path);
}

static void fileman_tree_on_select(atk_widget_t *tree, void *context, atk_tree_node_t *node)
{
    fileman_app_t *app = (fileman_app_t *)context;
    if (!app || !tree || !node)
    {
        return;
    }
    atk_tree_view_set_node_expanded(tree, node, true);
    const char *path = (const char *)atk_tree_view_node_user(node);
    if (path && path[0])
    {
        fileman_set_current_path(app, path);
    }
}

static void fileman_list_on_select(atk_widget_t *list, void *context, size_t row)
{
    (void)list;
    fileman_app_t *app = (fileman_app_t *)context;
    if (!app || row >= app->entry_count)
    {
        return;
    }
    fileman_entry_t *entry = &app->entries[row];
    if (fileman_is_double_click(app, entry))
    {
        fileman_open_entry(app, entry);
    }
}

static void fileman_icon_action(atk_widget_t *button, void *context)
{
    (void)button;
    fileman_entry_t *entry = (fileman_entry_t *)context;
    fileman_app_t *app = entry ? entry->app : NULL;
    if (!app || !entry)
    {
        return;
    }
    if (fileman_is_double_click(app, entry))
    {
        fileman_open_entry(app, entry);
    }
}

static void fileman_set_view_mode(fileman_app_t *app, size_t index)
{
    if (!app)
    {
        return;
    }
    if (index > FILEMAN_VIEW_ICONS)
    {
        index = FILEMAN_VIEW_LIST;
    }
    app->view_mode = index;
    fileman_apply_view_state(app);
    if (app->view_mode == FILEMAN_VIEW_LIST && app->list_view)
    {
        atk_list_view_relayout(app->list_view);
    }
    else if (app->view_mode == FILEMAN_VIEW_ICONS && app->iconbox)
    {
        atk_iconbox_relayout(app->iconbox);
    }
    if (app->window)
    {
        atk_window_mark_dirty(app->window);
    }
}

static void fileman_set_sort_mode(fileman_app_t *app, size_t index)
{
    if (!app)
    {
        return;
    }
    if (index > FILEMAN_SORT_SIZE)
    {
        index = FILEMAN_SORT_NAME;
    }
    if (app->sort_mode == index)
    {
        return;
    }
    app->sort_mode = index;
    fileman_refresh_right_view(app);
}

static void fileman_list_view_action(atk_widget_t *button, void *context)
{
    (void)button;
    fileman_set_view_mode((fileman_app_t *)context, FILEMAN_VIEW_LIST);
}

static void fileman_icon_view_action(atk_widget_t *button, void *context)
{
    (void)button;
    fileman_set_view_mode((fileman_app_t *)context, FILEMAN_VIEW_ICONS);
}

static void fileman_sort_on_select(atk_widget_t *dropdown, void *context, size_t index, uintptr_t value)
{
    (void)dropdown;
    (void)index;
    fileman_set_sort_mode((fileman_app_t *)context, (size_t)value);
}

static void fileman_layout(fileman_app_t *app)
{
    if (!app || !app->window || !app->tree || !app->list_view || !app->iconbox)
    {
        return;
    }

    int chrome_top = atk_window_is_chrome_visible(app->window) ? ATK_WINDOW_TITLE_HEIGHT : 0;
    int content_x = FILEMAN_MARGIN;
    int content_y = chrome_top + FILEMAN_MARGIN;
    int content_w = app->window->width - FILEMAN_MARGIN * 2;
    int content_h = app->window->height - chrome_top - FILEMAN_MARGIN * 2;
    if (content_w < 0)
    {
        content_w = 0;
    }
    if (content_h < 0)
    {
        content_h = 0;
    }

    int tree_w = content_w / 3;
    if (tree_w < FILEMAN_TREE_MIN_WIDTH)
    {
        tree_w = FILEMAN_TREE_MIN_WIDTH;
    }
    if (tree_w > FILEMAN_TREE_MAX_WIDTH)
    {
        tree_w = FILEMAN_TREE_MAX_WIDTH;
    }
    if (tree_w > content_w)
    {
        tree_w = content_w;
    }
    int right_w = content_w - tree_w - FILEMAN_MARGIN;
    if (right_w < 0)
    {
        right_w = 0;
    }

    app->tree->x = content_x;
    app->tree->y = content_y;
    app->tree->width = tree_w;
    app->tree->height = content_h;

    int right_x = content_x + tree_w + FILEMAN_MARGIN;
    int right_y = content_y;
    int right_h = content_h;

    int button_w = FILEMAN_VIEW_BUTTON_WIDTH;
    int button_h = FILEMAN_VIEW_BUTTON_HEIGHT;
    int sort_w = FILEMAN_SORT_DROPDOWN_WIDTH;
    int total_controls = button_w * 2 + FILEMAN_VIEW_BUTTON_GAP + FILEMAN_SORT_DROPDOWN_GAP + sort_w;
    if (right_w > 0 && right_w < total_controls)
    {
        int available = right_w - FILEMAN_VIEW_BUTTON_GAP - FILEMAN_SORT_DROPDOWN_GAP;
        if (available < 0)
        {
            available = 0;
        }
        button_w = available / 3;
        sort_w = available - button_w * 2;
        if (button_w < 0)
        {
            button_w = 0;
        }
        if (sort_w < 0)
        {
            sort_w = 0;
        }
    }
    if (button_h > right_h)
    {
        button_h = right_h;
    }

    if (app->list_button)
    {
        app->list_button->x = right_x;
        app->list_button->y = right_y;
        app->list_button->width = button_w;
        app->list_button->height = button_h;
    }
    if (app->icon_button)
    {
        app->icon_button->x = right_x + button_w + FILEMAN_VIEW_BUTTON_GAP;
        app->icon_button->y = right_y;
        app->icon_button->width = button_w;
        app->icon_button->height = button_h;
    }
    if (app->sort_dropdown)
    {
        app->sort_dropdown->x = right_x + button_w * 2 + FILEMAN_VIEW_BUTTON_GAP + FILEMAN_SORT_DROPDOWN_GAP;
        app->sort_dropdown->y = right_y;
        app->sort_dropdown->width = sort_w;
        app->sort_dropdown->height = button_h;
    }

    int view_y = right_y + button_h + FILEMAN_VIEW_BUTTON_SPACING;
    int view_h = right_h - (button_h + FILEMAN_VIEW_BUTTON_SPACING);
    if (view_h < 0)
    {
        view_h = 0;
    }

    atk_tree_view_relayout(app->tree);
    app->list_view->x = right_x;
    app->list_view->y = view_y;
    app->list_view->width = right_w;
    app->list_view->height = view_h;
    atk_list_view_relayout(app->list_view);

    app->iconbox->x = right_x;
    app->iconbox->y = view_y;
    app->iconbox->width = right_w;
    app->iconbox->height = view_h;
    atk_iconbox_relayout(app->iconbox);
    fileman_apply_view_state(app);
    atk_window_mark_dirty(app->window);
}

static bool fileman_init_ui(fileman_app_t *app)
{
    if (!app)
    {
        return false;
    }

    atk_init();
    atk_state_t *state = atk_state_get();
    if (!state)
    {
        return false;
    }
    state->theme.desktop_icon_text = state->theme.button_text;
    atk_state_theme_commit(state);
    atk_menu_bar_set_enabled(state, false);

    atk_widget_t *window = atk_window_create_at(state, FILEMAN_WINDOW_WIDTH / 2, FILEMAN_WINDOW_HEIGHT / 2);
    if (!window)
    {
        return false;
    }
    atk_window_set_title_text(window, "File Manager");
    atk_window_set_chrome_visible(window, false);
    window->x = 0;
    window->y = 0;
    window->width = FILEMAN_WINDOW_WIDTH;
    window->height = FILEMAN_WINDOW_HEIGHT;

    atk_widget_t *tree = atk_window_add_tree_view(window, 0, 0, 100, 100);
    if (!tree)
    {
        return false;
    }

    atk_widget_t *list_view = atk_window_add_list_view(window, 0, 0, 100, 100);
    if (!list_view)
    {
        return false;
    }
    static const atk_list_view_column_def_t FILEMAN_COLUMNS[] = {
        { "Name", 0 },
        { "Size", ATK_COL(10) },
        { "Bytes", ATK_COL(12) },
    };
    atk_list_view_configure_columns(list_view, FILEMAN_COLUMNS, sizeof(FILEMAN_COLUMNS) / sizeof(FILEMAN_COLUMNS[0]));
    atk_list_view_force_vertical_scrollbar(list_view, true);
    atk_list_view_set_select_handler(list_view, fileman_list_on_select, app);

    atk_widget_t *iconbox = atk_window_add_iconbox(window, 0, 0, 100, 100);
    if (!iconbox)
    {
        return false;
    }

    atk_widget_t *list_button = atk_window_add_button(window,
                                                      "List",
                                                      0,
                                                      0,
                                                      FILEMAN_VIEW_BUTTON_WIDTH,
                                                      FILEMAN_VIEW_BUTTON_HEIGHT,
                                                      ATK_BUTTON_STYLE_TITLE_INSIDE,
                                                      false,
                                                      fileman_list_view_action,
                                                      app);
    if (!list_button)
    {
        return false;
    }

    atk_widget_t *icon_button = atk_window_add_button(window,
                                                      "Icons",
                                                      0,
                                                      0,
                                                      FILEMAN_VIEW_BUTTON_WIDTH,
                                                      FILEMAN_VIEW_BUTTON_HEIGHT,
                                                      ATK_BUTTON_STYLE_TITLE_INSIDE,
                                                      false,
                                                      fileman_icon_view_action,
                                                      app);
    if (!icon_button)
    {
        return false;
    }

    atk_widget_t *sort_dropdown = atk_window_add_dropdown(window,
                                                          0,
                                                          0,
                                                          FILEMAN_SORT_DROPDOWN_WIDTH,
                                                          FILEMAN_VIEW_BUTTON_HEIGHT,
                                                          ATK_DROPDOWN_STYLE_COMBO,
                                                          fileman_sort_on_select,
                                                          app);
    if (!sort_dropdown)
    {
        return false;
    }
    atk_dropdown_set_title(sort_dropdown, "Sort");
    if (!atk_dropdown_add_item(sort_dropdown, "Name", FILEMAN_SORT_NAME) ||
        !atk_dropdown_add_item(sort_dropdown, "Size", FILEMAN_SORT_SIZE) ||
        !atk_dropdown_set_selected(sort_dropdown, FILEMAN_SORT_NAME))
    {
        return false;
    }

    atk_window_priv_t *wpriv = (atk_window_priv_t *)atk_widget_priv(window, &ATK_WINDOW_CLASS);
    if (!wpriv)
    {
        return false;
    }

    atk_widget_t *context_menu = atk_menu_create();
    if (!context_menu)
    {
        return false;
    }
    context_menu->parent = window;
    atk_list_node_t *menu_node = atk_list_push_back(&wpriv->children, context_menu);
    if (!menu_node)
    {
        atk_menu_destroy(context_menu);
        return false;
    }
    if (!atk_menu_add_item(context_menu, "Properties", fileman_context_menu_action_properties, app))
    {
        atk_list_remove(&wpriv->children, menu_node);
        atk_menu_destroy(context_menu);
        return false;
    }

    atk_tree_view_set_select_handler(tree, fileman_tree_on_select, app);
    atk_tree_view_set_lazy_load_handler(tree, fileman_tree_lazy_load, app);
    atk_tree_view_set_node_destroy_handler(tree, fileman_tree_destroy_node, app);

    char *root_path = fileman_strdup("/");
    atk_tree_node_t *root = atk_tree_view_add_root(tree, "/", root_path);
    if (!root)
    {
        free(root_path);
        return false;
    }
    atk_tree_view_set_node_expandable(root, true);
    atk_tree_view_set_selected(tree, root);

    app->window = window;
    app->tree = tree;
    app->list_button = list_button;
    app->icon_button = icon_button;
    app->sort_dropdown = sort_dropdown;
    app->list_view = list_view;
    app->iconbox = iconbox;
    app->context_menu = context_menu;
    app->view_mode = FILEMAN_VIEW_ICONS;
    app->sort_mode = FILEMAN_SORT_NAME;

    fileman_layout(app);
    fileman_set_view_mode(app, FILEMAN_VIEW_ICONS);
    fileman_tree_on_select(tree, app, root);
    return true;
}

static void fileman_thumb_start(fileman_app_t *app)
{
    if (!app)
    {
        return;
    }

    app->thumbs_enabled = false;
    alix_mutex_init(&app->thumb_task_lock);
    alix_mutex_init(&app->thumb_msg_lock);
    app->thumb_task_head = NULL;
    app->thumb_task_tail = NULL;
    app->thumb_msg_head = NULL;
    app->thumb_msg_tail = NULL;

    if (!fileman_thumb_dir_init(app))
    {
        return;
    }

    alix_thread_t thread = 0;
    if (alix_thread_create(&thread, "fileman_thumb", fileman_thumb_thread, app) != 0)
    {
        return;
    }

    app->thumb_thread = thread;
    app->thumbs_enabled = true;
}

static void fileman_thumb_stop(fileman_app_t *app)
{
    if (!app)
    {
        return;
    }

    __atomic_store_n(&app->running, false, __ATOMIC_RELEASE);
    if (app->thumb_thread)
    {
        (void)alix_thread_join(app->thumb_thread, NULL);
        app->thumb_thread = 0;
    }

    fileman_thumb_queue_clear(app);
    free(app->thumb_dir);
    app->thumb_dir = NULL;
    app->thumbs_enabled = false;
}

static bool fileman_on_resize_event(uint32_t width, uint32_t height, void *context)
{
    fileman_app_t *app = (fileman_app_t *)context;
    if (!app || !app->window)
    {
        return false;
    }
    app->window->width = (int)width;
    app->window->height = (int)height;
    atk_window_request_layout(app->window);
    fileman_layout(app);
    return true;
}

static void fileman_on_close_event(void *context)
{
    fileman_app_t *app = (fileman_app_t *)context;
    if (app)
    {
        __atomic_store_n(&app->running, false, __ATOMIC_RELEASE);
    }
    atk_main_request_exit();
}

int main(void)
{
    fileman_app_t *app = (fileman_app_t *)calloc(1, sizeof(*app));
    if (!app)
    {
        printf("atk_fileman: failed to allocate app state\n");
        return 1;
    }
    app->shell_handle = sys_shell_open();
    __atomic_store_n(&app->running, true, __ATOMIC_RELEASE);

    if (!atk_user_window_open_with_flags(&app->remote,
                                         "File Manager",
                                         FILEMAN_WINDOW_WIDTH,
                                         FILEMAN_WINDOW_HEIGHT,
                                         USER_ATK_WINDOW_FLAG_RESIZABLE))
    {
        printf("atk_fileman: failed to open remote window\n");
        if (app->shell_handle >= 0)
        {
            sys_shell_close(app->shell_handle);
        }
        free(app);
        return 1;
    }
    atk_user_enable_dirty_tracking(&app->remote, true);
    fileman_thumb_start(app);

    if (!fileman_init_ui(app))
    {
        printf("atk_fileman: failed to init UI\n");
        fileman_thumb_stop(app);
        atk_user_close(&app->remote);
        if (app->shell_handle >= 0)
        {
            sys_shell_close(app->shell_handle);
        }
        free(app);
        return 1;
    }

    (void)fileman_default_apps_load(app);

    atk_render();
    atk_user_present_force(&app->remote);

    atk_main_config_t main_cfg = {
        .window = &app->remote,
        .tick = fileman_on_tick,
        .tick_context = app,
        .present_on_idle = false,
        .legacy_input = false,
        .tick_interval_ms = 0
    };

    atk_main_register_resize_handler(fileman_on_resize_event, app);
    atk_main_register_close_handler(fileman_on_close_event, app);
    atk_main_register_mouse_handler(fileman_on_mouse_event, app);

    atk_main(&main_cfg);

    if (app->properties_window)
    {
        atk_window_close(atk_state_get(), app->properties_window);
    }
    fileman_thumb_stop(app);
    fileman_entries_clear(app);
    fileman_icon_cache_clear(app);
    fileman_default_apps_clear(app);
    if (app->shell_handle >= 0)
    {
        sys_shell_close(app->shell_handle);
    }
    atk_user_close(&app->remote);
    free(app);
    return 0;
}
