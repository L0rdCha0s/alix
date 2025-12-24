#include "atk_user.h"

#include "atk.h"
#include "atk_app.h"
#include "atk_internal.h"
#include "atk_window.h"
#include "atk/layout.h"
#include "atk/atk_iconbox.h"
#include "atk/atk_nav_stack.h"
#include "atk/atk_font.h"
#include "atk_button.h"
#include "atk_menu_bar.h"
#include "libc.h"
#include "serial.h"
#include "video.h"
#include "usyscall.h"
#include "user_atk_defs.h"
#include "fcntl.h"

#define CP_WINDOW_WIDTH  820
#define CP_WINDOW_HEIGHT 520
#define CP_PANE_PADDING  18
#define CP_PANE_LINE_SPACING 4
#define CP_PANE_BUTTON_WIDTH 180
#define CP_PANE_BUTTON_HEIGHT (ATK_FONT_HEIGHT + 10)
#define CP_BODY_CAP_DISPLAY 512
#define CP_BODY_CAP_HW 1024
#define CP_BODY_CAP_NET 2048

typedef enum
{
    CP_PANE_KIND_GENERIC = 0,
    CP_PANE_KIND_DISPLAY,
    CP_PANE_KIND_HW,
    CP_PANE_KIND_NET
} cp_pane_kind_t;

typedef struct control_panel_app control_panel_app_t;

typedef struct
{
    control_panel_app_t *app;
    const char *title;
    cp_pane_kind_t kind;
} cp_icon_ctx_t;

struct control_panel_app
{
    atk_user_window_t remote;
    atk_widget_t *window;
    atk_widget_t *nav;
    atk_widget_t *iconbox;
    atk_widget_t *display_pane;
    cp_icon_ctx_t hw_ctx;
    cp_icon_ctx_t net_ctx;
    cp_icon_ctx_t display_ctx;
    atk_widget_t *file_dialog;
    atk_modal_session_t dialog_modal;
    int shell_handle;
    char display_status[96];
    bool display_status_valid;
    bool running;
};

typedef struct
{
    char title[64];
    cp_pane_kind_t kind;
    control_panel_app_t *app;
    atk_widget_t *open_button;
    char *body_text;
    int last_width;
    int last_height;
    bool layout_dirty;
} cp_pane_priv_t;

typedef struct
{
    char *data;
    size_t len;
    size_t cap;
} cp_builder_t;

static void cp_pane_draw(const atk_state_t *state, const atk_widget_t *widget, int origin_x, int origin_y, void *context);
static bool cp_pane_hit(const atk_widget_t *widget,
                        int origin_x,
                        int origin_y,
                        int px,
                        int py,
                        void *context);
static atk_mouse_response_t cp_pane_mouse(atk_widget_t *widget,
                                          const atk_mouse_event_t *event,
                                          void *context);
static void cp_pane_destroy(atk_widget_t *widget, void *context);

static const atk_class_t CP_PANE_CLASS = { "CPPane", &ATK_WIDGET_CLASS, NULL, sizeof(cp_pane_priv_t) };

static const atk_widget_ops_t g_cp_pane_ops = {
    .destroy = cp_pane_destroy,
    .draw = cp_pane_draw,
    .hit_test = cp_pane_hit,
    .on_mouse = cp_pane_mouse,
    .on_key = NULL
};

static char *cp_strdup(const char *text)
{
    if (!text)
    {
        return NULL;
    }
    size_t len = strlen(text);
    char *copy = (char *)malloc(len + 1);
    if (!copy)
    {
        return NULL;
    }
    memcpy(copy, text, len);
    copy[len] = '\0';
    return copy;
}

static void cp_builder_init(cp_builder_t *builder, size_t initial_cap)
{
    if (!builder)
    {
        return;
    }
    builder->len = 0;
    builder->cap = initial_cap ? initial_cap : 256;
    builder->data = (char *)malloc(builder->cap);
    if (builder->data)
    {
        builder->data[0] = '\0';
    }
}

static bool cp_builder_ensure(cp_builder_t *builder, size_t extra)
{
    if (!builder || !builder->data)
    {
        return false;
    }
    size_t needed = builder->len + extra + 1;
    if (needed <= builder->cap)
    {
        return true;
    }
    return false;
}

static bool cp_builder_append_len(cp_builder_t *builder, const char *text, size_t len)
{
    if (!builder || !builder->data || !text || len == 0)
    {
        return true;
    }
    if (!cp_builder_ensure(builder, len))
    {
        return false;
    }
    memcpy(builder->data + builder->len, text, len);
    builder->len += len;
    builder->data[builder->len] = '\0';
    return true;
}

static bool cp_builder_append(cp_builder_t *builder, const char *text)
{
    if (!text)
    {
        return true;
    }
    return cp_builder_append_len(builder, text, strlen(text));
}

static bool cp_builder_append_char(cp_builder_t *builder, char ch)
{
    if (!builder || !builder->data)
    {
        return false;
    }
    if (!cp_builder_ensure(builder, 1))
    {
        return false;
    }
    builder->data[builder->len++] = ch;
    builder->data[builder->len] = '\0';
    return true;
}

static bool cp_builder_append_line(cp_builder_t *builder, const char *text)
{
    if (!cp_builder_append(builder, text))
    {
        return false;
    }
    return cp_builder_append_char(builder, '\n');
}

static char *cp_builder_detach(cp_builder_t *builder)
{
    if (!builder)
    {
        return NULL;
    }
    char *data = builder->data;
    builder->data = NULL;
    builder->len = 0;
    builder->cap = 0;
    return data;
}

static char *cp_read_file(const char *path, size_t max_bytes)
{
    if (!path || max_bytes == 0)
    {
        return NULL;
    }
    int fd = open(path, O_RDONLY);
    if (fd < 0)
    {
        return NULL;
    }
    char *buf = (char *)malloc(max_bytes + 1);
    if (!buf)
    {
        close(fd);
        return NULL;
    }
    size_t len = 0;
    while (len < max_bytes)
    {
        ssize_t got = read(fd, buf + len, max_bytes - len);
        if (got < 0)
        {
            free(buf);
            close(fd);
            return NULL;
        }
        if (got == 0)
        {
            break;
        }
        len += (size_t)got;
    }
    buf[len] = '\0';
    close(fd);
    return buf;
}

static void cp_trim_trailing_ws(char *text)
{
    if (!text)
    {
        return;
    }
    size_t len = strlen(text);
    while (len > 0)
    {
        char ch = text[len - 1];
        if (ch != '\n' && ch != '\r' && ch != ' ' && ch != '\t')
        {
            break;
        }
        text[--len] = '\0';
    }
}

static bool cp_extract_line_value(const char *text, const char *key, const char **value_out, size_t *len_out)
{
    if (!text || !key || !value_out || !len_out)
    {
        return false;
    }
    size_t key_len = strlen(key);
    const char *cursor = text;
    while (cursor && *cursor)
    {
        const char *line_end = strchr(cursor, '\n');
        size_t line_len = line_end ? (size_t)(line_end - cursor) : strlen(cursor);
        if (line_len > key_len + 1 &&
            strncmp(cursor, key, key_len) == 0 &&
            cursor[key_len] == ':')
        {
            const char *value = cursor + key_len + 1;
            while (*value == ' ' || *value == '\t')
            {
                ++value;
            }
            size_t value_len = (size_t)((cursor + line_len) - value);
            while (value_len > 0 &&
                   (value[value_len - 1] == ' ' ||
                    value[value_len - 1] == '\t' ||
                    value[value_len - 1] == '\r'))
            {
                --value_len;
            }
            *value_out = value;
            *len_out = value_len;
            return true;
        }
        cursor = line_end ? line_end + 1 : NULL;
    }
    return false;
}

static void cp_builder_append_kv(cp_builder_t *builder, const char *label, const char *text, const char *key)
{
    const char *value = NULL;
    size_t value_len = 0;
    cp_builder_append(builder, "  ");
    cp_builder_append(builder, label);
    cp_builder_append(builder, ": ");
    if (text && cp_extract_line_value(text, key, &value, &value_len))
    {
        cp_builder_append_len(builder, value, value_len);
    }
    else
    {
        cp_builder_append(builder, "-");
    }
    cp_builder_append_char(builder, '\n');
}

static char *cp_build_hw_body(void)
{
    cp_builder_t builder = { 0 };
    cp_builder_init(&builder, CP_BODY_CAP_HW);
    if (!builder.data)
    {
        return cp_strdup("Hardware information unavailable.");
    }

    cp_builder_append_line(&builder, "CPU");
    char *cpu = cp_read_file("/proc/devices/cpu/info", 512);
    if (cpu)
    {
        cp_trim_trailing_ws(cpu);
        cp_builder_append_kv(&builder, "Model", cpu, "model");
        cp_builder_append_kv(&builder, "Vendor", cpu, "vendor");
        cp_builder_append_kv(&builder, "Cores", cpu, "cores");
        cp_builder_append_kv(&builder, "Base MHz", cpu, "base_mhz");
        cp_builder_append_kv(&builder, "Max MHz", cpu, "max_mhz");
        cp_builder_append_kv(&builder, "Bus MHz", cpu, "bus_mhz");
    }
    else
    {
        cp_builder_append_line(&builder, "  (unavailable)");
    }
    cp_builder_append_char(&builder, '\n');

    cp_builder_append_line(&builder, "Memory");
    char *mem = cp_read_file("/proc/devices/memory/info", 512);
    if (mem)
    {
        cp_trim_trailing_ws(mem);
        cp_builder_append_kv(&builder, "Usable (MiB)", mem, "usable_mib");
        cp_builder_append_kv(&builder, "Total (MiB)", mem, "total_mib");
        cp_builder_append_kv(&builder, "Usable (bytes)", mem, "usable_bytes");
        cp_builder_append_kv(&builder, "Total (bytes)", mem, "total_bytes");
        cp_builder_append_kv(&builder, "E820 entries", mem, "e820_entries");
    }
    else
    {
        cp_builder_append_line(&builder, "  (unavailable)");
    }

    if (cpu)
    {
        free(cpu);
    }
    if (mem)
    {
        free(mem);
    }

    return cp_builder_detach(&builder);
}

static void cp_append_net_entry(cp_builder_t *builder, char *line)
{
    if (!builder || !builder->data || !line)
    {
        return;
    }

    const char *name = NULL;
    const char *present = NULL;
    const char *link_up = NULL;
    const char *mac = NULL;
    const char *ipv4 = NULL;
    const char *rx_bytes = NULL;
    const char *tx_bytes = NULL;
    const char *rx_packets = NULL;
    const char *tx_packets = NULL;

    char *cursor = line;
    while (cursor && *cursor)
    {
        while (*cursor == ' ')
        {
            ++cursor;
        }
        if (*cursor == '\0')
        {
            break;
        }
        char *end = cursor;
        while (*end != '\0' && *end != ' ')
        {
            ++end;
        }
        if (*end != '\0')
        {
            *end = '\0';
            ++end;
        }

        char *eq = strchr(cursor, '=');
        if (eq)
        {
            *eq = '\0';
            const char *key = cursor;
            const char *value = eq + 1;
            if (strcmp(key, "name") == 0)
            {
                name = value;
            }
            else if (strcmp(key, "present") == 0)
            {
                present = value;
            }
            else if (strcmp(key, "link_up") == 0)
            {
                link_up = value;
            }
            else if (strcmp(key, "mac") == 0)
            {
                mac = value;
            }
            else if (strcmp(key, "ipv4") == 0)
            {
                ipv4 = value;
            }
            else if (strcmp(key, "rx_bytes") == 0)
            {
                rx_bytes = value;
            }
            else if (strcmp(key, "tx_bytes") == 0)
            {
                tx_bytes = value;
            }
            else if (strcmp(key, "rx_packets") == 0)
            {
                rx_packets = value;
            }
            else if (strcmp(key, "tx_packets") == 0)
            {
                tx_packets = value;
            }
        }
        cursor = end;
    }

    bool is_present = present && present[0] == '1';
    bool is_up = link_up && link_up[0] == '1';

    cp_builder_append(builder, "Interface: ");
    cp_builder_append(builder, name ? name : "-");
    cp_builder_append_char(builder, '\n');
    cp_builder_append(builder, "  State: ");
    cp_builder_append(builder, is_up ? "Up" : "Down");
    cp_builder_append(builder, is_present ? " (present)" : " (absent)");
    cp_builder_append_char(builder, '\n');
    cp_builder_append(builder, "  MAC: ");
    cp_builder_append(builder, mac ? mac : "-");
    cp_builder_append_char(builder, '\n');
    cp_builder_append(builder, "  IPv4: ");
    cp_builder_append(builder, ipv4 ? ipv4 : "-");
    cp_builder_append_char(builder, '\n');
    cp_builder_append(builder, "  RX: ");
    cp_builder_append(builder, rx_bytes ? rx_bytes : "-");
    cp_builder_append(builder, " bytes");
    cp_builder_append_char(builder, '\n');
    cp_builder_append(builder, "  TX: ");
    cp_builder_append(builder, tx_bytes ? tx_bytes : "-");
    cp_builder_append(builder, " bytes");
    cp_builder_append_char(builder, '\n');
    cp_builder_append(builder, "  Packets: RX ");
    cp_builder_append(builder, rx_packets ? rx_packets : "-");
    cp_builder_append(builder, ", TX ");
    cp_builder_append(builder, tx_packets ? tx_packets : "-");
    cp_builder_append_char(builder, '\n');
}

static char *cp_build_net_body(void)
{
    cp_builder_t builder = { 0 };
    cp_builder_init(&builder, CP_BODY_CAP_NET);
    if (!builder.data)
    {
        return cp_strdup("Network information unavailable.");
    }

    char *raw = cp_read_file("/proc/devices/net/info", CP_BODY_CAP_NET);
    if (!raw)
    {
        cp_builder_append_line(&builder, "No network information available.");
        return cp_builder_detach(&builder);
    }
    cp_trim_trailing_ws(raw);

    if (raw[0] == '\0' || strcmp(raw, "(none)") == 0)
    {
        cp_builder_append_line(&builder, "No network interfaces detected.");
        free(raw);
        return cp_builder_detach(&builder);
    }

    char *line = raw;
    bool first = true;
    while (line && *line)
    {
        char *line_end = strchr(line, '\n');
        if (line_end)
        {
            *line_end = '\0';
        }
        if (line[0] != '\0' && strcmp(line, "(none)") != 0)
        {
            if (!first)
            {
                cp_builder_append_char(&builder, '\n');
            }
            cp_append_net_entry(&builder, line);
            first = false;
        }
        if (!line_end)
        {
            break;
        }
        line = line_end + 1;
    }

    free(raw);
    return cp_builder_detach(&builder);
}

static bool cp_path_has_space(const char *path)
{
    if (!path)
    {
        return false;
    }
    for (const char *p = path; *p; ++p)
    {
        if (*p == ' ' || *p == '\t')
        {
            return true;
        }
    }
    return false;
}

static void cp_set_display_status(control_panel_app_t *app, const char *text)
{
    if (!app)
    {
        return;
    }
    app->display_status_valid = false;
    app->display_status[0] = '\0';
    if (!text || *text == '\0')
    {
        return;
    }
    size_t len = strlen(text);
    if (len >= sizeof(app->display_status))
    {
        len = sizeof(app->display_status) - 1;
    }
    memcpy(app->display_status, text, len);
    app->display_status[len] = '\0';
    app->display_status_valid = true;
}

static char *cp_build_display_body(control_panel_app_t *app)
{
    cp_builder_t builder = { 0 };
    cp_builder_init(&builder, CP_BODY_CAP_DISPLAY);
    if (!builder.data)
    {
        return cp_strdup("Display information unavailable.");
    }

    cp_builder_append_line(&builder, "Desktop Background");
    cp_builder_append_char(&builder, '\n');
    cp_builder_append(&builder, "Current: ");

    char *path = cp_read_file("/etc/display/background", CP_BODY_CAP_DISPLAY);
    if (path)
    {
        cp_trim_trailing_ws(path);
    }
    if (!path || path[0] == '\0')
    {
        cp_builder_append_line(&builder, "(none)");
    }
    else
    {
        cp_builder_append_line(&builder, path);
    }
    cp_builder_append_line(&builder, "PNG images are supported.");
    cp_builder_append_line(&builder, "Use the button below to choose a file.");

    if (app && app->display_status_valid && app->display_status[0])
    {
        cp_builder_append_char(&builder, '\n');
        cp_builder_append_line(&builder, app->display_status);
    }

    if (path)
    {
        free(path);
    }

    return cp_builder_detach(&builder);
}

static void cp_pane_set_body(cp_pane_priv_t *priv, char *text)
{
    if (!priv)
    {
        if (text)
        {
            free(text);
        }
        return;
    }
    if (priv->body_text)
    {
        free(priv->body_text);
    }
    priv->body_text = text ? text : cp_strdup("");
    priv->layout_dirty = true;
}

static void cp_pane_refresh(cp_pane_priv_t *priv)
{
    if (!priv)
    {
        return;
    }
    char *body = NULL;
    switch (priv->kind)
    {
        case CP_PANE_KIND_DISPLAY:
            body = cp_build_display_body(priv->app);
            break;
        case CP_PANE_KIND_HW:
            body = cp_build_hw_body();
            break;
        case CP_PANE_KIND_NET:
            body = cp_build_net_body();
            break;
        case CP_PANE_KIND_GENERIC:
        default:
            body = cp_strdup("");
            break;
    }
    cp_pane_set_body(priv, body);
}

static int cp_body_line_count(const char *text)
{
    if (!text || *text == '\0')
    {
        return 0;
    }
    int lines = 1;
    for (const char *p = text; *p; ++p)
    {
        if (*p == '\n')
        {
            ++lines;
        }
    }
    return lines;
}

static int cp_body_height(const char *text)
{
    int lines = cp_body_line_count(text);
    if (lines <= 0)
    {
        return 0;
    }
    int line_height = atk_font_line_height();
    return lines * line_height + (lines - 1) * CP_PANE_LINE_SPACING;
}

static void cp_pane_layout(cp_pane_priv_t *priv, atk_widget_t *pane)
{
    if (!priv || !pane)
    {
        return;
    }
    priv->last_width = pane->width;
    priv->last_height = pane->height;
    priv->layout_dirty = false;

    if (priv->open_button)
    {
        int line_height = atk_font_line_height();
        int text_height = cp_body_height(priv->body_text);
        int button_y = CP_PANE_PADDING + text_height + (line_height > 0 ? line_height : 0);
        if (button_y + CP_PANE_BUTTON_HEIGHT > pane->height - CP_PANE_PADDING)
        {
            button_y = pane->height - CP_PANE_PADDING - CP_PANE_BUTTON_HEIGHT;
        }
        if (button_y < CP_PANE_PADDING)
        {
            button_y = CP_PANE_PADDING;
        }
        priv->open_button->x = CP_PANE_PADDING;
        priv->open_button->y = button_y;
        priv->open_button->width = CP_PANE_BUTTON_WIDTH;
        priv->open_button->height = CP_PANE_BUTTON_HEIGHT;
    }
}

static void cp_draw_body_text(const atk_state_t *state,
                              cp_pane_priv_t *priv,
                              int x,
                              int y,
                              int width,
                              int height)
{
    if (!state || !priv || !priv->body_text)
    {
        return;
    }

    int line_height = atk_font_line_height();
    if (line_height <= 0)
    {
        return;
    }

    int max_y = y + height;
    char *cursor = priv->body_text;
    int draw_y = y;
    video_color_t text_color = state->theme.menu_dropdown_text;
    video_color_t bg_color = state->theme.window_body;

    while (*cursor && draw_y + line_height <= max_y)
    {
        char *line_end = strchr(cursor, '\n');
        if (line_end)
        {
            *line_end = '\0';
        }

        if (*cursor != '\0')
        {
            atk_rect_t clip = { x, draw_y, width, line_height };
            int baseline = atk_font_baseline_for_rect(draw_y, line_height);
            atk_font_draw_string_clipped(x, baseline, cursor, text_color, bg_color, &clip);
        }

        if (line_end)
        {
            *line_end = '\n';
            cursor = line_end + 1;
        }
        else
        {
            break;
        }
        draw_y += line_height + CP_PANE_LINE_SPACING;
    }
}

static bool cp_write_background_path(const char *path)
{
    if (!path || path[0] != '/')
    {
        return false;
    }
    int fd = open("/etc/display/background", O_WRONLY | O_CREAT | O_TRUNC);
    if (fd < 0)
    {
        return false;
    }
    size_t len = strlen(path);
    ssize_t written = write(fd, path, len);
    close(fd);
    if (written < 0 || (size_t)written != len)
    {
        return false;
    }
    atk_dirty_mark_all();
    video_request_refresh();
    return true;
}

static bool cp_exec_bgset(control_panel_app_t *app, const char *path)
{
    if (!app || !path || path[0] != '/')
    {
        return false;
    }
    if (cp_path_has_space(path))
    {
        cp_set_display_status(app, "Paths with spaces are not supported.");
        return false;
    }
    if (app->shell_handle < 0)
    {
        return cp_write_background_path(path);
    }
    size_t path_len = strlen(path);
    size_t cmd_len = 6 + path_len;
    char *cmd = (char *)malloc(cmd_len + 1);
    if (!cmd)
    {
        return false;
    }
    memcpy(cmd, "bgset ", 6);
    memcpy(cmd + 6, path, path_len);
    cmd[cmd_len] = '\0';
    int rc = sys_shell_exec(app->shell_handle, cmd, 0);
    free(cmd);
    return rc >= 0;
}

static const char *cp_dialog_initial_path(char *buf, size_t cap)
{
    if (!buf || cap == 0)
    {
        return "/root";
    }
    buf[0] = '\0';

    char *path = cp_read_file("/etc/display/background", CP_BODY_CAP_DISPLAY);
    if (path)
    {
        cp_trim_trailing_ws(path);
    }
    if (!path || path[0] == '\0')
    {
        if (path)
        {
            free(path);
        }
        memcpy(buf, "/root", 6);
        return buf;
    }

    size_t len = strlen(path);
    if (len >= cap)
    {
        len = cap - 1;
    }
    memcpy(buf, path, len);
    buf[len] = '\0';
    free(path);

    while (len > 1 && buf[len - 1] == '/')
    {
        buf[--len] = '\0';
    }

    char *last_slash = NULL;
    for (size_t i = 0; i < len; ++i)
    {
        if (buf[i] == '/')
        {
            last_slash = &buf[i];
        }
    }
    if (!last_slash)
    {
        memcpy(buf, "/root", 6);
    }
    else if (buf[len - 1] != '/')
    {
        if (last_slash == buf)
        {
            buf[1] = '\0';
        }
        else
        {
            *last_slash = '\0';
        }
    }

    if (buf[0] == '\0')
    {
        memcpy(buf, "/root", 6);
    }
    return buf;
}

static void cp_close_file_dialog(control_panel_app_t *app)
{
    if (!app)
    {
        return;
    }
    if (app->file_dialog && app->file_dialog->used)
    {
        atk_state_t *state = atk_state_get();
        if (state)
        {
            atk_window_close(state, app->file_dialog);
        }
    }
    if (app->dialog_modal.active)
    {
        atk_modal_end(&app->dialog_modal);
    }
    app->file_dialog = NULL;
    if (app->window)
    {
        atk_window_mark_dirty(app->window);
    }
    atk_dirty_mark_all();
    atk_render();
    atk_user_present_force(&app->remote);
}

static void cp_refresh_display_pane(control_panel_app_t *app)
{
    if (!app || !app->display_pane)
    {
        return;
    }
    cp_pane_priv_t *priv = (cp_pane_priv_t *)atk_widget_priv(app->display_pane, &CP_PANE_CLASS);
    if (!priv)
    {
        return;
    }
    cp_pane_refresh(priv);
    if (app->window)
    {
        atk_window_mark_dirty(app->window);
    }
}

static void cp_on_bg_dialog_result(atk_widget_t *requester, const char *path, bool confirmed, void *context)
{
    (void)requester;
    control_panel_app_t *app = (control_panel_app_t *)context;
    if (!app)
    {
        return;
    }

    if (confirmed && path && path[0] != '\0')
    {
        if (path[0] != '/')
        {
            cp_set_display_status(app, "Background path must be absolute.");
        }
        else if (cp_exec_bgset(app, path))
        {
            cp_set_display_status(app, "Background update requested.");
        }
        else if (!app->display_status_valid)
        {
            cp_set_display_status(app, "Failed to update background.");
        }
    }

    cp_refresh_display_pane(app);
    cp_close_file_dialog(app);
}

static void cp_open_bg_dialog(control_panel_app_t *app)
{
    if (!app || !app->window)
    {
        return;
    }
    if (app->file_dialog && app->file_dialog->used)
    {
        return;
    }

    char initial_path[256];
    const char *initial = cp_dialog_initial_path(initial_path, sizeof(initial_path));
    const uint32_t dialog_w = 720;
    const uint32_t dialog_h = 420;

    app->file_dialog = atk_app_open_file_dialog_modal(&app->dialog_modal,
                                                      app->window,
                                                      "Choose Background",
                                                      initial,
                                                      cp_on_bg_dialog_result,
                                                      app,
                                                      dialog_w,
                                                      dialog_h,
                                                      USER_ATK_WINDOW_FLAG_RESIZABLE);
    if (!app->file_dialog)
    {
        cp_set_display_status(app, "Open dialog unavailable.");
        cp_refresh_display_pane(app);
        return;
    }
    cp_set_display_status(app, "Select a PNG file.");
    cp_refresh_display_pane(app);
}

static void cp_on_bg_open_button(atk_widget_t *button, void *context)
{
    (void)button;
    cp_open_bg_dialog((control_panel_app_t *)context);
}

static atk_widget_t *cp_create_pane(control_panel_app_t *app, const char *title, cp_pane_kind_t kind)
{
    atk_widget_t *pane = atk_widget_create(&CP_PANE_CLASS);
    if (!pane)
    {
        return NULL;
    }
    pane->used = true;
    pane->x = 0;
    pane->y = 0;
    pane->width = 0;
    pane->height = 0;
    atk_widget_set_ops(pane, &g_cp_pane_ops, NULL);

    cp_pane_priv_t *priv = (cp_pane_priv_t *)atk_widget_priv(pane, &CP_PANE_CLASS);
    if (priv && title)
    {
        size_t len = strlen(title);
        if (len >= sizeof(priv->title))
        {
            len = sizeof(priv->title) - 1;
        }
        memcpy(priv->title, title, len);
        priv->title[len] = '\0';
    }
    else if (priv)
    {
        priv->title[0] = '\0';
    }
    if (priv)
    {
        priv->kind = kind;
        priv->app = app;
        priv->open_button = NULL;
        priv->body_text = NULL;
        priv->last_width = -1;
        priv->last_height = -1;
        priv->layout_dirty = true;
        if (kind == CP_PANE_KIND_DISPLAY)
        {
            atk_widget_t *btn = atk_widget_create(&ATK_BUTTON_CLASS);
            if (btn)
            {
                btn->used = true;
                btn->parent = pane;
                atk_button_configure(btn,
                                     "Choose Image...",
                                     ATK_BUTTON_STYLE_TITLE_INSIDE,
                                     false,
                                     false,
                                     cp_on_bg_open_button,
                                     app);
                priv->open_button = btn;
            }
        }
        cp_pane_refresh(priv);
        if (kind == CP_PANE_KIND_DISPLAY && app)
        {
            app->display_pane = pane;
        }
    }
    return pane;
}

static void cp_pane_draw(const atk_state_t *state, const atk_widget_t *widget, int origin_x, int origin_y, void *context)
{
    (void)context;
    if (!state || !widget || !widget->used)
    {
        return;
    }
    const atk_theme_t *theme = &state->theme;
    int x = origin_x + widget->x;
    int y = origin_y + widget->y;
    video_draw_rect(x, y, widget->width, widget->height, theme->window_body);
    cp_pane_priv_t *priv = (cp_pane_priv_t *)atk_widget_priv(widget, &CP_PANE_CLASS);
    if (!priv)
    {
        return;
    }

    if (priv->layout_dirty || priv->last_width != widget->width || priv->last_height != widget->height)
    {
        cp_pane_layout(priv, (atk_widget_t *)widget);
    }

    int content_x = x + CP_PANE_PADDING;
    int content_y = y + CP_PANE_PADDING;
    int content_w = widget->width - CP_PANE_PADDING * 2;
    int content_h = widget->height - CP_PANE_PADDING * 2;
    if (content_w < 0) content_w = 0;
    if (content_h < 0) content_h = 0;

    cp_draw_body_text(state, priv, content_x, content_y, content_w, content_h);

    if (priv->open_button && priv->open_button->used)
    {
        atk_widget_draw_any(state, priv->open_button);
    }
}

static bool cp_pane_hit(const atk_widget_t *widget,
                        int origin_x,
                        int origin_y,
                        int px,
                        int py,
                        void *context)
{
    (void)context;
    if (!widget || !widget->used)
    {
        return false;
    }
    int x0 = origin_x + widget->x;
    int y0 = origin_y + widget->y;
    int x1 = x0 + widget->width;
    int y1 = y0 + widget->height;
    return (px >= x0 && px < x1 && py >= y0 && py < y1);
}

static atk_mouse_response_t cp_dispatch_mouse_to_child(atk_widget_t *child,
                                                       const atk_mouse_event_t *event)
{
    if (!child || !child->used || !event)
    {
        return ATK_MOUSE_RESPONSE_NONE;
    }

    atk_mouse_event_t ev = *event;
    int abs_x = 0, abs_y = 0;
    atk_widget_absolute_position(child, &abs_x, &abs_y);
    ev.origin_x = abs_x - child->x;
    ev.origin_y = abs_y - child->y;
    ev.local_x = event->cursor_x - abs_x;
    ev.local_y = event->cursor_y - abs_y;
    return atk_widget_dispatch_mouse(child, &ev);
}

static atk_mouse_response_t cp_pane_mouse(atk_widget_t *widget,
                                          const atk_mouse_event_t *event,
                                          void *context)
{
    (void)context;
    cp_pane_priv_t *priv = (cp_pane_priv_t *)atk_widget_priv(widget, &CP_PANE_CLASS);
    if (!priv || !event)
    {
        return ATK_MOUSE_RESPONSE_NONE;
    }
    if (priv->open_button && priv->open_button->used)
    {
        int origin_x = 0;
        int origin_y = 0;
        atk_widget_absolute_position(widget, &origin_x, &origin_y);
        if (atk_button_hit_test(priv->open_button, origin_x, origin_y, event->cursor_x, event->cursor_y))
        {
            return cp_dispatch_mouse_to_child(priv->open_button, event);
        }
    }
    return ATK_MOUSE_RESPONSE_NONE;
}

static void cp_pane_destroy(atk_widget_t *widget, void *context)
{
    (void)context;
    if (!widget)
    {
        return;
    }
    cp_pane_priv_t *priv = (cp_pane_priv_t *)atk_widget_priv(widget, &CP_PANE_CLASS);
    if (priv)
    {
        if (priv->body_text)
        {
            free(priv->body_text);
            priv->body_text = NULL;
        }
        if (priv->open_button)
        {
            atk_widget_destroy_any(priv->open_button);
            priv->open_button = NULL;
        }
        if (priv->app && priv->app->display_pane == widget)
        {
            priv->app->display_pane = NULL;
        }
    }
    atk_widget_destroy(widget);
}

static void cp_log(const char *msg)
{
    if (msg)
    {
        serial_printf("%s", msg);
    }
}

static void cp_apply_theme(atk_state_t *state)
{
    if (!state)
    {
        return;
    }

    state->theme.background = video_make_color(0x25, 0x2E, 0x38);
    state->theme.window_border = video_make_color(0x1A, 0x1F, 0x26);
    state->theme.window_title = video_make_color(0x35, 0x55, 0x86);
    state->theme.window_title_text = video_make_color(0xF3, 0xF6, 0xFA);
    state->theme.window_body = video_make_color(0xD8, 0xDB, 0xE0);
    state->theme.button_face = video_make_color(0x4A, 0x6B, 0x9A);
    state->theme.button_border = video_make_color(0x21, 0x2B, 0x38);
    state->theme.button_text = video_make_color(0xF5, 0xF7, 0xFB);
    state->theme.desktop_icon_face = video_make_color(0x56, 0x79, 0xA8);
    state->theme.desktop_icon_text = video_make_color(0x00, 0x00, 0x00);
    state->theme.menu_bar_face = video_make_color(0x1F, 0x27, 0x33);
    state->theme.menu_bar_text = video_make_color(0xEC, 0xEF, 0xF1);
    state->theme.menu_bar_highlight = video_make_color(0x2F, 0x3C, 0x4F);
    state->theme.menu_dropdown_face = video_make_color(0xF2, 0xF4, 0xF7);
    state->theme.menu_dropdown_border = video_make_color(0x2B, 0x31, 0x3B);
    state->theme.menu_dropdown_text = video_make_color(0x18, 0x1E, 0x26);
    state->theme.menu_dropdown_highlight = video_make_color(0x3C, 0x52, 0x75);
    atk_state_theme_commit(state);
}

static void cp_render(control_panel_app_t *app)
{
    if (!app)
    {
        return;
    }
    atk_render();
    atk_user_present_force(&app->remote);
}

static void cp_layout(control_panel_app_t *app)
{
    if (!app || !app->window || !app->nav)
    {
        return;
    }

    int chrome_top = atk_window_is_chrome_visible(app->window) ? ATK_WINDOW_TITLE_HEIGHT : 0;
    atk_layout_t layout;
    atk_layout_init(&layout,
                    0,
                    chrome_top,
                    app->window->width,
                    app->window->height - chrome_top);
    atk_layout_set_padding(&layout, 18, 18, 18, 18);
    atk_layout_region_t content = atk_layout_content(&layout);

    app->nav->x = content.x;
    app->nav->y = content.y;
    app->nav->width = content.width;
    app->nav->height = content.height;
    atk_nav_stack_relayout(app->nav);
}

static void cp_icon_action(atk_widget_t *button, void *context)
{
    (void)button;
    cp_icon_ctx_t *ctx = (cp_icon_ctx_t *)context;
    if (!ctx || !ctx->app || !ctx->app->nav)
    {
        return;
    }
    const char *label = ctx->title ? ctx->title : "Details";
    atk_widget_t *pane = cp_create_pane(ctx->app, label, ctx->kind);
    if (!pane)
    {
        return;
    }
    atk_nav_stack_push(ctx->app->nav, pane, label);
    atk_window_mark_dirty(ctx->app->window);
}

static bool cp_init_ui(control_panel_app_t *app)
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

    atk_menu_bar_set_enabled(state, false);
    cp_apply_theme(state);

    atk_widget_t *window = atk_window_create_at(state, CP_WINDOW_WIDTH / 2, CP_WINDOW_HEIGHT / 2);
    if (!window)
    {
        return false;
    }

    atk_window_set_chrome_visible(window, false);
    window->x = 0;
    window->y = 0;
    window->width = CP_WINDOW_WIDTH;
    window->height = CP_WINDOW_HEIGHT;
    atk_window_set_title_text(window, "Control Panel");
    atk_window_ensure_inside(window);

    atk_widget_t *nav = atk_window_add_nav_stack(window,
                                                 0,
                                                 ATK_WINDOW_TITLE_HEIGHT,
                                                 window->width,
                                                 window->height - ATK_WINDOW_TITLE_HEIGHT);
    if (!nav)
    {
        atk_window_close(state, window);
        return false;
    }

    atk_widget_t *iconbox = atk_window_add_iconbox(window,
                                                   0,
                                                   ATK_WINDOW_TITLE_HEIGHT,
                                                   window->width,
                                                   window->height - ATK_WINDOW_TITLE_HEIGHT);
    if (!iconbox)
    {
        atk_window_close(state, window);
        return false;
    }
    atk_nav_stack_push_owned(nav, iconbox, "Home", false);

    app->hw_ctx.app = app;
    app->hw_ctx.title = "Hardware Info";
    app->hw_ctx.kind = CP_PANE_KIND_HW;
    app->net_ctx.app = app;
    app->net_ctx.title = "Network Info";
    app->net_ctx.kind = CP_PANE_KIND_NET;
    app->display_ctx.app = app;
    app->display_ctx.title = "Display";
    app->display_ctx.kind = CP_PANE_KIND_DISPLAY;

    if (!atk_iconbox_add_icon(iconbox, "Display", cp_icon_action, &app->display_ctx) ||
        !atk_iconbox_add_icon(iconbox, "Hardware Info", cp_icon_action, &app->hw_ctx) ||
        !atk_iconbox_add_icon(iconbox, "Network Info", cp_icon_action, &app->net_ctx))
    {
        atk_window_close(state, window);
        return false;
    }

    app->nav = nav;
    app->window = window;
    app->iconbox = iconbox;
    cp_layout(app);
    atk_window_mark_dirty(window);
    return true;
}

static void cp_handle_resize(control_panel_app_t *app, uint32_t width, uint32_t height)
{
    if (!app || !app->window)
    {
        return;
    }

    app->window->width = (int)width;
    app->window->height = (int)height;
    atk_window_request_layout(app->window);
    cp_layout(app);
}

static bool cp_on_resize_event(uint32_t width, uint32_t height, void *context)
{
    cp_handle_resize((control_panel_app_t *)context, width, height);
    return true;
}

static void cp_on_close_event(void *context)
{
    control_panel_app_t *app = (control_panel_app_t *)context;
    if (app)
    {
        app->running = false;
    }
    atk_main_request_exit();
}

static bool cp_on_tick(void *context)
{
    control_panel_app_t *app = (control_panel_app_t *)context;
    if (!app)
    {
        return false;
    }
    bool sliding = app->nav && atk_nav_stack_sliding(app->nav);
    if (sliding && app->window)
    {
        atk_window_mark_dirty(app->window);
    }
    return sliding;
}

int main(void)
{
    control_panel_app_t app;
    memset(&app, 0, sizeof(app));
    app.shell_handle = sys_shell_open();
    app.running = true;

    if (!atk_user_window_open_with_flags(&app.remote,
                                         "Control Panel",
                                         CP_WINDOW_WIDTH,
                                         CP_WINDOW_HEIGHT,
                                         USER_ATK_WINDOW_FLAG_RESIZABLE))
    {
        cp_log("[cp] failed to open remote window");
        if (app.shell_handle >= 0)
        {
            sys_shell_close(app.shell_handle);
        }
        return 1;
    }
    atk_user_enable_dirty_tracking(&app.remote, true);

    if (!cp_init_ui(&app))
    {
        cp_log("[cp] ui init failed");
        atk_user_close(&app.remote);
        if (app.shell_handle >= 0)
        {
            sys_shell_close(app.shell_handle);
        }
        return 1;
    }

    cp_render(&app);

    atk_main_config_t main_cfg = {
        .window = &app.remote,
        .tick = cp_on_tick,
        .tick_context = &app,
        .present_on_idle = false,
        .legacy_input = false
    };

    atk_main_register_resize_handler(cp_on_resize_event, &app);
    atk_main_register_close_handler(cp_on_close_event, &app);

    atk_main(&main_cfg);

    cp_close_file_dialog(&app);
    atk_user_close(&app.remote);
    if (app.shell_handle >= 0)
    {
        sys_shell_close(app.shell_handle);
    }
    return 0;
}
