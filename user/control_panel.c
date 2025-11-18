#include "atk_user.h"

#include "atk.h"
#include "atk_internal.h"
#include "atk_window.h"
#include "atk/layout.h"
#include "atk/atk_list_view.h"
#include "atk_menu_bar.h"
#include "serial.h"
#include "libc.h"
#include "video.h"
#include "syscall_defs.h"
#include "usyscall.h"
#include "user_atk_defs.h"

#define CP_COL(chars) ((chars) * ATK_FONT_WIDTH)
#define CP_KV_MAX     32
#define CP_BUF_SMALL  256
#define CP_BUF_MEDIUM 768
#define CP_BUF_LARGE  1536
#define CP_REFRESH_TICKS 120

static void cp_log(const char *msg)
{
    if (!msg)
    {
        return;
    }
    serial_printf("%s", "[cp] ");
    serial_printf("%s", msg);
    serial_printf("%s", "\r\n");
}

typedef struct
{
    char key[32];
    char value[96];
} cp_kv_t;

typedef struct
{
    atk_user_window_t remote;
    atk_widget_t *window;
    atk_widget_t *home_tile;
    atk_widget_t *back_button;
    atk_widget_t *summary_list;
    atk_widget_t *block_list;
    atk_widget_t *net_list;
    atk_widget_t *pci_list;
    bool running;
    bool refresh_pending;
    uint32_t refresh_counter;
    bool showing_info;
    bool layout_dirty;
} control_panel_app_t;

static void cp_apply_theme(atk_state_t *state)
{
    state->theme.background = video_make_color(0x15, 0x1C, 0x27);
    state->theme.window_border = video_make_color(0x32, 0x32, 0x32);
    state->theme.window_title = video_make_color(0x45, 0x70, 0xB2);
    state->theme.window_title_text = video_make_color(0xFF, 0xFF, 0xFF);
    state->theme.window_body = video_make_color(0xF2, 0xF2, 0xF2);
    state->theme.button_face = video_make_color(0x58, 0x7A, 0xB8);
    state->theme.button_border = video_make_color(0x1F, 0x2A, 0x3B);
    state->theme.button_text = video_make_color(0xFF, 0xFF, 0xFF);
    state->theme.desktop_icon_face = video_make_color(0x58, 0x7A, 0xB8);
    state->theme.desktop_icon_text = state->theme.window_title_text;
}

static void cp_copy_string(char *dst, size_t dst_len, const char *src)
{
    if (!dst || dst_len == 0)
    {
        return;
    }
    if (!src)
    {
        dst[0] = '\0';
        return;
    }
    size_t len = strlen(src);
    if (len >= dst_len)
    {
        len = dst_len - 1;
    }
    memcpy(dst, src, len);
    dst[len] = '\0';
}

static void cp_trim_trailing(char *str)
{
    if (!str)
    {
        return;
    }
    size_t len = strlen(str);
    while (len > 0)
    {
        char c = str[len - 1];
        if (c == '\n' || c == '\r' || c == ' ' || c == '\t')
        {
            str[len - 1] = '\0';
            --len;
        }
        else
        {
            break;
        }
    }
}

static const char *cp_find_char(const char *text, char ch)
{
    if (!text)
    {
        return NULL;
    }
    while (*text)
    {
        if (*text == ch)
        {
            return text;
        }
        ++text;
    }
    return NULL;
}

static const char *cp_find_substring(const char *haystack, const char *needle)
{
    if (!haystack || !needle || *needle == '\0')
    {
        return NULL;
    }
    size_t needle_len = strlen(needle);
    const char *cursor = haystack;
    while (*cursor)
    {
        if (strncmp(cursor, needle, needle_len) == 0)
        {
            return cursor;
        }
        ++cursor;
    }
    return NULL;
}

static void cp_format_u32(uint32_t value, char *out, size_t len)
{
    if (!out || len == 0)
    {
        return;
    }
    char tmp[16];
    size_t pos = 0;
    do
    {
        tmp[pos++] = (char)('0' + (value % 10U));
        value /= 10U;
    } while (value != 0 && pos < sizeof(tmp));

    size_t out_pos = 0;
    while (pos > 0 && out_pos + 1 < len)
    {
        out[out_pos++] = tmp[--pos];
    }
    out[out_pos] = '\0';
}

static uint32_t cp_parse_u32(const char *text)
{
    if (!text)
    {
        return 0;
    }
    uint32_t value = 0;
    while (*text >= '0' && *text <= '9')
    {
        value = value * 10U + (uint32_t)(*text - '0');
        ++text;
    }
    return value;
}

static void cp_format_bdf(char *out, size_t len, uint32_t bus, uint32_t dev, uint32_t func)
{
    if (!out || len == 0)
    {
        return;
    }
    char bus_s[12];
    char dev_s[12];
    char func_s[12];
    cp_format_u32(bus, bus_s, sizeof(bus_s));
    cp_format_u32(dev, dev_s, sizeof(dev_s));
    cp_format_u32(func, func_s, sizeof(func_s));

    size_t pos = 0;
    const char *parts[] = { bus_s, ":", dev_s, ".", func_s };
    for (size_t i = 0; i < sizeof(parts) / sizeof(parts[0]); ++i)
    {
        const char *p = parts[i];
        while (*p && pos + 1 < len)
        {
            out[pos++] = *p++;
        }
        if (pos + 1 >= len)
        {
            break;
        }
    }
    out[pos] = '\0';
}

static ssize_t cp_read_file(const char *path, char *buffer, size_t capacity)
{
    if (!path || !buffer || capacity == 0)
    {
        return -1;
    }

    int fd = open(path, SYSCALL_OPEN_READ);
    if (fd < 0)
    {
        buffer[0] = '\0';
        serial_printf("%s", "[cp] open failed ");
        serial_printf("%s", path ? path : "<null>");
        serial_printf("%s", "\r\n");
        return -1;
    }

    size_t total = 0;
    while (total + 1 < capacity)
    {
        ssize_t read_bytes = read(fd, buffer + total, capacity - 1 - total);
        if (read_bytes <= 0)
        {
            break;
        }
        total += (size_t)read_bytes;
    }
    buffer[total] = '\0';
    close(fd);
    serial_printf("%s", "[cp] read ");
    serial_printf("%s", path ? path : "<null>");
    serial_printf("%s", " -> ");
    serial_printf("%016llX", (unsigned long long)total);
    serial_printf("%s", " bytes\r\n");
    return (ssize_t)total;
}

static void cp_collect_kv_lines(const char *text, const char *section, cp_kv_t *entries, size_t *count, size_t capacity)
{
    if (!entries || !count || *count >= capacity)
    {
        return;
    }
    size_t idx = *count;
    if (section && section[0] != '\0')
    {
        cp_copy_string(entries[idx].key, sizeof(entries[idx].key), section);
        entries[idx].value[0] = '\0';
        ++idx;
    }

    const char *cursor = text;
    while (cursor && *cursor && idx < capacity)
    {
        const char *line_end = cursor;
        while (*line_end && *line_end != '\n')
        {
            ++line_end;
        }
        size_t line_len = (size_t)(line_end - cursor);
        if (line_len > 0)
        {
            char line[CP_BUF_SMALL];
            size_t copy_len = (line_len >= sizeof(line)) ? (sizeof(line) - 1) : line_len;
            memcpy(line, cursor, copy_len);
            line[copy_len] = '\0';
            const char *sep_const = cp_find_char(line, ':');
            if (sep_const && sep_const != line)
            {
                char *sep = (char *)sep_const;
                *sep = '\0';
                cp_trim_trailing(line);
                char *value = sep + 1;
                while (*value == ' ')
                {
                    ++value;
                }
                cp_trim_trailing(value);
                cp_copy_string(entries[idx].key, sizeof(entries[idx].key), line);
                cp_copy_string(entries[idx].value, sizeof(entries[idx].value), value);
                ++idx;
            }
        }
        cursor = (*line_end == '\0') ? line_end : line_end + 1;
    }
    *count = idx;
}

static const char *cp_next_token(const char *cursor, char *key_out, size_t key_len, char *value_out, size_t value_len)
{
    if (!cursor || !key_out || !value_out || key_len == 0 || value_len == 0)
    {
        return NULL;
    }
    while (*cursor == ' ' || *cursor == '\t')
    {
        ++cursor;
    }
    if (*cursor == '\0' || *cursor == '\n' || *cursor == '\r')
    {
        return NULL;
    }

    const char *eq = cp_find_char(cursor, '=');
    if (!eq)
    {
        return NULL;
    }
    size_t klen = (size_t)(eq - cursor);
    if (klen >= key_len)
    {
        klen = key_len - 1;
    }
    memcpy(key_out, cursor, klen);
    key_out[klen] = '\0';

    const char *end = eq + 1;
    while (*end && *end != ' ' && *end != '\n' && *end != '\r')
    {
        ++end;
    }
    size_t vlen = (size_t)(end - (eq + 1));
    if (vlen >= value_len)
    {
        vlen = value_len - 1;
    }
    memcpy(value_out, eq + 1, vlen);
    value_out[vlen] = '\0';
    return end;
}

static bool cp_extract_tail(const char *line, const char *key, char *out, size_t out_len)
{
    if (!line || !key || !out || out_len == 0)
    {
        return false;
    }
    const char *start = cp_find_substring(line, key);
    if (!start)
    {
        return false;
    }
    start += strlen(key);
    if (*start != '=')
    {
        return false;
    }
    start++;
    while (*start == ' ')
    {
        ++start;
    }
    size_t len = strlen(start);
    while (len > 0 && (start[len - 1] == '\n' || start[len - 1] == '\r'))
    {
        --len;
    }
    if (len >= out_len)
    {
        len = out_len - 1;
    }
    memcpy(out, start, len);
    out[len] = '\0';
    return true;
}

static void cp_set_kv_list(atk_widget_t *list, const cp_kv_t *entries, size_t count)
{
    if (!list)
    {
        return;
    }
    atk_list_view_set_row_count(list, count);
    for (size_t i = 0; i < count; ++i)
    {
        atk_list_view_set_cell_text(list, i, 0, entries[i].key);
        atk_list_view_set_cell_text(list, i, 1, entries[i].value);
    }
}

static void cp_update_summary(control_panel_app_t *app)
{
    if (!app || !app->summary_list)
    {
        return;
    }
    cp_kv_t entries[CP_KV_MAX];
    size_t count = 0;

    char buffer[CP_BUF_SMALL];
    ssize_t len = cp_read_file("/proc/devices/cpu/info", buffer, sizeof(buffer));
    if (len > 0)
    {
        cp_collect_kv_lines(buffer, "CPU", entries, &count, CP_KV_MAX);
    }
    len = cp_read_file("/proc/devices/memory/info", buffer, sizeof(buffer));
    if (len > 0 && count < CP_KV_MAX)
    {
        cp_collect_kv_lines(buffer, "Memory", entries, &count, CP_KV_MAX);
    }

    if (count == 0)
    {
        cp_copy_string(entries[0].key, sizeof(entries[0].key), "status");
        cp_copy_string(entries[0].value, sizeof(entries[0].value), "no data");
        count = 1;
    }

    cp_set_kv_list(app->summary_list, entries, count);
    serial_printf("%s", "[cp] summary rows=");
    serial_printf("%016llX", (unsigned long long)count);
    serial_printf("%s", "\r\n");
}

static void cp_update_block(control_panel_app_t *app)
{
    if (!app || !app->block_list)
    {
        return;
    }

    atk_list_view_set_row_count(app->block_list, 0);

    char buffer[CP_BUF_SMALL];
    ssize_t len = cp_read_file("/proc/devices/block/info", buffer, sizeof(buffer));
    if (len <= 0)
    {
        atk_list_view_set_row_count(app->block_list, 1);
        atk_list_view_set_cell_text(app->block_list, 0, 0, "no data");
        serial_printf("%s", "[cp] block rows=0\r\n");
        return;
    }

    size_t rows = 0;
    const char *cursor = buffer;
    while (*cursor && rows < 16)
    {
        while (*cursor == '\n')
        {
            ++cursor;
        }
        if (*cursor == '\0')
        {
            break;
        }
        const char *line_end = cp_find_char(cursor, '\n');
        size_t line_len = line_end ? (size_t)(line_end - cursor) : strlen(cursor);
        if (line_len > 0 && rows < 16)
        {
            char line[CP_BUF_SMALL];
            size_t copy_len = (line_len >= sizeof(line)) ? (sizeof(line) - 1) : line_len;
            memcpy(line, cursor, copy_len);
            line[copy_len] = '\0';

            if (strcmp(line, "(none)") == 0)
            {
                break;
            }

            char key_buf[32];
            char val_buf[64];
            char name[32] = {0};
            char size_mib[24] = {0};
            char sector_size[24] = {0};
            char sector_count[32] = {0};

            const char *tok_cursor = line;
            while ((tok_cursor = cp_next_token(tok_cursor, key_buf, sizeof(key_buf), val_buf, sizeof(val_buf))) != NULL)
            {
                if (strcmp(key_buf, "name") == 0)
                {
                    cp_copy_string(name, sizeof(name), val_buf);
                }
                else if (strcmp(key_buf, "size_mib") == 0)
                {
                    cp_copy_string(size_mib, sizeof(size_mib), val_buf);
                }
                else if (strcmp(key_buf, "sector_size") == 0)
                {
                    cp_copy_string(sector_size, sizeof(sector_size), val_buf);
                }
                else if (strcmp(key_buf, "sector_count") == 0)
                {
                    cp_copy_string(sector_count, sizeof(sector_count), val_buf);
                }
            }

            atk_list_view_set_row_count(app->block_list, rows + 1);
            atk_list_view_set_cell_text(app->block_list, rows, 0, name);
            atk_list_view_set_cell_text(app->block_list, rows, 1, size_mib);
            atk_list_view_set_cell_text(app->block_list, rows, 2, sector_size);
            atk_list_view_set_cell_text(app->block_list, rows, 3, sector_count);
            ++rows;
        }
        cursor = line_end ? line_end + 1 : cursor + line_len;
    }
    serial_printf("%s", "[cp] block rows=");
    serial_printf("%016llX", (unsigned long long)rows);
    serial_printf("%s", "\r\n");
}

static void cp_update_net(control_panel_app_t *app)
{
    if (!app || !app->net_list)
    {
        return;
    }
    atk_list_view_set_row_count(app->net_list, 0);

    char buffer[CP_BUF_LARGE];
    ssize_t len = cp_read_file("/proc/devices/net/info", buffer, sizeof(buffer));
    if (len <= 0)
    {
        atk_list_view_set_row_count(app->net_list, 1);
        atk_list_view_set_cell_text(app->net_list, 0, 0, "no data");
        serial_printf("%s", "[cp] net rows=0\r\n");
        return;
    }

    size_t rows = 0;
    const char *cursor = buffer;
    while (*cursor && rows < 16)
    {
        while (*cursor == '\n')
        {
            ++cursor;
        }
        if (*cursor == '\0')
        {
            break;
        }
        const char *line_end = cp_find_char(cursor, '\n');
        size_t line_len = line_end ? (size_t)(line_end - cursor) : strlen(cursor);
        if (line_len > 0 && rows < 16)
        {
            char line[CP_BUF_MEDIUM];
            size_t copy_len = (line_len >= sizeof(line)) ? (sizeof(line) - 1) : line_len;
            memcpy(line, cursor, copy_len);
            line[copy_len] = '\0';

            if (strcmp(line, "(none)") == 0)
            {
                break;
            }

            char key_buf[32];
            char val_buf[64];
            char name[32] = {0};
            char link[8] = {0};
            char mac[24] = {0};
            char ipv4[24] = {0};
            char rx_bytes[32] = {0};
            char tx_bytes[32] = {0};

            const char *tok_cursor = line;
            while ((tok_cursor = cp_next_token(tok_cursor, key_buf, sizeof(key_buf), val_buf, sizeof(val_buf))) != NULL)
            {
                if (strcmp(key_buf, "name") == 0)
                {
                    cp_copy_string(name, sizeof(name), val_buf);
                }
                else if (strcmp(key_buf, "link_up") == 0)
                {
                    cp_copy_string(link, sizeof(link), strcmp(val_buf, "1") == 0 ? "up" : "down");
                }
                else if (strcmp(key_buf, "mac") == 0)
                {
                    cp_copy_string(mac, sizeof(mac), val_buf);
                }
                else if (strcmp(key_buf, "ipv4") == 0)
                {
                    cp_copy_string(ipv4, sizeof(ipv4), val_buf);
                }
                else if (strcmp(key_buf, "rx_bytes") == 0)
                {
                    cp_copy_string(rx_bytes, sizeof(rx_bytes), val_buf);
                }
                else if (strcmp(key_buf, "tx_bytes") == 0)
                {
                    cp_copy_string(tx_bytes, sizeof(tx_bytes), val_buf);
                }
            }

            atk_list_view_set_row_count(app->net_list, rows + 1);
            atk_list_view_set_cell_text(app->net_list, rows, 0, name);
            atk_list_view_set_cell_text(app->net_list, rows, 1, link);
            atk_list_view_set_cell_text(app->net_list, rows, 2, mac);
            atk_list_view_set_cell_text(app->net_list, rows, 3, ipv4);
            atk_list_view_set_cell_text(app->net_list, rows, 4, rx_bytes);
            atk_list_view_set_cell_text(app->net_list, rows, 5, tx_bytes);
            ++rows;
        }
        cursor = line_end ? line_end + 1 : cursor + line_len;
    }
    serial_printf("%s", "[cp] net rows=");
    serial_printf("%016llX", (unsigned long long)rows);
    serial_printf("%s", "\r\n");
}

static void cp_update_pci(control_panel_app_t *app)
{
    if (!app || !app->pci_list)
    {
        return;
    }
    atk_list_view_set_row_count(app->pci_list, 0);

    char buffer[CP_BUF_LARGE];
    ssize_t len = cp_read_file("/proc/devices/pci/info", buffer, sizeof(buffer));
    if (len <= 0)
    {
        atk_list_view_set_row_count(app->pci_list, 1);
        atk_list_view_set_cell_text(app->pci_list, 0, 0, "no data");
        serial_printf("%s", "[cp] pci rows=0\r\n");
        return;
    }

    size_t rows = 0;
    const char *cursor = buffer;
    while (*cursor && rows < 24)
    {
        while (*cursor == '\n')
        {
            ++cursor;
        }
        if (*cursor == '\0')
        {
            break;
        }
        const char *line_end = cp_find_char(cursor, '\n');
        size_t line_len = line_end ? (size_t)(line_end - cursor) : strlen(cursor);
        if (line_len > 0 && rows < 24)
        {
            char line[CP_BUF_MEDIUM];
            size_t copy_len = (line_len >= sizeof(line)) ? (sizeof(line) - 1) : line_len;
            memcpy(line, cursor, copy_len);
            line[copy_len] = '\0';

            if (strcmp(line, "(none)") == 0)
            {
                break;
            }

            char key_buf[32];
            char val_buf[64];
            char bdf[16] = {0};
            char vendor[32] = {0};
            char device_id[16] = {0};
            char class_code[16] = {0};
            char vendor_name[64] = {0};

            const char *tok_cursor = line;
            uint32_t bus = 0, dev = 0, func = 0;

            while ((tok_cursor = cp_next_token(tok_cursor, key_buf, sizeof(key_buf), val_buf, sizeof(val_buf))) != NULL)
            {
                if (strcmp(key_buf, "bus") == 0)
                {
                    bus = cp_parse_u32(val_buf);
                }
                else if (strcmp(key_buf, "device") == 0)
                {
                    dev = cp_parse_u32(val_buf);
                }
                else if (strcmp(key_buf, "function") == 0)
                {
                    func = cp_parse_u32(val_buf);
                }
                else if (strcmp(key_buf, "vendor") == 0)
                {
                    cp_copy_string(vendor, sizeof(vendor), val_buf);
                }
                else if (strcmp(key_buf, "device_id") == 0)
                {
                    cp_copy_string(device_id, sizeof(device_id), val_buf);
                }
                else if (strcmp(key_buf, "class") == 0)
                {
                    cp_copy_string(class_code, sizeof(class_code), val_buf);
                }
            }

            if (!cp_extract_tail(line, "vendor_name", vendor_name, sizeof(vendor_name)))
            {
                vendor_name[0] = '\0';
            }

            cp_format_bdf(bdf, sizeof(bdf), bus, dev, func);

            atk_list_view_set_row_count(app->pci_list, rows + 1);
            atk_list_view_set_cell_text(app->pci_list, rows, 0, bdf);
            atk_list_view_set_cell_text(app->pci_list, rows, 1, vendor);
            atk_list_view_set_cell_text(app->pci_list, rows, 2, device_id);
            atk_list_view_set_cell_text(app->pci_list, rows, 3, class_code);
            atk_list_view_set_cell_text(app->pci_list, rows, 4, vendor_name);
            ++rows;
        }
        cursor = line_end ? line_end + 1 : cursor + line_len;
    }
    serial_printf("%s", "[cp] pci rows=");
    serial_printf("%016llX", (unsigned long long)rows);
    serial_printf("%s", "\r\n");
}

static void cp_refresh_data(control_panel_app_t *app)
{
    cp_log("refresh begin");
    cp_update_summary(app);
    cp_update_block(app);
    cp_update_net(app);
    cp_update_pci(app);
    cp_log("refresh end");
}

static void cp_render(control_panel_app_t *app)
{
    atk_render();
    atk_user_present(&app->remote);
}

static void cp_on_hardware_click(atk_widget_t *button, void *context)
{
    (void)button;
    control_panel_app_t *app = (control_panel_app_t *)context;
    if (app)
    {
        app->refresh_pending = true;
        cp_refresh_data(app);
        app->showing_info = true;
        app->layout_dirty = true;
    }
}

static void cp_on_back(atk_widget_t *button, void *context)
{
    (void)button;
    control_panel_app_t *app = (control_panel_app_t *)context;
    if (!app)
    {
        return;
    }
    app->showing_info = false;
    app->refresh_pending = false;
    app->layout_dirty = true;
}

static void cp_layout_views(control_panel_app_t *app)
{
    if (!app || !app->window)
    {
        return;
    }

    int win_w = app->window->width;
    int win_h = app->window->height;
    if (win_w < 0) win_w = 0;
    if (win_h < 0) win_h = 0;
    int chrome_top = atk_window_is_chrome_visible(app->window) ? ATK_WINDOW_TITLE_HEIGHT : 0;

    if (!app->showing_info)
    {
        /* Home view: only the tile is visible, center it. */
        if (app->home_tile)
        {
            app->home_tile->width = 128;
            app->home_tile->height = 128;
            app->home_tile->x = (win_w - app->home_tile->width) / 2;
            app->home_tile->y = (win_h - app->home_tile->height) / 2;
        }
        if (app->back_button)
        {
            app->back_button->width = 0;
            app->back_button->height = 0;
        }
        /* Hide lists. */
        atk_widget_t *lists[] = { app->summary_list, app->block_list, app->net_list, app->pci_list };
        for (size_t i = 0; i < sizeof(lists) / sizeof(lists[0]); ++i)
        {
            if (lists[i])
            {
                lists[i]->x = 0;
                lists[i]->y = 0;
                lists[i]->width = 0;
                lists[i]->height = 0;
            }
        }
        app->layout_dirty = false;
        return;
    }

    /* Info view layout. */
    if (app->home_tile)
    {
        app->home_tile->width = 0;
        app->home_tile->height = 0;
    }
    if (app->back_button)
    {
        app->back_button->x = 12;
        app->back_button->y = chrome_top + 12;
        app->back_button->width = 96;
        app->back_button->height = 32;
    }

    int content_x = 160;
    int content_y = chrome_top + 12;
    int content_w = win_w - 176;
    int content_h = win_h - chrome_top - 24;
    if (content_w < 0) content_w = 0;
    if (content_h < 0) content_h = 0;

    atk_layout_t layout;
    atk_layout_init(&layout, content_x, content_y, content_w, content_h);
    atk_layout_set_padding(&layout, 0, 0, 0, 0);

    atk_layout_region_t summary_region = atk_layout_take_top(&layout, 140, 12);
    atk_layout_region_t block_region = atk_layout_take_top(&layout, 110, 12);
    atk_layout_region_t net_region = atk_layout_take_top(&layout, 120, 12);
    atk_layout_region_t pci_region = atk_layout_content(&layout);

    if (app->summary_list)
    {
        app->summary_list->x = summary_region.x;
        app->summary_list->y = summary_region.y;
        app->summary_list->width = summary_region.width;
        app->summary_list->height = summary_region.height;
    }
    if (app->block_list)
    {
        app->block_list->x = block_region.x;
        app->block_list->y = block_region.y;
        app->block_list->width = block_region.width;
        app->block_list->height = block_region.height;
    }
    if (app->net_list)
    {
        app->net_list->x = net_region.x;
        app->net_list->y = net_region.y;
        app->net_list->width = net_region.width;
        app->net_list->height = net_region.height;
    }
    if (app->pci_list)
    {
        app->pci_list->x = pci_region.x;
        app->pci_list->y = pci_region.y;
        app->pci_list->width = pci_region.width;
        app->pci_list->height = pci_region.height;
    }
    app->layout_dirty = false;
}

static bool cp_init_ui(control_panel_app_t *app)
{
    atk_init();
    atk_state_t *state = atk_state_get();
    atk_menu_bar_set_enabled(state, false);
    cp_apply_theme(state);

    atk_widget_t *window = atk_window_create_at(state, 860, 540);
    if (!window)
    {
        return false;
    }
    atk_window_set_title_text(window, "Control Panel");
    atk_window_set_chrome_visible(window, false);
    window->x = 0;
    window->y = 0;
    window->width = 860;
    window->height = 540;

    atk_widget_t *tile = atk_window_add_button(window,
                                               "Hardware Info",
                                               0,
                                               0,
                                               128,
                                               128,
                                               ATK_BUTTON_STYLE_TITLE_BELOW,
                                               false,
                                               cp_on_hardware_click,
                                               app);
    if (!tile)
    {
        cp_log("home tile creation failed");
        return false;
    }

    int chrome_top = atk_window_is_chrome_visible(window) ? ATK_WINDOW_TITLE_HEIGHT : 0;
    atk_widget_t *back = atk_window_add_button(window,
                                               "Back",
                                               0,
                                               chrome_top + 12,
                                               96,
                                               32,
                                               ATK_BUTTON_STYLE_TITLE_INSIDE,
                                               false,
                                               cp_on_back,
                                               app);
    if (!back)
    {
        cp_log("back button creation failed");
        return false;
    }

    atk_widget_t *summary = atk_window_add_list_view(window, 0, 0, 10, 10);
    if (!summary)
    {
        cp_log("summary list creation failed");
        return false;
    }
    static const atk_list_view_column_def_t SUMMARY_COLS[] = {
        { "Item", CP_COL(18) },
        { "Value", CP_COL(32) }
    };
    atk_list_view_configure_columns(summary, SUMMARY_COLS, sizeof(SUMMARY_COLS) / sizeof(SUMMARY_COLS[0]));
    atk_widget_set_layout(summary,
                          ATK_WIDGET_ANCHOR_LEFT |
                          ATK_WIDGET_ANCHOR_TOP |
                          ATK_WIDGET_ANCHOR_RIGHT);

    atk_widget_t *block_list = atk_window_add_list_view(window, 0, 0, 10, 10);
    if (!block_list)
    {
        cp_log("block list creation failed");
        return false;
    }
    static const atk_list_view_column_def_t BLOCK_COLS[] = {
        { "Device", CP_COL(12) },
        { "Size (MiB)", CP_COL(10) },
        { "Sector", CP_COL(10) },
        { "Sectors", CP_COL(12) }
    };
    atk_list_view_configure_columns(block_list, BLOCK_COLS, sizeof(BLOCK_COLS) / sizeof(BLOCK_COLS[0]));
    atk_widget_set_layout(block_list,
                          ATK_WIDGET_ANCHOR_LEFT |
                          ATK_WIDGET_ANCHOR_TOP |
                          ATK_WIDGET_ANCHOR_RIGHT);

    atk_widget_t *net_list = atk_window_add_list_view(window, 0, 0, 10, 10);
    if (!net_list)
    {
        cp_log("net list creation failed");
        return false;
    }
    static const atk_list_view_column_def_t NET_COLS[] = {
        { "Interface", CP_COL(12) },
        { "Link", CP_COL(8) },
        { "MAC", CP_COL(16) },
        { "IPv4", CP_COL(16) },
        { "RX bytes", CP_COL(14) },
        { "TX bytes", CP_COL(14) }
    };
    atk_list_view_configure_columns(net_list, NET_COLS, sizeof(NET_COLS) / sizeof(NET_COLS[0]));
    atk_widget_set_layout(net_list,
                          ATK_WIDGET_ANCHOR_LEFT |
                          ATK_WIDGET_ANCHOR_TOP |
                          ATK_WIDGET_ANCHOR_RIGHT);

    atk_widget_t *pci_list = atk_window_add_list_view(window, 0, 0, 10, 10);
    if (!pci_list)
    {
        cp_log("pci list creation failed");
        return false;
    }
    static const atk_list_view_column_def_t PCI_COLS[] = {
        { "BDF", CP_COL(10) },
        { "Vendor", CP_COL(10) },
        { "Device", CP_COL(10) },
        { "Class", CP_COL(10) },
        { "Vendor Name", CP_COL(24) }
    };
    atk_list_view_configure_columns(pci_list, PCI_COLS, sizeof(PCI_COLS) / sizeof(PCI_COLS[0]));
    atk_widget_set_layout(pci_list,
                          ATK_WIDGET_ANCHOR_LEFT |
                          ATK_WIDGET_ANCHOR_TOP |
                          ATK_WIDGET_ANCHOR_RIGHT |
                          ATK_WIDGET_ANCHOR_BOTTOM);

    app->window = window;
    app->home_tile = tile;
    app->back_button = back;
    app->summary_list = summary;
    app->block_list = block_list;
    app->net_list = net_list;
    app->pci_list = pci_list;
    app->showing_info = true;
    app->refresh_pending = true;
    app->layout_dirty = true;
    cp_layout_views(app);
    cp_log("init_ui ok");
    return true;
}

static void cp_handle_mouse(const user_atk_event_t *event, bool *needs_render)
{
    if (!event)
    {
        return;
    }
    atk_mouse_event_result_t result = atk_handle_mouse_event(event->x,
                                                             event->y,
                                                             (event->flags & USER_ATK_MOUSE_FLAG_PRESS) != 0,
                                                             (event->flags & USER_ATK_MOUSE_FLAG_RELEASE) != 0,
                                                             (event->flags & USER_ATK_MOUSE_FLAG_LEFT) != 0);
    if (result.redraw)
    {
        *needs_render = true;
    }
}

static void cp_handle_key(const user_atk_event_t *event, bool *needs_render)
{
    atk_key_event_result_t result = atk_handle_key_char((char)event->data0);
    if (result.redraw)
    {
        *needs_render = true;
    }
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
    cp_layout_views(app);
}

int main(void)
{
    control_panel_app_t app;
    memset(&app, 0, sizeof(app));
    app.running = true;

    if (!atk_user_window_open_with_flags(&app.remote,
                                         "Control Panel",
                                         860,
                                         540,
                                         USER_ATK_WINDOW_FLAG_RESIZABLE))
    {
        cp_log("failed to open remote window");
        return 1;
    }
    atk_user_enable_dirty_tracking(&app.remote, true);

    if (!cp_init_ui(&app))
    {
        cp_log("failed to init UI");
        atk_user_close(&app.remote);
        return 1;
    }

    cp_layout_views(&app);
    cp_refresh_data(&app);
    cp_render(&app);

    while (app.running)
    {
        if (app.layout_dirty)
        {
            cp_layout_views(&app);
        }
        bool needs_render = false;
        user_atk_event_t event;
        while (atk_user_poll_event(&app.remote, &event))
        {
            switch (event.type)
            {
                case USER_ATK_EVENT_MOUSE:
                    cp_handle_mouse(&event, &needs_render);
                    break;
                case USER_ATK_EVENT_KEY:
                    cp_handle_key(&event, &needs_render);
                    break;
                case USER_ATK_EVENT_CLOSE:
                    app.running = false;
                    break;
                case USER_ATK_EVENT_RESIZE:
                    cp_handle_resize(&app, (uint32_t)event.data0, (uint32_t)event.data1);
                    needs_render = true;
                    break;
                default:
                    break;
            }
        }

        if (!app.running)
        {
            break;
        }

        if (app.layout_dirty)
        {
            cp_layout_views(&app);
            needs_render = true;
        }

        if (app.refresh_pending)
        {
            cp_refresh_data(&app);
            needs_render = true;
            app.refresh_pending = false;
        }

        if (needs_render)
        {
            cp_render(&app);
        }

        sys_yield();
    }

    atk_user_close(&app.remote);
    return 0;
}
