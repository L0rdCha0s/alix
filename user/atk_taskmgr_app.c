#include "atk_user.h"

#include "atk.h"
#include "atk_internal.h"
#include "atk_menu_bar.h"
#include "atk_window.h"
#include "atk/layout.h"
#include "atk/atk_tabs.h"
#include "atk/atk_list_view.h"
#include "libc.h"
#include "video.h"
#include "usyscall.h"
#include "user_atk_defs.h"

#define ATK_COL(chars) ((chars) * ATK_FONT_WIDTH)

#define TASKMGR_PROCESS_CAP 64
#define TASKMGR_CPU_CAP     SYSCALL_CPU_MAX
#define TASKMGR_NET_CAP     8
#define TASKMGR_REFRESH_MS 5000
#define TASKMGR_WINDOW_WIDTH  800
#define TASKMGR_WINDOW_HEIGHT 600

typedef struct
{
    atk_user_window_t remote;
    atk_widget_t *window;
    atk_widget_t *tab_view;
    atk_widget_t *cpu_list;
    atk_widget_t *process_list;
    atk_widget_t *memory_list;
    atk_widget_t *network_list;
    bool running;
    uint64_t last_refresh_ms;
    uint64_t last_render_ms;
} atk_taskmgr_app_t;

typedef struct
{
    char name[SYSCALL_NET_IF_NAME_MAX];
    uint64_t last_rx_bytes;
    uint64_t last_tx_bytes;
} taskmgr_net_history_t;

typedef struct
{
    uint32_t cpu_index;
    uint64_t last_total_ticks;
    uint64_t last_idle_ticks;
    bool valid;
} taskmgr_cpu_history_t;

typedef struct
{
    uint64_t pid;
    uint64_t last_runtime_ticks;
    bool valid;
} taskmgr_proc_history_t;

static taskmgr_net_history_t g_net_history[TASKMGR_NET_CAP];
static taskmgr_cpu_history_t g_cpu_history[TASKMGR_CPU_CAP];
static taskmgr_proc_history_t g_proc_history[TASKMGR_PROCESS_CAP];

static const char *process_state_name(uint32_t state)
{
    switch (state)
    {
        case SYSCALL_PROCESS_STATE_READY:   return "ready";
        case SYSCALL_PROCESS_STATE_RUNNING: return "running";
        case SYSCALL_PROCESS_STATE_ZOMBIE:  return "zombie";
    }
    return "unknown";
}

static const char *thread_state_name(uint32_t state)
{
    switch (state)
    {
        case SYSCALL_THREAD_STATE_READY:   return "ready";
        case SYSCALL_THREAD_STATE_RUNNING: return "running";
        case SYSCALL_THREAD_STATE_BLOCKED: return "blocked";
        case SYSCALL_THREAD_STATE_ZOMBIE:  return "zombie";
    }
    return "unknown";
}

static void taskmgr_apply_theme(atk_state_t *state)
{
    state->theme.background = video_make_color(0x18, 0x1C, 0x24);
    state->theme.window_border = video_make_color(0x33, 0x33, 0x33);
    state->theme.window_title = video_make_color(0x55, 0x77, 0xAA);
    state->theme.window_title_text = video_make_color(0xFF, 0xFF, 0xFF);
    state->theme.window_body = video_make_color(0x0F, 0x12, 0x18);
    state->theme.button_face = video_make_color(0x2A, 0x3A, 0x52);
    state->theme.button_border = video_make_color(0x10, 0x10, 0x10);
    state->theme.button_text = video_make_color(0xEE, 0xEE, 0xEE);
    state->theme.desktop_icon_face = video_make_color(0x44, 0x66, 0x99);
    state->theme.desktop_icon_text = state->theme.window_title_text;
}

static void taskmgr_copy_string(char *dst, size_t len, const char *src)
{
    if (!dst || len == 0)
    {
        return;
    }
    size_t i = 0;
    if (src)
    {
        while (src[i] != '\0' && i + 1 < len)
        {
            dst[i] = src[i];
            ++i;
        }
    }
    dst[i] = '\0';
}

static void taskmgr_format_u64(uint64_t value, char *buffer, size_t len)
{
    if (!buffer || len == 0)
    {
        return;
    }
    char tmp[32];
    size_t pos = 0;
    do
    {
        tmp[pos++] = (char)('0' + (value % 10ULL));
        value /= 10ULL;
    } while (value != 0 && pos < sizeof(tmp));

    size_t out = 0;
    while (out < pos && out + 1 < len)
    {
        buffer[out] = tmp[pos - 1 - out];
        ++out;
    }
    buffer[out] = '\0';
}

static void taskmgr_format_bytes(uint64_t value, char *buffer, size_t len)
{
    static const char *suffixes[] = { "B", "KB", "MB", "GB", "TB" };
    size_t suffix = 0;
    uint64_t scaled = value;
    uint64_t remainder = 0;
    while (scaled >= 1024ULL && suffix < (sizeof(suffixes) / sizeof(suffixes[0])) - 1)
    {
        remainder = scaled % 1024ULL;
        scaled /= 1024ULL;
        ++suffix;
    }

    taskmgr_format_u64(scaled, buffer, len);
    uint64_t tenths = 0;
    if (suffix != 0 && scaled < 100)
    {
        tenths = (remainder * 10ULL) / 1024ULL;
    }
    if (tenths > 0)
    {
        size_t used = strlen(buffer);
        if (used + 2 < len)
        {
            buffer[used++] = '.';
            buffer[used++] = (char)('0' + (tenths % 10ULL));
            buffer[used] = '\0';
        }
    }

    size_t used = strlen(buffer);
    if (used + 2 < len)
    {
        buffer[used++] = ' ';
        const char *unit = suffixes[suffix];
        while (*unit && used + 1 < len)
        {
            buffer[used++] = *unit++;
        }
        buffer[used] = '\0';
    }
}

static void taskmgr_format_percent(uint32_t value, char *buffer, size_t len)
{
    if (!buffer || len == 0)
    {
        return;
    }
    taskmgr_format_u64((uint64_t)value, buffer, len);
    size_t used = strlen(buffer);
    if (used + 1 < len)
    {
        buffer[used++] = '%';
        buffer[used] = '\0';
    }
}

static uint32_t taskmgr_percent_of_total(uint64_t numerator, uint64_t denominator, uint32_t cap)
{
    if (denominator == 0)
    {
        return 0;
    }

    uint64_t limit = (uint64_t)(~(uint64_t)0);
    uint64_t scaled = numerator;
    if (scaled > limit / 100ULL)
    {
        scaled = limit;
    }
    else
    {
        scaled *= 100ULL;
    }

    uint64_t value = scaled / denominator;
    if (value > cap)
    {
        value = cap;
    }
    return (uint32_t)value;
}

static taskmgr_net_history_t *taskmgr_history_slot(const char *name)
{
    taskmgr_net_history_t *empty = NULL;
    for (size_t i = 0; i < TASKMGR_NET_CAP; ++i)
    {
        taskmgr_net_history_t *hist = &g_net_history[i];
        if (hist->name[0] == '\0')
        {
            if (!empty)
            {
                empty = hist;
            }
            continue;
        }
        if (strcmp(hist->name, name) == 0)
        {
            return hist;
        }
    }
    if (empty)
    {
        taskmgr_copy_string(empty->name, sizeof(empty->name), name);
        empty->last_rx_bytes = 0;
        empty->last_tx_bytes = 0;
        return empty;
    }
    return &g_net_history[0];
}

static taskmgr_cpu_history_t *taskmgr_cpu_history_slot(uint32_t cpu_index)
{
    taskmgr_cpu_history_t *empty = NULL;
    for (size_t i = 0; i < TASKMGR_CPU_CAP; ++i)
    {
        taskmgr_cpu_history_t *hist = &g_cpu_history[i];
        if (hist->valid && hist->cpu_index == cpu_index)
        {
            return hist;
        }
        if (!hist->valid && !empty)
        {
            empty = hist;
        }
    }

    if (empty)
    {
        memset(empty, 0, sizeof(*empty));
        empty->cpu_index = cpu_index;
        empty->valid = true;
        return empty;
    }

    return &g_cpu_history[0];
}

static taskmgr_proc_history_t *taskmgr_proc_history_slot(uint64_t pid)
{
    taskmgr_proc_history_t *empty = NULL;
    for (size_t i = 0; i < TASKMGR_PROCESS_CAP; ++i)
    {
        taskmgr_proc_history_t *hist = &g_proc_history[i];
        if (hist->valid && hist->pid == pid)
        {
            return hist;
        }
        if (!hist->valid && !empty)
        {
            empty = hist;
        }
    }

    if (empty)
    {
        memset(empty, 0, sizeof(*empty));
        empty->pid = pid;
        empty->valid = true;
        return empty;
    }

    return &g_proc_history[0];
}

static void taskmgr_format_mac(const uint8_t mac[6], char *out, size_t len)
{
    if (!out || len < 18)
    {
        if (len > 0)
        {
            out[0] = '\0';
        }
        return;
    }
    static const char hex[] = "0123456789ABCDEF";
    size_t pos = 0;
    for (int i = 0; i < 6; ++i)
    {
        out[pos++] = hex[(mac[i] >> 4) & 0xF];
        out[pos++] = hex[mac[i] & 0xF];
        if (i != 5)
        {
            out[pos++] = ':';
        }
    }
    out[pos] = '\0';
}

static void taskmgr_format_ipv4(uint32_t addr, char *out, size_t len)
{
    if (!out || len == 0)
    {
        return;
    }
    if (addr == 0)
    {
        taskmgr_copy_string(out, len, "-");
        return;
    }
    char buf[16];
    size_t pos = 0;
    for (int i = 3; i >= 0; --i)
    {
        uint8_t octet = (uint8_t)((addr >> (i * 8)) & 0xFF);
        char tmp[4];
        size_t tlen = 0;
        do
        {
            tmp[tlen++] = (char)('0' + (octet % 10));
            octet /= 10;
        } while (octet && tlen < sizeof(tmp));
        while (tlen-- > 0 && pos + 1 < sizeof(buf))
        {
            buf[pos++] = tmp[tlen];
        }
        if (i != 0 && pos + 1 < sizeof(buf))
        {
            buf[pos++] = '.';
        }
    }
    buf[pos] = '\0';
    taskmgr_copy_string(out, len, buf);
}

static void taskmgr_populate_process_table(atk_taskmgr_app_t *app,
                                           const syscall_process_info_t *procs,
                                           size_t count,
                                           uint64_t total_tick_delta)
{
    if (!app || !app->process_list)
    {
        return;
    }

    atk_list_view_set_row_count(app->process_list, count);
    for (size_t i = 0; i < count; ++i)
    {
        const syscall_process_info_t *info = &procs[i];
        char cells[10][32];

        taskmgr_proc_history_t *hist = taskmgr_proc_history_slot(info->pid);
        uint32_t cpu_percent = 0;
        if (hist && hist->valid && info->runtime_ticks >= hist->last_runtime_ticks && total_tick_delta > 0)
        {
            uint64_t runtime_delta = info->runtime_ticks - hist->last_runtime_ticks;
            cpu_percent = taskmgr_percent_of_total(runtime_delta, total_tick_delta, 999);
        }
        if (hist)
        {
            hist->pid = info->pid;
            hist->last_runtime_ticks = info->runtime_ticks;
            hist->valid = true;
        }

        taskmgr_copy_string(cells[0], sizeof(cells[0]), info->is_idle ? "*" : "");
        taskmgr_format_u64(info->pid, cells[1], sizeof(cells[1]));
        taskmgr_copy_string(cells[2], sizeof(cells[2]), process_state_name(info->process_state));
        taskmgr_copy_string(cells[3], sizeof(cells[3]), thread_state_name(info->thread_state));
        taskmgr_format_percent(cpu_percent, cells[4], sizeof(cells[4]));
        taskmgr_copy_string(cells[5], sizeof(cells[5]), info->is_idle ? "yes" : "no");
        if (info->stdout_fd < 0)
        {
            taskmgr_copy_string(cells[6], sizeof(cells[6]), "-");
        }
        else
        {
            taskmgr_format_u64((uint64_t)info->stdout_fd, cells[6], sizeof(cells[6]));
        }
        taskmgr_copy_string(cells[7], sizeof(cells[7]), info->process_name);
        taskmgr_copy_string(cells[8], sizeof(cells[8]), info->thread_name);
        taskmgr_format_u64(info->time_slice_remaining, cells[9], sizeof(cells[9]));

        for (int col = 0; col < 10; ++col)
        {
            atk_list_view_set_cell_text(app->process_list, i, (size_t)col, cells[col]);
        }
    }
}

static void taskmgr_populate_memory_table(atk_taskmgr_app_t *app,
                                          const syscall_process_info_t *procs,
                                          size_t count)
{
    if (!app || !app->memory_list)
    {
        return;
    }

    atk_list_view_set_row_count(app->memory_list, count);
    for (size_t i = 0; i < count; ++i)
    {
        const syscall_process_info_t *info = &procs[i];
        char cells[5][32];

        taskmgr_copy_string(cells[0], sizeof(cells[0]), info->is_idle ? "*" : "");
        taskmgr_format_u64(info->pid, cells[1], sizeof(cells[1]));
        taskmgr_copy_string(cells[2], sizeof(cells[2]), info->process_name);
        taskmgr_format_bytes(info->heap_used_bytes, cells[3], sizeof(cells[3]));
        taskmgr_format_bytes(info->heap_committed_bytes, cells[4], sizeof(cells[4]));

        for (int col = 0; col < 5; ++col)
        {
            atk_list_view_set_cell_text(app->memory_list, i, (size_t)col, cells[col]);
        }
    }
}

static uint64_t taskmgr_refresh_cpu(atk_taskmgr_app_t *app)
{
    if (!app || !app->cpu_list)
    {
        return 0;
    }

    syscall_cpu_stats_t stats[TASKMGR_CPU_CAP];
    ssize_t count = sys_cpu_snapshot(stats, TASKMGR_CPU_CAP);
    if (count < 0)
    {
        atk_list_view_clear(app->cpu_list);
        if (app->window)
        {
            atk_window_mark_dirty(app->window);
        }
        return 0;
    }
    if ((size_t)count > TASKMGR_CPU_CAP)
    {
        count = TASKMGR_CPU_CAP;
    }

    uint64_t total_delta_sum = 0;
    atk_list_view_set_row_count(app->cpu_list, (size_t)count);
    for (ssize_t i = 0; i < count; ++i)
    {
        const syscall_cpu_stats_t *info = &stats[i];
        taskmgr_cpu_history_t *hist = taskmgr_cpu_history_slot((uint32_t)info->cpu_index);
        uint64_t total_delta = 0;
        uint64_t idle_delta = 0;
        uint32_t load_percent = 0;

        if (hist)
        {
            if (hist->valid)
            {
                if (info->total_ticks >= hist->last_total_ticks)
                {
                    total_delta = info->total_ticks - hist->last_total_ticks;
                }
                if (info->idle_ticks >= hist->last_idle_ticks)
                {
                    idle_delta = info->idle_ticks - hist->last_idle_ticks;
                }
                if (total_delta > 0 && idle_delta <= total_delta)
                {
                    uint64_t busy = total_delta - idle_delta;
                    load_percent = taskmgr_percent_of_total(busy, total_delta, 100);
                }
            }
            hist->cpu_index = (uint32_t)info->cpu_index;
            hist->last_total_ticks = info->total_ticks;
            hist->last_idle_ticks = info->idle_ticks;
            hist->valid = true;
        }

        total_delta_sum += total_delta;

        char cells[9][32];
        taskmgr_format_u64(info->cpu_index, cells[0], sizeof(cells[0]));
        taskmgr_copy_string(cells[1], sizeof(cells[1]), info->online ? "yes" : "no");
        taskmgr_format_percent(load_percent, cells[2], sizeof(cells[2]));
        taskmgr_format_u64(info->run_queue_depth, cells[3], sizeof(cells[3]));
        taskmgr_format_u64(info->switch_count, cells[4], sizeof(cells[4]));
        taskmgr_format_u64(info->current_pid, cells[5], sizeof(cells[5]));
        if (info->online)
        {
            taskmgr_copy_string(cells[6], sizeof(cells[6]), thread_state_name(info->current_thread_state));
            taskmgr_copy_string(cells[7], sizeof(cells[7]), info->current_process_name);
            taskmgr_copy_string(cells[8], sizeof(cells[8]), info->current_thread_name);
        }
        else
        {
            taskmgr_copy_string(cells[6], sizeof(cells[6]), "-");
            taskmgr_copy_string(cells[7], sizeof(cells[7]), "-");
            taskmgr_copy_string(cells[8], sizeof(cells[8]), "-");
        }

        for (int col = 0; col < 9; ++col)
        {
            atk_list_view_set_cell_text(app->cpu_list, (size_t)i, (size_t)col, cells[col]);
        }
    }

    if (app->window)
    {
        atk_window_mark_dirty(app->window);
    }

    return total_delta_sum;
}

static void taskmgr_refresh_processes(atk_taskmgr_app_t *app, uint64_t total_tick_delta)
{
    syscall_process_info_t procs[TASKMGR_PROCESS_CAP];
    ssize_t count = sys_proc_snapshot(procs, TASKMGR_PROCESS_CAP);
    if (count < 0)
    {
        atk_list_view_clear(app->process_list);
        if (app->memory_list)
        {
            atk_list_view_clear(app->memory_list);
        }
        return;
    }
    if ((size_t)count > TASKMGR_PROCESS_CAP)
    {
        count = TASKMGR_PROCESS_CAP;
    }

    size_t rows = (size_t)count;
    taskmgr_populate_process_table(app, procs, rows, total_tick_delta);
    taskmgr_populate_memory_table(app, procs, rows);
    if (app->window)
    {
        atk_window_mark_dirty(app->window);
    }
}

static void taskmgr_refresh_network(atk_taskmgr_app_t *app)
{
    syscall_net_stats_t stats[TASKMGR_NET_CAP];
    ssize_t count = sys_net_snapshot(stats, TASKMGR_NET_CAP);
    if (count < 0)
    {
        atk_list_view_clear(app->network_list);
        if (app->window)
        {
            atk_window_mark_dirty(app->window);
        }
        return;
    }
    if ((size_t)count > TASKMGR_NET_CAP)
    {
        count = TASKMGR_NET_CAP;
    }

    atk_list_view_set_row_count(app->network_list, (size_t)count);
    for (ssize_t i = 0; i < count; ++i)
    {
        const syscall_net_stats_t *entry = &stats[i];
        char cells[10][32];

        taskmgr_net_history_t *hist = taskmgr_history_slot(entry->name);
        uint64_t delta_rx = 0;
        uint64_t delta_tx = 0;
        if (hist)
        {
            if (hist->name[0] == '\0')
            {
                taskmgr_copy_string(hist->name, sizeof(hist->name), entry->name);
            }
            delta_rx = entry->rx_bytes - hist->last_rx_bytes;
            delta_tx = entry->tx_bytes - hist->last_tx_bytes;
            hist->last_rx_bytes = entry->rx_bytes;
            hist->last_tx_bytes = entry->tx_bytes;
        }

        taskmgr_copy_string(cells[0], sizeof(cells[0]), entry->name);
        taskmgr_copy_string(cells[1], sizeof(cells[1]), entry->link_up ? "up" : "down");
        taskmgr_format_mac(entry->mac, cells[2], sizeof(cells[2]));
        taskmgr_format_ipv4(entry->ipv4_addr, cells[3], sizeof(cells[3]));
        taskmgr_format_u64(entry->rx_packets, cells[4], sizeof(cells[4]));
        taskmgr_format_u64(entry->tx_packets, cells[5], sizeof(cells[5]));
        taskmgr_format_bytes(entry->rx_bytes, cells[6], sizeof(cells[6]));
        taskmgr_format_bytes(entry->tx_bytes, cells[7], sizeof(cells[7]));
        taskmgr_format_bytes(delta_rx, cells[8], sizeof(cells[8]));
        taskmgr_format_bytes(delta_tx, cells[9], sizeof(cells[9]));

        for (int col = 0; col < 10; ++col)
        {
            atk_list_view_set_cell_text(app->network_list, (size_t)i, (size_t)col, cells[col]);
        }
    }
    if (app->window)
    {
        atk_window_mark_dirty(app->window);
    }
}

static bool taskmgr_init_ui(atk_taskmgr_app_t *app)
{
    atk_init();
    atk_state_t *state = atk_state_get();
    atk_menu_bar_set_enabled(state, false);
    taskmgr_apply_theme(state);

    atk_widget_t *window = atk_window_create_at(state, TASKMGR_WINDOW_WIDTH, TASKMGR_WINDOW_HEIGHT);
    if (!window)
    {
        return false;
    }
    atk_window_set_title_text(window, "Task Manager");
    atk_window_set_chrome_visible(window, false);
    window->x = 0;
    window->y = 0;
    window->width = TASKMGR_WINDOW_WIDTH;
    window->height = TASKMGR_WINDOW_HEIGHT;

    atk_layout_t layout;
    int chrome_top = atk_window_is_chrome_visible(window) ? ATK_WINDOW_TITLE_HEIGHT : 0;
    atk_layout_init(&layout,
                    0,
                    chrome_top,
                    window->width,
                    window->height - chrome_top);
    atk_layout_set_padding(&layout, 12, 12, 12, 12);
    atk_layout_region_t content = atk_layout_content(&layout);

    atk_widget_t *tab_view = atk_window_add_tab_view(window, content.x, content.y, content.width, content.height);
    if (!tab_view)
    {
        return false;
    }
    app->tab_view = tab_view;
    atk_widget_set_layout(tab_view,
                          ATK_WIDGET_ANCHOR_LEFT |
                          ATK_WIDGET_ANCHOR_TOP |
                          ATK_WIDGET_ANCHOR_RIGHT |
                          ATK_WIDGET_ANCHOR_BOTTOM);

    atk_widget_t *process_list = atk_list_view_create();
    if (!process_list)
    {
        return false;
    }
    static const atk_list_view_column_def_t PROCESS_COLUMNS[] = {
        { "*", ATK_COL(3) },
        { "PID", ATK_COL(6) },
        { "PSTATE", ATK_COL(8) },
        { "TSTATE", ATK_COL(8) },
        { "CPU%", ATK_COL(6) },
        { "IDLE", ATK_COL(5) },
        { "FD", ATK_COL(6) },
        { "PROC", ATK_COL(20) },
        { "THREAD", ATK_COL(20) },
        { "REM", ATK_COL(8) },
    };
    atk_list_view_configure_columns(process_list, PROCESS_COLUMNS, sizeof(PROCESS_COLUMNS) / sizeof(PROCESS_COLUMNS[0]));
    atk_tab_view_add_page(tab_view, "Processes", process_list);
    app->process_list = process_list;

    atk_widget_t *cpu_list = atk_list_view_create();
    if (!cpu_list)
    {
        return false;
    }
    static const atk_list_view_column_def_t CPU_COLUMNS[] = {
        { "CPU", ATK_COL(4) },
        { "ONLINE", ATK_COL(8) },
        { "LOAD", ATK_COL(7) },
        { "RUNQ", ATK_COL(6) },
        { "SWITCH", ATK_COL(10) },
        { "PID", ATK_COL(6) },
        { "STATE", ATK_COL(8) },
        { "PROC", ATK_COL(18) },
        { "THREAD", ATK_COL(18) },
    };
    atk_list_view_configure_columns(cpu_list, CPU_COLUMNS, sizeof(CPU_COLUMNS) / sizeof(CPU_COLUMNS[0]));
    atk_tab_view_add_page(tab_view, "CPU", cpu_list);
    app->cpu_list = cpu_list;

    atk_widget_t *memory_list = atk_list_view_create();
    if (!memory_list)
    {
        return false;
    }
    static const atk_list_view_column_def_t MEMORY_COLUMNS[] = {
        { "*", ATK_COL(3) },
        { "PID", ATK_COL(6) },
        { "PROC", ATK_COL(26) },
        { "HEAP", ATK_COL(14) },
        { "COMMIT", ATK_COL(14) },
    };
    atk_list_view_configure_columns(memory_list, MEMORY_COLUMNS, sizeof(MEMORY_COLUMNS) / sizeof(MEMORY_COLUMNS[0]));
    atk_tab_view_add_page(tab_view, "Memory", memory_list);
    app->memory_list = memory_list;

    atk_widget_t *network_list = atk_list_view_create();
    if (!network_list)
    {
        return false;
    }
    static const atk_list_view_column_def_t NETWORK_COLUMNS[] = {
        { "IFACE", ATK_COL(8) },
        { "LINK", ATK_COL(6) },
        { "MAC", ATK_COL(18) },
        { "IPv4", ATK_COL(16) },
        { "RXpkts", ATK_COL(12) },
        { "TXpkts", ATK_COL(12) },
        { "RXbytes", ATK_COL(14) },
        { "TXbytes", ATK_COL(14) },
        { "ΔRX", ATK_COL(12) },
        { "ΔTX", ATK_COL(12) },
    };
    atk_list_view_configure_columns(network_list, NETWORK_COLUMNS, sizeof(NETWORK_COLUMNS) / sizeof(NETWORK_COLUMNS[0]));
    atk_tab_view_add_page(tab_view, "Network", network_list);
    app->network_list = network_list;

    app->window = window;
    return true;
}

static void taskmgr_handle_mouse(const user_atk_event_t *event, bool *needs_render)
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

static void taskmgr_handle_key(const user_atk_event_t *event, bool *needs_render)
{
    atk_key_event_result_t result = atk_handle_key_char((char)event->data0);
    if (result.redraw)
    {
        *needs_render = true;
    }
}

static void taskmgr_render(atk_taskmgr_app_t *app)
{
    if (!app)
    {
        return;
    }
    atk_render();
    bool ok = atk_user_present(&app->remote);
    app->last_render_ms = sys_time_millis();
    if (!ok)
    {
        printf("atk_taskmgr: present failed at ms=%llu\n", (unsigned long long)app->last_render_ms);
    }
}

static void taskmgr_handle_resize(atk_taskmgr_app_t *app, uint32_t width, uint32_t height)
{
    if (!app || !app->window)
    {
        return;
    }
    app->window->width = (int)width;
    app->window->height = (int)height;
    atk_window_request_layout(app->window);
}

int main(void)
{
    atk_taskmgr_app_t app;
    memset(&app, 0, sizeof(app));
    app.running = true;

    if (!atk_user_window_open_with_flags(&app.remote,
                                         "Task Manager",
                                         TASKMGR_WINDOW_WIDTH,
                                         TASKMGR_WINDOW_HEIGHT,
                                         USER_ATK_WINDOW_FLAG_RESIZABLE))
    {
        printf("atk_taskmgr: failed to open remote window\n");
        return 1;
    }
    atk_user_enable_dirty_tracking(&app.remote, true);

    if (!taskmgr_init_ui(&app))
    {
        printf("atk_taskmgr: failed to init UI\n");
        atk_user_close(&app.remote);
        return 1;
    }

    memset(g_net_history, 0, sizeof(g_net_history));
    memset(g_cpu_history, 0, sizeof(g_cpu_history));
    memset(g_proc_history, 0, sizeof(g_proc_history));
    uint64_t cpu_delta = taskmgr_refresh_cpu(&app);
    taskmgr_refresh_processes(&app, cpu_delta);
    taskmgr_refresh_network(&app);
    taskmgr_render(&app);
    app.last_refresh_ms = sys_time_millis();
    app.last_render_ms = app.last_refresh_ms;

    while (app.running)
    {
        bool needs_render = false;
        user_atk_event_t event;
        while (atk_user_poll_event(&app.remote, &event))
        {
            switch (event.type)
            {
                case USER_ATK_EVENT_MOUSE:
                    taskmgr_handle_mouse(&event, &needs_render);
                    break;
                case USER_ATK_EVENT_KEY:
                    taskmgr_handle_key(&event, &needs_render);
                    break;
                case USER_ATK_EVENT_CLOSE:
                    app.running = false;
                    break;
                case USER_ATK_EVENT_RESIZE:
                    taskmgr_handle_resize(&app, (uint32_t)event.data0, (uint32_t)event.data1);
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

        uint64_t now_ms = sys_time_millis();
        /* Handle clock adjustments or wrap: if time goes backwards, reset the baseline. */
        if (now_ms < app.last_refresh_ms)
        {
            app.last_refresh_ms = now_ms;
        }
        uint64_t elapsed_ms = now_ms - app.last_refresh_ms;
        if (elapsed_ms >= TASKMGR_REFRESH_MS)
        {
            uint64_t refresh_cpu_delta = taskmgr_refresh_cpu(&app);
            taskmgr_refresh_processes(&app, refresh_cpu_delta);
            taskmgr_refresh_network(&app);
            needs_render = true;
            app.last_refresh_ms = now_ms;
        }

        if (needs_render)
        {
            taskmgr_render(&app);
        }

        /* Watchdog: if nothing has rendered for a while, force a present. */
        uint64_t since_render = now_ms - app.last_render_ms;
        if (!needs_render && since_render >= 5000)
        {
            if (app.window)
            {
                atk_window_mark_dirty(app.window);
            }
            printf("atk_taskmgr: watchdog forcing render after %llu ms idle\n",
                   (unsigned long long)since_render);
            taskmgr_render(&app);
        }

        sys_yield();
    }

    atk_user_close(&app.remote);
    return 0;
}
