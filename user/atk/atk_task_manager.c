#ifdef KERNEL_BUILD

#include "atk/atk_task_manager.h"

#include "atk_internal.h"
#include "atk/atk_list_view.h"
#include "atk/atk_tabs.h"
#include "atk/layout.h"
#include "atk_window.h"
#include "libc.h"
#include "logger.h"
#include "process.h"
#include "net/interface.h"
#include "timer.h"

#define TASKMGR_PROCESS_CAPACITY 48
#define ATK_COL(chars) ((chars) * ATK_FONT_WIDTH)

typedef struct
{
    char name[NET_IF_NAME_MAX];
    uint64_t last_rx_bytes;
    uint64_t last_tx_bytes;
    uint64_t last_ticks;
} atk_taskmgr_net_history_t;

typedef struct
{
    atk_state_t *state;
    atk_widget_t *window;
    atk_widget_t *tab_view;
    atk_widget_t *process_list;
    atk_widget_t *network_list;
    size_t active_tab;
    bool timer_registered;
    uint32_t timer_interval;
    atk_taskmgr_net_history_t net_history[NET_MAX_INTERFACES];
} atk_task_manager_view_t;

static bool atk_task_manager_init_ui(atk_task_manager_view_t *view);
static void atk_task_manager_view_destroy(void *context);
static void atk_task_manager_timer(void *context);
static void atk_task_manager_on_tab_changed(atk_widget_t *tab_view, void *context, size_t index);
static void atk_task_manager_refresh_processes(atk_task_manager_view_t *view);
static void atk_task_manager_refresh_network(atk_task_manager_view_t *view);
static void taskmgr_format_u64(uint64_t value, char *buffer, size_t len);
static void taskmgr_format_bytes(uint64_t value, char *buffer, size_t len);
static void taskmgr_format_rate(uint64_t bytes_per_sec, char *buffer, size_t len);
static void taskmgr_format_mac(const uint8_t mac[6], char *out, size_t len);
static void taskmgr_format_ipv4(uint32_t addr, char *out, size_t len);
static void taskmgr_copy_string(char *dst, size_t len, const char *src);
static atk_taskmgr_net_history_t *taskmgr_history_slot(atk_task_manager_view_t *view, const char *name);

bool atk_task_manager_open(atk_state_t *state)
{
    logger_log("taskmgr: open requested");
    if (!state)
    {
        logger_log("taskmgr: open aborted (no state)");
        return false;
    }

    atk_task_manager_view_t *view = (atk_task_manager_view_t *)malloc(sizeof(atk_task_manager_view_t));
    if (!view)
    {
        logger_log("taskmgr: view allocation failed");
        return false;
    }
    memset(view, 0, sizeof(*view));
    view->state = state;

    if (!atk_task_manager_init_ui(view))
    {
        logger_log("taskmgr: init_ui failed");
        atk_task_manager_view_destroy(view);
        return false;
    }

    view->timer_interval = timer_frequency() / 2;
    if (view->timer_interval == 0)
    {
        view->timer_interval = 1;
    }
    view->timer_registered = timer_register_periodic(atk_task_manager_timer, view, view->timer_interval);
    if (!view->timer_registered)
    {
        logger_log("taskmgr: timer registration failed");
    }

    atk_task_manager_refresh_processes(view);
    atk_task_manager_refresh_network(view);
    atk_tab_view_set_change_handler(view->tab_view, atk_task_manager_on_tab_changed, view);
    atk_window_mark_dirty(view->window);
    logger_log("taskmgr: open complete");
    return true;
}

#endif /* KERNEL_BUILD */

static bool atk_task_manager_init_ui(atk_task_manager_view_t *view)
{
    atk_widget_t *window = atk_window_create_at(view->state, 320, 240);
    if (!window)
    {
        logger_log("taskmgr: window creation failed");
        return false;
    }
    window->width = 720;
    window->height = 460;
    atk_window_ensure_inside(window);

    atk_layout_t layout;
    atk_layout_init(&layout,
                    0,
                    ATK_WINDOW_TITLE_HEIGHT,
                    window->width,
                    window->height - ATK_WINDOW_TITLE_HEIGHT);
    atk_layout_set_padding(&layout, 12, 12, 12, 12);
    atk_layout_region_t content = atk_layout_content(&layout);

    atk_widget_t *tab_view = atk_window_add_tab_view(window, content.x, content.y, content.width, content.height);
    if (!tab_view)
    {
        logger_log("taskmgr: tab view creation failed");
        atk_window_close(view->state, window);
        return false;
    }
    view->tab_view = tab_view;

    atk_widget_t *process_list = atk_list_view_create();
    if (!process_list)
    {
        logger_log("taskmgr: process list widget alloc failed");
        atk_window_close(view->state, window);
        return false;
    }

    static const atk_list_view_column_def_t PROCESS_COLUMNS[] = {
        { "*", ATK_COL(2) },
        { "PID", ATK_COL(6) },
        { "PSTATE", ATK_COL(8) },
        { "TSTATE", ATK_COL(8) },
        { "IDLE", ATK_COL(5) },
        { "FD", ATK_COL(4) },
        { "PROC", ATK_COL(16) },
        { "THREAD", ATK_COL(16) },
        { "REM", ATK_COL(6) },
    };
    if (!atk_list_view_configure_columns(process_list, PROCESS_COLUMNS, sizeof(PROCESS_COLUMNS) / sizeof(PROCESS_COLUMNS[0])))
    {
        logger_log("taskmgr: process list column config failed");
        atk_list_view_destroy(process_list);
        atk_widget_destroy(process_list);
        atk_window_close(view->state, window);
        return false;
    }
    if (!atk_tab_view_add_page(tab_view, "Processes", process_list))
    {
        logger_log("taskmgr: failed to add process tab");
        atk_list_view_destroy(process_list);
        atk_widget_destroy(process_list);
        atk_window_close(view->state, window);
        return false;
    }
    view->process_list = process_list;

    atk_widget_t *network_list = atk_list_view_create();
    if (!network_list)
    {
        logger_log("taskmgr: network list widget alloc failed");
        atk_window_close(view->state, window);
        return false;
    }

    static const atk_list_view_column_def_t NETWORK_COLUMNS[] = {
        { "IFACE", ATK_COL(6) },
        { "LINK", ATK_COL(6) },
        { "MAC", ATK_COL(18) },
        { "IPv4", ATK_COL(15) },
        { "RXpkts", ATK_COL(10) },
        { "TXpkts", ATK_COL(10) },
        { "RXbytes", ATK_COL(12) },
        { "TXbytes", ATK_COL(12) },
        { "RX/s", ATK_COL(10) },
        { "TX/s", ATK_COL(10) },
    };
    if (!atk_list_view_configure_columns(network_list, NETWORK_COLUMNS, sizeof(NETWORK_COLUMNS) / sizeof(NETWORK_COLUMNS[0])))
    {
        logger_log("taskmgr: network list column config failed");
        atk_list_view_destroy(network_list);
        atk_widget_destroy(network_list);
        atk_window_close(view->state, window);
        return false;
    }
    if (!atk_tab_view_add_page(tab_view, "Network", network_list))
    {
        logger_log("taskmgr: failed to add network tab");
        atk_list_view_destroy(network_list);
        atk_widget_destroy(network_list);
        atk_window_close(view->state, window);
        return false;
    }
    view->network_list = network_list;

    atk_tab_view_relayout(tab_view);
    memset(view->net_history, 0, sizeof(view->net_history));
    view->active_tab = 0;
    view->window = window;
    atk_window_set_context(window, view, atk_task_manager_view_destroy);
    return true;
}

static void atk_task_manager_view_destroy(void *context)
{
    atk_task_manager_view_t *view = (atk_task_manager_view_t *)context;
    if (!view)
    {
        return;
    }

    if (view->timer_registered)
    {
        timer_unregister(atk_task_manager_timer, view);
        view->timer_registered = false;
    }

    view->window = NULL;
    view->tab_view = NULL;
    view->process_list = NULL;
    view->network_list = NULL;
    free(view);
}

static void atk_task_manager_timer(void *context)
{
    atk_task_manager_view_t *view = (atk_task_manager_view_t *)context;
    if (!view || !view->window || !view->window->used)
    {
        return;
    }

    size_t tab = atk_tab_view_active(view->tab_view);
    if (tab == 0)
    {
        atk_task_manager_refresh_processes(view);
    }
    else
    {
        atk_task_manager_refresh_network(view);
    }
    atk_window_mark_dirty(view->window);
}

static void atk_task_manager_on_tab_changed(atk_widget_t *tab_view, void *context, size_t index)
{
    (void)tab_view;
    atk_task_manager_view_t *view = (atk_task_manager_view_t *)context;
    if (!view)
    {
        return;
    }
    view->active_tab = index;
    if (index == 0)
    {
        atk_task_manager_refresh_processes(view);
    }
    else
    {
        atk_task_manager_refresh_network(view);
    }
    if (view->window)
    {
        atk_window_mark_dirty(view->window);
    }
}

static void atk_task_manager_refresh_processes(atk_task_manager_view_t *view)
{
    process_info_t infos[TASKMGR_PROCESS_CAPACITY];
    size_t count = process_snapshot(infos, TASKMGR_PROCESS_CAPACITY);
    atk_list_view_set_row_count(view->process_list, count);

    for (size_t i = 0; i < count; ++i)
    {
        const process_info_t *info = &infos[i];
        char buffer[32];

        atk_list_view_set_cell_text(view->process_list, i, 0, info->is_current ? "*" : "");

        taskmgr_format_u64(info->pid, buffer, sizeof(buffer));
        atk_list_view_set_cell_text(view->process_list, i, 1, buffer);

        atk_list_view_set_cell_text(view->process_list, i, 2, process_state_name(info->state));
        atk_list_view_set_cell_text(view->process_list, i, 3, thread_state_name(info->thread_state));
        atk_list_view_set_cell_text(view->process_list, i, 4, info->is_idle ? "idle" : "");

        if (info->stdout_fd < 0)
        {
            atk_list_view_set_cell_text(view->process_list, i, 5, "-");
        }
        else
        {
            taskmgr_format_u64((uint64_t)info->stdout_fd, buffer, sizeof(buffer));
            atk_list_view_set_cell_text(view->process_list, i, 5, buffer);
        }

        atk_list_view_set_cell_text(view->process_list, i, 6, info->name ? info->name : "");
        atk_list_view_set_cell_text(view->process_list, i, 7, info->thread_name ? info->thread_name : "");

        taskmgr_format_u64(info->time_slice_remaining, buffer, sizeof(buffer));
        atk_list_view_set_cell_text(view->process_list, i, 8, buffer);
    }
}

static void atk_task_manager_refresh_network(atk_task_manager_view_t *view)
{
    net_interface_stats_t stats[NET_MAX_INTERFACES];
    size_t count = net_if_snapshot(stats, NET_MAX_INTERFACES);
    atk_list_view_set_row_count(view->network_list, count);

    if (count == 0)
    {
        return;
    }

    uint64_t now_ticks = timer_ticks();
    uint32_t freq = timer_frequency();
    if (freq == 0)
    {
        freq = 1000;
    }

    for (size_t i = 0; i < count; ++i)
    {
        net_interface_stats_t *entry = &stats[i];
        atk_taskmgr_net_history_t *hist = taskmgr_history_slot(view, entry->name);
        uint64_t rx_rate = 0;
        uint64_t tx_rate = 0;
        if (hist)
        {
            if (hist->last_ticks != 0 && now_ticks > hist->last_ticks)
            {
                uint64_t elapsed_ticks = now_ticks - hist->last_ticks;
                uint64_t rx_delta = entry->rx_bytes - hist->last_rx_bytes;
                uint64_t tx_delta = entry->tx_bytes - hist->last_tx_bytes;
                rx_rate = (rx_delta * freq) / elapsed_ticks;
                tx_rate = (tx_delta * freq) / elapsed_ticks;
            }
            hist->last_ticks = now_ticks;
            hist->last_rx_bytes = entry->rx_bytes;
            hist->last_tx_bytes = entry->tx_bytes;
        }

        char buffer[32];
        atk_list_view_set_cell_text(view->network_list, i, 0, entry->name);
        atk_list_view_set_cell_text(view->network_list, i, 1, entry->link_up ? "up" : "down");

        char mac_buf[20];
        taskmgr_format_mac(entry->mac, mac_buf, sizeof(mac_buf));
        atk_list_view_set_cell_text(view->network_list, i, 2, mac_buf);

        char ip_buf[20];
        taskmgr_format_ipv4(entry->ipv4_addr, ip_buf, sizeof(ip_buf));
        atk_list_view_set_cell_text(view->network_list, i, 3, ip_buf);

        taskmgr_format_u64(entry->rx_packets, buffer, sizeof(buffer));
        atk_list_view_set_cell_text(view->network_list, i, 4, buffer);
        taskmgr_format_u64(entry->tx_packets, buffer, sizeof(buffer));
        atk_list_view_set_cell_text(view->network_list, i, 5, buffer);

        taskmgr_format_bytes(entry->rx_bytes, buffer, sizeof(buffer));
        atk_list_view_set_cell_text(view->network_list, i, 6, buffer);
        taskmgr_format_bytes(entry->tx_bytes, buffer, sizeof(buffer));
        atk_list_view_set_cell_text(view->network_list, i, 7, buffer);

        taskmgr_format_rate(rx_rate, buffer, sizeof(buffer));
        atk_list_view_set_cell_text(view->network_list, i, 8, buffer);
        taskmgr_format_rate(tx_rate, buffer, sizeof(buffer));
        atk_list_view_set_cell_text(view->network_list, i, 9, buffer);
    }
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
            i++;
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
        tmp[pos++] = (char)('0' + (value % 10));
        value /= 10;
    } while (value != 0 && pos < sizeof(tmp));

    size_t out = 0;
    while (out < pos && out + 1 < len)
    {
        buffer[out] = tmp[pos - 1 - out];
        out++;
    }
    buffer[out] = '\0';
}

static void taskmgr_format_bytes(uint64_t value, char *buffer, size_t len)
{
    static const char *suffixes[] = { "B", "KB", "MB", "GB", "TB" };
    size_t suffix = 0;
    uint64_t scaled = value;
    uint64_t remainder = 0;
    while (scaled >= 1024 && suffix < (sizeof(suffixes) / sizeof(suffixes[0])) - 1)
    {
        remainder = scaled % 1024;
        scaled /= 1024;
        suffix++;
    }

    taskmgr_format_u64(scaled, buffer, len);
    uint64_t tenths = 0;
    if (suffix != 0 && scaled < 100)
    {
        tenths = (remainder * 10) / 1024;
    }
    if (tenths > 0)
    {
        size_t used = strlen(buffer);
        if (used + 2 < len)
        {
            buffer[used++] = '.';
            buffer[used++] = (char)('0' + (tenths % 10));
            buffer[used] = '\0';
        }
    }

    size_t used = strlen(buffer);
    if (used + 1 < len)
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

static void taskmgr_format_rate(uint64_t bytes_per_sec, char *buffer, size_t len)
{
    if (bytes_per_sec == 0)
    {
        taskmgr_copy_string(buffer, len, "0 B/s");
        return;
    }
    taskmgr_format_bytes(bytes_per_sec, buffer, len);
    size_t used = strlen(buffer);
    if (used + 3 < len)
    {
        buffer[used++] = '/';
        buffer[used++] = 's';
        buffer[used] = '\0';
    }
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
    net_format_ipv4(addr, out);
}

static atk_taskmgr_net_history_t *taskmgr_history_slot(atk_task_manager_view_t *view, const char *name)
{
    if (!view || !name)
    {
        return NULL;
    }

    atk_taskmgr_net_history_t *empty = NULL;
    for (size_t i = 0; i < NET_MAX_INTERFACES; ++i)
    {
        atk_taskmgr_net_history_t *hist = &view->net_history[i];
        if (hist->name[0] == '\0')
        {
            if (!empty)
            {
                empty = hist;
            }
            continue;
        }
        if (strncmp(hist->name, name, NET_IF_NAME_MAX) == 0)
        {
            return hist;
        }
    }

    if (empty)
    {
        taskmgr_copy_string(empty->name, NET_IF_NAME_MAX, name);
        empty->last_rx_bytes = 0;
        empty->last_tx_bytes = 0;
        empty->last_ticks = 0;
        return empty;
    }

    /* fallback: reuse first slot */
    atk_taskmgr_net_history_t *hist = &view->net_history[0];
    taskmgr_copy_string(hist->name, NET_IF_NAME_MAX, name);
    hist->last_rx_bytes = 0;
    hist->last_tx_bytes = 0;
    hist->last_ticks = 0;
    return hist;
}
