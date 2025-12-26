#include "browser_internal.h"

#include "atk/atk_rich_text.h"
#include "stdarg.h"
#include "stdio.h"
#include "string.h"
#include "fcntl.h"
#include "unistd.h"

static const char *const BROWSER_DEBUG_LOG_PATH = "/tmp/atk_browser_debug.log";

static void browser_debug_log_trim_locked(browser_app_t *app)
{
    if (!app || !app->debug_log)
    {
        return;
    }

    if (app->debug_log_len <= BROWSER_DEBUG_LOG_MAX_BYTES)
    {
        return;
    }

    size_t excess = app->debug_log_len - BROWSER_DEBUG_LOG_MAX_BYTES;
    size_t drop = excess;
    while (drop < app->debug_log_len && app->debug_log[drop] != '\n')
    {
        drop++;
    }
    if (drop < app->debug_log_len)
    {
        drop++;
    }
    if (drop == 0 || drop > app->debug_log_len)
    {
        return;
    }

    memmove(app->debug_log, app->debug_log + drop, app->debug_log_len - drop + 1);
    app->debug_log_len -= drop;
    app->debug_log_flush_offset = 0;
    app->debug_log_resync = true;
}

static void browser_debug_log_make_room_locked(browser_app_t *app, size_t extra)
{
    if (!app || !app->debug_log || extra == 0)
    {
        return;
    }

    size_t cap = app->debug_log_cap;
    if (cap == 0 || app->debug_log_len + extra + 1 <= cap)
    {
        return;
    }

    size_t needed = app->debug_log_len + extra + 1 - cap;
    size_t drop = needed;
    while (drop < app->debug_log_len && app->debug_log[drop] != '\n')
    {
        drop++;
    }
    if (drop < app->debug_log_len)
    {
        drop++;
    }
    if (drop == 0 || drop > app->debug_log_len)
    {
        return;
    }

    memmove(app->debug_log, app->debug_log + drop, app->debug_log_len - drop + 1);
    app->debug_log_len -= drop;
    app->debug_log_flush_offset = 0;
    app->debug_log_resync = true;
}

static void browser_debug_log_append_locked(browser_app_t *app, const char *data, size_t len)
{
    if (!app || !data || len == 0)
    {
        return;
    }

    if (app->debug_log_cap == 0)
    {
        return;
    }

    if (len >= app->debug_log_cap)
    {
        data += len - (app->debug_log_cap - 1);
        len = app->debug_log_cap - 1;
        app->debug_log_len = 0;
        app->debug_log_flush_offset = 0;
        app->debug_log_resync = true;
    }

    browser_debug_log_make_room_locked(app, len);

    memcpy(app->debug_log + app->debug_log_len, data, len);
    app->debug_log_len += len;
    app->debug_log[app->debug_log_len] = '\0';

    browser_debug_log_trim_locked(app);
}

static bool browser_debug_log_ensure_buffer(browser_app_t *app)
{
    if (!app)
    {
        return false;
    }

    const size_t cap = BROWSER_DEBUG_LOG_MAX_BYTES + 1;
    if (app->debug_log && app->debug_log_cap >= cap)
    {
        return true;
    }

    char *buf = (char *)malloc(cap);
    if (!buf)
    {
        return false;
    }
    buf[0] = '\0';

    char *old_buf = NULL;
    size_t old_len = 0;
    bool keep_new = false;

    alix_mutex_lock(&app->lock);
    if (!app->debug_log)
    {
        app->debug_log = buf;
        app->debug_log_cap = cap;
        app->debug_log_len = 0;
        keep_new = true;
    }
    else if (app->debug_log_cap < cap)
    {
        old_buf = app->debug_log;
        old_len = app->debug_log_len;
        if (old_len >= cap)
        {
            old_len = cap - 1;
        }
        memcpy(buf, old_buf, old_len);
        buf[old_len] = '\0';
        app->debug_log = buf;
        app->debug_log_cap = cap;
        app->debug_log_len = old_len;
        app->debug_log_flush_offset = 0;
        app->debug_log_resync = true;
        keep_new = true;
    }
    alix_mutex_unlock(&app->lock);

    if (!keep_new)
    {
        free(buf);
        return true;
    }
    if (old_buf)
    {
        free(old_buf);
    }
    return true;
}

static void browser_debug_log_line(browser_app_t *app, const char *line)
{
    if (!app || !line)
    {
        return;
    }
    if (!browser_debug_log_ensure_buffer(app))
    {
        return;
    }
    size_t len = strlen(line);

    bool add_newline = (len == 0 || line[len - 1] != '\n');

    alix_mutex_lock(&app->lock);
    browser_debug_log_append_locked(app, line, len);
    if (add_newline)
    {
        browser_debug_log_append_locked(app, "\n", 1);
    }
    alix_mutex_unlock(&app->lock);

    int fd = open(BROWSER_DEBUG_LOG_PATH, O_WRONLY | O_CREAT);
    if (fd >= 0)
    {
        (void)lseek(fd, 0, SYSCALL_SEEK_END);
        (void)browser_write_all(fd, (const uint8_t *)line, len);
        if (add_newline)
        {
            (void)browser_write_all(fd, (const uint8_t *)"\n", 1);
        }
        close(fd);
    }
}

void browser_debug_log_reset_file(browser_app_t *app)
{
    if (!app)
    {
        return;
    }

    int fd = open(BROWSER_DEBUG_LOG_PATH, O_WRONLY | O_CREAT | O_TRUNC);
    if (fd >= 0)
    {
        close(fd);
    }
}

typedef struct
{
    bool dirty_full;
    bool dirty_active;
    int dirty_x0;
    int dirty_y0;
    int dirty_x1;
    int dirty_y1;
} browser_dirty_snapshot_t;

static browser_dirty_snapshot_t browser_dirty_snapshot(const atk_state_t *state)
{
    browser_dirty_snapshot_t snap = {0};
    if (!state)
    {
        return snap;
    }
    snap.dirty_full = state->dirty_full;
    snap.dirty_active = state->dirty_active;
    snap.dirty_x0 = state->dirty_x0;
    snap.dirty_y0 = state->dirty_y0;
    snap.dirty_x1 = state->dirty_x1;
    snap.dirty_y1 = state->dirty_y1;
    return snap;
}

static void browser_dirty_restore(atk_state_t *state, const browser_dirty_snapshot_t *snap)
{
    if (!state || !snap)
    {
        return;
    }
    state->dirty_full = snap->dirty_full;
    state->dirty_active = snap->dirty_active;
    state->dirty_x0 = snap->dirty_x0;
    state->dirty_y0 = snap->dirty_y0;
    state->dirty_x1 = snap->dirty_x1;
    state->dirty_y1 = snap->dirty_y1;
}

static void browser_attach_remote(atk_user_window_t *win)
{
    if (!win || win->handle == 0 || !win->buffer || win->width == 0 || win->height == 0)
    {
        return;
    }
    video_surface_attach(win->buffer, win->width, win->height, win->buffer_bytes);
    video_surface_set_tracking(win->track_dirty);
}

static bool browser_debug_flush(browser_app_t *app);

void browser_debug_logf(browser_app_t *app, const char *fmt, ...)
{
    if (!app || !fmt)
    {
        return;
    }

    char stack_buf[256];
    va_list args;
    va_start(args, fmt);
    int n = vsnprintf(stack_buf, sizeof(stack_buf), fmt, args);
    va_end(args);

    if (n < 0)
    {
        return;
    }

    if ((size_t)n < sizeof(stack_buf))
    {
        browser_debug_log_line(app, stack_buf);
        return;
    }

    size_t len = (size_t)n;
    char *heap_buf = (char *)malloc(len + 1);
    if (!heap_buf)
    {
        browser_debug_log_line(app, "<debug log alloc failed>");
        return;
    }

    va_start(args, fmt);
    (void)vsnprintf(heap_buf, len + 1, fmt, args);
    va_end(args);

    browser_debug_log_line(app, heap_buf);
    free(heap_buf);
}

static void browser_debug_window_on_destroy(void *context)
{
    browser_app_t *app = (browser_app_t *)context;
    if (!app)
    {
        return;
    }

    alix_mutex_lock(&app->lock);
    app->debug_window = NULL;
    app->debug_text = NULL;
    app->debug_log_flush_offset = 0;
    app->debug_log_resync = true;
    alix_mutex_unlock(&app->lock);
}

void browser_debug_close_window(browser_app_t *app)
{
    if (!app)
    {
        return;
    }

    bool has_remote = app->debug_remote.handle != 0;
    if (has_remote)
    {
        browser_attach_remote(&app->debug_remote);
    }

    atk_state_t *state = atk_state_get();
    if (state && app->debug_window)
    {
        atk_window_close(state, app->debug_window);
    }

    if (has_remote)
    {
        atk_user_close(&app->debug_remote);
        memset(&app->debug_remote, 0, sizeof(app->debug_remote));
    }

    app->debug_window = NULL;
    app->debug_text = NULL;

    browser_attach_remote(&app->remote);
}

void browser_debug_open_window(browser_app_t *app)
{
    if (!app)
    {
        return;
    }

    atk_state_t *state = atk_state_get();
    if (!state)
    {
        return;
    }

    if (app->debug_remote.handle != 0)
    {
        alix_mutex_lock(&app->lock);
        atk_widget_t *existing = app->debug_window;
        atk_widget_t *existing_text = app->debug_text;
        alix_mutex_unlock(&app->lock);
        if (existing && existing_text && existing_text->used)
        {
            atk_rich_text_scroll_to_bottom(existing_text);
        }
        return;
    }

    browser_dirty_snapshot_t dirty_before = browser_dirty_snapshot(state);

    if (!atk_user_window_open_with_flags(&app->debug_remote,
                                         "Browser Debug",
                                         BROWSER_DEBUG_WINDOW_WIDTH,
                                         BROWSER_DEBUG_WINDOW_HEIGHT,
                                         USER_ATK_WINDOW_FLAG_RESIZABLE))
    {
        browser_attach_remote(&app->remote);
        browser_dirty_restore(state, &dirty_before);
        return;
    }
    atk_user_enable_dirty_tracking(&app->debug_remote, true);

    int screen_w = (int)app->debug_remote.width;
    int screen_h = (int)app->debug_remote.height;
    if (screen_w <= 0)
    {
        screen_w = (int)BROWSER_DEBUG_WINDOW_WIDTH;
    }
    if (screen_h <= 0)
    {
        screen_h = (int)BROWSER_DEBUG_WINDOW_HEIGHT;
    }

    atk_widget_t *window = atk_window_create_at(state, screen_w / 2, screen_h / 2);
    if (!window)
    {
        atk_user_close(&app->debug_remote);
        memset(&app->debug_remote, 0, sizeof(app->debug_remote));
        browser_attach_remote(&app->remote);
        browser_dirty_restore(state, &dirty_before);
        return;
    }

    atk_window_set_chrome_visible(window, false);
    atk_window_set_title_text(window, "Browser Debug");
    window->x = 0;
    window->y = 0;
    window->width = screen_w;
    window->height = screen_h;
    atk_window_ensure_inside(window);
    atk_window_set_context(window, app, browser_debug_window_on_destroy);
    atk_window_bring_to_front(state, window);

    int margin = 10;
    int content_x = margin;
    int content_y = margin;
    int content_w = window->width - margin * 2;
    int content_h = window->height - margin * 2;
    if (content_w < 16)
    {
        content_w = 16;
    }
    if (content_h < 16)
    {
        content_h = 16;
    }

    atk_widget_t *editor = atk_window_add_rich_text(window, content_x, content_y, content_w, content_h);
    if (!editor)
    {
        atk_window_close(state, window);
        atk_user_close(&app->debug_remote);
        memset(&app->debug_remote, 0, sizeof(app->debug_remote));
        browser_attach_remote(&app->remote);
        browser_dirty_restore(state, &dirty_before);
        return;
    }
    atk_widget_set_layout(editor,
                          ATK_WIDGET_ANCHOR_LEFT | ATK_WIDGET_ANCHOR_RIGHT |
                              ATK_WIDGET_ANCHOR_TOP | ATK_WIDGET_ANCHOR_BOTTOM);
    atk_rich_text_set_read_only(editor, true);

    alix_mutex_lock(&app->lock);
    app->debug_window = window;
    app->debug_text = editor;
    app->debug_log_flush_offset = 0;
    app->debug_log_resync = true;
    alix_mutex_unlock(&app->lock);

    bool saved_browser_used = app->window ? app->window->used : true;
    if (app->window)
    {
        app->window->used = false;
    }
    window->used = true;
    (void)browser_debug_flush(app);
    atk_dirty_mark_all();
    atk_render();
    atk_user_present_force(&app->debug_remote);

    window->used = false;
    if (app->window)
    {
        app->window->used = saved_browser_used;
    }
    browser_attach_remote(&app->remote);
    browser_dirty_restore(state, &dirty_before);
}

static void browser_debug_sync_window_to_remote(browser_app_t *app)
{
    if (!app || !app->debug_window || app->debug_remote.handle == 0)
    {
        return;
    }

    int screen_w = (int)app->debug_remote.width;
    int screen_h = (int)app->debug_remote.height;
    if (screen_w <= 0)
    {
        screen_w = (int)BROWSER_DEBUG_WINDOW_WIDTH;
    }
    if (screen_h <= 0)
    {
        screen_h = (int)BROWSER_DEBUG_WINDOW_HEIGHT;
    }

    atk_widget_t *window = app->debug_window;
    if (window->x != 0 || window->y != 0 || window->width != screen_w || window->height != screen_h)
    {
        window->x = 0;
        window->y = 0;
        window->width = screen_w;
        window->height = screen_h;
        atk_window_ensure_inside(window);
        atk_window_request_layout(window);
    }
}

void browser_debug_clear(browser_app_t *app)
{
    if (!app)
    {
        return;
    }

    atk_widget_t *editor = NULL;
    alix_mutex_lock(&app->lock);
    if (app->debug_log)
    {
        app->debug_log[0] = '\0';
    }
    app->debug_log_len = 0;
    app->debug_log_flush_offset = 0;
    app->debug_log_resync = false;
    editor = app->debug_text;
    alix_mutex_unlock(&app->lock);

    if (editor && editor->used)
    {
        atk_rich_text_set_text(editor, "");
        atk_rich_text_scroll_to_top(editor);
    }
}

static bool browser_debug_flush(browser_app_t *app)
{
    if (!app)
    {
        return false;
    }

    atk_widget_t *editor = NULL;
    atk_widget_t *window = NULL;
    bool resync = false;
    size_t start = 0;
    size_t take = 0;
    char chunk[4096];

    alix_mutex_lock(&app->lock);
    editor = app->debug_text;
    window = app->debug_window;

    if (!editor || !editor->used)
    {
        alix_mutex_unlock(&app->lock);
        return false;
    }

    if (app->debug_log_resync)
    {
        resync = true;
        start = app->debug_log_flush_offset;
    }
    else if (app->debug_log && app->debug_log_flush_offset < app->debug_log_len)
    {
        start = app->debug_log_flush_offset;
    }

    if (app->debug_log && start < app->debug_log_len)
    {
        size_t available = app->debug_log_len - start;
        take = available < (sizeof(chunk) - 1) ? available : (sizeof(chunk) - 1);
        memcpy(chunk, app->debug_log + start, take);
        chunk[take] = '\0';
        app->debug_log_flush_offset = start + take;
        if (resync && app->debug_log_flush_offset >= app->debug_log_len)
        {
            app->debug_log_resync = false;
        }
    }
    else if (resync)
    {
        app->debug_log_resync = false;
    }
    alix_mutex_unlock(&app->lock);

    if (take == 0)
    {
        return false;
    }

    if (resync && start == 0)
    {
        atk_rich_text_set_text(editor, chunk);
    }
    else
    {
        atk_rich_text_append(editor, chunk);
    }
    atk_rich_text_scroll_to_bottom(editor);

    if (window && window->used)
    {
        atk_window_mark_dirty(window);
    }
    return true;
}

void browser_debug_service(browser_app_t *app)
{
    if (!app || app->debug_remote.handle == 0 || !app->debug_window)
    {
        return;
    }

    atk_state_t *state = atk_state_get();
    if (!state)
    {
        return;
    }

    browser_dirty_snapshot_t dirty_before = browser_dirty_snapshot(state);
    bool saved_browser_used = app->window ? app->window->used : true;
    bool saved_debug_used = app->debug_window->used;

    browser_attach_remote(&app->debug_remote);
    if (app->window)
    {
        app->window->used = false;
    }
    app->debug_window->used = true;
    browser_debug_sync_window_to_remote(app);

    bool had_event = false;
    bool close_requested = false;
    user_atk_event_t ev;
    while (atk_user_poll_event(&app->debug_remote, &ev))
    {
        had_event = true;
        switch (ev.type)
        {
            case USER_ATK_EVENT_MOUSE:
            {
                bool left = (ev.flags & USER_ATK_MOUSE_FLAG_LEFT) != 0;
                bool press = (ev.flags & USER_ATK_MOUSE_FLAG_PRESS) != 0;
                bool release = (ev.flags & USER_ATK_MOUSE_FLAG_RELEASE) != 0;
                bool right = (ev.flags & USER_ATK_MOUSE_FLAG_RIGHT) != 0;
                bool right_press = (ev.flags & USER_ATK_MOUSE_FLAG_RIGHT_PRESS) != 0;
                bool right_release = (ev.flags & USER_ATK_MOUSE_FLAG_RIGHT_RELEASE) != 0;
                int dx = 0;
                int dy = 0;
                if (ev.flags & USER_ATK_MOUSE_FLAG_RELATIVE)
                {
                    dx = (int32_t)ev.data0;
                    dy = (int32_t)ev.data1;
                }
                (void)atk_handle_mouse_event(dx,
                                             dy,
                                             ev.x,
                                             ev.y,
                                             press,
                                             release,
                                             left,
                                             right_press,
                                             right_release,
                                             right);
                break;
            }
            case USER_ATK_EVENT_KEY:
                /* Ignore key events for now (read-only log view). */
                break;
            case USER_ATK_EVENT_RESIZE:
                browser_debug_sync_window_to_remote(app);
                break;
            case USER_ATK_EVENT_CLOSE:
                close_requested = true;
                break;
            default:
                break;
        }

        if (close_requested)
        {
            break;
        }
    }

    if (close_requested)
    {
        browser_debug_close_window(app);
        browser_dirty_restore(state, &dirty_before);
        if (app->window)
        {
            app->window->used = saved_browser_used;
        }
        browser_attach_remote(&app->remote);
        return;
    }

    bool flushed = browser_debug_flush(app);
    if (had_event || flushed)
    {
        atk_dirty_mark_all();
        atk_render();
        atk_user_present(&app->debug_remote);
    }

    if (app->debug_window)
    {
        app->debug_window->used = saved_debug_used;
    }
    if (app->window)
    {
        app->window->used = saved_browser_used;
    }
    browser_attach_remote(&app->remote);
    browser_dirty_restore(state, &dirty_before);
}
