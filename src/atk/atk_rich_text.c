#include "atk/atk_rich_text.h"

#include "atk_internal.h"
#include "atk/atk_scrollbar.h"
#include "libc.h"
#include "ttf.h"
#include "video.h"
#if ATK_NO_DESKTOP_APPS
#include "usyscall.h"
#else
#include "vfs.h"
#endif

#define ATK_RICH_TEXT_FONT_PATH "/usr/share/fonts/PublicSans.ttf"
#define ATK_RICH_TEXT_PADDING 8
#define ATK_RICH_TEXT_SCROLLBAR_WIDTH 14
#define ATK_RICH_TEXT_LINE_SPACING 4
#define ATK_RICH_TEXT_MIN_FONT 10
#define ATK_RICH_TEXT_MAX_FONT 64
#define ATK_RICH_TEXT_DEFAULT_FONT 18
#define ATK_RICH_TEXT_CACHE_SLOTS 8
#define ATK_RICH_TEXT_GLYPH_FIRST 32
#define ATK_RICH_TEXT_GLYPH_LAST 126
#define ATK_RICH_TEXT_GLYPH_COUNT (ATK_RICH_TEXT_GLYPH_LAST - ATK_RICH_TEXT_GLYPH_FIRST + 1)

typedef struct
{
    bool ready;
    uint8_t *alpha;
    int width;
    int height;
    int stride;
    int advance;
    int bearing_x;
    int bearing_y;
} atk_rich_glyph_t;

typedef struct
{
    bool used;
    int size_px;
    ttf_font_metrics_t metrics;
    atk_rich_glyph_t glyphs[ATK_RICH_TEXT_GLYPH_COUNT];
} atk_rich_font_size_cache_t;

typedef struct
{
    bool ready;
    ttf_font_t font;
    uint8_t *blob;
    size_t blob_size;
    bool blob_owned;
    atk_rich_font_size_cache_t caches[ATK_RICH_TEXT_CACHE_SLOTS];
} atk_rich_font_state_t;

typedef struct
{
    char ch;
    int size;
} atk_rich_char_t;

typedef struct
{
    size_t start;
    size_t end;
    int top;
    int height;
    int baseline;
} atk_rich_line_t;

typedef struct
{
    atk_list_node_t *list_node;
    atk_widget_t *scrollbar;
    atk_rich_char_t *chars;
    size_t length;
    size_t capacity;
    size_t cursor;
    atk_rich_line_t *lines;
    size_t line_count;
    size_t line_capacity;
    int content_height;
    int view_width;
    int view_height;
    int scroll_y;
    int scrollbar_width;
    int current_font_size;
    int last_width;
    int last_height;
    bool layout_dirty;
    bool focused;
    bool selecting;
    size_t sel_anchor;
    size_t sel_start;
    size_t sel_end;
    video_color_t *row_buffer;
    int row_buffer_capacity;
    atk_rich_text_change_t change;
    void *change_context;
} atk_rich_text_priv_t;

static atk_rich_font_state_t g_font_state = { 0 };

static atk_rich_text_priv_t *rich_text_priv_mut(atk_widget_t *editor);
static const atk_rich_text_priv_t *rich_text_priv(const atk_widget_t *editor);
static void rich_text_invalidate(const atk_widget_t *editor);
static bool rich_text_update_layout(atk_widget_t *editor, atk_rich_text_priv_t *priv);
static void rich_text_position_scrollbar(atk_widget_t *editor, atk_rich_text_priv_t *priv);
static void rich_text_update_scrollbar(atk_rich_text_priv_t *priv);
static void rich_text_scrollbar_changed(atk_widget_t *scrollbar, void *context, int value);
static bool rich_text_cursor_rect(const atk_widget_t *editor,
                                  atk_rich_text_priv_t *priv,
                                  int origin_x,
                                  int origin_y,
                                  int *x_out,
                                  int *y_out,
                                  int *h_out);
static void rich_text_ensure_cursor_visible(atk_widget_t *editor, atk_rich_text_priv_t *priv);
static size_t rich_text_index_for_point(atk_widget_t *editor, atk_rich_text_priv_t *priv, int local_x, int local_y);
static bool rich_text_insert_char(atk_widget_t *editor, atk_rich_text_priv_t *priv, char ch);
static bool rich_text_backspace(atk_widget_t *editor, atk_rich_text_priv_t *priv);
static void rich_text_notify_change(atk_widget_t *editor, atk_rich_text_priv_t *priv);
static void rich_text_clear(atk_widget_t *editor, atk_rich_text_priv_t *priv);
static bool rich_row_buffer_ensure(atk_rich_text_priv_t *priv, int width);
static int rich_text_clamp_font_size(int size);
static int rich_text_fallback_advance(int size, char ch);
static void rich_text_clear_selection(atk_rich_text_priv_t *priv);
static void rich_text_set_selection(atk_rich_text_priv_t *priv, size_t a, size_t b);

static bool rich_font_load(void);
#if ATK_NO_DESKTOP_APPS
static bool rich_font_read_user(uint8_t **data_out, size_t *size_out);
#endif
static atk_rich_font_size_cache_t *rich_font_cache_for_size(int size);
static atk_rich_glyph_t *rich_font_get_glyph(atk_rich_font_size_cache_t *cache, uint32_t codepoint);

static atk_mouse_response_t rich_text_mouse_cb(atk_widget_t *widget,
                                               const atk_mouse_event_t *event,
                                               void *context);
static bool rich_text_hit_test_cb(const atk_widget_t *widget,
                                  int origin_x,
                                  int origin_y,
                                  int px,
                                  int py,
                                  void *context);
static void rich_text_draw_cb(const atk_state_t *state,
                              const atk_widget_t *widget,
                              int origin_x,
                              int origin_y,
                              void *context);
static void rich_text_destroy_cb(atk_widget_t *widget, void *context);
static atk_key_response_t rich_text_key_cb(atk_widget_t *widget,
                                           int key,
                                           int modifiers,
                                           int action,
                                           void *context);

static const atk_widget_vtable_t rich_text_vtable = { 0 };
static const atk_widget_ops_t g_rich_text_ops = {
    .destroy = rich_text_destroy_cb,
    .draw = rich_text_draw_cb,
    .hit_test = rich_text_hit_test_cb,
    .on_mouse = rich_text_mouse_cb,
    .on_key = rich_text_key_cb
};

const atk_class_t ATK_RICH_TEXT_CLASS = { "RichText", &ATK_WIDGET_CLASS, &rich_text_vtable, sizeof(atk_rich_text_priv_t) };

atk_widget_t *atk_window_add_rich_text(atk_widget_t *window, int x, int y, int width, int height)
{
    if (!window || width <= 0 || height <= 0)
    {
        return NULL;
    }

    atk_window_priv_t *wpriv = (atk_window_priv_t *)atk_widget_priv(window, &ATK_WINDOW_CLASS);
    if (!wpriv)
    {
        return NULL;
    }

    atk_widget_t *editor = atk_widget_create(&ATK_RICH_TEXT_CLASS);
    if (!editor)
    {
        return NULL;
    }

    editor->x = x;
    editor->y = y;
    editor->width = width;
    editor->height = height;
    editor->parent = window;
    editor->used = true;
    atk_widget_set_ops(editor, &g_rich_text_ops, NULL);

    atk_rich_text_priv_t *priv = rich_text_priv_mut(editor);
    if (!priv)
    {
        atk_widget_destroy(editor);
        return NULL;
    }
    priv->list_node = NULL;
    priv->scrollbar = NULL;
    priv->chars = NULL;
    priv->length = 0;
    priv->capacity = 0;
    priv->cursor = 0;
    priv->lines = NULL;
    priv->line_count = 0;
    priv->line_capacity = 0;
    priv->content_height = 0;
    priv->view_width = 0;
    priv->view_height = 0;
    priv->scroll_y = 0;
    priv->scrollbar_width = ATK_RICH_TEXT_SCROLLBAR_WIDTH;
    priv->current_font_size = ATK_RICH_TEXT_DEFAULT_FONT;
    priv->last_width = width;
    priv->last_height = height;
    priv->layout_dirty = true;
    priv->focused = false;
    priv->row_buffer = NULL;
    priv->row_buffer_capacity = 0;
    priv->change = NULL;
    priv->change_context = NULL;
    priv->selecting = false;
    priv->sel_anchor = 0;
    priv->sel_start = 0;
    priv->sel_end = 0;

    atk_list_node_t *child_node = atk_list_push_back(&wpriv->children, editor);
    if (!child_node)
    {
        atk_widget_destroy(editor);
        return NULL;
    }
    priv->list_node = child_node;

    int sb_x = x + width - priv->scrollbar_width;
    if (sb_x < x)
    {
        sb_x = x;
    }
    atk_widget_t *scrollbar = atk_window_add_scrollbar(window,
                                                       sb_x,
                                                       y,
                                                       priv->scrollbar_width,
                                                       height,
                                                       ATK_SCROLLBAR_VERTICAL);
    if (scrollbar)
    {
        priv->scrollbar = scrollbar;
        atk_scrollbar_set_change_handler(scrollbar, rich_text_scrollbar_changed, editor);
        rich_text_update_scrollbar(priv);
    }

    return editor;
}

void atk_rich_text_focus(atk_state_t *state, atk_widget_t *editor)
{
    if (!state)
    {
        return;
    }

    atk_widget_t *current = atk_state_focus_widget(state);
    if (current && current != editor && atk_widget_is_a(current, &ATK_RICH_TEXT_CLASS))
    {
        atk_rich_text_priv_t *curr_priv = rich_text_priv_mut(current);
        if (curr_priv)
        {
            curr_priv->focused = false;
            rich_text_invalidate(current);
        }
    }

    if (editor && atk_widget_validate(editor, "atk_rich_text_focus"))
    {
        atk_rich_text_priv_t *priv = rich_text_priv_mut(editor);
        if (priv)
        {
            priv->focused = true;
            rich_text_invalidate(editor);
        }
        atk_state_set_focus_widget(state, editor);
    }
}

void atk_rich_text_set_font_size(atk_widget_t *editor, int size_px)
{
    atk_rich_text_priv_t *priv = rich_text_priv_mut(editor);
    if (!priv)
    {
        return;
    }
    int clamped = rich_text_clamp_font_size(size_px);
    if (clamped == priv->current_font_size)
    {
        return;
    }
    priv->current_font_size = clamped;
    priv->layout_dirty = true;
    rich_text_invalidate(editor);
}

void atk_rich_text_apply_font_size(atk_widget_t *editor, int size_px)
{
    atk_rich_text_priv_t *priv = rich_text_priv_mut(editor);
    if (!priv)
    {
        return;
    }
    int clamped = rich_text_clamp_font_size(size_px);

    /* Update default font for new text regardless of selection. */
    priv->current_font_size = clamped;

    /* If no selection or no buffer, just mark dirty and exit. */
    if (!priv->chars || priv->sel_start == priv->sel_end || priv->length == 0)
    {
        priv->layout_dirty = true;
        rich_text_invalidate(editor);
        return;
    }

    size_t start = priv->sel_start;
    size_t end = priv->sel_end;
    if (start > priv->length) start = priv->length;
    if (end > priv->length) end = priv->length;
    if (start > end)
    {
        size_t tmp = start;
        start = end;
        end = tmp;
    }

    for (size_t i = start; i < end; ++i)
    {
        priv->chars[i].size = clamped;
    }

    priv->layout_dirty = true;
    rich_text_invalidate(editor);
}

int atk_rich_text_current_font_size(const atk_widget_t *editor)
{
    const atk_rich_text_priv_t *priv = rich_text_priv(editor);
    return priv ? priv->current_font_size : ATK_RICH_TEXT_DEFAULT_FONT;
}

void atk_rich_text_set_text(atk_widget_t *editor, const char *text)
{
    atk_rich_text_priv_t *priv = rich_text_priv_mut(editor);
    if (!priv)
    {
        return;
    }
    rich_text_clear(editor, priv);
    if (!text)
    {
        rich_text_invalidate(editor);
        return;
    }

    size_t len = strlen(text);
    if (len == 0)
    {
        rich_text_invalidate(editor);
        return;
    }

    if (!priv->chars && len > 0)
    {
        size_t cap = len + 16;
        priv->chars = (atk_rich_char_t *)malloc(cap * sizeof(atk_rich_char_t));
        if (!priv->chars)
        {
            return;
        }
        priv->capacity = cap;
    }

    for (size_t i = 0; i < len; ++i)
    {
        if (priv->length >= priv->capacity)
        {
            size_t new_cap = priv->capacity ? priv->capacity * 2 : len + 16;
            atk_rich_char_t *buf = (atk_rich_char_t *)realloc(priv->chars, new_cap * sizeof(atk_rich_char_t));
            if (!buf)
            {
                break;
            }
            priv->chars = buf;
            priv->capacity = new_cap;
        }
        priv->chars[priv->length].ch = text[i];
        priv->chars[priv->length].size = priv->current_font_size;
        priv->length++;
    }
    priv->cursor = priv->length;
    priv->layout_dirty = true;
    rich_text_notify_change(editor, priv);
    rich_text_invalidate(editor);
}

void atk_rich_text_append(atk_widget_t *editor, const char *text)
{
    if (!text || *text == '\0')
    {
        return;
    }
    atk_rich_text_priv_t *priv = rich_text_priv_mut(editor);
    if (!priv)
    {
        return;
    }

    size_t add_len = strlen(text);
    if (priv->length + add_len > priv->capacity)
    {
        size_t new_cap = priv->capacity ? priv->capacity : 64;
        while (new_cap < priv->length + add_len)
        {
            new_cap *= 2;
        }
        atk_rich_char_t *buf = (atk_rich_char_t *)realloc(priv->chars, new_cap * sizeof(atk_rich_char_t));
        if (!buf)
        {
            return;
        }
        priv->chars = buf;
        priv->capacity = new_cap;
    }

    for (size_t i = 0; i < add_len; ++i)
    {
        priv->chars[priv->length + i].ch = text[i];
        priv->chars[priv->length + i].size = priv->current_font_size;
    }
    priv->length += add_len;
    priv->cursor = priv->length;
    priv->layout_dirty = true;
    rich_text_notify_change(editor, priv);
    rich_text_invalidate(editor);
}

void atk_rich_text_scroll_to_top(atk_widget_t *editor)
{
    atk_rich_text_priv_t *priv = rich_text_priv_mut(editor);
    if (!priv)
    {
        return;
    }
    if (priv->scroll_y != 0)
    {
        priv->scroll_y = 0;
        rich_text_update_scrollbar(priv);
        rich_text_invalidate(editor);
    }
}

void atk_rich_text_scroll_to_bottom(atk_widget_t *editor)
{
    atk_rich_text_priv_t *priv = rich_text_priv_mut(editor);
    if (!priv)
    {
        return;
    }
    if (!rich_text_update_layout(editor, priv))
    {
        return;
    }
    int max_scroll = priv->content_height - priv->view_height;
    if (max_scroll < 0)
    {
        max_scroll = 0;
    }
    if (priv->scroll_y != max_scroll)
    {
        priv->scroll_y = max_scroll;
        rich_text_update_scrollbar(priv);
        rich_text_invalidate(editor);
    }
}

void atk_rich_text_set_change_handler(atk_widget_t *editor, atk_rich_text_change_t handler, void *context)
{
    atk_rich_text_priv_t *priv = rich_text_priv_mut(editor);
    if (!priv)
    {
        return;
    }
    priv->change = handler;
    priv->change_context = context;
}

static atk_rich_text_priv_t *rich_text_priv_mut(atk_widget_t *editor)
{
    if (!editor)
    {
        return NULL;
    }
    return (atk_rich_text_priv_t *)atk_widget_priv(editor, &ATK_RICH_TEXT_CLASS);
}

static const atk_rich_text_priv_t *rich_text_priv(const atk_widget_t *editor)
{
    if (!editor)
    {
        return NULL;
    }
    return (const atk_rich_text_priv_t *)atk_widget_priv(editor, &ATK_RICH_TEXT_CLASS);
}

static void rich_text_invalidate(const atk_widget_t *editor)
{
    if (!editor || !editor->parent)
    {
        return;
    }
    int origin_x = editor->parent->x + editor->x;
    int origin_y = editor->parent->y + editor->y;
    atk_dirty_mark_rect(origin_x, origin_y, editor->width, editor->height);
    video_request_refresh_window(editor->parent);
}

static bool rich_row_buffer_ensure(atk_rich_text_priv_t *priv, int width)
{
    if (!priv || width <= 0)
    {
        return false;
    }
    if (width <= priv->row_buffer_capacity)
    {
        return true;
    }
    int new_cap = priv->row_buffer_capacity ? priv->row_buffer_capacity : 64;
    while (new_cap < width)
    {
        new_cap *= 2;
    }
    video_color_t *buf = (video_color_t *)realloc(priv->row_buffer, (size_t)new_cap * sizeof(video_color_t));
    if (!buf)
    {
        return false;
    }
    priv->row_buffer = buf;
    priv->row_buffer_capacity = new_cap;
    return true;
}

static int rich_text_clamp_font_size(int size)
{
    if (size < ATK_RICH_TEXT_MIN_FONT)
    {
        return ATK_RICH_TEXT_MIN_FONT;
    }
    if (size > ATK_RICH_TEXT_MAX_FONT)
    {
        return ATK_RICH_TEXT_MAX_FONT;
    }
    return size;
}

static int rich_text_fallback_advance(int size, char ch)
{
    (void)ch;
    int base = size / 2;
    if (base < ATK_FONT_WIDTH)
    {
        base = ATK_FONT_WIDTH;
    }
    return base;
}

static void rich_text_notify_change(atk_widget_t *editor, atk_rich_text_priv_t *priv)
{
    if (priv && priv->change)
    {
        priv->change(editor, priv->change_context);
    }
}

static void rich_text_clear_selection(atk_rich_text_priv_t *priv)
{
    if (!priv)
    {
        return;
    }
    priv->selecting = false;
    priv->sel_anchor = priv->cursor;
    priv->sel_start = priv->cursor;
    priv->sel_end = priv->cursor;
}

static void rich_text_set_selection(atk_rich_text_priv_t *priv, size_t a, size_t b)
{
    if (!priv)
    {
        return;
    }
    size_t lo = (a < b) ? a : b;
    size_t hi = (a < b) ? b : a;
    if (lo > priv->length) lo = priv->length;
    if (hi > priv->length) hi = priv->length;
    priv->sel_start = lo;
    priv->sel_end = hi;
}

static void rich_text_clear(atk_widget_t *editor, atk_rich_text_priv_t *priv)
{
    (void)editor;
    if (!priv)
    {
        return;
    }
    if (priv->chars)
    {
        free(priv->chars);
        priv->chars = NULL;
    }
    if (priv->lines)
    {
        free(priv->lines);
        priv->lines = NULL;
    }
    priv->capacity = 0;
    priv->length = 0;
    priv->cursor = 0;
    priv->line_capacity = 0;
    priv->line_count = 0;
    priv->layout_dirty = true;
    priv->scroll_y = 0;
    rich_text_clear_selection(priv);
}

static bool rich_text_insert_char(atk_widget_t *editor, atk_rich_text_priv_t *priv, char ch)
{
    if (!priv)
    {
        return false;
    }
    if (!priv->chars || priv->capacity == 0)
    {
        size_t cap = 64;
        priv->chars = (atk_rich_char_t *)malloc(cap * sizeof(atk_rich_char_t));
        if (!priv->chars)
        {
            return false;
        }
        priv->capacity = cap;
    }
    if (priv->length + 1 > priv->capacity)
    {
        size_t new_cap = priv->capacity * 2;
        atk_rich_char_t *buf = (atk_rich_char_t *)realloc(priv->chars, new_cap * sizeof(atk_rich_char_t));
        if (!buf)
        {
            return false;
        }
        priv->chars = buf;
        priv->capacity = new_cap;
    }

    if (priv->cursor < priv->length)
    {
        memmove(priv->chars + priv->cursor + 1,
                priv->chars + priv->cursor,
                (priv->length - priv->cursor) * sizeof(atk_rich_char_t));
    }
    priv->chars[priv->cursor].ch = ch;
    priv->chars[priv->cursor].size = priv->current_font_size;
    priv->cursor++;
    priv->length++;
    priv->layout_dirty = true;
    rich_text_clear_selection(priv);
    rich_text_notify_change(editor, priv);
    return true;
}

static bool rich_text_backspace(atk_widget_t *editor, atk_rich_text_priv_t *priv)
{
    if (!priv || priv->cursor == 0 || priv->length == 0)
    {
        return false;
    }
    if (priv->cursor < priv->length)
    {
        memmove(priv->chars + priv->cursor - 1,
                priv->chars + priv->cursor,
                (priv->length - priv->cursor) * sizeof(atk_rich_char_t));
    }
    priv->cursor--;
    priv->length--;
    priv->layout_dirty = true;
    rich_text_clear_selection(priv);
    rich_text_notify_change(editor, priv);
    return true;
}

static void rich_text_position_scrollbar(atk_widget_t *editor, atk_rich_text_priv_t *priv)
{
    if (!editor || !priv || !priv->scrollbar)
    {
        return;
    }

    int sb_width = priv->scrollbar_width;
    if (sb_width < 1)
    {
        sb_width = 1;
    }
    if (sb_width > editor->width)
    {
        sb_width = editor->width;
    }

    atk_widget_t *scrollbar = priv->scrollbar;
    scrollbar->x = editor->x + editor->width - sb_width;
    scrollbar->y = editor->y;
    scrollbar->width = sb_width;
    scrollbar->height = editor->height;
    atk_scrollbar_mark_dirty(scrollbar);
}

static void rich_text_update_scrollbar(atk_rich_text_priv_t *priv)
{
    if (!priv || !priv->scrollbar)
    {
        return;
    }
    int max_scroll = priv->content_height - priv->view_height;
    if (max_scroll < 0)
    {
        max_scroll = 0;
    }
    atk_scrollbar_set_range(priv->scrollbar, 0, max_scroll, priv->view_height);
    atk_scrollbar_set_value(priv->scrollbar, priv->scroll_y);
}

static void rich_text_scrollbar_changed(atk_widget_t *scrollbar, void *context, int value)
{
    (void)scrollbar;
    atk_widget_t *editor = (atk_widget_t *)context;
    atk_rich_text_priv_t *priv = rich_text_priv_mut(editor);
    if (!priv)
    {
        return;
    }
    int max_scroll = priv->content_height - priv->view_height;
    if (max_scroll < 0)
    {
        max_scroll = 0;
    }
    if (value < 0)
    {
        value = 0;
    }
    if (value > max_scroll)
    {
        value = max_scroll;
    }
    if (priv->scroll_y != value)
    {
        priv->scroll_y = value;
        rich_text_invalidate(editor);
    }
}

static bool rich_text_update_layout(atk_widget_t *editor, atk_rich_text_priv_t *priv)
{
    if (!editor || !priv)
    {
        return false;
    }

    /* If we lost the char buffer, forget the text to avoid OOB. */
    if (priv->length > 0 && !priv->chars)
    {
        priv->length = 0;
        priv->capacity = 0;
        priv->cursor = 0;
        rich_text_clear_selection(priv);
    }

    if (editor->width != priv->last_width || editor->height != priv->last_height)
    {
        priv->last_width = editor->width;
        priv->last_height = editor->height;
        priv->layout_dirty = true;
    }

    int viewport_width = editor->width - priv->scrollbar_width - ATK_RICH_TEXT_PADDING * 2;
    int viewport_height = editor->height - ATK_RICH_TEXT_PADDING * 2;
    if (viewport_width < 1) viewport_width = 1;
    if (viewport_height < 1) viewport_height = 1;
    priv->view_width = viewport_width;
    priv->view_height = viewport_height;

    if (!priv->layout_dirty)
    {
        return true;
    }

    if (priv->line_capacity == 0)
    {
        priv->line_capacity = 16;
        priv->lines = (atk_rich_line_t *)malloc(priv->line_capacity * sizeof(atk_rich_line_t));
        if (!priv->lines)
        {
            priv->line_capacity = 0;
            return false;
        }
    }

    priv->line_count = 0;
    int x = 0;
    int y = ATK_RICH_TEXT_PADDING;
    int line_ascent = 0;
    int line_descent = 0;
    int line_height = 0;
    size_t line_start = 0;

    size_t idx = 0;
    while (true)
    {
        bool at_end = (idx >= priv->length);
        char ch = '\n';
        int ch_size = priv->current_font_size;
        if (!at_end && priv->chars)
        {
            ch = priv->chars[idx].ch;
            ch_size = priv->chars[idx].size;
        }
        ch_size = rich_text_clamp_font_size(ch_size);

        atk_rich_font_size_cache_t *cache = rich_font_cache_for_size(ch_size);
        ttf_font_metrics_t metrics = { 0 };
        if (cache)
        {
            metrics = cache->metrics;
        }
        int ascent = metrics.ascent;
        int descent = metrics.descent;
        if (ascent < 0) ascent = -ascent;
        if (descent < 0) descent = -descent;
        int gap = metrics.line_gap;
        if (gap < 0) gap = 0;

        if (ascent > line_ascent) line_ascent = ascent;
        if (descent > line_descent) line_descent = descent;
        int computed_height = ascent + descent + gap;
        if (computed_height < ATK_FONT_HEIGHT)
        {
            computed_height = ATK_FONT_HEIGHT;
        }
        if (computed_height > line_height) line_height = computed_height;

        int advance = 0;
        if (!at_end && ch != '\n')
        {
            atk_rich_glyph_t *glyph = rich_font_get_glyph(cache, (uint32_t)(unsigned char)ch);
            if (glyph && glyph->ready)
            {
                advance = glyph->advance;
            }
            else
            {
                advance = rich_text_fallback_advance(ch_size, ch);
            }
            if (advance < 1)
            {
                advance = ch_size / 2;
            }
        }

        bool newline = (!at_end && ch == '\n');
        bool wrap = (!newline && !at_end && x > 0 && (x + advance) > viewport_width);
        if (newline || wrap || at_end)
        {
            if (priv->line_count >= priv->line_capacity)
            {
                size_t new_cap = priv->line_capacity * 2;
                atk_rich_line_t *tmp = (atk_rich_line_t *)realloc(priv->lines, new_cap * sizeof(atk_rich_line_t));
                if (!tmp)
                {
                    return false;
                }
                priv->lines = tmp;
                priv->line_capacity = new_cap;
            }
            atk_rich_line_t *line = &priv->lines[priv->line_count++];
            line->start = line_start;
            line->end = idx;
            line->top = y;
            line->height = line_height + ATK_RICH_TEXT_LINE_SPACING;
            int baseline_offset = line_ascent;
            if (baseline_offset <= 0)
            {
                baseline_offset = line_height - line_descent;
            }
            line->baseline = y + baseline_offset;

            y += line->height;
            x = 0;
            line_ascent = 0;
            line_descent = 0;
            line_height = 0;
            line_start = newline ? idx + 1 : idx;
            if (wrap && !newline && !at_end)
            {
                continue;
            }
        }

        if (at_end)
        {
            break;
        }

        if (ch != '\n')
        {
            x += advance;
        }
        idx++;
    }

    priv->content_height = y + ATK_RICH_TEXT_PADDING;
    if (priv->content_height < editor->height)
    {
        priv->content_height = editor->height;
    }

    if (priv->scroll_y < 0)
    {
        priv->scroll_y = 0;
    }
    int max_scroll = priv->content_height - priv->view_height;
    if (max_scroll < 0)
    {
        max_scroll = 0;
    }
    if (priv->scroll_y > max_scroll)
    {
        priv->scroll_y = max_scroll;
    }

    rich_text_position_scrollbar(editor, priv);
    rich_text_update_scrollbar(priv);
    priv->layout_dirty = false;
    return true;
}

static bool rich_text_cursor_rect(const atk_widget_t *editor,
                                  atk_rich_text_priv_t *priv,
                                  int origin_x,
                                  int origin_y,
                                  int *x_out,
                                  int *y_out,
                                  int *h_out)
{
    if (!editor || !priv)
    {
        return false;
    }
    if (priv->line_count == 0)
    {
        if (x_out) *x_out = origin_x + editor->x + ATK_RICH_TEXT_PADDING;
        if (y_out) *y_out = origin_y + editor->y + ATK_RICH_TEXT_PADDING - priv->scroll_y;
        if (h_out) *h_out = ATK_FONT_HEIGHT;
        return true;
    }

    size_t cursor = priv->cursor;
    const atk_rich_line_t *line = &priv->lines[priv->line_count - 1];
    for (size_t i = 0; i < priv->line_count; ++i)
    {
        const atk_rich_line_t *candidate = &priv->lines[i];
        if (cursor >= candidate->start && cursor <= candidate->end)
        {
            line = candidate;
            break;
        }
    }

    int pen_x = 0;
    for (size_t idx = line->start; idx < cursor && idx < priv->length; ++idx)
    {
        int size_px = rich_text_clamp_font_size(priv->chars[idx].size);
        atk_rich_font_size_cache_t *cache = rich_font_cache_for_size(size_px);
        atk_rich_glyph_t *glyph = rich_font_get_glyph(cache, (uint32_t)(unsigned char)priv->chars[idx].ch);
        if (glyph && glyph->ready)
        {
            pen_x += glyph->advance;
        }
        else
        {
            pen_x += rich_text_fallback_advance(size_px, priv->chars[idx].ch);
        }
    }

    int caret_height = line->height;
    int caret_x = origin_x + editor->x + ATK_RICH_TEXT_PADDING + pen_x;
    int caret_y = origin_y + editor->y + line->top - priv->scroll_y;

    if (x_out) *x_out = caret_x;
    if (y_out) *y_out = caret_y;
    if (h_out) *h_out = caret_height;
    return true;
}

static void rich_text_ensure_cursor_visible(atk_widget_t *editor, atk_rich_text_priv_t *priv)
{
    if (!editor || !priv)
    {
        return;
    }
    if (!rich_text_update_layout(editor, priv))
    {
        return;
    }

    int caret_x = 0;
    int caret_y = 0;
    int caret_h = ATK_FONT_HEIGHT;
    if (!rich_text_cursor_rect(editor, priv, 0, 0, &caret_x, &caret_y, &caret_h))
    {
        return;
    }

    int rel_y = caret_y - editor->y;
    int visible_top = ATK_RICH_TEXT_PADDING;
    int visible_bottom = ATK_RICH_TEXT_PADDING + priv->view_height;

    if (rel_y < visible_top)
    {
        priv->scroll_y += rel_y - visible_top;
        if (priv->scroll_y < 0)
        {
            priv->scroll_y = 0;
        }
        rich_text_update_scrollbar(priv);
    }
    else if (rel_y + caret_h > visible_bottom)
    {
        priv->scroll_y += (rel_y + caret_h) - visible_bottom;
        int max_scroll = priv->content_height - priv->view_height;
        if (max_scroll < 0)
        {
            max_scroll = 0;
        }
        if (priv->scroll_y > max_scroll)
        {
            priv->scroll_y = max_scroll;
        }
        rich_text_update_scrollbar(priv);
    }
}

static size_t rich_text_index_for_point(atk_widget_t *editor, atk_rich_text_priv_t *priv, int local_x, int local_y)
{
    if (!editor || !priv || priv->line_count == 0)
    {
        return 0;
    }
    int target_y = local_y + priv->scroll_y;
    size_t line_index = 0;
    for (size_t i = 0; i < priv->line_count; ++i)
    {
        const atk_rich_line_t *line = &priv->lines[i];
        if (target_y >= line->top && target_y < line->top + line->height)
        {
            line_index = i;
            break;
        }
        if (target_y < line->top)
        {
            line_index = i;
            break;
        }
        line_index = i;
    }
    const atk_rich_line_t *line = &priv->lines[line_index];
    int x = local_x - ATK_RICH_TEXT_PADDING;
    if (x <= 0)
    {
        return line->start;
    }

    if (!priv->chars || priv->length == 0)
    {
        return line->start;
    }

    int pen_x = 0;
    size_t idx = line->start;
    while (idx < line->end && idx < priv->length)
    {
        int size_px = rich_text_clamp_font_size(priv->chars ? priv->chars[idx].size : priv->current_font_size);
        atk_rich_font_size_cache_t *cache = rich_font_cache_for_size(size_px);
        atk_rich_glyph_t *glyph = rich_font_get_glyph(cache, (uint32_t)(unsigned char)priv->chars[idx].ch);
        int advance = 0;
        if (glyph && glyph->ready)
        {
            advance = glyph->advance;
        }
        else
        {
            advance = rich_text_fallback_advance(size_px, priv->chars[idx].ch);
        }
        if (pen_x + advance / 2 >= x)
        {
            return idx;
        }
        pen_x += advance;
        idx++;
    }
    return line->end;
}

static atk_mouse_response_t rich_text_mouse_cb(atk_widget_t *widget,
                                               const atk_mouse_event_t *event,
                                               void *context)
{
    (void)context;
    if (!widget || !event)
    {
        return ATK_MOUSE_RESPONSE_NONE;
    }
    atk_rich_text_priv_t *priv = rich_text_priv_mut(widget);
    if (!priv)
    {
        return ATK_MOUSE_RESPONSE_NONE;
    }

    atk_state_t *state = atk_state_get();
    atk_rich_text_focus(state, widget);

    if (priv->length > 0 && !priv->chars)
    {
        priv->length = 0;
        priv->capacity = 0;
        priv->cursor = 0;
        rich_text_clear_selection(priv);
    }

    rich_text_update_layout(widget, priv);
    size_t idx = rich_text_index_for_point(widget, priv, event->local_x, event->local_y);
    if (idx > priv->length)
    {
        idx = priv->length;
    }

    if (event->pressed_edge && event->left_pressed)
    {
        priv->selecting = true;
        priv->sel_anchor = idx;
        rich_text_set_selection(priv, idx, idx);
        priv->cursor = idx;
        rich_text_ensure_cursor_visible(widget, priv);
        rich_text_invalidate(widget);
        return ATK_MOUSE_RESPONSE_HANDLED | ATK_MOUSE_RESPONSE_REDRAW | ATK_MOUSE_RESPONSE_CAPTURE;
    }

    if (priv->selecting && event->left_pressed)
    {
        rich_text_set_selection(priv, priv->sel_anchor, idx);
        priv->cursor = idx;
        rich_text_ensure_cursor_visible(widget, priv);
        rich_text_invalidate(widget);
        return ATK_MOUSE_RESPONSE_HANDLED | ATK_MOUSE_RESPONSE_REDRAW | ATK_MOUSE_RESPONSE_CAPTURE;
    }

    if (event->released_edge && priv->selecting)
    {
        priv->selecting = false;
        return ATK_MOUSE_RESPONSE_HANDLED | ATK_MOUSE_RESPONSE_REDRAW | ATK_MOUSE_RESPONSE_RELEASE;
    }

    return ATK_MOUSE_RESPONSE_NONE;
}

static bool rich_text_hit_test_cb(const atk_widget_t *widget,
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

static void rich_text_draw_cb(const atk_state_t *state,
                              const atk_widget_t *widget,
                              int origin_x,
                              int origin_y,
                              void *context)
{
    (void)context;
    if (!state || !widget)
    {
        return;
    }
    const atk_theme_t *theme = &state->theme;
    atk_rich_text_priv_t *priv = rich_text_priv_mut((atk_widget_t *)widget);
    if (!priv)
    {
        return;
    }

    int abs_x = origin_x + widget->x;
    int abs_y = origin_y + widget->y;

    video_draw_rect(abs_x, abs_y, widget->width, widget->height, theme->window_body);
    video_draw_rect_outline(abs_x, abs_y, widget->width, widget->height, theme->window_border);

    if (!rich_text_update_layout((atk_widget_t *)widget, priv))
    {
        return;
    }

    int content_left = abs_x + ATK_RICH_TEXT_PADDING;
    int content_top = abs_y;
    int clip_x0 = abs_x;
    int clip_y0 = abs_y;
    int clip_x1 = abs_x + widget->width;
    int clip_y1 = abs_y + widget->height;

    for (size_t line_idx = 0; line_idx < priv->line_count; ++line_idx)
    {
        const atk_rich_line_t *line = &priv->lines[line_idx];
        int line_top = content_top + line->top - priv->scroll_y;
        int line_bottom = line_top + line->height;
        if (line_bottom <= clip_y0 || line_top >= clip_y1)
        {
            continue;
        }

        int pen_x = content_left;
        for (size_t idx = line->start; idx < line->end && idx < priv->length; ++idx)
        {
            if (!priv->chars)
            {
                break;
            }
            char ch = priv->chars[idx].ch;
            int size_px = rich_text_clamp_font_size(priv->chars[idx].size);
            atk_rich_font_size_cache_t *cache = rich_font_cache_for_size(size_px);
            atk_rich_glyph_t *glyph = rich_font_get_glyph(cache, (uint32_t)(unsigned char)ch);
            int advance = 0;
            bool selected = (priv->sel_start != priv->sel_end) &&
                            (idx >= priv->sel_start && idx < priv->sel_end) &&
                            ch != '\n';
            if (selected)
            {
                int bg_x0 = pen_x;
                int bg_y0 = line_top;
                int bg_w = 0;
                if (glyph && glyph->ready)
                {
                    bg_w = glyph->advance;
                }
                else
                {
                    bg_w = rich_text_fallback_advance(size_px, ch);
                }
                int bg_x1 = bg_x0 + bg_w;
                if (bg_x0 < clip_x0) bg_x0 = clip_x0;
                if (bg_x1 > clip_x1) bg_x1 = clip_x1;
                if (bg_x1 > bg_x0)
                {
                    video_draw_rect(bg_x0, bg_y0, bg_x1 - bg_x0, line->height, theme->menu_bar_highlight);
                }
            }
            if (glyph && glyph->ready)
            {
                const uint8_t *glyph_alpha = glyph->alpha;
                int glyph_w = glyph->width;
                int glyph_h = glyph->height;
                int glyph_stride = glyph->stride;

                if (glyph_alpha && glyph_w > 0 && glyph_h > 0 && glyph_stride > 0)
                {
                    int dst_x = pen_x + glyph->bearing_x;
                    int dst_y = abs_y + line->baseline - priv->scroll_y - glyph->bearing_y;
                    int glyph_x0 = dst_x;
                    int glyph_y0 = dst_y;
                    int glyph_x1 = glyph_x0 + glyph_w;
                    int glyph_y1 = glyph_y0 + glyph_h;

                    if (!(glyph_x1 <= clip_x0 || glyph_x0 >= clip_x1 || glyph_y1 <= clip_y0 || glyph_y0 >= clip_y1))
                    {
                        int visible_x0 = (glyph_x0 < clip_x0) ? clip_x0 : glyph_x0;
                        int visible_x1 = (glyph_x1 > clip_x1) ? clip_x1 : glyph_x1;
                        int visible_y0 = (glyph_y0 < clip_y0) ? clip_y0 : glyph_y0;
                        int visible_y1 = (glyph_y1 > clip_y1) ? clip_y1 : glyph_y1;

                        int start_col = visible_x0 - glyph_x0;
                        int start_row = visible_y0 - glyph_y0;
                        int draw_width = visible_x1 - visible_x0;
                        int draw_rows = visible_y1 - visible_y0;
                        if (start_col < 0) start_col = 0;
                        if (start_row < 0) start_row = 0;

                        if (start_col < glyph_stride && start_row < glyph_h &&
                            draw_width > 0 && draw_rows > 0 &&
                            rich_row_buffer_ensure(priv, draw_width))
                        {
                            if (draw_width > glyph_stride - start_col)
                            {
                                draw_width = glyph_stride - start_col;
                            }
                            if (draw_rows > glyph_h - start_row)
                            {
                                draw_rows = glyph_h - start_row;
                            }

                            for (int row = 0; row < draw_rows; ++row)
                            {
                                const uint8_t *src = glyph_alpha + (start_row + row) * glyph_stride + start_col;
                                for (int col = 0; col < draw_width; ++col)
                                {
                                    uint8_t alpha = src[col];
                                    priv->row_buffer[col] = ((video_color_t)alpha << 24) | (theme->button_text & 0x00FFFFFFu);
                                }
                                video_blit_rgba32(visible_x0,
                                                  visible_y0 + row,
                                                  draw_width,
                                                  1,
                                                  priv->row_buffer,
                                                  draw_width * (int)sizeof(video_color_t),
                                                  true);
                            }
                        }
                    }
                    advance = glyph->advance;
                }
                else
                {
                    advance = rich_text_fallback_advance(size_px, ch);
                }
            }
            else
            {
                advance = rich_text_fallback_advance(size_px, ch);
            }
            pen_x += advance;
        }
    }

    if (priv->focused)
    {
        int caret_x = 0;
        int caret_y = 0;
        int caret_h = ATK_FONT_HEIGHT;
        if (rich_text_cursor_rect(widget, priv, origin_x, origin_y, &caret_x, &caret_y, &caret_h))
        {
            if (caret_y < clip_y0)
            {
                int delta = clip_y0 - caret_y;
                caret_y += delta;
                caret_h -= delta;
            }
            if (caret_y + caret_h > clip_y1)
            {
                caret_h = clip_y1 - caret_y;
            }
            if (caret_h > 0)
            {
                video_draw_rect(caret_x, caret_y, 2, caret_h, theme->window_title);
            }
        }
    }
}

static void rich_text_destroy_cb(atk_widget_t *widget, void *context)
{
    (void)context;
    atk_rich_text_priv_t *priv = rich_text_priv_mut(widget);
    if (priv)
    {
        if (widget && widget->parent && priv->list_node)
        {
            atk_window_priv_t *wpriv = (atk_window_priv_t *)atk_widget_priv(widget->parent, &ATK_WINDOW_CLASS);
            if (wpriv)
            {
                atk_list_remove(&wpriv->children, priv->list_node);
            }
        }
        if (priv->chars)
        {
            free(priv->chars);
            priv->chars = NULL;
        }
        if (priv->lines)
        {
            free(priv->lines);
            priv->lines = NULL;
        }
        if (priv->row_buffer)
        {
            free(priv->row_buffer);
            priv->row_buffer = NULL;
        }
        priv->capacity = 0;
        priv->length = 0;
        priv->line_capacity = 0;
        priv->line_count = 0;
        priv->list_node = NULL;
        priv->scrollbar = NULL;
    }
    atk_widget_destroy(widget);
}

static atk_key_response_t rich_text_key_cb(atk_widget_t *widget,
                                           int key,
                                           int modifiers,
                                           int action,
                                           void *context)
{
    (void)modifiers;
    (void)action;
    (void)context;
    if (!widget)
    {
        return ATK_KEY_RESPONSE_NONE;
    }
    atk_rich_text_priv_t *priv = rich_text_priv_mut(widget);
    if (!priv)
    {
        return ATK_KEY_RESPONSE_NONE;
    }

    char ch = (char)key;
    bool handled = false;
    if (ch == '\b' || ch == 0x7F)
    {
        handled = rich_text_backspace(widget, priv);
    }
    else if (ch == '\r' || ch == '\n')
    {
        handled = rich_text_insert_char(widget, priv, '\n');
    }
    else if ((unsigned char)ch >= 32)
    {
        handled = rich_text_insert_char(widget, priv, ch);
    }

    if (handled)
    {
        priv->layout_dirty = true;
        rich_text_update_layout(widget, priv);
        rich_text_ensure_cursor_visible(widget, priv);
        rich_text_invalidate(widget);
        return ATK_KEY_RESPONSE_HANDLED | ATK_KEY_RESPONSE_REDRAW;
    }
    return ATK_KEY_RESPONSE_NONE;
}

static bool rich_font_load(void)
{
    if (g_font_state.ready)
    {
        return true;
    }

    uint8_t *blob = NULL;
    size_t blob_size = 0;

#if ATK_NO_DESKTOP_APPS
    if (!rich_font_read_user(&blob, &blob_size))
    {
        return false;
    }
    g_font_state.blob_owned = true;
#else
    vfs_node_t *node = vfs_open_file(vfs_root(), ATK_RICH_TEXT_FONT_PATH, false, false);
    if (!node)
    {
        return false;
    }
    size_t size = 0;
    const char *data = vfs_data(node, &size);
    if (!data || size == 0)
    {
        return false;
    }
    blob = (uint8_t *)data;
    blob_size = size;
    g_font_state.blob_owned = false;
#endif

    if (!blob || blob_size == 0)
    {
        return false;
    }

    if (!ttf_font_load(&g_font_state.font, blob, blob_size))
    {
        if (g_font_state.blob_owned)
        {
            free(blob);
        }
        return false;
    }

    g_font_state.blob = blob;
    g_font_state.blob_size = blob_size;
    g_font_state.ready = true;
    return true;
}

#if ATK_NO_DESKTOP_APPS
static bool rich_font_read_user(uint8_t **data_out, size_t *size_out)
{
    if (!data_out || !size_out)
    {
        return false;
    }
    *data_out = NULL;
    *size_out = 0;

    ssize_t size = sys_font_cache(NULL, 0);
    if (size <= 0)
    {
        return false;
    }

    uint8_t *buffer = (uint8_t *)malloc((size_t)size);
    if (!buffer)
    {
        return false;
    }

    ssize_t got = sys_font_cache(buffer, (size_t)size);
    if (got <= 0)
    {
        free(buffer);
        return false;
    }
    *data_out = buffer;
    *size_out = (size_t)got;
    return true;
}
#endif

static atk_rich_font_size_cache_t *rich_font_cache_for_size(int size)
{
    size = rich_text_clamp_font_size(size);
    if (!rich_font_load())
    {
        return NULL;
    }

    for (size_t i = 0; i < ATK_RICH_TEXT_CACHE_SLOTS; ++i)
    {
        atk_rich_font_size_cache_t *cache = &g_font_state.caches[i];
        if (cache->used && cache->size_px == size)
        {
            return cache;
        }
    }

    size_t slot = 0;
    for (; slot < ATK_RICH_TEXT_CACHE_SLOTS; ++slot)
    {
        if (!g_font_state.caches[slot].used)
        {
            break;
        }
    }
    if (slot >= ATK_RICH_TEXT_CACHE_SLOTS)
    {
        slot = 0;
    }

    atk_rich_font_size_cache_t *cache = &g_font_state.caches[slot];
    memset(cache, 0, sizeof(*cache));
    cache->used = true;
    cache->size_px = size;
    if (!ttf_font_metrics(&g_font_state.font, size, &cache->metrics))
    {
        cache->metrics.ascent = size;
        cache->metrics.descent = size / 4;
        cache->metrics.line_gap = ATK_RICH_TEXT_LINE_SPACING;
    }
    return cache;
}

static atk_rich_glyph_t *rich_font_get_glyph(atk_rich_font_size_cache_t *cache, uint32_t codepoint)
{
    if (!cache)
    {
        return NULL;
    }
    if (codepoint < ATK_RICH_TEXT_GLYPH_FIRST || codepoint > ATK_RICH_TEXT_GLYPH_LAST)
    {
        codepoint = '?';
    }
    size_t idx = (size_t)(codepoint - ATK_RICH_TEXT_GLYPH_FIRST);
    if (idx >= ATK_RICH_TEXT_GLYPH_COUNT)
    {
        return NULL;
    }

    atk_rich_glyph_t *glyph = &cache->glyphs[idx];
    if (glyph->ready)
    {
        return glyph;
    }

    ttf_bitmap_t bitmap = { 0 };
    ttf_glyph_metrics_t metrics = { 0 };
    if (!ttf_font_render_glyph_bitmap(&g_font_state.font,
                                      codepoint,
                                      cache->size_px,
                                      &bitmap,
                                      &metrics))
    {
        glyph->ready = true;
        glyph->alpha = NULL;
        glyph->width = 0;
        glyph->height = 0;
        glyph->stride = 0;
        glyph->advance = rich_text_fallback_advance(cache->size_px, (char)codepoint);
        glyph->bearing_x = 0;
        glyph->bearing_y = 0;
        return glyph;
    }

    size_t bytes = 0;
    if (__builtin_mul_overflow((size_t)bitmap.stride, (size_t)bitmap.height, &bytes))
    {
        ttf_bitmap_destroy(&bitmap);
        return NULL;
    }
    uint8_t *alpha = (uint8_t *)malloc(bytes);
    if (!alpha)
    {
        ttf_bitmap_destroy(&bitmap);
        return NULL;
    }
    memcpy(alpha, bitmap.pixels, bytes);

    glyph->alpha = alpha;
    glyph->width = bitmap.width;
    glyph->height = bitmap.height;
    glyph->stride = bitmap.stride;
    glyph->advance = metrics.advance;
    glyph->bearing_x = metrics.bearing_x;
    glyph->bearing_y = metrics.bearing_y;
    glyph->ready = true;

    ttf_bitmap_destroy(&bitmap);
    return glyph;
}
