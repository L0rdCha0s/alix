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
    uint8_t style;
    uint16_t size;
} atk_rich_char_t;

typedef struct
{
    size_t start;
    size_t end;
    int top;
    int height;
    int baseline;
} atk_rich_line_t;

typedef enum
{
    RICH_TEXT_INPUT_NORMAL = 0,
    RICH_TEXT_INPUT_ESC,
    RICH_TEXT_INPUT_ESC_BRACKET,
} rich_text_input_state_t;

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
    uint32_t current_style;
    int last_width;
    int last_height;
    bool layout_dirty;
    bool focused;
    bool read_only;
    bool pagination_enabled;
    int page_width;
    int page_height;
    int page_margin;
    int page_gap;
    int *page_tops;
    size_t page_count;
    size_t page_capacity;
    bool selecting;
    size_t sel_anchor;
    size_t sel_start;
    size_t sel_end;
    int nav_preferred_x;
    rich_text_input_state_t input_state;
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
static bool rich_page_tops_ensure(atk_rich_text_priv_t *priv, size_t desired);
static int rich_text_content_origin_x(const atk_rich_text_priv_t *priv);
static int rich_text_clamp_font_size(int size);
static int rich_text_fallback_advance(int size, char ch);
static void rich_text_clear_selection(atk_rich_text_priv_t *priv);
static void rich_text_set_selection(atk_rich_text_priv_t *priv, size_t a, size_t b);
static void rich_text_update_current_format(atk_rich_text_priv_t *priv);
static size_t rich_text_line_index_for_cursor(const atk_rich_text_priv_t *priv, size_t cursor);
static atk_key_response_t rich_text_handle_arrow_sequence(atk_widget_t *widget, atk_rich_text_priv_t *priv, char ch);

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
static void rich_text_draw_rect_clipped(int x,
                                        int y,
                                        int width,
                                        int height,
                                        video_color_t color,
                                        int clip_x0,
                                        int clip_y0,
                                        int clip_x1,
                                        int clip_y1);
static void rich_text_draw_rect_outline_clipped(int x,
                                                int y,
                                                int width,
                                                int height,
                                                video_color_t color,
                                                int clip_x0,
                                                int clip_y0,
                                                int clip_x1,
                                                int clip_y1);
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
    priv->current_style = 0;
    priv->last_width = width;
    priv->last_height = height;
    priv->layout_dirty = true;
    priv->focused = false;
    priv->read_only = false;
    priv->pagination_enabled = false;
    priv->page_width = 0;
    priv->page_height = 0;
    priv->page_margin = 0;
    priv->page_gap = 0;
    priv->page_tops = NULL;
    priv->page_count = 0;
    priv->page_capacity = 0;
    priv->row_buffer = NULL;
    priv->row_buffer_capacity = 0;
    priv->change = NULL;
    priv->change_context = NULL;
    priv->selecting = false;
    priv->sel_anchor = 0;
    priv->sel_start = 0;
    priv->sel_end = 0;
    priv->nav_preferred_x = -1;
    priv->input_state = RICH_TEXT_INPUT_NORMAL;

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
    rich_text_notify_change(editor, priv);
    rich_text_invalidate(editor);
}

int atk_rich_text_current_font_size(const atk_widget_t *editor)
{
    const atk_rich_text_priv_t *priv = rich_text_priv(editor);
    return priv ? priv->current_font_size : ATK_RICH_TEXT_DEFAULT_FONT;
}

int atk_rich_text_cursor_font_size(const atk_widget_t *editor)
{
    const atk_rich_text_priv_t *priv = rich_text_priv(editor);
    if (!priv)
    {
        return ATK_RICH_TEXT_DEFAULT_FONT;
    }
    if (!priv->chars || priv->length == 0)
    {
        return priv->current_font_size;
    }
    if (priv->cursor > 0)
    {
        size_t idx = priv->cursor - 1;
        if (idx >= priv->length)
        {
            idx = priv->length - 1;
        }
        return rich_text_clamp_font_size((int)priv->chars[idx].size);
    }
    return priv->current_font_size;
}

void atk_rich_text_apply_style(atk_widget_t *editor, uint32_t style_flags, bool enabled)
{
    atk_rich_text_priv_t *priv = rich_text_priv_mut(editor);
    if (!priv)
    {
        return;
    }

    uint32_t mask = style_flags & 0xFFu;
    if (enabled)
    {
        priv->current_style |= mask;
    }
    else
    {
        priv->current_style &= ~mask;
    }

    if (!priv->chars || priv->sel_start == priv->sel_end || priv->length == 0)
    {
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
        char ch = priv->chars[i].ch;
        if (ch == '\n' || ch == ATK_RICH_TEXT_PAGE_BREAK_CHAR)
        {
            continue;
        }
        uint32_t style = priv->chars[i].style;
        if (enabled)
        {
            style |= mask;
        }
        else
        {
            style &= ~mask;
        }
        priv->chars[i].style = (uint8_t)(style & 0xFFu);
    }

    rich_text_notify_change(editor, priv);
    rich_text_invalidate(editor);
}

void atk_rich_text_toggle_style(atk_widget_t *editor, uint32_t style_flags)
{
    atk_rich_text_priv_t *priv = rich_text_priv_mut(editor);
    if (!priv)
    {
        return;
    }

    uint32_t mask = style_flags & 0xFFu;
    if (!priv->chars || priv->sel_start == priv->sel_end || priv->length == 0)
    {
        priv->current_style ^= mask;
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

    bool all_set = true;
    for (size_t i = start; i < end; ++i)
    {
        char ch = priv->chars[i].ch;
        if (ch == '\n' || ch == ATK_RICH_TEXT_PAGE_BREAK_CHAR)
        {
            continue;
        }
        if ((priv->chars[i].style & mask) != mask)
        {
            all_set = false;
            break;
        }
    }

    atk_rich_text_apply_style(editor, mask, !all_set);
}

uint32_t atk_rich_text_current_style(const atk_widget_t *editor)
{
    const atk_rich_text_priv_t *priv = rich_text_priv(editor);
    return priv ? priv->current_style : 0;
}

uint32_t atk_rich_text_cursor_style(const atk_widget_t *editor)
{
    const atk_rich_text_priv_t *priv = rich_text_priv(editor);
    if (!priv)
    {
        return 0;
    }
    if (!priv->chars || priv->length == 0)
    {
        return priv->current_style;
    }
    size_t idx = 0;
    if (priv->cursor > 0)
    {
        idx = priv->cursor - 1;
        if (idx >= priv->length)
        {
            idx = priv->length - 1;
        }
        return priv->chars[idx].style;
    }
    return priv->current_style;
}

void atk_rich_text_insert_page_break(atk_widget_t *editor)
{
    atk_rich_text_priv_t *priv = rich_text_priv_mut(editor);
    if (!priv)
    {
        return;
    }
    if (rich_text_insert_char(editor, priv, ATK_RICH_TEXT_PAGE_BREAK_CHAR))
    {
        rich_text_invalidate(editor);
    }
}

void atk_rich_text_set_pagination_enabled(atk_widget_t *editor, bool enabled)
{
    atk_rich_text_priv_t *priv = rich_text_priv_mut(editor);
    if (!priv)
    {
        return;
    }
    if (enabled == priv->pagination_enabled)
    {
        return;
    }
    priv->pagination_enabled = enabled;
    priv->layout_dirty = true;
    rich_text_invalidate(editor);
}

bool atk_rich_text_pagination_enabled(const atk_widget_t *editor)
{
    const atk_rich_text_priv_t *priv = rich_text_priv(editor);
    return priv ? priv->pagination_enabled : false;
}

size_t atk_rich_text_page_count(const atk_widget_t *editor)
{
    atk_rich_text_priv_t *priv = rich_text_priv_mut((atk_widget_t *)editor);
    if (!priv)
    {
        return 0;
    }
    rich_text_update_layout((atk_widget_t *)editor, priv);
    return priv->page_count;
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
        priv->chars[priv->length].size = (uint16_t)priv->current_font_size;
        if (text[i] == '\n' || text[i] == ATK_RICH_TEXT_PAGE_BREAK_CHAR)
        {
            priv->chars[priv->length].style = 0;
        }
        else
        {
            priv->chars[priv->length].style = (uint8_t)(priv->current_style & 0xFFu);
        }
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
        priv->chars[priv->length + i].size = (uint16_t)priv->current_font_size;
        if (text[i] == '\n' || text[i] == ATK_RICH_TEXT_PAGE_BREAK_CHAR)
        {
            priv->chars[priv->length + i].style = 0;
        }
        else
        {
            priv->chars[priv->length + i].style = (uint8_t)(priv->current_style & 0xFFu);
        }
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

void atk_rich_text_set_read_only(atk_widget_t *editor, bool read_only)
{
    atk_rich_text_priv_t *priv = rich_text_priv_mut(editor);
    if (!priv)
    {
        return;
    }
    if (priv->read_only == read_only)
    {
        return;
    }
    priv->read_only = read_only;
}

bool atk_rich_text_is_read_only(const atk_widget_t *editor)
{
    const atk_rich_text_priv_t *priv = rich_text_priv(editor);
    return priv ? priv->read_only : false;
}

char *atk_rich_text_copy_text(const atk_widget_t *editor)
{
    const atk_rich_text_priv_t *priv = rich_text_priv(editor);
    size_t length = (priv && priv->chars) ? priv->length : 0;

    char *out = (char *)malloc(length + 1);
    if (!out)
    {
        return NULL;
    }
    for (size_t i = 0; i < length; ++i)
    {
        out[i] = priv->chars[i].ch;
    }
    out[length] = '\0';
    return out;
}

typedef struct __attribute__((packed))
{
    uint32_t magic;
    uint16_t version;
    uint16_t header_size;
    uint16_t default_size;
    uint8_t default_style;
    uint8_t flags;
    uint32_t length;
} atk_rich_text_serial_header_t;

typedef struct __attribute__((packed))
{
    uint8_t ch;
    uint8_t style;
    uint16_t size;
} atk_rich_text_serial_char_t;

#define ATK_RICH_TEXT_SERIAL_MAGIC 0x524B5441u /* "ATKR" */
#define ATK_RICH_TEXT_SERIAL_VERSION 1u
#define ATK_RICH_TEXT_SERIAL_FLAG_PAGINATION (1u << 0)

bool atk_rich_text_serialize(const atk_widget_t *editor, uint8_t **data_out, size_t *size_out)
{
    if (!data_out || !size_out)
    {
        return false;
    }
    *data_out = NULL;
    *size_out = 0;

    const atk_rich_text_priv_t *priv = rich_text_priv(editor);
    size_t length = priv ? priv->length : 0;
    if (length > (size_t)0xFFFFFFFFu)
    {
        return false;
    }

    size_t entry_size = sizeof(atk_rich_text_serial_char_t);
    if (length > 0 && entry_size > 0)
    {
        size_t max_len = ((size_t)-1 - sizeof(atk_rich_text_serial_header_t)) / entry_size;
        if (length > max_len)
        {
            return false;
        }
    }

    size_t total = sizeof(atk_rich_text_serial_header_t) + length * entry_size;
    uint8_t *buf = (uint8_t *)malloc(total);
    if (!buf)
    {
        return false;
    }

    atk_rich_text_serial_header_t header = { 0 };
    header.magic = ATK_RICH_TEXT_SERIAL_MAGIC;
    header.version = ATK_RICH_TEXT_SERIAL_VERSION;
    header.header_size = (uint16_t)sizeof(atk_rich_text_serial_header_t);
    header.default_size = (uint16_t)(priv ? priv->current_font_size : ATK_RICH_TEXT_DEFAULT_FONT);
    header.default_style = (uint8_t)(priv ? (priv->current_style & 0xFFu) : 0);
    header.flags = (priv && priv->pagination_enabled) ? ATK_RICH_TEXT_SERIAL_FLAG_PAGINATION : 0;
    header.length = (uint32_t)length;
    memcpy(buf, &header, sizeof(header));

    atk_rich_text_serial_char_t *out = (atk_rich_text_serial_char_t *)(buf + sizeof(header));
    if (priv && priv->chars)
    {
        for (size_t i = 0; i < length; ++i)
        {
            out[i].ch = (uint8_t)priv->chars[i].ch;
            out[i].style = priv->chars[i].style;
            out[i].size = priv->chars[i].size;
        }
    }
    else
    {
        memset(out, 0, length * sizeof(*out));
    }

    *data_out = buf;
    *size_out = total;
    return true;
}

bool atk_rich_text_deserialize(atk_widget_t *editor, const uint8_t *data, size_t size)
{
    if (!editor || !data)
    {
        return false;
    }

    atk_rich_text_priv_t *priv = rich_text_priv_mut(editor);
    if (!priv)
    {
        return false;
    }

    if (size < sizeof(atk_rich_text_serial_header_t))
    {
        return false;
    }

    atk_rich_text_serial_header_t header = { 0 };
    memcpy(&header, data, sizeof(header));
    if (header.magic != ATK_RICH_TEXT_SERIAL_MAGIC || header.version != ATK_RICH_TEXT_SERIAL_VERSION)
    {
        return false;
    }
    if (header.header_size < sizeof(atk_rich_text_serial_header_t) || header.header_size > size)
    {
        return false;
    }

    size_t length = header.length;
    size_t entry_size = sizeof(atk_rich_text_serial_char_t);
    if (length > 0 && entry_size > 0)
    {
        size_t max_len = ((size_t)-1 - header.header_size) / entry_size;
        if (length > max_len)
        {
            return false;
        }
    }
    size_t expected = header.header_size + length * entry_size;
    if (expected > size)
    {
        return false;
    }

    /* Reset current contents without triggering change callbacks. */
    if (priv->chars)
    {
        free(priv->chars);
        priv->chars = NULL;
    }
    priv->capacity = 0;
    priv->length = 0;
    priv->cursor = 0;

    if (length > 0)
    {
        size_t cap = length + 16;
        atk_rich_char_t *chars = (atk_rich_char_t *)malloc(cap * sizeof(atk_rich_char_t));
        if (!chars)
        {
            return false;
        }
        priv->chars = chars;
        priv->capacity = cap;
        priv->length = length;
        priv->cursor = length;

        const atk_rich_text_serial_char_t *in = (const atk_rich_text_serial_char_t *)(data + header.header_size);
        for (size_t i = 0; i < length; ++i)
        {
            priv->chars[i].ch = (char)in[i].ch;
            priv->chars[i].style = in[i].style;
            priv->chars[i].size = in[i].size;
        }
    }
    rich_text_clear_selection(priv);

    priv->current_font_size = rich_text_clamp_font_size((int)header.default_size);
    priv->current_style = (uint32_t)(header.default_style & 0xFFu);
    priv->pagination_enabled = (header.flags & ATK_RICH_TEXT_SERIAL_FLAG_PAGINATION) != 0;
    priv->layout_dirty = true;
    priv->scroll_y = 0;
    rich_text_invalidate(editor);
    return true;
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

static bool rich_page_tops_ensure(atk_rich_text_priv_t *priv, size_t desired)
{
    if (!priv)
    {
        return false;
    }
    if (desired <= priv->page_capacity)
    {
        return true;
    }
    size_t new_cap = priv->page_capacity ? priv->page_capacity * 2 : 4;
    while (new_cap < desired)
    {
        new_cap *= 2;
    }
    int *buf = (int *)realloc(priv->page_tops, new_cap * sizeof(int));
    if (!buf)
    {
        return false;
    }
    priv->page_tops = buf;
    priv->page_capacity = new_cap;
    return true;
}

static int rich_text_content_origin_x(const atk_rich_text_priv_t *priv)
{
    int x = ATK_RICH_TEXT_PADDING;
    if (!priv || !priv->pagination_enabled || priv->page_width <= 0)
    {
        return x;
    }
    int doc_w = priv->view_width;
    int left = (doc_w - priv->page_width) / 2;
    if (left < 0)
    {
        left = 0;
    }
    x += left + priv->page_margin;
    return x;
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

static void rich_text_update_current_format(atk_rich_text_priv_t *priv)
{
    if (!priv || !priv->chars || priv->length == 0)
    {
        return;
    }

    size_t idx = priv->cursor;
    if (idx > 0)
    {
        idx--;
    }
    if (idx >= priv->length)
    {
        idx = priv->length - 1;
    }

    while (idx > 0)
    {
        char ch = priv->chars[idx].ch;
        if (ch != '\n' && ch != ATK_RICH_TEXT_PAGE_BREAK_CHAR)
        {
            break;
        }
        idx--;
    }

    priv->current_font_size = rich_text_clamp_font_size((int)priv->chars[idx].size);
    priv->current_style = priv->chars[idx].style;
}

static size_t rich_text_line_index_for_cursor(const atk_rich_text_priv_t *priv, size_t cursor)
{
    if (!priv || priv->line_count == 0)
    {
        return 0;
    }

    for (size_t i = 0; i < priv->line_count; ++i)
    {
        const atk_rich_line_t *line = &priv->lines[i];
        if (cursor >= line->start && cursor <= line->end)
        {
            return i;
        }
    }

    return priv->line_count - 1;
}

static bool rich_text_nav_collapse_selection(atk_rich_text_priv_t *priv, bool to_end)
{
    if (!priv || priv->sel_start == priv->sel_end)
    {
        return false;
    }
    priv->cursor = to_end ? priv->sel_end : priv->sel_start;
    rich_text_clear_selection(priv);
    rich_text_update_current_format(priv);
    return true;
}

static bool rich_text_nav_left(atk_rich_text_priv_t *priv)
{
    if (!priv)
    {
        return false;
    }
    if (rich_text_nav_collapse_selection(priv, false))
    {
        return true;
    }
    if (priv->cursor == 0)
    {
        return false;
    }
    priv->cursor--;
    rich_text_clear_selection(priv);
    rich_text_update_current_format(priv);
    return true;
}

static bool rich_text_nav_right(atk_rich_text_priv_t *priv)
{
    if (!priv)
    {
        return false;
    }
    if (rich_text_nav_collapse_selection(priv, true))
    {
        return true;
    }
    if (priv->cursor >= priv->length)
    {
        return false;
    }
    priv->cursor++;
    rich_text_clear_selection(priv);
    rich_text_update_current_format(priv);
    return true;
}

static bool rich_text_nav_vertical(atk_widget_t *widget, atk_rich_text_priv_t *priv, int delta)
{
    if (!widget || !priv || delta == 0)
    {
        return false;
    }

    if (rich_text_nav_collapse_selection(priv, delta > 0))
    {
        priv->nav_preferred_x = -1;
        return true;
    }

    if (!rich_text_update_layout(widget, priv))
    {
        return false;
    }
    if (priv->line_count == 0)
    {
        return false;
    }

    size_t current_line = rich_text_line_index_for_cursor(priv, priv->cursor);
    size_t target_line = current_line;
    if (delta < 0)
    {
        if (current_line == 0)
        {
            return false;
        }
        target_line = current_line - 1;
    }
    else
    {
        if (current_line + 1 >= priv->line_count)
        {
            return false;
        }
        target_line = current_line + 1;
    }

    if (priv->nav_preferred_x < 0)
    {
        int caret_x = 0;
        int caret_y = 0;
        int caret_h = 0;
        if (rich_text_cursor_rect(widget, priv, 0, 0, &caret_x, &caret_y, &caret_h))
        {
            int pen_x = caret_x - widget->x - rich_text_content_origin_x(priv);
            if (pen_x < 0)
            {
                pen_x = 0;
            }
            priv->nav_preferred_x = pen_x;
        }
        else
        {
            priv->nav_preferred_x = 0;
        }
    }

    const atk_rich_line_t *line = &priv->lines[target_line];
    int local_x = rich_text_content_origin_x(priv) + priv->nav_preferred_x;
    int local_y = (line->top + line->height / 2) - priv->scroll_y;
    size_t new_cursor = rich_text_index_for_point(widget, priv, local_x, local_y);
    if (new_cursor > priv->length)
    {
        new_cursor = priv->length;
    }
    if (new_cursor == priv->cursor)
    {
        return false;
    }
    priv->cursor = new_cursor;
    rich_text_clear_selection(priv);
    rich_text_update_current_format(priv);
    return true;
}

static atk_key_response_t rich_text_handle_arrow_sequence(atk_widget_t *widget, atk_rich_text_priv_t *priv, char ch)
{
    if (!widget || !priv)
    {
        return ATK_KEY_RESPONSE_NONE;
    }

    if (priv->input_state == RICH_TEXT_INPUT_ESC)
    {
        if (ch == '[')
        {
            priv->input_state = RICH_TEXT_INPUT_ESC_BRACKET;
            return ATK_KEY_RESPONSE_HANDLED;
        }
        priv->input_state = RICH_TEXT_INPUT_NORMAL;
        return ATK_KEY_RESPONSE_HANDLED;
    }

    if (priv->input_state == RICH_TEXT_INPUT_ESC_BRACKET)
    {
        priv->input_state = RICH_TEXT_INPUT_NORMAL;
        bool moved = false;
        if (ch == 'A')
        {
            moved = rich_text_nav_vertical(widget, priv, -1);
        }
        else if (ch == 'B')
        {
            moved = rich_text_nav_vertical(widget, priv, 1);
        }
        else if (ch == 'C')
        {
            priv->nav_preferred_x = -1;
            moved = rich_text_nav_right(priv);
        }
        else if (ch == 'D')
        {
            priv->nav_preferred_x = -1;
            moved = rich_text_nav_left(priv);
        }
        else
        {
            priv->nav_preferred_x = -1;
            return ATK_KEY_RESPONSE_HANDLED;
        }

        if (moved)
        {
            rich_text_ensure_cursor_visible(widget, priv);
            rich_text_invalidate(widget);
            return ATK_KEY_RESPONSE_HANDLED | ATK_KEY_RESPONSE_REDRAW;
        }
        return ATK_KEY_RESPONSE_HANDLED;
    }

    if (ch == 0x1B)
    {
        priv->input_state = RICH_TEXT_INPUT_ESC;
        return ATK_KEY_RESPONSE_HANDLED;
    }
    priv->input_state = RICH_TEXT_INPUT_NORMAL;
    return ATK_KEY_RESPONSE_NONE;
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
    if (priv->page_tops)
    {
        free(priv->page_tops);
        priv->page_tops = NULL;
    }
    priv->capacity = 0;
    priv->length = 0;
    priv->cursor = 0;
    priv->line_capacity = 0;
    priv->line_count = 0;
    priv->page_capacity = 0;
    priv->page_count = 0;
    priv->page_width = 0;
    priv->page_height = 0;
    priv->page_margin = 0;
    priv->page_gap = 0;
    priv->layout_dirty = true;
    priv->scroll_y = 0;
    rich_text_clear_selection(priv);
}

static bool rich_text_delete_range(atk_rich_text_priv_t *priv, size_t start, size_t end)
{
    if (!priv || !priv->chars || priv->length == 0 || start == end)
    {
        return false;
    }
    if (start > priv->length) start = priv->length;
    if (end > priv->length) end = priv->length;
    if (start > end)
    {
        size_t tmp = start;
        start = end;
        end = tmp;
    }
    if (start >= end)
    {
        return false;
    }

    size_t remove = end - start;
    if (end < priv->length)
    {
        memmove(priv->chars + start,
                priv->chars + end,
                (priv->length - end) * sizeof(atk_rich_char_t));
    }
    priv->length -= remove;

    if (priv->cursor > end)
    {
        priv->cursor -= remove;
    }
    else if (priv->cursor > start)
    {
        priv->cursor = start;
    }

    rich_text_clear_selection(priv);
    return true;
}

static bool rich_text_insert_char(atk_widget_t *editor, atk_rich_text_priv_t *priv, char ch)
{
    if (!priv)
    {
        return false;
    }

    if (priv->sel_start != priv->sel_end)
    {
        rich_text_delete_range(priv, priv->sel_start, priv->sel_end);
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
    priv->chars[priv->cursor].size = (uint16_t)priv->current_font_size;
    if (ch == '\n' || ch == ATK_RICH_TEXT_PAGE_BREAK_CHAR)
    {
        priv->chars[priv->cursor].style = 0;
    }
    else
    {
        priv->chars[priv->cursor].style = (uint8_t)(priv->current_style & 0xFFu);
    }
    priv->cursor++;
    priv->length++;
    priv->layout_dirty = true;
    rich_text_clear_selection(priv);
    rich_text_notify_change(editor, priv);
    return true;
}

static bool rich_text_backspace(atk_widget_t *editor, atk_rich_text_priv_t *priv)
{
    if (!priv || priv->length == 0)
    {
        return false;
    }

    if (priv->sel_start != priv->sel_end)
    {
        bool deleted = rich_text_delete_range(priv, priv->sel_start, priv->sel_end);
        if (!deleted)
        {
            return false;
        }
        priv->layout_dirty = true;
        rich_text_notify_change(editor, priv);
        return true;
    }

    if (priv->cursor == 0)
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
    priv->page_count = 0;
    int wrap_width = viewport_width;
    int x = 0;
    int y = ATK_RICH_TEXT_PADDING;
    int page_index = 0;
    int page_top = ATK_RICH_TEXT_PADDING;
    int line_ascent = 0;
    int line_descent = 0;
    int line_height = 0;
    size_t line_start = 0;

    if (priv->pagination_enabled)
    {
        int page_w = viewport_width;
        int max_page_w = 760;
        if (page_w > max_page_w)
        {
            page_w = max_page_w;
        }
        if (page_w < 1)
        {
            page_w = 1;
        }

        int margin = page_w / 12;
        if (margin < 24)
        {
            margin = 24;
        }
        if (margin * 2 >= page_w)
        {
            margin = page_w / 4;
        }
        if (margin < 4)
        {
            margin = 4;
        }

        int page_h = (page_w * 1414) / 1000;
        int min_h = margin * 2 + ATK_FONT_HEIGHT * 2;
        if (page_h < min_h)
        {
            page_h = min_h;
        }

        priv->page_width = page_w;
        priv->page_height = page_h;
        priv->page_margin = margin;
        priv->page_gap = 32;

        wrap_width = page_w - margin * 2;
        if (wrap_width < 1)
        {
            wrap_width = 1;
        }

        if (!rich_page_tops_ensure(priv, 1))
        {
            return false;
        }
        priv->page_tops[0] = page_top;
        priv->page_count = 1;
        y = page_top + margin;
    }
    else
    {
        priv->page_width = 0;
        priv->page_height = 0;
        priv->page_margin = 0;
        priv->page_gap = 0;
    }

    size_t idx = 0;
    size_t last_break_end = (size_t)-1;
    int break_ascent = 0;
    int break_descent = 0;
    int break_height = 0;
    bool saw_nonspace = false;
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

        bool page_break = (!at_end && ch == ATK_RICH_TEXT_PAGE_BREAK_CHAR);
        bool newline = (!at_end && (ch == '\n' || page_break));

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

        int computed_height = ascent + descent + gap;
        if (computed_height < ATK_FONT_HEIGHT)
        {
            computed_height = ATK_FONT_HEIGHT;
        }

        int advance = 0;
        if (!at_end && !newline)
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

        if (newline || at_end)
        {
            if (ascent > line_ascent) line_ascent = ascent;
            if (descent > line_descent) line_descent = descent;
            if (computed_height > line_height) line_height = computed_height;
        }

        bool current_space = (!at_end && (ch == ' ' || ch == '\t'));
        bool overflow = (!newline && !at_end && x > 0 && (x + advance) > wrap_width);
        bool wrap_at_break = false;
        if (overflow && !current_space && last_break_end != (size_t)-1 && last_break_end > line_start)
        {
            int word_width = 0;
            bool word_fits = true;
            for (size_t word_idx = last_break_end; word_idx < priv->length; ++word_idx)
            {
                if (!priv->chars)
                {
                    break;
                }
                char word_ch = priv->chars[word_idx].ch;
                if (word_ch == '\n' ||
                    word_ch == ATK_RICH_TEXT_PAGE_BREAK_CHAR ||
                    word_ch == ' ' ||
                    word_ch == '\t')
                {
                    break;
                }

                int word_size = rich_text_clamp_font_size(priv->chars[word_idx].size);
                atk_rich_font_size_cache_t *word_cache = rich_font_cache_for_size(word_size);
                atk_rich_glyph_t *word_glyph = rich_font_get_glyph(word_cache, (uint32_t)(unsigned char)word_ch);
                int word_advance = 0;
                if (word_glyph && word_glyph->ready)
                {
                    word_advance = word_glyph->advance;
                }
                else
                {
                    word_advance = rich_text_fallback_advance(word_size, word_ch);
                }
                if (word_advance < 1)
                {
                    word_advance = word_size / 2;
                }
                if (word_width > wrap_width - word_advance)
                {
                    word_fits = false;
                    break;
                }
                word_width += word_advance;
            }
            wrap_at_break = word_fits;
        }

        size_t commit_end = idx;
        int commit_ascent = line_ascent;
        int commit_descent = line_descent;
        int commit_height = line_height;
        if (wrap_at_break)
        {
            commit_end = last_break_end;
            commit_ascent = break_ascent;
            commit_descent = break_descent;
            commit_height = break_height;
        }

        if (newline || overflow || at_end)
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

            if (priv->pagination_enabled)
            {
                int content_top = page_top + priv->page_margin;
                int content_bottom = page_top + priv->page_height - priv->page_margin;
                int projected = y + commit_height + ATK_RICH_TEXT_LINE_SPACING;
                if (projected > content_bottom && y > content_top)
                {
                    page_index++;
                    page_top += priv->page_height + priv->page_gap;
                    if (!rich_page_tops_ensure(priv, page_index + 1))
                    {
                        return false;
                    }
                    priv->page_tops[page_index] = page_top;
                    priv->page_count = page_index + 1;
                    y = page_top + priv->page_margin;
                }
            }

            atk_rich_line_t *line = &priv->lines[priv->line_count++];
            line->start = line_start;
            line->end = commit_end;
            line->top = y;
            line->height = commit_height + ATK_RICH_TEXT_LINE_SPACING;
            int baseline_offset = commit_ascent;
            if (baseline_offset <= 0)
            {
                baseline_offset = commit_height - commit_descent;
            }
            line->baseline = y + baseline_offset;

            y += line->height;
            x = 0;
            line_ascent = 0;
            line_descent = 0;
            line_height = 0;
            last_break_end = (size_t)-1;
            break_ascent = 0;
            break_descent = 0;
            break_height = 0;
            saw_nonspace = false;

            if (newline)
            {
                line_start = idx + 1;
                idx = line_start;
            }
            else if (overflow)
            {
                if (current_space)
                {
                    line_start = idx + 1;
                    idx = line_start;
                }
                else
                {
                    line_start = commit_end;
                    idx = line_start;
                }
            }
            else
            {
                line_start = idx;
            }

            if (page_break && priv->pagination_enabled)
            {
                page_index++;
                page_top += priv->page_height + priv->page_gap;
                if (!rich_page_tops_ensure(priv, page_index + 1))
                {
                    return false;
                }
                priv->page_tops[page_index] = page_top;
                priv->page_count = page_index + 1;
                y = page_top + priv->page_margin;
            }

            if (at_end)
            {
                break;
            }
            continue;
        }

        if (ascent > line_ascent) line_ascent = ascent;
        if (descent > line_descent) line_descent = descent;
        if (computed_height > line_height) line_height = computed_height;
        x += advance;

        if (ch == ' ' || ch == '\t')
        {
            if (saw_nonspace)
            {
                last_break_end = idx + 1;
                break_ascent = line_ascent;
                break_descent = line_descent;
                break_height = line_height;
            }
        }
        else
        {
            saw_nonspace = true;
        }
        idx++;
    }

    if (priv->pagination_enabled && priv->page_count > 0)
    {
        int last_top = priv->page_tops[priv->page_count - 1];
        priv->content_height = last_top + priv->page_height + ATK_RICH_TEXT_PADDING;
    }
    else
    {
        priv->content_height = y + ATK_RICH_TEXT_PADDING;
    }
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
        int top = ATK_RICH_TEXT_PADDING;
        if (priv->pagination_enabled)
        {
            top += priv->page_margin;
        }
        if (x_out) *x_out = origin_x + editor->x + rich_text_content_origin_x(priv);
        if (y_out) *y_out = origin_y + editor->y + top - priv->scroll_y;
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
    int caret_x = origin_x + editor->x + rich_text_content_origin_x(priv) + pen_x;
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
    int x = local_x - rich_text_content_origin_x(priv);
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
        priv->nav_preferred_x = -1;
        priv->input_state = RICH_TEXT_INPUT_NORMAL;
        if (priv->chars && priv->length > 0)
        {
            size_t probe = idx;
            if (probe > 0)
            {
                probe--;
            }
            if (probe >= priv->length)
            {
                probe = priv->length - 1;
            }
            while (probe > 0 &&
                   (priv->chars[probe].ch == '\n' || priv->chars[probe].ch == ATK_RICH_TEXT_PAGE_BREAK_CHAR))
            {
                probe--;
            }
            priv->current_font_size = rich_text_clamp_font_size((int)priv->chars[probe].size);
            priv->current_style = priv->chars[probe].style;
        }
        rich_text_ensure_cursor_visible(widget, priv);
        rich_text_invalidate(widget);
        return ATK_MOUSE_RESPONSE_HANDLED | ATK_MOUSE_RESPONSE_REDRAW | ATK_MOUSE_RESPONSE_CAPTURE;
    }

    if (priv->selecting && event->left_pressed)
    {
        rich_text_set_selection(priv, priv->sel_anchor, idx);
        priv->cursor = idx;
        priv->nav_preferred_x = -1;
        priv->input_state = RICH_TEXT_INPUT_NORMAL;
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

static void rich_text_draw_rect_clipped(int x,
                                        int y,
                                        int width,
                                        int height,
                                        video_color_t color,
                                        int clip_x0,
                                        int clip_y0,
                                        int clip_x1,
                                        int clip_y1)
{
    if (width <= 0 || height <= 0)
    {
        return;
    }

    int x0 = x;
    int y0 = y;
    int x1 = x + width;
    int y1 = y + height;

    if (x0 < clip_x0) x0 = clip_x0;
    if (y0 < clip_y0) y0 = clip_y0;
    if (x1 > clip_x1) x1 = clip_x1;
    if (y1 > clip_y1) y1 = clip_y1;

    if (x1 <= x0 || y1 <= y0)
    {
        return;
    }

    video_draw_rect(x0, y0, x1 - x0, y1 - y0, color);
}

static void rich_text_draw_rect_outline_clipped(int x,
                                                int y,
                                                int width,
                                                int height,
                                                video_color_t color,
                                                int clip_x0,
                                                int clip_y0,
                                                int clip_x1,
                                                int clip_y1)
{
    if (width <= 0 || height <= 0)
    {
        return;
    }

    int x0 = x;
    int y0 = y;
    int x1 = x + width;
    int y1 = y + height;
    int bottom_y = y1 - 1;
    int right_x = x1 - 1;

    if (y0 >= clip_y0 && y0 < clip_y1)
    {
        int ex0 = x0;
        int ex1 = x1;
        if (ex0 < clip_x0) ex0 = clip_x0;
        if (ex1 > clip_x1) ex1 = clip_x1;
        if (ex1 > ex0)
        {
            video_draw_rect(ex0, y0, ex1 - ex0, 1, color);
        }
    }

    if (bottom_y != y0 && bottom_y >= clip_y0 && bottom_y < clip_y1)
    {
        int ex0 = x0;
        int ex1 = x1;
        if (ex0 < clip_x0) ex0 = clip_x0;
        if (ex1 > clip_x1) ex1 = clip_x1;
        if (ex1 > ex0)
        {
            video_draw_rect(ex0, bottom_y, ex1 - ex0, 1, color);
        }
    }

    if (x0 >= clip_x0 && x0 < clip_x1)
    {
        int ey0 = y0;
        int ey1 = y1;
        if (ey0 < clip_y0) ey0 = clip_y0;
        if (ey1 > clip_y1) ey1 = clip_y1;
        if (ey1 > ey0)
        {
            video_draw_rect(x0, ey0, 1, ey1 - ey0, color);
        }
    }

    if (right_x != x0 && right_x >= clip_x0 && right_x < clip_x1)
    {
        int ey0 = y0;
        int ey1 = y1;
        if (ey0 < clip_y0) ey0 = clip_y0;
        if (ey1 > clip_y1) ey1 = clip_y1;
        if (ey1 > ey0)
        {
            video_draw_rect(right_x, ey0, 1, ey1 - ey0, color);
        }
    }
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

    int content_left = abs_x + rich_text_content_origin_x(priv);
    int content_top = abs_y;
    int clip_x0 = abs_x + ATK_RICH_TEXT_PADDING;
    int clip_y0 = abs_y + ATK_RICH_TEXT_PADDING;
    int clip_x1 = clip_x0 + priv->view_width;
    int clip_y1 = clip_y0 + priv->view_height;
    int widget_x1 = abs_x + widget->width;
    int widget_y1 = abs_y + widget->height;
    if (clip_x0 < abs_x) clip_x0 = abs_x;
    if (clip_y0 < abs_y) clip_y0 = abs_y;
    if (clip_x1 > widget_x1) clip_x1 = widget_x1;
    if (clip_y1 > widget_y1) clip_y1 = widget_y1;

    if (priv->pagination_enabled &&
        priv->page_count > 0 &&
        priv->page_width > 0 &&
        priv->page_height > 0)
    {
        int doc_left = abs_x + ATK_RICH_TEXT_PADDING;
        int doc_w = priv->view_width;
        int page_left = (doc_w - priv->page_width) / 2;
        if (page_left < 0)
        {
            page_left = 0;
        }
        int page_x = doc_left + page_left;
        int page_x1 = page_x + priv->page_width;

        for (size_t page_idx = 0; page_idx < priv->page_count; ++page_idx)
        {
            int page_y = abs_y + priv->page_tops[page_idx] - priv->scroll_y;
            int page_y1 = page_y + priv->page_height;
            if (page_x1 <= clip_x0 || page_x >= clip_x1 || page_y1 <= clip_y0 || page_y >= clip_y1)
            {
                continue;
            }
            rich_text_draw_rect_clipped(page_x,
                                        page_y,
                                        priv->page_width,
                                        priv->page_height,
                                        theme->menu_dropdown_face,
                                        clip_x0,
                                        clip_y0,
                                        clip_x1,
                                        clip_y1);
            rich_text_draw_rect_outline_clipped(page_x,
                                                page_y,
                                                priv->page_width,
                                                priv->page_height,
                                                theme->menu_dropdown_border,
                                                clip_x0,
                                                clip_y0,
                                                clip_x1,
                                                clip_y1);
        }
    }

    video_color_t normal_text = priv->pagination_enabled ? theme->menu_dropdown_text : theme->button_text;

    for (size_t line_idx = 0; line_idx < priv->line_count; ++line_idx)
    {
        const atk_rich_line_t *line = &priv->lines[line_idx];
        int line_top = content_top + line->top - priv->scroll_y;
        int line_bottom = line_top + line->height;
        if (line_bottom <= clip_y0 || line_top >= clip_y1)
        {
            continue;
        }

        int baseline_y = abs_y + line->baseline - priv->scroll_y;
        int pen_x = content_left;
        for (size_t idx = line->start; idx < line->end && idx < priv->length; ++idx)
        {
            if (!priv->chars)
            {
                break;
            }
            char ch = priv->chars[idx].ch;
            if (ch == '\n' || ch == ATK_RICH_TEXT_PAGE_BREAK_CHAR)
            {
                continue;
            }
            uint8_t style = priv->chars[idx].style;
            int size_px = rich_text_clamp_font_size(priv->chars[idx].size);
            atk_rich_font_size_cache_t *cache = rich_font_cache_for_size(size_px);
            atk_rich_glyph_t *glyph = rich_font_get_glyph(cache, (uint32_t)(unsigned char)ch);
            int advance = 0;
            bool selected = (priv->sel_start != priv->sel_end) &&
                            (idx >= priv->sel_start && idx < priv->sel_end) &&
                            ch != '\n' &&
                            ch != ATK_RICH_TEXT_PAGE_BREAK_CHAR;
            video_color_t fg = selected ? theme->menu_dropdown_face : normal_text;
            if (selected)
            {
                int bg_x0 = pen_x;
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
                int bg_y0 = line_top;
                int bg_y1 = line_top + line->height;
                if (bg_y0 < clip_y0) bg_y0 = clip_y0;
                if (bg_y1 > clip_y1) bg_y1 = clip_y1;
                if (bg_x1 > bg_x0 && bg_y1 > bg_y0)
                {
                    video_draw_rect(bg_x0, bg_y0, bg_x1 - bg_x0, bg_y1 - bg_y0, theme->menu_bar_highlight);
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
                    int dst_y = baseline_y - glyph->bearing_y;
                    bool italic = (style & ATK_RICH_TEXT_STYLE_ITALIC) != 0;
                    bool bold = (style & ATK_RICH_TEXT_STYLE_BOLD) != 0;

                    for (int row = 0; row < glyph_h; ++row)
                    {
                        int row_y = dst_y + row;
                        if (row_y < clip_y0 || row_y >= clip_y1)
                        {
                            continue;
                        }

                        int slant = italic ? ((glyph_h - 1 - row) / 4) : 0;
                        int row_x0 = dst_x + slant;
                        int row_x1 = row_x0 + glyph_w;
                        if (row_x1 <= clip_x0 || row_x0 >= clip_x1)
                        {
                            continue;
                        }

                        int visible_x0 = (row_x0 < clip_x0) ? clip_x0 : row_x0;
                        int visible_x1 = (row_x1 > clip_x1) ? clip_x1 : row_x1;
                        int draw_width = visible_x1 - visible_x0;
                        if (draw_width <= 0)
                        {
                            continue;
                        }

                        int start_col = visible_x0 - row_x0;
                        if (start_col < 0)
                        {
                            start_col = 0;
                        }
                        if (start_col >= glyph_stride)
                        {
                            continue;
                        }
                        if (draw_width > glyph_stride - start_col)
                        {
                            draw_width = glyph_stride - start_col;
                        }
                        if (draw_width <= 0)
                        {
                            continue;
                        }

                        if (!rich_row_buffer_ensure(priv, draw_width))
                        {
                            break;
                        }

                        const uint8_t *src = glyph_alpha + row * glyph_stride + start_col;
                        for (int col = 0; col < draw_width; ++col)
                        {
                            uint8_t alpha = src[col];
                            priv->row_buffer[col] = ((video_color_t)alpha << 24) | (fg & 0x00FFFFFFu);
                        }
                        int stride_bytes = draw_width * (int)sizeof(video_color_t);
                        video_blit_rgba32(visible_x0,
                                          row_y,
                                          draw_width,
                                          1,
                                          priv->row_buffer,
                                          stride_bytes,
                                          true);

                        if (bold)
                        {
                            int bold_x = visible_x0 + 1;
                            int bold_w = draw_width;
                            if (bold_x + bold_w > clip_x1)
                            {
                                bold_w = clip_x1 - bold_x;
                            }
                            if (bold_w > 0)
                            {
                                video_blit_rgba32(bold_x,
                                                  row_y,
                                                  bold_w,
                                                  1,
                                                  priv->row_buffer,
                                                  stride_bytes,
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

            if ((style & ATK_RICH_TEXT_STYLE_UNDERLINE) != 0 && advance > 0)
            {
                int ul_y = baseline_y + 2;
                if (ul_y >= clip_y0 && ul_y < clip_y1)
                {
                    int ul_x0 = pen_x;
                    int ul_x1 = pen_x + advance;
                    if (ul_x0 < clip_x0) ul_x0 = clip_x0;
                    if (ul_x1 > clip_x1) ul_x1 = clip_x1;
                    if (ul_x1 > ul_x0)
                    {
                        video_draw_rect(ul_x0, ul_y, ul_x1 - ul_x0, 1, fg);
                    }
                }
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
        if (priv->page_tops)
        {
            free(priv->page_tops);
            priv->page_tops = NULL;
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
        priv->page_capacity = 0;
        priv->page_count = 0;
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
    atk_key_response_t arrow = rich_text_handle_arrow_sequence(widget, priv, ch);
    if (arrow != ATK_KEY_RESPONSE_NONE)
    {
        return arrow;
    }

    if (priv->read_only)
    {
        return ATK_KEY_RESPONSE_NONE;
    }

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
        priv->nav_preferred_x = -1;
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
