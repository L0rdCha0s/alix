#ifndef ATK_HTML_VIEW_INTERNAL_H
#define ATK_HTML_VIEW_INTERNAL_H

#include "atk/atk_checkbox.h"
#include "atk/atk_font.h"
#include "atk/atk_html_view.h"
#include "atk/atk_radio.h"
#include "atk/atk_scrollbar.h"
#include "atk/atk_text_input.h"
#include "atk/util/png.h"
#include "atk/util/gif.h"
#include "atk_internal.h"
#include "atk_window.h"
#include "libc.h"
#include "ttf.h"
#include "usyscall.h"
#include "utf8.h"
#include "video.h"
#include "web/css.h"
#include "web/html.h"
#include "web/js.h"
#include "web/url.h"

#define ATK_HTML_VIEW_PADDING 8
#define ATK_HTML_VIEW_SCROLLBAR_WIDTH 14
#define ATK_HTML_VIEW_RENDER_TILE_H 256
#define HTML_VIEW_JS_DIRTY_RENDER 0x1u
#define HTML_VIEW_JS_DIRTY_STYLES 0x2u
#define HTML_VIEW_JS_DIRTY_CONTROLS 0x4u

#define HTML_VIEW_FONT_CACHE_FIRST 32
#define HTML_VIEW_FONT_CACHE_LAST  126
#define HTML_VIEW_FONT_CACHE_COUNT (HTML_VIEW_FONT_CACHE_LAST - HTML_VIEW_FONT_CACHE_FIRST + 1)
#define HTML_VIEW_FONT_EXTRA_CACHE_SLOTS 256
#define HTML_VIEW_FONT_SIZE_CACHE_SLOTS 8
#define HTML_VIEW_FONT_MAX_ROW_PIXELS 256
#define HTML_VIEW_FONT_TEXT_GUARD 2048
#define HTML_VIEW_FONT_MAX_PX 512

typedef struct html_view_js_script
{
    char *source;
    size_t len;
    js_program_t *program;
    struct html_view_js_script *next;
} html_view_js_script_t;

typedef struct html_view_js_listener
{
    size_t handle;
    char *handler_name;
    js_program_t *call_program;
    struct html_view_js_listener *next;
} html_view_js_listener_t;

typedef struct html_view_image
{
    char *src;
    video_color_t *pixels;
    int width;
    int height;
    int stride_bytes;
    struct html_view_image *next;
} html_view_image_t;

typedef enum
{
    HTML_VIEW_CONTROL_INPUT_TEXT = 0,
    HTML_VIEW_CONTROL_TEXTAREA,
    HTML_VIEW_CONTROL_BUTTON,
    HTML_VIEW_CONTROL_SELECT,
    HTML_VIEW_CONTROL_CHECKBOX,
    HTML_VIEW_CONTROL_RADIO
} html_view_control_kind_t;

typedef enum
{
    HTML_VIEW_PSEUDO_NONE = 0,
    HTML_VIEW_PSEUDO_BEFORE,
    HTML_VIEW_PSEUDO_AFTER
} html_view_pseudo_t;

typedef struct html_view_control
{
    const html_node_t *node;
    atk_widget_t *widget;
    html_view_control_kind_t kind;
    struct html_view_control *next;
} html_view_control_t;

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
} html_view_font_glyph_t;

typedef struct
{
    uint32_t codepoint;
    uint32_t last_used;
    html_view_font_glyph_t glyph;
} html_view_font_glyph_entry_t;

typedef struct
{
    bool used;
    int pixel_height;
    ttf_font_metrics_t metrics;
    html_view_font_glyph_t glyphs[HTML_VIEW_FONT_CACHE_COUNT];
    html_view_font_glyph_entry_t extra_glyphs[HTML_VIEW_FONT_EXTRA_CACHE_SLOTS];
    uint32_t glyph_use_counter;
    uint32_t last_used;
} html_view_font_size_cache_t;

typedef struct
{
    bool ready;
    ttf_font_t font;
    uint8_t *font_blob;
    size_t font_blob_size;
    uint32_t cache_use_counter;
    html_view_font_size_cache_t size_caches[HTML_VIEW_FONT_SIZE_CACHE_SLOTS];
} html_view_font_state_t;

typedef enum
{
    HTML_VIEW_OP_RECT = 0,
    HTML_VIEW_OP_TEXT,
    HTML_VIEW_OP_IMAGE,
    HTML_VIEW_OP_CONTROL
} html_view_op_kind_t;

typedef struct
{
    html_view_op_kind_t kind;
    int32_t x;
    int32_t y;
    int32_t w;
    int32_t h;
    video_color_t color;
    const char *text;
    uint32_t text_len;
    bool text_owned;
    const char *href;
    int16_t baseline_off;
    int16_t font_px;
    const video_color_t *pixels;
    int stride_bytes;
    int32_t z_index;
    bool fixed;
    bool has_clip;
    bool clip_scroll;
    int32_t clip_x;
    int32_t clip_y;
    int32_t clip_w;
    int32_t clip_h;
    atk_widget_t *widget;
} html_view_op_t;

typedef struct
{
    size_t *ops;
    size_t count;
    size_t cap;
} html_view_tile_t;

typedef struct
{
    const char *id;
    int y;
} html_view_anchor_t;

typedef struct
{
    bool valid;
    const html_document_t *doc;
    const css_stylesheet_t *sheet;
    int viewport_w;
    int viewport_h;
    int doc_origin_local_x;
    int doc_origin_local_y;
    int body_w;
    int base_font_px;
    int base_line_height;
    int body_box_h;
    int content_height;
    int tile_h;
    char **owned_text;
    size_t owned_text_count;
    size_t owned_text_cap;
    html_view_op_t *ops;
    size_t op_count;
    size_t op_cap;
    size_t *fixed_ops;
    size_t fixed_count;
    size_t fixed_cap;
    html_view_anchor_t *anchors;
    size_t anchor_count;
    size_t anchor_cap;
    html_view_tile_t *tiles;
    size_t tile_count;
    size_t tile_used;
} html_view_render_cache_t;

typedef struct
{
    atk_list_node_t *child_node;
    atk_widget_t *scrollbar;
    int scrollbar_width;
    bool scrollbar_hidden;
    int scroll_y;
    int content_height;
    int last_width;
    int last_height;
    html_document_t *doc;
    css_stylesheet_t *sheet;
    char *external_css;
    size_t external_css_len;
    html_view_image_t *images;
    html_view_control_t *controls;
    html_view_font_state_t font;
    html_view_render_cache_t render_cache;
    atk_html_view_link_t link_handler;
    void *link_context;
    const char *pressed_href;
    alix_mutex_t dom_lock;
    alix_mutex_t render_lock;
    alix_thread_t render_thread;
    volatile uint32_t render_stop;
    volatile uint32_t render_seq;
    volatile uint32_t render_done_seq;
    volatile uint32_t render_redraw_pending;
    volatile uint64_t render_request_ms;
    volatile uint32_t render_cache_dirty;
    volatile uint32_t stylesheet_dirty;
    bool render_async;
    alix_thread_t js_thread;
    volatile uint32_t js_stop;
    volatile uint32_t js_dirty;
    volatile uint32_t js_redraw_pending;
    js_runtime_t *js_runtime;
    bool js_runtime_ready;
    bool js_enabled;
    html_view_js_script_t *js_script_head;
    html_view_js_script_t *js_script_tail;
    html_view_js_listener_t *js_listeners;
    uint32_t js_listener_seq;
    html_node_t **js_handles;
    size_t js_handle_count;
    size_t js_handle_cap;
} atk_html_view_priv_t;

typedef struct
{
    int x;
    int y;
    int w;
    int h;
    css_float_t side;
} html_view_float_t;

typedef struct
{
    html_view_float_t items[128];
    size_t count;
} html_view_float_ctx_t;

typedef struct
{
    int max_pos;
    int min_neg;
    bool valid;
} html_view_margin_state_t;

typedef enum
{
    HTML_VIEW_PAINT_LAYER_BLOCK = 0,
    HTML_VIEW_PAINT_LAYER_FLOAT = 1,
    HTML_VIEW_PAINT_LAYER_INLINE = 2,
} html_view_paint_layer_t;

enum
{
    HTML_VIEW_Z_INDEX_STRIDE = 4
};

typedef struct html_view_style_block
{
    css_style_t styles[64];
    size_t used;
    struct html_view_style_block *prev;
} html_view_style_block_t;

typedef struct
{
    const atk_state_t *state;
    const atk_widget_t *widget;
    atk_html_view_priv_t *priv;
    const css_stylesheet_t *sheet;
    video_color_t bg;
    atk_rect_t clip;
    int viewport_x;
    int viewport_y;
    int viewport_w;
    int viewport_h;
    int scroll_y;
    int window_x;
    int window_y;
    int body_x;
    int body_w;
    int pos_x;
    int pos_y;
    int pos_w;
    int pos_h;
    int height_basis;
    bool height_basis_valid;
    bool height_basis_explicit;
    html_view_float_ctx_t *floats;
    int actual_font_px;
    int base_font_px;
    int base_line_height;
    int line_height;
    int space_w;
    int x;
    int y;
    int max_x;
    int measure_max_x;
    int content_bottom;
    html_view_margin_state_t pending_margin;
    int list_level;
    css_text_align_t text_align_mode;
    size_t line_op_start;
    int line_start_x;
    int line_start_y;
    bool text_underline;
    bool text_bold;
    bool underline_run_active;
    int underline_run_start_x;
    video_color_t underline_run_color;
    const char *active_href;
    bool pending_space;
    int32_t z_index;
    html_view_paint_layer_t paint_layer;
    bool draw;
    bool record;
    bool record_failed;
    bool fixed_mode;
    bool clip_scroll;
    bool table_mode;
    bool measure_shrink;
    int doc_origin_x;
    int doc_origin_y;
    html_view_style_block_t *style_block;
    size_t style_depth;
} html_view_ctx_t;

typedef struct
{
    int actual_font_px;
    int base_font_px;
    int line_height;
    int space_w;
} html_view_font_scope_t;

static inline int32_t html_view_effective_z_index(const html_view_ctx_t *ctx)
{
    if (!ctx)
    {
        return 0;
    }
    return ctx->z_index * HTML_VIEW_Z_INDEX_STRIDE + (int32_t)ctx->paint_layer;
}

static inline void html_view_margin_state_reset(html_view_margin_state_t *state)
{
    if (!state)
    {
        return;
    }
    state->max_pos = 0;
    state->min_neg = 0;
    state->valid = false;
}

static inline html_view_margin_state_t html_view_margin_state_from_value(int margin)
{
    html_view_margin_state_t state = {0};
    if (margin > 0)
    {
        state.max_pos = margin;
        state.valid = true;
    }
    else if (margin < 0)
    {
        state.min_neg = margin;
        state.valid = true;
    }
    return state;
}

static inline int html_view_margin_state_value(const html_view_margin_state_t *state)
{
    if (!state || !state->valid)
    {
        return 0;
    }
    return state->max_pos + state->min_neg;
}

static inline void html_view_margin_state_add(html_view_margin_state_t *state, int margin)
{
    if (!state || margin == 0)
    {
        return;
    }
    if (!state->valid)
    {
        *state = html_view_margin_state_from_value(margin);
        return;
    }
    if (margin > state->max_pos)
    {
        state->max_pos = margin;
    }
    if (margin < state->min_neg)
    {
        state->min_neg = margin;
    }
}

static inline void html_view_margin_state_merge(html_view_margin_state_t *state,
                                                const html_view_margin_state_t *other)
{
    if (!state || !other || !other->valid)
    {
        return;
    }
    if (!state->valid)
    {
        *state = *other;
        return;
    }
    if (other->max_pos > state->max_pos)
    {
        state->max_pos = other->max_pos;
    }
    if (other->min_neg < state->min_neg)
    {
        state->min_neg = other->min_neg;
    }
}

static inline int html_view_draw_y(const html_view_ctx_t *ctx, int doc_y)
{
    if (!ctx)
    {
        return doc_y;
    }
    if (ctx->fixed_mode)
    {
        return doc_y;
    }
    return doc_y - ctx->scroll_y;
}

static inline int html_view_record_x(const html_view_ctx_t *ctx, int draw_x)
{
    if (!ctx || ctx->fixed_mode)
    {
        return draw_x;
    }
    return draw_x - ctx->doc_origin_x;
}

static inline int html_view_record_y(const html_view_ctx_t *ctx, int draw_y)
{
    if (!ctx || ctx->fixed_mode)
    {
        return draw_y;
    }
    return (draw_y + ctx->scroll_y) - ctx->doc_origin_y;
}

atk_html_view_priv_t *html_view_priv_mut(atk_widget_t *view);
void html_view_invalidate(const atk_widget_t *view);
bool html_view_hit_test_cb(const atk_widget_t *widget,
                           int origin_x,
                           int origin_y,
                           int px,
                           int py,
                           void *context);
atk_mouse_response_t html_view_mouse_cb(atk_widget_t *widget,
                                        const atk_mouse_event_t *event,
                                        void *context);
atk_key_response_t html_view_key_cb(atk_widget_t *widget,
                                    int key,
                                    int modifiers,
                                    int action,
                                    void *context);

bool html_view_buf_append(char **buf, size_t *len, size_t *cap, const char *data, size_t data_len);
char *html_view_strdup(const char *src);
void html_view_render_cache_clear(html_view_render_cache_t *cache);
char *html_view_render_cache_strdup(html_view_render_cache_t *cache, const char *text);
bool html_view_render_cache_add_anchor(html_view_render_cache_t *cache, const char *id, int y);
bool html_view_render_cache_push_op(html_view_render_cache_t *cache, const html_view_op_t *op, int tile_h);
void html_view_render_cache_draw_visible(html_view_ctx_t *ctx);
html_view_control_t *html_view_control_find(atk_html_view_priv_t *priv, const html_node_t *node);
void html_view_images_clear(atk_html_view_priv_t *priv);
void html_view_window_remove_widget(atk_widget_t *window, atk_widget_t *child);
void html_view_controls_clear(atk_widget_t *view, atk_html_view_priv_t *priv);
void html_view_controls_hide_all(atk_html_view_priv_t *priv);
void html_view_collect_text(const html_node_t *node, char **buf, size_t *len, size_t *cap);
void html_view_trim_collapse_ws(char *text);

void html_view_draw_rect_clipped(html_view_ctx_t *ctx,
                                 int x,
                                 int y,
                                 int w,
                                 int h,
                                 video_color_t color,
                                 const atk_rect_t *clip);
void html_view_draw_border_clipped(html_view_ctx_t *ctx,
                                   int x,
                                   int y,
                                   int w,
                                   int h,
                                   int thickness,
                                   video_color_t color,
                                   const atk_rect_t *clip);
void html_view_blit_rgba32_clipped(html_view_ctx_t *ctx,
                                   int dst_x,
                                   int dst_y,
                                   int width,
                                   int height,
                                   const video_color_t *pixels,
                                   int stride_bytes,
                                   const atk_rect_t *clip);
void html_view_align_current_line(html_view_ctx_t *ctx);
void html_view_flush_underline_run(html_view_ctx_t *ctx);
void html_view_new_line(html_view_ctx_t *ctx);
void html_view_ensure_line_visible(html_view_ctx_t *ctx);
bool html_view_line_visible(const html_view_ctx_t *ctx);
void html_view_float_bounds_at_y(const html_view_float_ctx_t *floats,
                                 int y,
                                 int content_x,
                                 int content_w,
                                 int *out_left,
                                 int *out_right);
int html_view_float_next_y(const html_view_float_ctx_t *floats, int y);
int html_view_float_max_bottom(const html_view_float_ctx_t *floats, css_clear_t clear_mode);
void html_view_draw_border_sides_clipped(html_view_ctx_t *ctx,
                                         int x,
                                         int y,
                                         int w,
                                         int h,
                                         int top,
                                         int right,
                                         int bottom,
                                         int left,
                                         const css_style_t *style,
                                         const atk_rect_t *clip);
void html_view_draw_background_image(html_view_ctx_t *ctx,
                                     const css_style_t *style,
                                     int border_x,
                                     int border_y,
                                     int border_w,
                                     int border_h);
void html_view_draw_text(html_view_ctx_t *ctx,
                         const char *text,
                         video_color_t color,
                         bool underline,
                         bool bold);
void html_view_place_control_widget(html_view_ctx_t *ctx,
                                    atk_widget_t *child,
                                    int abs_x,
                                    int abs_y,
                                    int width,
                                    int height);
void html_view_place_inline_control(html_view_ctx_t *ctx, atk_widget_t *child, int width, int height);
void html_view_place_block_control(html_view_ctx_t *ctx, atk_widget_t *child, int width, int height);
bool html_view_is_block_tag(const char *tag);
bool html_view_is_form_control_tag(const char *tag);

int html_view_text_width(const html_view_ctx_t *ctx, const char *text);
int html_view_baseline_for_rect(const html_view_ctx_t *ctx, int top, int height);
void html_view_draw_string_clipped(const html_view_ctx_t *ctx,
                                   int x,
                                   int baseline_y,
                                   const char *text,
                                   video_color_t fg,
                                   const atk_rect_t *clip);
void html_view_font_state_reset(html_view_font_state_t *state);
html_view_font_size_cache_t *html_view_font_state_get_cache(html_view_font_state_t *state, int pixel_height);

void html_view_style_for_node(css_style_t *out,
                              const css_stylesheet_t *sheet,
                              const css_style_t *parent,
                              const html_node_t *node);
bool html_view_style_for_pseudo(css_style_t *out,
                                const css_stylesheet_t *sheet,
                                const css_style_t *parent,
                                const html_node_t *node,
                                html_view_pseudo_t pseudo);
void html_view_style_stack_destroy(html_view_ctx_t *ctx);
const css_style_t *html_view_style_push(html_view_ctx_t *ctx,
                                        const css_style_t *parent,
                                        const html_node_t *node);
void html_view_style_pop(html_view_ctx_t *ctx);
int html_view_length_to_px(const css_length_t *len,
                           int viewport_w,
                           int viewport_h,
                           int ref_w,
                           int ref_h,
                           int font_px,
                           bool horizontal);
int html_view_length_to_px_signed(const css_length_t *len,
                                  int viewport_w,
                                  int viewport_h,
                                  int ref_w,
                                  int ref_h,
                                  int font_px,
                                  bool horizontal);
bool html_view_length_to_px_height(const html_view_ctx_t *ctx,
                                   const css_length_t *len,
                                   int *out_px);

static inline void html_view_apply_border_style_none(const css_style_t *style,
                                                     int *top,
                                                     int *right,
                                                     int *bottom,
                                                     int *left)
{
    if (!style || !style->has_border_style)
    {
        return;
    }
    if (top && style->border_style_none[CSS_BORDER_SIDE_TOP])
    {
        *top = 0;
    }
    if (right && style->border_style_none[CSS_BORDER_SIDE_RIGHT])
    {
        *right = 0;
    }
    if (bottom && style->border_style_none[CSS_BORDER_SIDE_BOTTOM])
    {
        *bottom = 0;
    }
    if (left && style->border_style_none[CSS_BORDER_SIDE_LEFT])
    {
        *left = 0;
    }
}
int html_view_line_height_for_style(const html_view_ctx_t *ctx, const css_style_t *style);
int html_view_font_px_for_style(const html_view_ctx_t *ctx, const css_style_t *style, int parent_font_px);
void html_view_font_scope_push(html_view_ctx_t *ctx,
                               const css_style_t *style,
                               bool block,
                               html_view_font_scope_t *saved);
void html_view_font_scope_pop(html_view_ctx_t *ctx, const html_view_font_scope_t *saved);

void html_view_controls_build(atk_widget_t *view, atk_html_view_priv_t *priv);
html_view_image_t *html_view_image_find(atk_html_view_priv_t *priv, const char *src);
bool html_view_try_load_data_image_locked(atk_html_view_priv_t *priv, const char *src);
void html_view_rebuild_stylesheet(atk_html_view_priv_t *priv);
void html_view_stylesheet_mark_dirty(atk_html_view_priv_t *priv);
void html_view_stylesheet_rebuild_if_needed(atk_html_view_priv_t *priv);
const html_node_t *html_view_find_first_element(const html_node_t *root, const char *tag);

void html_view_dom_lock(atk_html_view_priv_t *priv);
bool html_view_dom_try_lock(atk_html_view_priv_t *priv);
void html_view_dom_unlock(atk_html_view_priv_t *priv);
bool html_view_render_try_lock(atk_html_view_priv_t *priv);
void html_view_render_unlock(atk_html_view_priv_t *priv);
void html_view_render_cache_invalidate(atk_html_view_priv_t *priv);
void html_view_render_cache_invalidate_locked(atk_html_view_priv_t *priv);
void html_view_js_dispatch_click(atk_widget_t *view, const html_node_t *node);
void html_view_js_apply_dirty(atk_widget_t *view, atk_html_view_priv_t *priv);
void html_view_js_init(atk_html_view_priv_t *priv);
void html_view_js_stop(atk_html_view_priv_t *priv);
void html_view_js_start(atk_widget_t *view, atk_html_view_priv_t *priv);
bool html_view_js_queue_external(atk_widget_t *view,
                                 atk_html_view_priv_t *priv,
                                 const char *script_text,
                                 size_t len);
bool html_view_js_queue_external_try(atk_widget_t *view,
                                     atk_html_view_priv_t *priv,
                                     const char *script_text,
                                     size_t len);
void html_view_js_shutdown(atk_widget_t *view, atk_html_view_priv_t *priv);

void html_view_render_request(atk_html_view_priv_t *priv);

void html_view_render_children(html_view_ctx_t *ctx, const html_node_t *node, const css_style_t *style);
bool html_view_render_inline_element(html_view_ctx_t *ctx, const html_node_t *node, const css_style_t *style);
void html_view_render_table(html_view_ctx_t *ctx,
                            const html_node_t *node,
                            const css_style_t *style,
                            const css_style_t *parent_style);
void html_view_render_float_box(html_view_ctx_t *ctx,
                                const html_node_t *node,
                                const css_style_t *style,
                                css_float_t side);
bool html_view_subtree_has_form_control(const html_node_t *root);

#endif /* ATK_HTML_VIEW_INTERNAL_H */
