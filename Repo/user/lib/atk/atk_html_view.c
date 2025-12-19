#include "atk/atk_html_view.h"

#include "atk/atk_checkbox.h"
#include "atk/atk_font.h"
#include "atk/atk_radio.h"
#include "atk/atk_scrollbar.h"
#include "atk/atk_text_input.h"
#include "atk/util/png.h"
#include "atk_internal.h"
#include "atk_window.h"
#include "ctype.h"
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

typedef struct html_view_js_script html_view_js_script_t;

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
    HTML_VIEW_CONTROL_CHECKBOX,
    HTML_VIEW_CONTROL_RADIO
} html_view_control_kind_t;

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
    html_view_tile_t *tiles;
    size_t tile_count;
    size_t tile_used;
} html_view_render_cache_t;

typedef struct
{
    atk_list_node_t *child_node;
    atk_widget_t *scrollbar;
    int scrollbar_width;
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
    alix_thread_t js_thread;
    volatile uint32_t js_stop;
    volatile uint32_t js_dirty;
    volatile uint32_t js_redraw_pending;
    js_runtime_t *js_runtime;
    bool js_runtime_ready;
    bool js_enabled;
    html_view_js_script_t *js_script_head;
    html_view_js_script_t *js_script_tail;
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
    int window_x;
    int window_y;
    int body_x;
    int body_w;
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
    int list_level;
    css_text_align_t text_align_mode;
    size_t line_op_start;
    int line_start_x;
    int line_start_y;
    bool text_underline;
    bool text_bold;
    const char *active_href;
    bool pending_space;
    bool draw;
    bool record;
    bool record_failed;
    int doc_origin_x;
    int doc_origin_y;
    html_view_style_block_t *style_block;
    size_t style_depth;
} html_view_ctx_t;

static void html_view_draw_rect_clipped(html_view_ctx_t *ctx,
                                        int x,
                                        int y,
                                        int w,
                                        int h,
                                        video_color_t color,
                                        const atk_rect_t *clip);
static void html_view_blit_rgba32_clipped(html_view_ctx_t *ctx,
                                         int dst_x,
                                         int dst_y,
                                         int w,
                                         int h,
                                         const video_color_t *src,
                                         int src_stride_bytes,
                                         const atk_rect_t *clip);
static void html_view_draw_string_clipped(const html_view_ctx_t *ctx,
                                          int x,
                                          int baseline_y,
                                          const char *text,
                                          video_color_t fg,
                                          const atk_rect_t *clip);
static void html_view_place_control_widget(html_view_ctx_t *ctx,
                                           atk_widget_t *child,
                                           int abs_x,
                                           int abs_y,
                                           int width,
                                           int height);

#include "html_view/core.c"
#include "html_view/font.c"
#include "html_view/controls.c"
#include "html_view/script.c"
#include "html_view/style.c"
#include "html_view/layout.c"
#include "html_view/table.c"
#include "html_view/render.c"
#include "html_view/widget.c"
