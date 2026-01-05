#ifndef WEB_CSS_PUBLIC_H
#define WEB_CSS_PUBLIC_H

#include "types.h"
#include "web/common/bloom.h"
#include "video.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum
{
    CSS_UNIT_NONE = 0,
    CSS_UNIT_PX,
    CSS_UNIT_VW,
    CSS_UNIT_VH,
    CSS_UNIT_EM,
    CSS_UNIT_PERCENT
} css_unit_t;

typedef struct
{
    bool valid;
    bool is_auto;
    int32_t value_milli;
    css_unit_t unit;
} css_length_t;

typedef enum
{
    CSS_MEDIA_COLOR_SCHEME_ANY = 0,
    CSS_MEDIA_COLOR_SCHEME_LIGHT,
    CSS_MEDIA_COLOR_SCHEME_DARK
} css_media_color_scheme_t;

typedef struct
{
    css_length_t top;
    css_length_t right;
    css_length_t bottom;
    css_length_t left;
} css_box_t;

typedef enum
{
    CSS_TEXT_ALIGN_LEFT = 0,
    CSS_TEXT_ALIGN_CENTER,
    CSS_TEXT_ALIGN_RIGHT
} css_text_align_t;

typedef enum
{
    CSS_TEXT_DECORATION_NONE = 0,
    CSS_TEXT_DECORATION_UNDERLINE
} css_text_decoration_t;

typedef enum
{
    CSS_BACKGROUND_REPEAT_REPEAT = 0,
    CSS_BACKGROUND_REPEAT_NO_REPEAT,
    CSS_BACKGROUND_REPEAT_REPEAT_X,
    CSS_BACKGROUND_REPEAT_REPEAT_Y
} css_background_repeat_t;

typedef enum
{
    CSS_BACKGROUND_ATTACHMENT_SCROLL = 0,
    CSS_BACKGROUND_ATTACHMENT_FIXED
} css_background_attachment_t;

typedef enum
{
    CSS_DISPLAY_INLINE = 0,
    CSS_DISPLAY_INLINE_BLOCK,
    CSS_DISPLAY_BLOCK,
    CSS_DISPLAY_LIST_ITEM,
    CSS_DISPLAY_TABLE,
    CSS_DISPLAY_TABLE_CELL,
    CSS_DISPLAY_FLEX,
    CSS_DISPLAY_INLINE_FLEX,
    CSS_DISPLAY_GRID,
    CSS_DISPLAY_INLINE_GRID,
    CSS_DISPLAY_NONE
} css_display_t;

typedef enum
{
    CSS_BOX_SIZING_CONTENT_BOX = 0,
    CSS_BOX_SIZING_BORDER_BOX
} css_box_sizing_t;

typedef enum
{
    CSS_LIST_STYLE_DISC = 0,
    CSS_LIST_STYLE_DECIMAL,
    CSS_LIST_STYLE_NONE
} css_list_style_type_t;

typedef enum
{
    CSS_POSITION_STATIC = 0,
    CSS_POSITION_RELATIVE,
    CSS_POSITION_ABSOLUTE,
    CSS_POSITION_FIXED
} css_position_t;

typedef enum
{
    CSS_FLOAT_NONE = 0,
    CSS_FLOAT_LEFT,
    CSS_FLOAT_RIGHT
} css_float_t;

typedef enum
{
    CSS_OVERFLOW_VISIBLE = 0,
    CSS_OVERFLOW_HIDDEN,
    CSS_OVERFLOW_SCROLL,
    CSS_OVERFLOW_AUTO
} css_overflow_t;

typedef enum
{
    CSS_CLEAR_NONE = 0,
    CSS_CLEAR_LEFT,
    CSS_CLEAR_RIGHT,
    CSS_CLEAR_BOTH
} css_clear_t;

typedef enum
{
    CSS_FLEX_DIRECTION_ROW = 0,
    CSS_FLEX_DIRECTION_ROW_REVERSE,
    CSS_FLEX_DIRECTION_COLUMN,
    CSS_FLEX_DIRECTION_COLUMN_REVERSE
} css_flex_direction_t;

typedef enum
{
    CSS_FLEX_WRAP_NOWRAP = 0,
    CSS_FLEX_WRAP_WRAP,
    CSS_FLEX_WRAP_WRAP_REVERSE
} css_flex_wrap_t;

typedef enum
{
    CSS_JUSTIFY_FLEX_START = 0,
    CSS_JUSTIFY_FLEX_END,
    CSS_JUSTIFY_CENTER,
    CSS_JUSTIFY_SPACE_BETWEEN,
    CSS_JUSTIFY_SPACE_AROUND,
    CSS_JUSTIFY_SPACE_EVENLY
} css_justify_content_t;

typedef enum
{
    CSS_ALIGN_STRETCH = 0,
    CSS_ALIGN_FLEX_START,
    CSS_ALIGN_FLEX_END,
    CSS_ALIGN_CENTER,
    CSS_ALIGN_BASELINE
} css_align_t;

typedef enum
{
    CSS_BORDER_SIDE_TOP = 0,
    CSS_BORDER_SIDE_RIGHT,
    CSS_BORDER_SIDE_BOTTOM,
    CSS_BORDER_SIDE_LEFT,
    CSS_BORDER_SIDE_COUNT
} css_border_side_t;

typedef struct
{
    bool has_background;
    video_color_t background;
    bool background_transparent;
    bool has_background_image;
    const char *background_image;
    bool background_image_owned;
    bool has_background_repeat;
    css_background_repeat_t background_repeat;
    bool has_background_attachment;
    css_background_attachment_t background_attachment;
    bool has_background_position;
    css_length_t background_pos_x;
    css_length_t background_pos_y;
    bool has_color;
    video_color_t color;
    bool has_font_size;
    css_length_t font_size;
    bool has_width;
    css_length_t width;
    bool has_min_width;
    css_length_t min_width;
    bool has_max_width;
    css_length_t max_width;
    bool has_height;
    css_length_t height;
    bool has_min_height;
    css_length_t min_height;
    bool has_max_height;
    css_length_t max_height;
    bool has_margin;
    css_box_t margin;
    bool has_padding;
    css_box_t padding;
    bool has_border;
    css_box_t border_width;
    bool has_border_style;
    bool border_style_none[CSS_BORDER_SIDE_COUNT];
    bool has_border_color;
    video_color_t border_color;
    bool border_transparent;
    bool border_color_side_set[CSS_BORDER_SIDE_COUNT];
    video_color_t border_color_side[CSS_BORDER_SIDE_COUNT];
    bool border_color_side_transparent[CSS_BORDER_SIDE_COUNT];
    bool has_position;
    css_position_t position;
    bool has_z_index;
    int32_t z_index;
    bool has_top;
    css_length_t top;
    bool has_right;
    css_length_t right;
    bool has_bottom;
    css_length_t bottom;
    bool has_left;
    css_length_t left;
    bool has_float;
    css_float_t float_mode;
    bool float_inherit;
    bool has_clear;
    css_clear_t clear_mode;
    bool has_overflow;
    css_overflow_t overflow;
    bool has_text_align;
    css_text_align_t text_align;
    bool has_text_decoration;
    css_text_decoration_t text_decoration;
    bool has_text_shadow;
    css_length_t text_shadow_x;
    css_length_t text_shadow_y;
    css_length_t text_shadow_blur;
    bool has_text_shadow_color;
    video_color_t text_shadow_color;
    bool has_display;
    css_display_t display;
    bool has_box_sizing;
    css_box_sizing_t box_sizing;
    bool box_sizing_inherit;
    bool has_list_style_type;
    css_list_style_type_t list_style_type;
    bool has_content;
    const char *content;
    bool content_owned;
    bool has_flex_direction;
    css_flex_direction_t flex_direction;
    bool has_flex_wrap;
    css_flex_wrap_t flex_wrap;
    bool has_justify_content;
    css_justify_content_t justify_content;
    bool has_align_items;
    css_align_t align_items;
    bool has_align_self;
    css_align_t align_self;
    bool has_align_content;
    css_align_t align_content;
    bool has_row_gap;
    css_length_t row_gap;
    bool has_column_gap;
    css_length_t column_gap;
    bool has_grid_template_columns;
    int32_t grid_template_columns;
    bool has_grid_column_span;
    int32_t grid_column_span;
    bool has_grid_column_start;
    int32_t grid_column_start;
    bool has_grid_column_end;
    int32_t grid_column_end;
    bool has_flex_grow;
    int32_t flex_grow_milli;
    bool has_flex_shrink;
    int32_t flex_shrink_milli;
    bool has_flex_basis;
    css_length_t flex_basis;
    bool has_line_height;
    int32_t line_height_milli;
    bool line_height_is_length;
    css_length_t line_height;
    bool has_letter_spacing;
    css_length_t letter_spacing;
    bool has_opacity;
    int32_t opacity_milli;
} css_style_t;

typedef struct css_selector_part
{
    uint32_t start;
    uint32_t end;
    char combinator;
} css_selector_part_t;

typedef struct css_selector_atom
{
    uint32_t start;
    uint32_t len;
} css_selector_atom_t;

typedef struct css_selector_attr_req
{
    uint32_t name_start;
    uint32_t name_len;
    uint32_t value_start;
    uint32_t value_len;
    char op;
    bool has_value;
} css_selector_attr_req_t;

typedef struct css_selector_compiled_part
{
    uint32_t tag_start;
    uint32_t tag_len;
    bool tag_any;
    bool id_valid;
    uint32_t id_start;
    uint32_t id_len;
    bool require_link;
    bool require_root;
    uint8_t pseudo_required;
    uint16_t class_count;
    uint16_t class_cap;
    css_selector_atom_t *classes;
    uint16_t attr_count;
    uint16_t attr_cap;
    css_selector_attr_req_t *attrs;
} css_selector_compiled_part_t;

typedef struct css_selector_cache
{
    css_selector_part_t *parts;
    size_t count;
    size_t cap;
    bool parsed;
    bool parse_failed;
    bool never_match;
    bool tag_hint_valid;
    bool tag_hint_any;
    uint32_t tag_hint_start;
    uint32_t tag_hint_len;
    bool class_hint_valid;
    uint32_t class_hint_start;
    uint32_t class_hint_len;
    bool scope_class_hint_valid;
    uint32_t scope_class_hint_start;
    uint32_t scope_class_hint_len;
    bool parent_class_hint_valid;
    uint32_t parent_class_hint_start;
    uint32_t parent_class_hint_len;
    bool id_hint_valid;
    uint32_t id_hint_start;
    uint32_t id_hint_len;
    bool attr_hint_valid;
    uint32_t attr_hint_name_start;
    uint32_t attr_hint_name_len;
    bool attr_hint_value_valid;
    uint32_t attr_hint_value_start;
    uint32_t attr_hint_value_len;
    char attr_hint_op;
    uint8_t pseudo_mask;
    web_bloom_t self_bloom_mask;
    web_bloom_t ancestor_bloom_mask;
    uint8_t self_class_count;
    uint8_t self_attr_count;
    bool self_class_truncated;
    bool self_attr_truncated;
    bool self_simple;
    uint32_t self_class_start[4];
    uint32_t self_class_len[4];
    uint32_t self_attr_start[2];
    uint32_t self_attr_len[2];
    css_selector_compiled_part_t *compiled_parts;
    size_t compiled_count;
    bool compiled;
    bool compiled_failed;
    uint32_t order;
} css_selector_cache_t;

typedef struct css_rule
{
    char *selector;
    css_style_t style;
    css_selector_cache_t *selector_cache;
    struct css_rule *next;
} css_rule_t;

typedef struct
{
    css_rule_t *rules;
} css_stylesheet_t;

void css_media_env_set(int width_px, int height_px, css_media_color_scheme_t scheme);
css_stylesheet_t *css_parse(const char *css_text);
void css_stylesheet_destroy(css_stylesheet_t *sheet);

bool css_rule_matches_tag(const css_rule_t *rule, const char *tag_name);
void css_style_merge(css_style_t *dst, const css_style_t *src);

#ifdef __cplusplus
}
#endif

#endif /* WEB_CSS_PUBLIC_H */
