#ifndef WEB_CSS_PUBLIC_H
#define WEB_CSS_PUBLIC_H

#include "types.h"
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
    CSS_DISPLAY_INLINE = 0,
    CSS_DISPLAY_BLOCK,
    CSS_DISPLAY_LIST_ITEM,
    CSS_DISPLAY_NONE
} css_display_t;

typedef enum
{
    CSS_FLOAT_NONE = 0,
    CSS_FLOAT_LEFT,
    CSS_FLOAT_RIGHT
} css_float_t;

typedef enum
{
    CSS_CLEAR_NONE = 0,
    CSS_CLEAR_LEFT,
    CSS_CLEAR_RIGHT,
    CSS_CLEAR_BOTH
} css_clear_t;

typedef struct
{
    bool has_background;
    video_color_t background;
    bool has_color;
    video_color_t color;
    bool has_font_size;
    css_length_t font_size;
    bool has_width;
    css_length_t width;
    bool has_height;
    css_length_t height;
    bool has_margin;
    css_box_t margin;
    bool has_padding;
    css_box_t padding;
    bool has_border;
    css_box_t border_width;
    bool has_border_color;
    video_color_t border_color;
    bool has_float;
    css_float_t float_mode;
    bool has_clear;
    css_clear_t clear_mode;
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
    bool has_line_height;
    int32_t line_height_milli;
    bool has_letter_spacing;
    css_length_t letter_spacing;
    bool has_opacity;
    int32_t opacity_milli;
} css_style_t;

typedef struct css_rule
{
    char *selector;
    css_style_t style;
    struct css_rule *next;
} css_rule_t;

typedef struct
{
    css_rule_t *rules;
} css_stylesheet_t;

css_stylesheet_t *css_parse(const char *css_text);
void css_stylesheet_destroy(css_stylesheet_t *sheet);

bool css_rule_matches_tag(const css_rule_t *rule, const char *tag_name);
void css_style_merge(css_style_t *dst, const css_style_t *src);

#ifdef __cplusplus
}
#endif

#endif /* WEB_CSS_PUBLIC_H */
