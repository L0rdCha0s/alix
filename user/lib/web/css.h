#ifndef WEB_CSS_H
#define WEB_CSS_H

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
    bool has_margin;
    css_box_t margin;
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

#endif /* WEB_CSS_H */

