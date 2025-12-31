#ifndef WEB_CSS_INTERNAL_H
#define WEB_CSS_INTERNAL_H

#include "web/css.h"

#ifdef __cplusplus
extern "C" {
#endif

void css_skip_ws_and_comments(const char **p);
void css_skip_ws_and_comments_range(const char **p, const char *end);
void css_trim_range(const char **start, const char **end);
char *css_strdup_lower(const char *start, const char *end);
bool css_parse_color(const char *start, const char *end, video_color_t *out);
bool css_parse_number_milli(const char *start, const char *end, int32_t *out_milli);
bool css_parse_length_token(const char *start, const char *end, css_length_t *out);
bool css_parse_margin_value(const char *start, const char *end, css_box_t *out);
css_box_t css_box_from_length(css_length_t len);
void css_style_apply_property(css_style_t *style,
                              const char *prop_start,
                              const char *prop_end,
                              const char *val_start,
                              const char *val_end);
void css_style_release(css_style_t *style);

#ifdef __cplusplus
}
#endif

#endif /* WEB_CSS_INTERNAL_H */
