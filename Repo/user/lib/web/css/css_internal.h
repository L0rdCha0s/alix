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
bool css_style_copy(css_style_t *dst, const css_style_t *src);
bool css_style_dup_owned_strings(css_style_t *style);
void css_style_resolve_deferred(css_style_t *style);

bool css_value_has_var(const char *start, const char *end);
char *css_expand_vars_range(const char *val_start,
                            const char *val_end,
                            const css_var_map_t *global_vars,
                            const css_var_map_t *local_vars,
                            int depth);

bool css_decl_list_push(css_decl_list_t *list,
                        const char *prop_start,
                        const char *prop_end,
                        const char *val_start,
                        const char *val_end,
                        bool important);
void css_decl_list_free(css_decl_list_t *list);

bool css_var_map_set(css_var_map_t *map,
                     const char *name_start,
                     const char *name_end,
                     const char *value_start,
                     const char *value_end,
                     const css_var_tokens_t *tokens,
                     bool allow_override);
bool css_var_map_set_parsed(css_stylesheet_t *sheet,
                            css_var_map_t *map,
                            const char *name_start,
                            const char *name_end,
                            const char *value_start,
                            const char *value_end,
                            bool allow_override);
bool css_var_map_set_entry(css_var_map_t *map,
                           const css_var_entry_t *entry,
                           bool allow_override);
void css_var_map_free(css_var_map_t *map);
bool css_var_map_clone(css_var_map_t *dst, const css_var_map_t *src);
const char *css_var_map_lookup(const css_var_map_t *map,
                               const css_var_map_t *fallback_map,
                               const char *name_start,
                               const char *name_end,
                               size_t *out_len);

css_var_env_t *css_var_env_create(css_var_env_t *parent);
css_var_env_t *css_var_env_ref(css_var_env_t *env);
void css_var_env_release(css_var_env_t *env);
bool css_var_env_ensure_local(css_style_t *style);
bool css_style_apply_custom_props(css_style_t *style, const css_var_map_t *props);

const css_var_tokens_t *css_var_tokens_parse_range(css_stylesheet_t *sheet,
                                                   const char *start,
                                                   const char *end);

bool css_deferred_map_set(css_deferred_map_t *map,
                          const char *prop_start,
                          const char *prop_end,
                          const css_var_tokens_t *tokens,
                          bool allow_override);
void css_deferred_map_free(css_deferred_map_t *map);
bool css_deferred_map_clone(css_deferred_map_t *dst, const css_deferred_map_t *src);
bool css_deferred_map_merge(css_deferred_map_t *dst, const css_deferred_map_t *src);

void css_perf_reset(bool enabled);
void css_perf_dump(void);

#ifdef __cplusplus
}
#endif

#endif /* WEB_CSS_INTERNAL_H */
