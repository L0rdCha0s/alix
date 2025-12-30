#ifndef ATK_HTML_VIEW_RENDER_INTERNAL_H
#define ATK_HTML_VIEW_RENDER_INTERNAL_H

#include "atk/html_view/html_view_internal.h"

void html_view_render_node_internal(html_view_ctx_t *ctx,
                                    const html_node_t *node,
                                    const css_style_t *parent_style);
void html_view_render_flex_container(html_view_ctx_t *ctx,
                                     const html_node_t *node,
                                     const css_style_t *style,
                                     bool inline_container);
bool html_view_render_positioned_element(html_view_ctx_t *ctx,
                                         const html_node_t *node,
                                         const css_style_t *style,
                                         const css_style_t *parent_style);
void html_view_record_anchor(html_view_ctx_t *ctx, const html_node_t *node);

bool html_view_render_break_element(html_view_ctx_t *ctx, const html_node_t *node);
bool html_view_render_table_element(html_view_ctx_t *ctx,
                                    const html_node_t *node,
                                    const css_style_t *style,
                                    const css_style_t *parent_style);
bool html_view_render_form_element(html_view_ctx_t *ctx, const html_node_t *node, const css_style_t *style);
bool html_view_render_block_element(html_view_ctx_t *ctx, const html_node_t *node, const css_style_t *style);
bool html_view_render_inline_element(html_view_ctx_t *ctx, const html_node_t *node, const css_style_t *style);

#endif /* ATK_HTML_VIEW_RENDER_INTERNAL_H */
