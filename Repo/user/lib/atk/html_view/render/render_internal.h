#ifndef ATK_HTML_VIEW_RENDER_INTERNAL_H
#define ATK_HTML_VIEW_RENDER_INTERNAL_H

#include "atk/html_view/html_view_internal.h"

#include "string.h"

static inline const char *html_view_scroller_anchor_for_node(const html_node_t *node)
{
    if (!node || node->type != HTML_NODE_ELEMENT)
    {
        return NULL;
    }
    const char *anchor = html_attr_get(node, "data-sticky-anchor");
    if (anchor && anchor[0] != '\0')
    {
        return anchor;
    }
    const char *id = html_attr_get(node, "id");
    if (id && strcmp(id, "scroller") == 0)
    {
        return "scroller-anchor";
    }
    return NULL;
}

static inline bool html_view_anchor_lookup_y(const html_view_render_cache_t *cache,
                                             const char *id,
                                             int *out_y)
{
    if (!cache || !id || id[0] == '\0')
    {
        return false;
    }
    for (size_t i = 0; i < cache->anchor_count; ++i)
    {
        const html_view_anchor_t *anchor = &cache->anchors[i];
        if (anchor->id && strcmp(anchor->id, id) == 0)
        {
            if (out_y)
            {
                *out_y = anchor->y;
            }
            return true;
        }
    }
    return false;
}

static inline int html_view_scroll_padding_top(const html_view_ctx_t *ctx)
{
    if (!ctx || !ctx->priv)
    {
        return 0;
    }
    const html_view_render_cache_t *cache = &ctx->priv->render_cache;
    int pad = cache->doc_origin_local_y - cache->body_box_y_local - cache->border_px;
    if (pad < 0)
    {
        pad = 0;
    }
    return pad;
}

void html_view_render_node_internal(html_view_ctx_t *ctx,
                                    const html_node_t *node,
                                    const css_style_t *parent_style);
void html_view_render_flex_container(html_view_ctx_t *ctx,
                                     const html_node_t *node,
                                     const css_style_t *style,
                                     bool inline_container);
void html_view_render_grid_container(html_view_ctx_t *ctx,
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
