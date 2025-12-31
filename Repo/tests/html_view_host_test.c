#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "atk/html_view/html_view_internal.h"
#include "libc.h"
#include "video.h"
#include "web/css.h"
#include "web/html.h"

int atk_font_line_height(void)
{
    return 16;
}

int html_view_text_width(const html_view_ctx_t *ctx, const char *text)
{
    (void)ctx;
    if (!text)
    {
        return 0;
    }
    return (int)strlen(text) * 8;
}

html_view_font_size_cache_t *html_view_font_state_get_cache(html_view_font_state_t *state, int pixel_height)
{
    (void)state;
    (void)pixel_height;
    return NULL;
}

char *html_view_strdup(const char *src)
{
    if (!src)
    {
        return NULL;
    }
    size_t len = strlen(src);
    char *copy = (char *)malloc(len + 1);
    if (!copy)
    {
        return NULL;
    }
    memcpy(copy, src, len + 1);
    return copy;
}

video_color_t video_make_color(uint8_t r, uint8_t g, uint8_t b)
{
    return 0xFF000000U | ((video_color_t)r << 16) | ((video_color_t)g << 8) | (video_color_t)b;
}

static bool css_length_is(const css_length_t *len, int32_t milli, css_unit_t unit)
{
    if (!len)
    {
        return false;
    }
    return len->valid && !len->is_auto && len->value_milli == milli && len->unit == unit;
}

static const html_node_t *find_first_tag(const html_node_t *root, const char *tag)
{
    if (!root || !tag || tag[0] == '\0')
    {
        return NULL;
    }

    const html_node_t *stack[64];
    size_t sp = 0;
    stack[sp++] = root;

    while (sp > 0)
    {
        const html_node_t *node = stack[--sp];
        if (node->type == HTML_NODE_ELEMENT && node->name && strcmp(node->name, tag) == 0)
        {
            return node;
        }
        for (const html_node_t *child = node->last_child; child; child = child->prev_sibling)
        {
            if (sp < sizeof(stack) / sizeof(stack[0]))
            {
                stack[sp++] = child;
            }
        }
    }
    return NULL;
}

static const html_node_t *find_node_by_id(const html_node_t *root, const char *id)
{
    if (!root || !id || id[0] == '\0')
    {
        return NULL;
    }

    const html_node_t *stack[64];
    size_t sp = 0;
    stack[sp++] = root;

    while (sp > 0)
    {
        const html_node_t *node = stack[--sp];
        if (node->type == HTML_NODE_ELEMENT)
        {
            const char *node_id = html_attr_get(node, "id");
            if (node_id && strcmp(node_id, id) == 0)
            {
                return node;
            }
        }
        for (const html_node_t *child = node->last_child; child; child = child->prev_sibling)
        {
            if (sp < sizeof(stack) / sizeof(stack[0]))
            {
                stack[sp++] = child;
            }
        }
    }
    return NULL;
}

static bool test_table_cell_alignment(void)
{
    html_parse_error_t err = {0};
    html_document_t *doc = html_parse("<center><table><tr><td>Hi</td></tr></table></center>", &err);
    if (!doc)
    {
        return false;
    }

    const html_node_t *td = find_first_tag(doc->root, "td");
    if (!td)
    {
        html_document_destroy(doc);
        return false;
    }

    css_style_t parent = {0};
    parent.has_text_align = true;
    parent.text_align = CSS_TEXT_ALIGN_CENTER;

    css_style_t out = {0};
    html_view_style_for_node(&out, NULL, &parent, td);

    html_document_destroy(doc);
    return out.has_text_align && out.text_align == CSS_TEXT_ALIGN_LEFT;
}

static bool test_table_header_alignment(void)
{
    html_parse_error_t err = {0};
    html_document_t *doc = html_parse("<table><tr><th>Head</th></tr></table>", &err);
    if (!doc)
    {
        return false;
    }

    const html_node_t *th = find_first_tag(doc->root, "th");
    if (!th)
    {
        html_document_destroy(doc);
        return false;
    }

    css_style_t parent = {0};
    parent.has_text_align = true;
    parent.text_align = CSS_TEXT_ALIGN_LEFT;

    css_style_t out = {0};
    html_view_style_for_node(&out, NULL, &parent, th);

    html_document_destroy(doc);
    return out.has_text_align && out.text_align == CSS_TEXT_ALIGN_CENTER;
}

static bool test_line_height_length_px(void)
{
    html_view_ctx_t ctx = {0};
    ctx.actual_font_px = 12;
    ctx.base_font_px = 12;
    ctx.viewport_w = 800;
    ctx.viewport_h = 600;

    css_style_t style = {0};
    style.has_line_height = true;
    style.line_height_is_length = true;
    style.line_height.valid = true;
    style.line_height.is_auto = false;
    style.line_height.value_milli = 18000;
    style.line_height.unit = CSS_UNIT_PX;

    int lh = html_view_line_height_for_style(&ctx, &style);
    return lh == 18;
}

static bool test_border_style_none_zeroes_width(void)
{
    html_view_ctx_t ctx = {0};
    ctx.viewport_w = 800;
    ctx.viewport_h = 600;
    ctx.body_w = 800;
    ctx.base_font_px = 16;

    css_style_t style = {0};
    style.has_border = true;
    style.has_border_style = true;
    style.border_style_none[CSS_BORDER_SIDE_TOP] = true;
    style.border_style_none[CSS_BORDER_SIDE_BOTTOM] = true;
    style.border_style_none[CSS_BORDER_SIDE_LEFT] = false;
    style.border_style_none[CSS_BORDER_SIDE_RIGHT] = false;
    style.border_width.top = (css_length_t){ .valid = true, .is_auto = false, .value_milli = 2000, .unit = CSS_UNIT_PX };
    style.border_width.right = (css_length_t){ .valid = true, .is_auto = false, .value_milli = 2000, .unit = CSS_UNIT_PX };
    style.border_width.bottom = (css_length_t){ .valid = true, .is_auto = false, .value_milli = 2000, .unit = CSS_UNIT_PX };
    style.border_width.left = (css_length_t){ .valid = true, .is_auto = false, .value_milli = 2000, .unit = CSS_UNIT_PX };

    int top = html_view_length_to_px(&style.border_width.top,
                                     ctx.viewport_w,
                                     ctx.viewport_h,
                                     ctx.body_w,
                                     ctx.viewport_h,
                                     ctx.base_font_px,
                                     false);
    int right = html_view_length_to_px(&style.border_width.right,
                                       ctx.viewport_w,
                                       ctx.viewport_h,
                                       ctx.body_w,
                                       ctx.viewport_h,
                                       ctx.base_font_px,
                                       true);
    int bottom = html_view_length_to_px(&style.border_width.bottom,
                                        ctx.viewport_w,
                                        ctx.viewport_h,
                                        ctx.body_w,
                                        ctx.viewport_h,
                                        ctx.base_font_px,
                                        false);
    int left = html_view_length_to_px(&style.border_width.left,
                                      ctx.viewport_w,
                                      ctx.viewport_h,
                                      ctx.body_w,
                                      ctx.viewport_h,
                                      ctx.base_font_px,
                                      true);

    html_view_apply_border_style_none(&style, &top, &right, &bottom, &left);

    return top == 0 && bottom == 0 && right == 2 && left == 2;
}

static bool test_height_percent_requires_basis(void)
{
    html_view_ctx_t ctx = {0};
    ctx.viewport_w = 800;
    ctx.viewport_h = 600;
    ctx.body_w = 800;
    ctx.base_font_px = 16;

    css_length_t len = {
        .valid = true,
        .is_auto = false,
        .value_milli = 50000,
        .unit = CSS_UNIT_PERCENT,
    };
    int px = 123;
    bool ok = !html_view_length_to_px_height(&ctx, &len, &px);
    return ok && px == 0;
}

static bool test_height_percent_with_basis(void)
{
    html_view_ctx_t ctx = {0};
    ctx.viewport_w = 800;
    ctx.viewport_h = 600;
    ctx.body_w = 800;
    ctx.base_font_px = 16;
    ctx.height_basis_valid = true;
    ctx.height_basis_explicit = true;
    ctx.height_basis = 200;

    css_length_t len = {
        .valid = true,
        .is_auto = false,
        .value_milli = 50000,
        .unit = CSS_UNIT_PERCENT,
    };
    int px = 0;
    bool ok = html_view_length_to_px_height(&ctx, &len, &px);
    return ok && px == 100;
}

static bool test_height_px_without_basis(void)
{
    html_view_ctx_t ctx = {0};
    ctx.viewport_w = 800;
    ctx.viewport_h = 600;
    ctx.body_w = 800;
    ctx.base_font_px = 16;

    css_length_t len = {
        .valid = true,
        .is_auto = false,
        .value_milli = 24000,
        .unit = CSS_UNIT_PX,
    };
    int px = 0;
    bool ok = html_view_length_to_px_height(&ctx, &len, &px);
    return ok && px == 24;
}

static bool test_margin_collapse_siblings(void)
{
    html_view_ctx_t ctx = {0};
    ctx.viewport_w = 200;
    ctx.viewport_h = 200;
    ctx.body_w = 200;
    ctx.max_x = 200;
    ctx.base_font_px = 16;
    ctx.base_line_height = 16;
    ctx.line_height = 16;
    ctx.paint_layer = HTML_VIEW_PAINT_LAYER_BLOCK;
    ctx.body_x = 0;
    ctx.x = 0;
    ctx.y = 0;

    html_node_t node1 = {0};
    node1.type = HTML_NODE_ELEMENT;
    node1.name = (char *)"div";

    css_style_t style1 = {0};
    style1.has_margin = true;
    style1.margin.bottom.valid = true;
    style1.margin.bottom.value_milli = 20000;
    style1.margin.bottom.unit = CSS_UNIT_PX;
    style1.margin.bottom.is_auto = false;
    style1.has_height = true;
    style1.height.valid = true;
    style1.height.is_auto = false;
    style1.height.value_milli = 10000;
    style1.height.unit = CSS_UNIT_PX;

    html_node_t node2 = {0};
    node2.type = HTML_NODE_ELEMENT;
    node2.name = (char *)"div";

    css_style_t style2 = {0};
    style2.has_margin = true;
    style2.margin.top.valid = true;
    style2.margin.top.value_milli = 10000;
    style2.margin.top.unit = CSS_UNIT_PX;
    style2.margin.top.is_auto = false;
    style2.has_height = true;
    style2.height.valid = true;
    style2.height.is_auto = false;
    style2.height.value_milli = 10000;
    style2.height.unit = CSS_UNIT_PX;

    bool ok1 = html_view_render_block_element(&ctx, &node1, &style1);
    int after_first = ctx.y;
    bool ok2 = html_view_render_block_element(&ctx, &node2, &style2);

    return ok1 && ok2 && after_first == 10 && ctx.y == 40;
}

static bool test_margin_collapse_empty_block(void)
{
    html_view_ctx_t ctx = {0};
    ctx.viewport_w = 200;
    ctx.viewport_h = 200;
    ctx.body_w = 200;
    ctx.max_x = 200;
    ctx.base_font_px = 16;
    ctx.base_line_height = 16;
    ctx.line_height = 16;
    ctx.paint_layer = HTML_VIEW_PAINT_LAYER_BLOCK;
    ctx.body_x = 0;
    ctx.x = 0;
    ctx.y = 0;

    html_node_t node = {0};
    node.type = HTML_NODE_ELEMENT;
    node.name = (char *)"div";

    css_style_t style = {0};
    style.has_margin = true;
    style.margin.top.valid = true;
    style.margin.top.value_milli = 10000;
    style.margin.top.unit = CSS_UNIT_PX;
    style.margin.top.is_auto = false;
    style.margin.bottom.valid = true;
    style.margin.bottom.value_milli = 20000;
    style.margin.bottom.unit = CSS_UNIT_PX;
    style.margin.bottom.is_auto = false;

    bool ok = html_view_render_block_element(&ctx, &node, &style);
    return ok && ctx.y == 0 && ctx.pending_margin_valid && ctx.pending_margin == 20;
}

static bool test_attribute_selectors_with_escapes(void)
{
    html_parse_error_t err = {0};
    html_document_t *doc = html_parse("<div class=\"first one\"><span class=\"second two\"></span></div>", &err);
    if (!doc)
    {
        return false;
    }

    const html_node_t *div = find_first_tag(doc->root, "div");
    const html_node_t *span = find_first_tag(doc->root, "span");
    if (!div || !span)
    {
        html_document_destroy(doc);
        return false;
    }

    const char *css =
        "[class~=one].first.one { position: absolute; }\n"
        "[class=second\\ two][class=\"second two\"] { float: right; }\n";
    css_stylesheet_t *sheet = css_parse(css);
    if (!sheet)
    {
        html_document_destroy(doc);
        return false;
    }

    css_style_t parent = {0};
    css_style_t out_div = {0};
    html_view_style_for_node(&out_div, sheet, &parent, div);
    bool ok_div = out_div.has_position && out_div.position == CSS_POSITION_ABSOLUTE;

    css_style_t out_span = {0};
    html_view_style_for_node(&out_span, sheet, &parent, span);
    bool ok_span = out_span.has_float && out_span.float_mode == CSS_FLOAT_RIGHT;

    css_stylesheet_destroy(sheet);
    html_document_destroy(doc);
    return ok_div && ok_span;
}

static bool test_adjacent_sibling_selector(void)
{
    html_parse_error_t err = {0};
    html_document_t *doc = html_parse("<div class=\"picture\"><p id=\"first\"></p><table></table><p id=\"second\"></p></div>", &err);
    if (!doc)
    {
        return false;
    }

    const html_node_t *first = find_node_by_id(doc->root, "first");
    const html_node_t *second = find_node_by_id(doc->root, "second");
    if (!first || !second)
    {
        html_document_destroy(doc);
        return false;
    }

    const char *css = ".picture p + table + p { background: yellow; }";
    css_stylesheet_t *sheet = css_parse(css);
    if (!sheet)
    {
        html_document_destroy(doc);
        return false;
    }

    css_style_t parent = {0};
    css_style_t out_first = {0};
    html_view_style_for_node(&out_first, sheet, &parent, first);
    css_style_t out_second = {0};
    html_view_style_for_node(&out_second, sheet, &parent, second);

    css_stylesheet_destroy(sheet);
    html_document_destroy(doc);

    return !out_first.has_background && out_second.has_background;
}

static bool test_child_and_descendant_selectors(void)
{
    html_parse_error_t err = {0};
    html_document_t *doc = html_parse("<div class=\"nose\"><div id=\"child\"><div id=\"grand\"></div></div></div>", &err);
    if (!doc)
    {
        return false;
    }

    const html_node_t *nose = find_first_tag(doc->root, "div");
    const html_node_t *child = find_node_by_id(doc->root, "child");
    const html_node_t *grand = find_node_by_id(doc->root, "grand");
    if (!nose || !child || !grand)
    {
        html_document_destroy(doc);
        return false;
    }

    const char *css =
        ".nose > div { background: yellow; }\n"
        ".nose div div { background: red; }\n";
    css_stylesheet_t *sheet = css_parse(css);
    if (!sheet)
    {
        html_document_destroy(doc);
        return false;
    }

    css_style_t parent = {0};
    css_style_t out_nose = {0};
    css_style_t out_child = {0};
    css_style_t out_grand = {0};
    html_view_style_for_node(&out_nose, sheet, &parent, nose);
    html_view_style_for_node(&out_child, sheet, &parent, child);
    html_view_style_for_node(&out_grand, sheet, &parent, grand);

    css_stylesheet_destroy(sheet);
    html_document_destroy(doc);

    bool nose_ok = !out_nose.has_background;
    bool child_ok = out_child.has_background && out_child.background == video_make_color(0xFF, 0xFF, 0x00);
    bool grand_ok = out_grand.has_background && out_grand.background == video_make_color(0xFF, 0x00, 0x00);
    return nose_ok && child_ok && grand_ok;
}

static bool test_link_pseudo_class(void)
{
    html_parse_error_t err = {0};
    html_document_t *doc = html_parse("<a href=\"x\" id=\"link\">link</a>", &err);
    if (!doc)
    {
        return false;
    }

    const html_node_t *link = find_node_by_id(doc->root, "link");
    if (!link)
    {
        html_document_destroy(doc);
        return false;
    }

    const char *css =
        "a:link { color: blue; }\n"
        "a:visited { color: purple; }\n";
    css_stylesheet_t *sheet = css_parse(css);
    if (!sheet)
    {
        html_document_destroy(doc);
        return false;
    }

    css_style_t parent = {0};
    css_style_t out = {0};
    html_view_style_for_node(&out, sheet, &parent, link);

    css_stylesheet_destroy(sheet);
    html_document_destroy(doc);

    return out.has_color && out.color == video_make_color(0x00, 0x00, 0xFF);
}

static bool test_pseudo_element_style(void)
{
    html_parse_error_t err = {0};
    html_document_t *doc = html_parse("<div class=\"nose\"><div id=\"child\"></div></div>", &err);
    if (!doc)
    {
        return false;
    }

    const html_node_t *child = find_node_by_id(doc->root, "child");
    if (!child)
    {
        html_document_destroy(doc);
        return false;
    }

    const char *css = ".nose div:before { background: yellow; content: ''; border-top: 1px solid red; }";
    css_stylesheet_t *sheet = css_parse(css);
    if (!sheet)
    {
        html_document_destroy(doc);
        return false;
    }

    css_style_t parent = {0};
    css_style_t base = {0};
    html_view_style_for_node(&base, sheet, &parent, child);

    css_style_t out = {0};
    bool has_pseudo = html_view_style_for_pseudo(&out, sheet, &base, child, HTML_VIEW_PSEUDO_BEFORE);

    css_stylesheet_destroy(sheet);
    html_document_destroy(doc);
    bool ok = has_pseudo &&
              out.has_background &&
              out.background == video_make_color(0xFF, 0xFF, 0x00) &&
              out.has_content &&
              out.border_color_side_set[CSS_BORDER_SIDE_TOP] &&
              out.border_color_side[CSS_BORDER_SIDE_TOP] == video_make_color(0xFF, 0x00, 0x00);
    return ok;
}

static bool test_inline_background_style(void)
{
    html_parse_error_t err = {0};
    html_document_t *doc = html_parse("<div id=\"box\" style=\"background: red url(foo.png) no-repeat fixed 1px 2px;\"></div>", &err);
    if (!doc)
    {
        return false;
    }

    const html_node_t *node = find_node_by_id(doc->root, "box");
    if (!node)
    {
        html_document_destroy(doc);
        return false;
    }

    css_style_t parent = {0};
    css_style_t out = {0};
    html_view_style_for_node(&out, NULL, &parent, node);

    bool ok = out.has_background &&
              !out.background_transparent &&
              out.background == video_make_color(0xFF, 0x00, 0x00);
    ok = ok && out.has_background_image &&
         out.background_image &&
         strcmp(out.background_image, "foo.png") == 0;
    ok = ok && out.has_background_repeat &&
         out.background_repeat == CSS_BACKGROUND_REPEAT_NO_REPEAT;
    ok = ok && out.has_background_attachment &&
         out.background_attachment == CSS_BACKGROUND_ATTACHMENT_FIXED;
    ok = ok && out.has_background_position &&
         css_length_is(&out.background_pos_x, 1000, CSS_UNIT_PX) &&
         css_length_is(&out.background_pos_y, 2000, CSS_UNIT_PX);

    if (out.background_image_owned && out.background_image)
    {
        free((void *)out.background_image);
    }
    html_document_destroy(doc);
    return ok;
}

static bool test_link_stylesheet_data_url(void)
{
    html_parse_error_t err = {0};
    const char *html =
        "<html><head>"
        "<style>div{background:red;}</style>"
        "<link rel=\"appendix stylesheet\" href=\"data:text/css,div%7Bbackground%3Ablue%3B%7D\">"
        "</head><body><div id=\"box\"></div></body></html>";
    html_document_t *doc = html_parse(html, &err);
    if (!doc)
    {
        return false;
    }

    const html_node_t *box = find_node_by_id(doc->root, "box");
    if (!box)
    {
        html_document_destroy(doc);
        return false;
    }

    atk_html_view_priv_t priv = {0};
    priv.doc = doc;
    html_view_rebuild_stylesheet(&priv);
    if (!priv.sheet)
    {
        html_document_destroy(doc);
        return false;
    }

    css_style_t parent = {0};
    css_style_t out = {0};
    html_view_style_for_node(&out, priv.sheet, &parent, box);

    bool ok = out.has_background &&
              !out.background_transparent &&
              out.background == video_make_color(0x00, 0x00, 0xFF);

    css_stylesheet_destroy(priv.sheet);
    priv.sheet = NULL;
    html_document_destroy(doc);
    return ok;
}

static bool test_object_fallback_text(void)
{
    html_parse_error_t err = {0};
    html_document_t *doc = html_parse("<object data=\"data:application/x-unknown,ERROR\">OK</object>", &err);
    if (!doc)
    {
        return false;
    }

    const html_node_t *obj = find_first_tag(doc->root, "object");
    if (!obj)
    {
        html_document_destroy(doc);
        return false;
    }

    html_view_ctx_t ctx = {0};
    ctx.viewport_w = 200;
    ctx.viewport_h = 200;
    ctx.body_w = 200;
    ctx.max_x = 200;
    ctx.actual_font_px = 16;
    ctx.base_font_px = 16;
    ctx.base_line_height = 16;
    ctx.line_height = 16;
    ctx.space_w = html_view_text_width(&ctx, " ");
    ctx.paint_layer = HTML_VIEW_PAINT_LAYER_BLOCK;

    css_style_t parent = {0};
    css_style_t style = {0};
    html_view_style_for_node(&style, NULL, &parent, obj);

    bool rendered = html_view_render_inline_element(&ctx, obj, &style);
    html_document_destroy(doc);
    return rendered && ctx.x == 16;
}

static bool test_float_inherit(void)
{
    html_parse_error_t err = {0};
    html_document_t *doc = html_parse("<span id=\"parent\"><em id=\"child\"></em></span>", &err);
    if (!doc)
    {
        return false;
    }

    const html_node_t *parent_node = find_node_by_id(doc->root, "parent");
    const html_node_t *child_node = find_node_by_id(doc->root, "child");
    if (!parent_node || !child_node)
    {
        html_document_destroy(doc);
        return false;
    }

    const char *css = "span { float: right; } em { float: inherit; }";
    css_stylesheet_t *sheet = css_parse(css);
    if (!sheet)
    {
        html_document_destroy(doc);
        return false;
    }

    css_style_t root = {0};
    css_style_t parent_style = {0};
    html_view_style_for_node(&parent_style, sheet, &root, parent_node);

    css_style_t child_style = {0};
    html_view_style_for_node(&child_style, sheet, &parent_style, child_node);

    bool ok = parent_style.has_float && parent_style.float_mode == CSS_FLOAT_RIGHT;
    ok = ok && child_style.has_float && child_style.float_mode == CSS_FLOAT_RIGHT;
    ok = ok && !child_style.float_inherit;

    css_stylesheet_destroy(sheet);
    html_document_destroy(doc);
    return ok;
}

static bool test_float_measure_width(void)
{
    html_view_ctx_t ctx = {0};
    ctx.viewport_w = 200;
    ctx.viewport_h = 200;
    ctx.body_w = 200;
    ctx.max_x = 200;
    ctx.actual_font_px = 16;
    ctx.base_font_px = 16;
    ctx.base_line_height = 16;
    ctx.line_height = 16;
    ctx.paint_layer = HTML_VIEW_PAINT_LAYER_BLOCK;

    css_style_t style = {0};
    style.has_float = true;
    style.float_mode = CSS_FLOAT_RIGHT;
    style.has_width = true;
    style.width.valid = true;
    style.width.is_auto = false;
    style.width.value_milli = 40000;
    style.width.unit = CSS_UNIT_PX;

    html_node_t node = {0};
    node.type = HTML_NODE_ELEMENT;
    node.name = (char *)"div";

    html_view_render_float_box(&ctx, &node, &style, CSS_FLOAT_RIGHT);

    return ctx.measure_max_x >= 40;
}

typedef struct
{
    const char *name;
    bool (*fn)(void);
} hv_case_t;

int main(void)
{
    hv_case_t cases[] = {
        { "table-cell-align-left", test_table_cell_alignment },
        { "table-header-align-center", test_table_header_alignment },
        { "line-height-length-px", test_line_height_length_px },
        { "border-style-none-zeroes", test_border_style_none_zeroes_width },
        { "height-percent-requires-basis", test_height_percent_requires_basis },
        { "height-percent-with-basis", test_height_percent_with_basis },
        { "height-px-without-basis", test_height_px_without_basis },
        { "margin-collapse-siblings", test_margin_collapse_siblings },
        { "margin-collapse-empty-block", test_margin_collapse_empty_block },
        { "attribute-selectors-escapes", test_attribute_selectors_with_escapes },
        { "adjacent-sibling-selector", test_adjacent_sibling_selector },
        { "child-descendant-selector", test_child_and_descendant_selectors },
        { "link-pseudo-class", test_link_pseudo_class },
        { "pseudo-element-style", test_pseudo_element_style },
        { "inline-background-style", test_inline_background_style },
        { "link-stylesheet-data-url", test_link_stylesheet_data_url },
        { "object-fallback-text", test_object_fallback_text },
        { "float-inherit", test_float_inherit },
        { "float-measure-width", test_float_measure_width },
    };

    size_t pass = 0;
    size_t fail = 0;
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i)
    {
        bool ok = cases[i].fn();
        if (ok)
        {
            pass++;
        }
        else
        {
            fail++;
            printf("html_view_host_test: case %s failed\n", cases[i].name);
        }
    }

    printf("html_view_host_test: total=%zu pass=%zu fail=%zu\n", pass + fail, pass, fail);
    return fail == 0 ? 0 : 1;
}
