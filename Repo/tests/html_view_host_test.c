#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "libc.h"
#include "video.h"
#include "web/css.h"
#include "web/html.h"

typedef struct html_view_style_block
{
    css_style_t styles[64];
    size_t used;
    struct html_view_style_block *prev;
} html_view_style_block_t;

typedef struct
{
    const css_stylesheet_t *sheet;
    int actual_font_px;
    int base_font_px;
    int base_line_height;
    int line_height;
    int space_w;
    int viewport_w;
    int viewport_h;
    html_view_style_block_t *style_block;
    size_t style_depth;
} html_view_ctx_t;

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

video_color_t video_make_color(uint8_t r, uint8_t g, uint8_t b)
{
    return 0xFF000000U | ((video_color_t)r << 16) | ((video_color_t)g << 8) | (video_color_t)b;
}

#include "../user/lib/atk/html_view/style.c"

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
