#include "web/css/css_internal.h"

#include "ctype.h"
#include "libc.h"

void css_style_merge(css_style_t *dst, const css_style_t *src)
{
    if (!dst || !src)
    {
        return;
    }
    if (src->has_background)
    {
        dst->has_background = true;
        dst->background = src->background;
        dst->background_transparent = src->background_transparent;
    }
    if (src->has_background_image)
    {
        dst->has_background_image = true;
        dst->background_image = src->background_image;
        dst->background_image_owned = false;
    }
    if (src->has_background_repeat)
    {
        dst->has_background_repeat = true;
        dst->background_repeat = src->background_repeat;
    }
    if (src->has_background_attachment)
    {
        dst->has_background_attachment = true;
        dst->background_attachment = src->background_attachment;
    }
    if (src->has_background_position)
    {
        dst->has_background_position = true;
        dst->background_pos_x = src->background_pos_x;
        dst->background_pos_y = src->background_pos_y;
    }
    if (src->has_color)
    {
        dst->has_color = true;
        dst->color = src->color;
    }
    if (src->has_font_size)
    {
        dst->has_font_size = true;
        dst->font_size = src->font_size;
    }
    if (src->has_width)
    {
        dst->has_width = true;
        dst->width = src->width;
    }
    if (src->has_min_width)
    {
        dst->has_min_width = true;
        dst->min_width = src->min_width;
    }
    if (src->has_max_width)
    {
        dst->has_max_width = true;
        dst->max_width = src->max_width;
    }
    if (src->has_height)
    {
        dst->has_height = true;
        dst->height = src->height;
    }
    if (src->has_min_height)
    {
        dst->has_min_height = true;
        dst->min_height = src->min_height;
    }
    if (src->has_max_height)
    {
        dst->has_max_height = true;
        dst->max_height = src->max_height;
    }
    if (src->has_margin)
    {
        dst->has_margin = true;
        dst->margin = src->margin;
    }
    if (src->has_padding)
    {
        dst->has_padding = true;
        dst->padding = src->padding;
    }
    if (src->has_border)
    {
        dst->has_border = true;
        dst->border_width = src->border_width;
    }
    if (src->has_border_style)
    {
        dst->has_border_style = true;
        memcpy(dst->border_style_none, src->border_style_none, sizeof(dst->border_style_none));
    }
    if (src->has_border_color)
    {
        dst->has_border_color = true;
        dst->border_color = src->border_color;
        dst->border_transparent = src->border_transparent;
    }
    for (size_t i = 0; i < sizeof(dst->border_color_side_set) / sizeof(dst->border_color_side_set[0]); ++i)
    {
        if (src->border_color_side_set[i])
        {
            dst->border_color_side_set[i] = true;
            dst->border_color_side[i] = src->border_color_side[i];
            dst->border_color_side_transparent[i] = src->border_color_side_transparent[i];
        }
    }
    if (src->has_position)
    {
        dst->has_position = true;
        dst->position = src->position;
    }
    if (src->has_z_index)
    {
        dst->has_z_index = true;
        dst->z_index = src->z_index;
    }
    if (src->has_top)
    {
        dst->has_top = true;
        dst->top = src->top;
    }
    if (src->has_right)
    {
        dst->has_right = true;
        dst->right = src->right;
    }
    if (src->has_bottom)
    {
        dst->has_bottom = true;
        dst->bottom = src->bottom;
    }
    if (src->has_left)
    {
        dst->has_left = true;
        dst->left = src->left;
    }
    if (src->has_float)
    {
        dst->has_float = true;
        dst->float_mode = src->float_mode;
        dst->float_inherit = src->float_inherit;
    }
    if (src->has_clear)
    {
        dst->has_clear = true;
        dst->clear_mode = src->clear_mode;
    }
    if (src->has_overflow)
    {
        dst->has_overflow = true;
        dst->overflow = src->overflow;
    }
    if (src->has_text_align)
    {
        dst->has_text_align = true;
        dst->text_align = src->text_align;
    }
    if (src->has_text_decoration)
    {
        dst->has_text_decoration = true;
        dst->text_decoration = src->text_decoration;
    }
    if (src->has_text_shadow)
    {
        dst->has_text_shadow = true;
        dst->text_shadow_x = src->text_shadow_x;
        dst->text_shadow_y = src->text_shadow_y;
        dst->text_shadow_blur = src->text_shadow_blur;
        if (src->has_text_shadow_color)
        {
            dst->has_text_shadow_color = true;
            dst->text_shadow_color = src->text_shadow_color;
        }
    }
    if (src->has_display)
    {
        dst->has_display = true;
        dst->display = src->display;
    }
    if (src->has_content)
    {
        dst->has_content = true;
        dst->content = src->content;
        dst->content_owned = false;
    }
    if (src->has_flex_direction)
    {
        dst->has_flex_direction = true;
        dst->flex_direction = src->flex_direction;
    }
    if (src->has_flex_wrap)
    {
        dst->has_flex_wrap = true;
        dst->flex_wrap = src->flex_wrap;
    }
    if (src->has_justify_content)
    {
        dst->has_justify_content = true;
        dst->justify_content = src->justify_content;
    }
    if (src->has_align_items)
    {
        dst->has_align_items = true;
        dst->align_items = src->align_items;
    }
    if (src->has_align_self)
    {
        dst->has_align_self = true;
        dst->align_self = src->align_self;
    }
    if (src->has_align_content)
    {
        dst->has_align_content = true;
        dst->align_content = src->align_content;
    }
    if (src->has_row_gap)
    {
        dst->has_row_gap = true;
        dst->row_gap = src->row_gap;
    }
    if (src->has_column_gap)
    {
        dst->has_column_gap = true;
        dst->column_gap = src->column_gap;
    }
    if (src->has_flex_grow)
    {
        dst->has_flex_grow = true;
        dst->flex_grow_milli = src->flex_grow_milli;
    }
    if (src->has_flex_shrink)
    {
        dst->has_flex_shrink = true;
        dst->flex_shrink_milli = src->flex_shrink_milli;
    }
    if (src->has_flex_basis)
    {
        dst->has_flex_basis = true;
        dst->flex_basis = src->flex_basis;
    }
    if (src->has_line_height)
    {
        dst->has_line_height = true;
        dst->line_height_milli = src->line_height_milli;
        dst->line_height_is_length = src->line_height_is_length;
        dst->line_height = src->line_height;
    }
    if (src->has_letter_spacing)
    {
        dst->has_letter_spacing = true;
        dst->letter_spacing = src->letter_spacing;
    }
    if (src->has_opacity)
    {
        dst->has_opacity = true;
        dst->opacity_milli = src->opacity_milli;
    }
}

bool css_rule_matches_tag(const css_rule_t *rule, const char *tag_name)
{
    if (!rule || !rule->selector || !tag_name || tag_name[0] == '\0')
    {
        return false;
    }

    const char *sel = rule->selector;
    while (*sel && isspace((unsigned char)*sel))
    {
        sel++;
    }
    if (*sel == '\0')
    {
        return false;
    }

    const char *end = sel;
    while (*end && *end != ':' && *end != '.' && *end != '#' && *end != '[' && !isspace((unsigned char)*end))
    {
        end++;
    }
    size_t len = (size_t)(end - sel);
    if (len == 0)
    {
        return false;
    }

    if (strlen(tag_name) != len)
    {
        return false;
    }
    return strncasecmp(sel, tag_name, len) == 0;
}
