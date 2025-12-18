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
    if (src->has_height)
    {
        dst->has_height = true;
        dst->height = src->height;
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
    if (src->has_border_color)
    {
        dst->has_border_color = true;
        dst->border_color = src->border_color;
    }
    if (src->has_float)
    {
        dst->has_float = true;
        dst->float_mode = src->float_mode;
    }
    if (src->has_clear)
    {
        dst->has_clear = true;
        dst->clear_mode = src->clear_mode;
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
