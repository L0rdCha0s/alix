#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "video.h"
#include "web/css.h"

video_color_t video_make_color(uint8_t r, uint8_t g, uint8_t b)
{
    return 0xFF000000U | ((video_color_t)r << 16) | ((video_color_t)g << 8) | (video_color_t)b;
}

typedef struct
{
    const char *name;
    bool (*fn)(void);
} css_case_t;

static bool test_display_table(void)
{
    css_stylesheet_t *sheet = css_parse("ul { display: table; } li { display: table-cell; }");
    if (!sheet || !sheet->rules || !sheet->rules->next)
    {
        css_stylesheet_destroy(sheet);
        return false;
    }

    const css_rule_t *ul = sheet->rules;
    const css_rule_t *li = sheet->rules->next;
    bool ok = ul->style.has_display && ul->style.display == CSS_DISPLAY_TABLE;
    ok = ok && li->style.has_display && li->style.display == CSS_DISPLAY_TABLE_CELL;

    css_stylesheet_destroy(sheet);
    return ok;
}

static bool test_z_index(void)
{
    css_stylesheet_t *sheet = css_parse("div { z-index: -3; }");
    if (!sheet || !sheet->rules)
    {
        css_stylesheet_destroy(sheet);
        return false;
    }

    const css_rule_t *rule = sheet->rules;
    bool ok = rule->style.has_z_index && rule->style.z_index == -3;
    css_stylesheet_destroy(sheet);
    return ok;
}

static bool css_length_is(const css_length_t *len, int32_t milli, css_unit_t unit)
{
    if (!len)
    {
        return false;
    }
    return len->valid && !len->is_auto && len->value_milli == milli && len->unit == unit;
}

static bool test_background_shorthand(void)
{
    css_stylesheet_t *sheet = css_parse("div { background: red url(foo.png) no-repeat fixed 1px 2px; }");
    if (!sheet || !sheet->rules)
    {
        css_stylesheet_destroy(sheet);
        return false;
    }

    const css_style_t *style = &sheet->rules->style;
    bool ok = style->has_background &&
              !style->background_transparent &&
              style->background == video_make_color(0xFF, 0x00, 0x00);
    ok = ok && style->has_background_image &&
         style->background_image &&
         strcmp(style->background_image, "foo.png") == 0;
    ok = ok && style->has_background_repeat &&
         style->background_repeat == CSS_BACKGROUND_REPEAT_NO_REPEAT;
    ok = ok && style->has_background_attachment &&
         style->background_attachment == CSS_BACKGROUND_ATTACHMENT_FIXED;
    ok = ok && style->has_background_position &&
         css_length_is(&style->background_pos_x, 1000, CSS_UNIT_PX) &&
         css_length_is(&style->background_pos_y, 2000, CSS_UNIT_PX);

    css_stylesheet_destroy(sheet);
    return ok;
}

static bool test_background_shorthand_fixed_first(void)
{
    css_stylesheet_t *sheet = css_parse("div { background: fixed url(foo.png) 1px 0; }");
    if (!sheet || !sheet->rules)
    {
        css_stylesheet_destroy(sheet);
        return false;
    }

    const css_style_t *style = &sheet->rules->style;
    bool ok = style->has_background_image &&
              style->background_image &&
              strcmp(style->background_image, "foo.png") == 0;
    ok = ok && style->has_background_attachment &&
         style->background_attachment == CSS_BACKGROUND_ATTACHMENT_FIXED;
    ok = ok && style->has_background_position &&
         css_length_is(&style->background_pos_x, 1000, CSS_UNIT_PX) &&
         css_length_is(&style->background_pos_y, 0, CSS_UNIT_NONE);

    css_stylesheet_destroy(sheet);
    return ok;
}

static bool test_background_image_none(void)
{
    css_stylesheet_t *sheet = css_parse("div { background-image: none; }");
    if (!sheet || !sheet->rules)
    {
        css_stylesheet_destroy(sheet);
        return false;
    }

    const css_style_t *style = &sheet->rules->style;
    bool ok = style->has_background_image && style->background_image == NULL;

    css_stylesheet_destroy(sheet);
    return ok;
}

static bool test_background_position_property(void)
{
    css_stylesheet_t *sheet = css_parse("div { background-position: 1px 0; }");
    if (!sheet || !sheet->rules)
    {
        css_stylesheet_destroy(sheet);
        return false;
    }

    const css_style_t *style = &sheet->rules->style;
    bool ok = style->has_background_position &&
              css_length_is(&style->background_pos_x, 1000, CSS_UNIT_PX) &&
              css_length_is(&style->background_pos_y, 0, CSS_UNIT_NONE);

    css_stylesheet_destroy(sheet);
    return ok;
}

static bool test_border_style_none(void)
{
    css_stylesheet_t *sheet = css_parse("div { border-style: none solid; }");
    if (!sheet || !sheet->rules)
    {
        css_stylesheet_destroy(sheet);
        return false;
    }

    const css_style_t *style = &sheet->rules->style;
    bool ok = style->has_border_style &&
              style->border_style_none[CSS_BORDER_SIDE_TOP] &&
              style->border_style_none[CSS_BORDER_SIDE_BOTTOM] &&
              !style->border_style_none[CSS_BORDER_SIDE_LEFT] &&
              !style->border_style_none[CSS_BORDER_SIDE_RIGHT];

    css_stylesheet_destroy(sheet);
    return ok;
}

static bool test_border_color_sides(void)
{
    css_stylesheet_t *sheet = css_parse("div { border-color: red green blue yellow; }");
    if (!sheet || !sheet->rules)
    {
        css_stylesheet_destroy(sheet);
        return false;
    }

    const css_style_t *style = &sheet->rules->style;
    bool ok = style->has_border_color &&
              style->border_color_side_set[CSS_BORDER_SIDE_TOP] &&
              style->border_color_side_set[CSS_BORDER_SIDE_RIGHT] &&
              style->border_color_side_set[CSS_BORDER_SIDE_BOTTOM] &&
              style->border_color_side_set[CSS_BORDER_SIDE_LEFT];
    ok = ok && style->border_color_side[CSS_BORDER_SIDE_TOP] == video_make_color(0xFF, 0x00, 0x00);
    ok = ok && style->border_color_side[CSS_BORDER_SIDE_RIGHT] == video_make_color(0x00, 0x80, 0x00);
    ok = ok && style->border_color_side[CSS_BORDER_SIDE_BOTTOM] == video_make_color(0x00, 0x00, 0xFF);
    ok = ok && style->border_color_side[CSS_BORDER_SIDE_LEFT] == video_make_color(0xFF, 0xFF, 0x00);

    css_stylesheet_destroy(sheet);
    return ok;
}

static bool test_border_top_color_sets_side(void)
{
    css_stylesheet_t *sheet = css_parse("div { border-top: 2px solid red; }");
    if (!sheet || !sheet->rules)
    {
        css_stylesheet_destroy(sheet);
        return false;
    }

    const css_style_t *style = &sheet->rules->style;
    bool ok = style->has_border_color &&
              style->border_color_side_set[CSS_BORDER_SIDE_TOP] &&
              style->border_color_side[CSS_BORDER_SIDE_TOP] == video_make_color(0xFF, 0x00, 0x00);
    ok = ok && !style->border_color_side_set[CSS_BORDER_SIDE_RIGHT] &&
              !style->border_color_side_set[CSS_BORDER_SIDE_BOTTOM] &&
              !style->border_color_side_set[CSS_BORDER_SIDE_LEFT];

    css_stylesheet_destroy(sheet);
    return ok;
}

int main(void)
{
    css_case_t cases[] = {
        { "display-table", test_display_table },
        { "z-index", test_z_index },
        { "background-shorthand", test_background_shorthand },
        { "background-shorthand-fixed-first", test_background_shorthand_fixed_first },
        { "background-image-none", test_background_image_none },
        { "background-position", test_background_position_property },
        { "border-style-none", test_border_style_none },
        { "border-color-sides", test_border_color_sides },
        { "border-top-color-sides", test_border_top_color_sets_side },
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
            printf("css_test: case %s failed\n", cases[i].name);
        }
    }

    printf("css_test: total=%zu pass=%zu fail=%zu\n", pass + fail, pass, fail);
    return fail == 0 ? 0 : 1;
}
