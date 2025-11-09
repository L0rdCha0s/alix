#include "atk_menu_bar.h"

#include "atk/atk_image.h"
#include "atk/atk_label.h"
#include "atk/atk_menu.h"
#include "atk/atk_font.h"
#include "atk_window.h"
#include "font.h"
#include "libc.h"
#include "video.h"

#define ATK_MENU_BAR_TITLE_PADDING 14
#define ATK_MENU_BAR_ENTRY_SPACING 8
#define ATK_MENU_BAR_LOGO_MARGIN_X 12
#define ATK_MENU_BAR_LOGO_MARGIN_Y 6

struct atk_menu_bar_entry
{
    char title[ATK_MENU_ITEM_TITLE_MAX];
    atk_widget_t *menu;
    atk_list_node_t *list_node;
    int x;
    int width;
    int text_width;
};

static void atk_menu_bar_entry_destroy(void *value);
static void atk_menu_bar_update_layout(atk_state_t *state);
static atk_menu_bar_entry_t *atk_menu_bar_entry_hit_test(atk_state_t *state, int px);
static bool atk_menu_bar_build_logo(atk_state_t *state);
static void menu_action_welcome(void *context);
static int atk_menu_bar_measure_title(const char *title);
static int atk_menu_bar_height_pixels(const atk_state_t *state);
static void atk_menu_bar_mark_dirty(const atk_state_t *state);
static void atk_menu_bar_mark_menu_area(const atk_widget_t *menu);

void atk_menu_bar_reset(atk_state_t *state)
{
    if (!state)
    {
        return;
    }

    atk_list_clear(&state->menu_entries, atk_menu_bar_entry_destroy);
    atk_list_init(&state->menu_entries);
    state->menu_open_entry = NULL;
    state->menu_hover_entry = NULL;

    if (state->menu_logo)
    {
        atk_image_destroy(state->menu_logo);
        atk_widget_destroy(state->menu_logo);
        state->menu_logo = NULL;
    }

    state->menu_bar_height = ATK_MENU_BAR_DEFAULT_HEIGHT;
}

void atk_menu_bar_build_default(atk_state_t *state)
{
    if (!state)
    {
        return;
    }

    if (state->menu_bar_height <= 0)
    {
        state->menu_bar_height = ATK_MENU_BAR_DEFAULT_HEIGHT;
    }

    if (!atk_menu_bar_build_logo(state))
    {
        state->menu_logo = NULL;
    }

    atk_widget_t *help_menu = atk_menu_create();
    if (help_menu)
    {
        if (!atk_menu_add_item(help_menu, "Welcome", menu_action_welcome, state))
        {
            atk_menu_destroy(help_menu);
            help_menu = NULL;
        }
    }

    if (help_menu)
    {
        atk_menu_bar_entry_t *entry = (atk_menu_bar_entry_t *)malloc(sizeof(atk_menu_bar_entry_t));
        if (entry)
        {
            memset(entry, 0, sizeof(*entry));
            const char help_title[] = "Help";
            size_t len = strlen(help_title);
            if (len >= sizeof(entry->title))
            {
                len = sizeof(entry->title) - 1;
            }
            memcpy(entry->title, help_title, len);
            entry->title[len] = '\0';
            entry->menu = help_menu;
            entry->text_width = atk_font_text_width(entry->title);
            entry->width = atk_menu_bar_measure_title(entry->title);
            atk_list_node_t *node = atk_list_push_back(&state->menu_entries, entry);
            if (!node)
            {
                atk_menu_destroy(help_menu);
                free(entry);
            }
            else
            {
                entry->list_node = node;
            }
        }
        else
        {
            atk_menu_destroy(help_menu);
        }
    }

    atk_menu_bar_update_layout(state);
    atk_menu_bar_mark_dirty(state);
}

void atk_menu_bar_draw(const atk_state_t *state)
{
    if (!state)
    {
        return;
    }

    int height = atk_menu_bar_height_pixels(state);
    const atk_theme_t *theme = &state->theme;

    video_draw_rect(0, 0, VIDEO_WIDTH, height, theme->menu_bar_face);
    video_draw_rect(0, height - 1, VIDEO_WIDTH, 1, theme->menu_dropdown_border);

    if (state->menu_logo && state->menu_logo->used)
    {
        atk_image_draw(state, state->menu_logo);
    }

    ATK_LIST_FOR_EACH(node, &state->menu_entries)
    {
        atk_menu_bar_entry_t *entry = (atk_menu_bar_entry_t *)node->value;
        if (!entry)
        {
            continue;
        }
        bool highlighted = (entry == state->menu_hover_entry) || (entry == state->menu_open_entry);
        if (highlighted)
        {
            video_draw_rect(entry->x,
                            0,
                            entry->width,
                            height - 1,
                            theme->menu_bar_highlight);
        }
        uint16_t fg = highlighted ? theme->menu_dropdown_border : theme->menu_bar_text;
        uint16_t bg = highlighted ? theme->menu_bar_highlight : theme->menu_bar_face;
        int text_width = entry->text_width;
        if (text_width <= 0)
        {
            text_width = atk_font_text_width(entry->title);
        }
        int text_x = entry->x + (entry->width - text_width) / 2;
        if (text_x < entry->x + 2)
        {
            text_x = entry->x + 2;
        }
        int baseline = atk_font_baseline_for_rect(0, height - 1);
        atk_font_draw_string(text_x, baseline, entry->title, fg, bg);
    }

    if (state->menu_open_entry && state->menu_open_entry->menu)
    {
        atk_menu_draw(state, state->menu_open_entry->menu);
    }
}

bool atk_menu_bar_handle_mouse(atk_state_t *state,
                               int cursor_x,
                               int cursor_y,
                               bool pressed_edge,
                               bool released_edge,
                               bool left_pressed,
                               bool *redraw_out)
{
    (void)left_pressed;
    bool consumed = false;
    bool redraw = false;

    if (!state)
    {
        if (redraw_out)
        {
            *redraw_out = false;
        }
        return false;
    }

    int height = state->menu_bar_height > 0 ? state->menu_bar_height : ATK_MENU_BAR_DEFAULT_HEIGHT;
    bool inside_bar = (cursor_y >= 0 && cursor_y < height);
    atk_menu_bar_entry_t *hover_entry = inside_bar ? atk_menu_bar_entry_hit_test(state, cursor_x) : NULL;

    if (hover_entry != state->menu_hover_entry)
    {
        state->menu_hover_entry = hover_entry;
        redraw = true;
        atk_menu_bar_mark_dirty(state);
    }

    if (pressed_edge && inside_bar && hover_entry)
    {
        consumed = true;
        if (state->menu_open_entry == hover_entry)
        {
            atk_menu_hide(hover_entry->menu);
            state->menu_open_entry = NULL;
            atk_menu_bar_mark_menu_area(hover_entry->menu);
            atk_menu_bar_mark_dirty(state);
        }
        else
        {
            if (state->menu_open_entry && state->menu_open_entry->menu)
            {
                atk_menu_hide(state->menu_open_entry->menu);
                atk_menu_bar_mark_menu_area(state->menu_open_entry->menu);
            }
            int menu_x = hover_entry->x;
            if (hover_entry->menu)
            {
                int menu_width = hover_entry->menu->width;
                if (menu_x + menu_width > VIDEO_WIDTH - 2)
                {
                    menu_x = VIDEO_WIDTH - menu_width - 2;
                }
                if (menu_x < 0)
                {
                    menu_x = 0;
                }
                atk_menu_show(hover_entry->menu, menu_x, height);
            }
            state->menu_open_entry = hover_entry;
            atk_menu_bar_mark_dirty(state);
        }
        redraw = true;
    }
    else if (pressed_edge && state->menu_open_entry && !inside_bar)
    {
        atk_menu_hide(state->menu_open_entry->menu);
        state->menu_open_entry = NULL;
        consumed = true;
        redraw = true;
        atk_menu_bar_mark_dirty(state);
    }

    if (state->menu_open_entry && state->menu_open_entry->menu)
    {
        if (!pressed_edge && !released_edge)
        {
            if (atk_menu_update_hover(state->menu_open_entry->menu, cursor_x, cursor_y))
            {
                redraw = true;
            }
        }

        if (released_edge)
        {
            if (atk_menu_contains(state->menu_open_entry->menu, cursor_x, cursor_y))
            {
                if (atk_menu_handle_click(state->menu_open_entry->menu, cursor_x, cursor_y))
                {
                    atk_menu_hide(state->menu_open_entry->menu);
                    state->menu_open_entry = NULL;
                    redraw = true;
                    atk_menu_bar_mark_dirty(state);
                }
                consumed = true;
            }
            else if (!inside_bar)
            {
                atk_menu_hide(state->menu_open_entry->menu);
                state->menu_open_entry = NULL;
                redraw = true;
                consumed = true;
            }
        }
    }

    bool menu_visible = state->menu_open_entry &&
                        state->menu_open_entry->menu &&
                        atk_menu_is_visible(state->menu_open_entry->menu);
    if (!consumed && menu_visible)
    {
        consumed = true;
    }

    if (redraw_out)
    {
        *redraw_out = redraw;
    }
    return consumed;
}

static void atk_menu_bar_entry_destroy(void *value)
{
    atk_menu_bar_entry_t *entry = (atk_menu_bar_entry_t *)value;
    if (!entry)
    {
        return;
    }
    if (entry->menu)
    {
        atk_menu_destroy(entry->menu);
        entry->menu = NULL;
    }
    entry->list_node = NULL;
    free(entry);
}

static void atk_menu_bar_update_layout(atk_state_t *state)
{
    if (!state)
    {
        return;
    }
    int cursor = ATK_MENU_BAR_LOGO_MARGIN_X;
    if (state->menu_logo)
    {
        cursor = state->menu_logo->x + state->menu_logo->width + ATK_MENU_BAR_ENTRY_SPACING * 2;
    }

    ATK_LIST_FOR_EACH(node, &state->menu_entries)
    {
        atk_menu_bar_entry_t *entry = (atk_menu_bar_entry_t *)node->value;
        if (!entry)
        {
            continue;
        }
        entry->text_width = atk_font_text_width(entry->title);
        entry->width = atk_menu_bar_measure_title(entry->title);
        entry->x = cursor;
        cursor += entry->width + ATK_MENU_BAR_ENTRY_SPACING;
    }
}

static atk_menu_bar_entry_t *atk_menu_bar_entry_hit_test(atk_state_t *state, int px)
{
    if (!state)
    {
        return NULL;
    }
    ATK_LIST_FOR_EACH(node, &state->menu_entries)
    {
        atk_menu_bar_entry_t *entry = (atk_menu_bar_entry_t *)node->value;
        if (!entry)
        {
            continue;
        }
        if (px >= entry->x && px < entry->x + entry->width)
        {
            return entry;
        }
    }
    return NULL;
}

static bool atk_menu_bar_build_logo(atk_state_t *state)
{
    if (!state)
    {
        return false;
    }

    static const char logo_text[] = "AlixOS";
    size_t text_len = strlen(logo_text);
    if (text_len == 0)
    {
        return false;
    }

    int glyph_width = FONT_BASIC_WIDTH;
    int glyph_height = FONT_BASIC_HEIGHT_X2;
    int spacing = 2;
    int margin_x = ATK_MENU_BAR_LOGO_MARGIN_X;
    int margin_y = ATK_MENU_BAR_LOGO_MARGIN_Y;
    int width = margin_x * 2 + (int)text_len * glyph_width + (int)(text_len - 1) * spacing;
    int height = margin_y * 2 + glyph_height;

    size_t pixel_count = (size_t)width * (size_t)height;
    uint16_t *pixels = (uint16_t *)malloc(pixel_count * sizeof(uint16_t));
    if (!pixels)
    {
        return false;
    }

    uint16_t bg = video_make_color(0x18, 0x2F, 0x4C);
    uint16_t fg_primary = video_make_color(0xF2, 0xF4, 0xF8);
    uint16_t fg_accent = video_make_color(0xFF, 0xA3, 0x3C);
    for (size_t i = 0; i < pixel_count; ++i)
    {
        pixels[i] = bg;
    }

    int pen_x = margin_x;
    for (size_t idx = 0; idx < text_len; ++idx)
    {
        char ch = logo_text[idx];
        if (ch >= 'a' && ch <= 'z')
        {
            ch = (char)(ch - ('a' - 'A'));
        }

        uint8_t glyph[FONT_BASIC_HEIGHT_X2];
        font_basic_copy_glyph8x16((uint8_t)ch, glyph);
        uint16_t fg = (idx < 3) ? fg_primary : fg_accent;

        for (int row = 0; row < glyph_height; ++row)
        {
            for (int col = 0; col < glyph_width; ++col)
            {
                bool on = (glyph[row] & (1u << (7 - col))) != 0;
                if (!on)
                {
                    continue;
                }
                int px = pen_x + col;
                int py = margin_y + row;
                if (px < 0 || py < 0 || px >= width || py >= height)
                {
                    continue;
                }
                pixels[py * width + px] = fg;
            }
        }

        pen_x += glyph_width + spacing;
    }

    atk_widget_t *image = atk_widget_create(&ATK_IMAGE_CLASS);
    if (!image)
    {
        free(pixels);
        return false;
    }

    image->used = true;
    image->parent = NULL;
    image->x = ATK_MENU_BAR_LOGO_MARGIN_X;
    image->y = (state->menu_bar_height - height) / 2;
    if (image->y < 0)
    {
        image->y = 0;
    }

    if (!atk_image_set_pixels(image, pixels, width, height, width * (int)sizeof(uint16_t), true))
    {
        free(pixels);
        atk_widget_destroy(image);
        return false;
    }

    state->menu_logo = image;
    return true;
}

static void menu_action_welcome(void *context)
{
    atk_state_t *state = (atk_state_t *)context;
    if (!state)
    {
        return;
    }

    atk_widget_t *window = atk_window_create_at(state, VIDEO_WIDTH / 2, state->menu_bar_height + 120);
    if (!window)
    {
        return;
    }

    atk_window_set_title_text(window, "Welcome to AlixOS");
    int padding = 20;
    int label_y = ATK_WINDOW_TITLE_HEIGHT + 12;
    atk_widget_t *label = atk_window_add_label(window,
                                               padding,
                                               label_y,
                                               window->width - padding * 2,
                                               window->height - label_y - padding);
    if (label)
    {
        atk_label_set_text(label,
                           "Thank you for trying AlixOS!\n\n"
                           "Networking now comes up automatically thanks to\n"
                           "the new startup scripts (dhclient rtl0).\n"
                           "Use the top menu bar to find Help items like this.");
    }
    atk_window_mark_dirty(window);
}

static int atk_menu_bar_measure_title(const char *title)
{
    int text_width = atk_font_text_width(title);
    if (text_width <= 0)
    {
        size_t len = title ? strlen(title) : 0;
        text_width = (int)len * ATK_FONT_WIDTH;
    }
    int width = text_width + ATK_MENU_BAR_TITLE_PADDING * 2;
    if (width < ATK_FONT_WIDTH * 3)
    {
        width = ATK_FONT_WIDTH * 3;
    }
    return width;
}

static int atk_menu_bar_height_pixels(const atk_state_t *state)
{
    if (!state || state->menu_bar_height <= 0)
    {
        return ATK_MENU_BAR_DEFAULT_HEIGHT;
    }
    return state->menu_bar_height;
}

static void atk_menu_bar_mark_dirty(const atk_state_t *state)
{
    if (!state)
    {
        return;
    }
    int height = atk_menu_bar_height_pixels(state);
    atk_dirty_mark_rect(0, 0, VIDEO_WIDTH, height);
}

static void atk_menu_bar_mark_menu_area(const atk_widget_t *menu)
{
    if (!menu || !menu->used)
    {
        return;
    }
    atk_dirty_mark_rect(menu->x, menu->y, menu->width, menu->height);
}
