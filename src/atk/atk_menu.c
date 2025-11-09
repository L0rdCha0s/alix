#include "atk/atk_menu.h"

#include "atk_internal.h"
#include "video.h"
#include "libc.h"
#include "atk/atk_font.h"

#define ATK_MENU_ITEM_PADDING_X 12

typedef struct
{
    char title[ATK_MENU_ITEM_TITLE_MAX];
    atk_menu_action_t action;
    void *context;
} atk_menu_item_t;

typedef struct
{
    atk_menu_item_t *items;
    size_t count;
    size_t capacity;
    int item_height;
    int highlighted_index;
    bool visible;
    int preferred_width;
} atk_menu_priv_t;

static const atk_widget_vtable_t menu_vtable = { 0 };
const atk_class_t ATK_MENU_CLASS = { "Menu", &ATK_WIDGET_CLASS, &menu_vtable, sizeof(atk_menu_priv_t) };

static atk_menu_priv_t *menu_priv_mut(atk_widget_t *menu);
static const atk_menu_priv_t *menu_priv_const(const atk_widget_t *menu);
static bool menu_ensure_capacity(atk_menu_priv_t *priv, size_t desired);
static int menu_measure_text_width(const char *title);
static void atk_menu_mark_dirty(const atk_widget_t *menu);

atk_widget_t *atk_menu_create(void)
{
    atk_widget_t *menu = atk_widget_create(&ATK_MENU_CLASS);
    if (!menu)
    {
        return NULL;
    }

    atk_menu_priv_t *priv = menu_priv_mut(menu);
    if (!priv)
    {
        atk_widget_destroy(menu);
        return NULL;
    }

    menu->used = true;
    menu->x = 0;
    menu->y = 0;
    menu->width = ATK_FONT_WIDTH * 8;
    menu->height = 0;
    menu->parent = NULL;

    priv->items = NULL;
    priv->count = 0;
    priv->capacity = 0;
    priv->item_height = ATK_FONT_HEIGHT + 8;
    priv->highlighted_index = -1;
    priv->visible = false;
    priv->preferred_width = menu->width;

    return menu;
}

void atk_menu_destroy(atk_widget_t *menu)
{
    if (!menu)
    {
        return;
    }
    atk_menu_clear(menu);
    atk_widget_destroy(menu);
}

void atk_menu_clear(atk_widget_t *menu)
{
    atk_menu_priv_t *priv = menu_priv_mut(menu);
    if (!priv)
    {
        return;
    }
    if (priv->items)
    {
        free(priv->items);
        priv->items = NULL;
    }
    priv->count = 0;
    priv->capacity = 0;
    priv->highlighted_index = -1;
    priv->visible = false;
    priv->preferred_width = ATK_FONT_WIDTH * 8;
    menu->width = priv->preferred_width;
    menu->height = 0;
}

bool atk_menu_add_item(atk_widget_t *menu,
                       const char *title,
                       atk_menu_action_t action,
                       void *context)
{
    atk_menu_priv_t *priv = menu_priv_mut(menu);
    if (!priv || !title)
    {
        return false;
    }

    if (!menu_ensure_capacity(priv, priv->count + 1))
    {
        return false;
    }

    atk_menu_item_t *item = &priv->items[priv->count++];
    size_t len = strlen(title);
    if (len >= ATK_MENU_ITEM_TITLE_MAX)
    {
        len = ATK_MENU_ITEM_TITLE_MAX - 1;
    }
    memcpy(item->title, title, len);
    item->title[len] = '\0';
    item->action = action;
    item->context = context;

    int width = menu_measure_text_width(item->title);
    if (width > priv->preferred_width)
    {
        priv->preferred_width = width;
        menu->width = priv->preferred_width;
    }

    menu->height = priv->count * priv->item_height;
    return true;
}

void atk_menu_show(atk_widget_t *menu, int x, int y)
{
    atk_menu_priv_t *priv = menu_priv_mut(menu);
    if (!priv)
    {
        return;
    }
    menu->x = x;
    menu->y = y;
    menu->width = priv->preferred_width;
    menu->height = priv->count * priv->item_height;
    priv->visible = true;
    atk_menu_mark_dirty(menu);
}

void atk_menu_hide(atk_widget_t *menu)
{
    atk_menu_priv_t *priv = menu_priv_mut(menu);
    if (!priv)
    {
        return;
    }
    if (priv->visible)
    {
        atk_menu_mark_dirty(menu);
    }
    priv->visible = false;
    priv->highlighted_index = -1;
}

bool atk_menu_is_visible(const atk_widget_t *menu)
{
    const atk_menu_priv_t *priv = menu_priv_const(menu);
    return priv ? priv->visible : false;
}

bool atk_menu_contains(const atk_widget_t *menu, int px, int py)
{
    const atk_menu_priv_t *priv = menu_priv_const(menu);
    if (!priv || !priv->visible || !menu)
    {
        return false;
    }
    return px >= menu->x && px < menu->x + menu->width &&
           py >= menu->y && py < menu->y + menu->height;
}

bool atk_menu_handle_click(atk_widget_t *menu, int px, int py)
{
    atk_menu_priv_t *priv = menu_priv_mut(menu);
    if (!priv || !priv->visible || priv->count == 0)
    {
        return false;
    }
    if (!atk_menu_contains(menu, px, py))
    {
        return false;
    }

    int relative_y = py - menu->y;
    int index = relative_y / priv->item_height;
    if (index < 0 || (size_t)index >= priv->count)
    {
        return false;
    }

    priv->highlighted_index = -1;
    atk_menu_item_t *item = &priv->items[index];
    if (item->action)
    {
        item->action(item->context);
        return true;
    }
    return false;
}

bool atk_menu_update_hover(atk_widget_t *menu, int px, int py)
{
    atk_menu_priv_t *priv = menu_priv_mut(menu);
    if (!priv || !priv->visible || priv->count == 0)
    {
        return false;
    }

    int new_index = -1;
    if (atk_menu_contains(menu, px, py))
    {
        int relative_y = py - menu->y;
        new_index = relative_y / priv->item_height;
        if (new_index < 0 || (size_t)new_index >= priv->count)
        {
            new_index = -1;
        }
    }

    if (new_index != priv->highlighted_index)
    {
        priv->highlighted_index = new_index;
        atk_menu_mark_dirty(menu);
        return true;
    }
    return false;
}

void atk_menu_draw(const atk_state_t *state, const atk_widget_t *menu)
{
    const atk_menu_priv_t *priv = menu_priv_const(menu);
    if (!state || !menu || !priv || !priv->visible || priv->count == 0)
    {
        return;
    }

    const atk_theme_t *theme = &state->theme;
    video_draw_rect(menu->x,
                    menu->y,
                    menu->width,
                    menu->height,
                    theme->menu_dropdown_face);
    video_draw_rect_outline(menu->x,
                            menu->y,
                            menu->width,
                            menu->height,
                            theme->menu_dropdown_border);

    for (size_t i = 0; i < priv->count; ++i)
    {
        int item_y = menu->y + (int)i * priv->item_height;
        uint16_t bg = theme->menu_dropdown_face;
        uint16_t fg = theme->menu_dropdown_text;
        if ((int)i == priv->highlighted_index)
        {
            bg = theme->menu_dropdown_highlight;
            fg = theme->menu_dropdown_face;
            video_draw_rect(menu->x + 1,
                            item_y + 1,
                            menu->width - 2,
                            priv->item_height - 2,
                            bg);
        }
        int text_x = menu->x + ATK_MENU_ITEM_PADDING_X;
        int baseline = atk_font_baseline_for_rect(item_y, priv->item_height);
        atk_font_draw_string(text_x, baseline, priv->items[i].title, fg, bg);
    }
}

static atk_menu_priv_t *menu_priv_mut(atk_widget_t *menu)
{
    return (atk_menu_priv_t *)atk_widget_priv(menu, &ATK_MENU_CLASS);
}

static const atk_menu_priv_t *menu_priv_const(const atk_widget_t *menu)
{
    return (const atk_menu_priv_t *)atk_widget_priv(menu, &ATK_MENU_CLASS);
}

static bool menu_ensure_capacity(atk_menu_priv_t *priv, size_t desired)
{
    if (!priv)
    {
        return false;
    }
    if (desired <= priv->capacity)
    {
        return true;
    }
    size_t new_capacity = priv->capacity ? priv->capacity * 2 : 4;
    while (new_capacity < desired)
    {
        new_capacity *= 2;
    }
    atk_menu_item_t *items = (atk_menu_item_t *)realloc(priv->items, new_capacity * sizeof(atk_menu_item_t));
    if (!items)
    {
        return false;
    }
    priv->items = items;
    priv->capacity = new_capacity;
    return true;
}

static int menu_measure_text_width(const char *title)
{
    int text_width = atk_font_text_width(title);
    if (text_width <= 0)
    {
        size_t len = title ? strlen(title) : 0;
        text_width = (int)len * ATK_FONT_WIDTH;
    }
    int width = text_width + ATK_MENU_ITEM_PADDING_X * 2;
    if (width < ATK_MENU_ITEM_PADDING_X * 2)
    {
        width = ATK_MENU_ITEM_PADDING_X * 2;
    }
    return width;
}

static void atk_menu_mark_dirty(const atk_widget_t *menu)
{
    if (!menu || !menu->used)
    {
        return;
    }
    atk_dirty_mark_rect(menu->x, menu->y, menu->width, menu->height);
}
