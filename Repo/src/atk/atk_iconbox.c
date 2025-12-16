#include "atk/atk_iconbox.h"

#include "atk_internal.h"
#include "atk/atk_scrollbar.h"
#include "atk_window.h"
#include "atk/atk_font.h"
#include "video.h"
#include "libc.h"

#define ATK_ICONBOX_PADDING         12
#define ATK_ICONBOX_GAP_X           16
#define ATK_ICONBOX_GAP_Y           16
#define ATK_ICONBOX_ICON_WIDTH      88
#define ATK_ICONBOX_ICON_HEIGHT     88
#define ATK_ICONBOX_SCROLLBAR_WIDTH 14

typedef struct
{
    atk_widget_t *button;
    atk_list_node_t *node;
    bool manual_position;
} atk_iconbox_icon_t;

typedef struct
{
    atk_list_t icons;
    atk_widget_t *scrollbar;
    atk_list_node_t *list_node;
    int scroll_y;
    int content_height;
    int padding;
    int gap_x;
    int gap_y;
    int scrollbar_size;
    int icon_width;
    int icon_height;
    bool layout_dirty;
    atk_widget_t *drag_icon;
    int drag_offset_x;
    int drag_offset_y;
    bool drag_moved;
} atk_iconbox_priv_t;

static void iconbox_destroy_cb(atk_widget_t *widget, void *context);
static void iconbox_draw_cb(const atk_state_t *state,
                            const atk_widget_t *widget,
                            int origin_x,
                            int origin_y,
                            void *context);
static bool iconbox_hit_test_cb(const atk_widget_t *widget,
                                int origin_x,
                                int origin_y,
                                int px,
                                int py,
                                void *context);
static atk_mouse_response_t iconbox_mouse_cb(atk_widget_t *widget,
                                             const atk_mouse_event_t *event,
                                             void *context);

static const atk_widget_vtable_t iconbox_vtable = { 0 };
static const atk_widget_ops_t g_iconbox_ops = {
    .destroy = iconbox_destroy_cb,
    .draw = iconbox_draw_cb,
    .hit_test = iconbox_hit_test_cb,
    .on_mouse = iconbox_mouse_cb,
    .on_key = NULL
};
const atk_class_t ATK_ICONBOX_CLASS = { "IconBox", &ATK_WIDGET_CLASS, &iconbox_vtable, sizeof(atk_iconbox_priv_t) };

static atk_iconbox_priv_t *iconbox_priv_mut(atk_widget_t *iconbox)
{
    if (!iconbox)
    {
        return NULL;
    }
    return (atk_iconbox_priv_t *)atk_widget_priv(iconbox, &ATK_ICONBOX_CLASS);
}

static const atk_iconbox_priv_t *iconbox_priv(const atk_widget_t *iconbox)
{
    if (!iconbox)
    {
        return NULL;
    }
    return (const atk_iconbox_priv_t *)atk_widget_priv(iconbox, &ATK_ICONBOX_CLASS);
}

static void iconbox_mark_dirty(const atk_widget_t *iconbox)
{
    if (!iconbox)
    {
        return;
    }
    int x = 0;
    int y = 0;
    int w = 0;
    int h = 0;
    atk_widget_absolute_bounds(iconbox, &x, &y, &w, &h);
    if (w > 0 && h > 0)
    {
        atk_dirty_mark_rect(x, y, w, h);
    }
}

static void iconbox_destroy_icon(void *value)
{
    atk_iconbox_icon_t *icon = (atk_iconbox_icon_t *)value;
    if (!icon)
    {
        return;
    }
    if (icon->button)
    {
        atk_widget_destroy(icon->button);
        icon->button = NULL;
    }
    free(icon);
}

static void iconbox_scroll_changed(atk_widget_t *scrollbar, void *context, int value)
{
    (void)scrollbar;
    atk_widget_t *iconbox = (atk_widget_t *)context;
    atk_iconbox_priv_t *priv = iconbox_priv_mut(iconbox);
    if (!priv)
    {
        return;
    }
    if (value < 0)
    {
        value = 0;
    }
    priv->scroll_y = value;
    iconbox_mark_dirty(iconbox);
}

static atk_iconbox_icon_t *iconbox_find_icon(const atk_iconbox_priv_t *priv, const atk_widget_t *button)
{
    if (!priv || !button)
    {
        return NULL;
    }
    ATK_LIST_FOR_EACH(node, &priv->icons)
    {
        atk_iconbox_icon_t *icon = (atk_iconbox_icon_t *)node->value;
        if (icon && icon->button == button)
        {
            return icon;
        }
    }
    return NULL;
}

static atk_iconbox_icon_t *iconbox_icon_at(atk_widget_t *iconbox,
                                           atk_iconbox_priv_t *priv,
                                           int cursor_x,
                                           int cursor_y)
{
    if (!iconbox || !priv)
    {
        return NULL;
    }
    int origin_x = 0;
    int origin_y = 0;
    atk_widget_absolute_position(iconbox, &origin_x, &origin_y);
    int button_origin_y = origin_y - priv->scroll_y;

    ATK_LIST_FOR_EACH_REVERSE(node, &priv->icons)
    {
        atk_iconbox_icon_t *icon = (atk_iconbox_icon_t *)node->value;
        if (!icon || !icon->button || !icon->button->used)
        {
            continue;
        }
        if (atk_button_hit_test(icon->button, origin_x, button_origin_y, cursor_x, cursor_y))
        {
            return icon;
        }
    }
    return NULL;
}

static void iconbox_update_scrollbar(atk_widget_t *iconbox, atk_iconbox_priv_t *priv)
{
    if (!iconbox || !priv || !priv->scrollbar)
    {
        return;
    }
    int max_scroll = priv->content_height - iconbox->height;
    if (max_scroll < 0)
    {
        max_scroll = 0;
    }
    int page = iconbox->height > 1 ? iconbox->height : 1;
    atk_scrollbar_set_range(priv->scrollbar, 0, max_scroll, page);
    if (priv->scroll_y > max_scroll)
    {
        priv->scroll_y = max_scroll;
        atk_scrollbar_set_value(priv->scrollbar, priv->scroll_y);
    }

    int abs_x = 0;
    int abs_y = 0;
    atk_widget_absolute_position(iconbox, &abs_x, &abs_y);
    int parent_abs_x = 0;
    int parent_abs_y = 0;
    if (priv->scrollbar->parent)
    {
        atk_widget_absolute_position(priv->scrollbar->parent, &parent_abs_x, &parent_abs_y);
    }

    priv->scrollbar->x = abs_x - parent_abs_x + iconbox->width - priv->scrollbar_size;
    priv->scrollbar->y = abs_y - parent_abs_y;
    priv->scrollbar->width = priv->scrollbar_size;
    priv->scrollbar->height = iconbox->height;
}

static void iconbox_refresh_content_height(atk_iconbox_priv_t *priv)
{
    if (!priv)
    {
        return;
    }
    int max_y = priv->padding;
    ATK_LIST_FOR_EACH(node, &priv->icons)
    {
        atk_iconbox_icon_t *icon = (atk_iconbox_icon_t *)node->value;
        if (!icon || !icon->button || !icon->button->used)
        {
            continue;
        }
        int tile_height = atk_button_effective_height(icon->button);
        int bottom = icon->button->y + tile_height;
        if (bottom > max_y)
        {
            max_y = bottom;
        }
    }
    priv->content_height = max_y + priv->padding;
    if (priv->content_height < priv->padding * 2)
    {
        priv->content_height = priv->padding * 2;
    }
}

static void iconbox_apply_layout(atk_widget_t *iconbox, atk_iconbox_priv_t *priv)
{
    if (!iconbox || !priv)
    {
        return;
    }

    int client_width = iconbox->width - priv->scrollbar_size - priv->padding * 2;
    if (client_width < priv->icon_width)
    {
        client_width = priv->icon_width;
    }

    int cursor_x = priv->padding;
    int cursor_y = priv->padding;
    int row_height = 0;
    int max_y = priv->padding;

    ATK_LIST_FOR_EACH(node, &priv->icons)
    {
        atk_iconbox_icon_t *icon = (atk_iconbox_icon_t *)node->value;
        if (!icon || !icon->button || !icon->button->used)
        {
            continue;
        }

        if (!icon->manual_position)
        {
            int tile_height = atk_button_effective_height(icon->button);
            if (cursor_x + icon->button->width > priv->padding + client_width)
            {
                cursor_x = priv->padding;
                cursor_y += row_height + priv->gap_y;
                row_height = 0;
            }
            icon->button->x = cursor_x;
            icon->button->y = cursor_y;
            cursor_x += icon->button->width + priv->gap_x;
            if (tile_height > row_height)
            {
                row_height = tile_height;
            }
        }

        int tile_height = atk_button_effective_height(icon->button);
        int bottom = icon->button->y + tile_height;
        if (bottom > max_y)
        {
            max_y = bottom;
        }
    }

    if (cursor_x != priv->padding || row_height > 0)
    {
        int row_bottom = cursor_y + row_height;
        if (row_bottom > max_y)
        {
            max_y = row_bottom;
        }
    }

    priv->content_height = max_y + priv->padding;
    priv->layout_dirty = false;
    iconbox_update_scrollbar(iconbox, priv);
}

static void iconbox_sync_layout(atk_widget_t *iconbox, atk_iconbox_priv_t *priv)
{
    if (!iconbox || !priv)
    {
        return;
    }
    if (priv->layout_dirty)
    {
        iconbox_apply_layout(iconbox, priv);
    }
}

atk_widget_t *atk_window_add_iconbox(atk_widget_t *window, int x, int y, int width, int height)
{
    if (!window || width <= 0 || height <= 0)
    {
        return NULL;
    }

    atk_window_priv_t *win_priv = (atk_window_priv_t *)atk_widget_priv(window, &ATK_WINDOW_CLASS);
    if (!win_priv)
    {
        return NULL;
    }

    atk_widget_t *iconbox = atk_widget_create(&ATK_ICONBOX_CLASS);
    if (!iconbox)
    {
        return NULL;
    }

    iconbox->x = x;
    iconbox->y = y;
    iconbox->width = width;
    iconbox->height = height;
    iconbox->parent = window;
    iconbox->used = true;
    atk_widget_set_ops(iconbox, &g_iconbox_ops, NULL);

    atk_iconbox_priv_t *priv = iconbox_priv_mut(iconbox);
    if (!priv)
    {
        atk_widget_destroy(iconbox);
        return NULL;
    }

    atk_list_init(&priv->icons);
    priv->scrollbar = NULL;
    priv->list_node = NULL;
    priv->scroll_y = 0;
    priv->content_height = height;
    priv->padding = ATK_ICONBOX_PADDING;
    priv->gap_x = ATK_ICONBOX_GAP_X;
    priv->gap_y = ATK_ICONBOX_GAP_Y;
    priv->scrollbar_size = ATK_ICONBOX_SCROLLBAR_WIDTH;
    priv->icon_width = ATK_ICONBOX_ICON_WIDTH;
    priv->icon_height = ATK_ICONBOX_ICON_HEIGHT;
    priv->layout_dirty = true;
    priv->drag_icon = NULL;
    priv->drag_offset_x = 0;
    priv->drag_offset_y = 0;
    priv->drag_moved = false;

    atk_widget_t *scrollbar = atk_window_add_scrollbar(window,
                                                       x + width - priv->scrollbar_size,
                                                       y,
                                                       priv->scrollbar_size,
                                                       height,
                                                       ATK_SCROLLBAR_VERTICAL);
    if (!scrollbar)
    {
        atk_widget_destroy(iconbox);
        return NULL;
    }

    priv->scrollbar = scrollbar;
    atk_scrollbar_set_change_handler(scrollbar, iconbox_scroll_changed, iconbox);
    atk_scrollbar_set_range(scrollbar, 0, 0, height);

    atk_list_node_t *child_node = atk_list_push_back(&win_priv->children, iconbox);
    if (!child_node)
    {
        priv->scrollbar->used = false;
        atk_widget_destroy(iconbox);
        return NULL;
    }
    priv->list_node = child_node;
    return iconbox;
}

bool atk_iconbox_add_icon(atk_widget_t *iconbox, const char *title, atk_button_action_t action, void *context)
{
    atk_iconbox_priv_t *priv = iconbox_priv_mut(iconbox);
    if (!priv)
    {
        return false;
    }

    atk_iconbox_icon_t *icon = (atk_iconbox_icon_t *)malloc(sizeof(atk_iconbox_icon_t));
    if (!icon)
    {
        return false;
    }
    memset(icon, 0, sizeof(*icon));

    atk_widget_t *btn = atk_widget_create(&ATK_BUTTON_CLASS);
    if (!btn)
    {
        free(icon);
        return false;
    }
    btn->used = true;
    btn->width = priv->icon_width;
    btn->height = priv->icon_height;
    btn->parent = iconbox;
    atk_button_configure(btn,
                         title ? title : "",
                         ATK_BUTTON_STYLE_TITLE_BELOW,
                         true,
                         true,
                         action,
                         context);

    icon->button = btn;
    icon->manual_position = false;
    icon->node = atk_list_push_back(&priv->icons, icon);
    if (!icon->node)
    {
        atk_widget_destroy(btn);
        free(icon);
        return false;
    }

    priv->layout_dirty = true;
    iconbox_mark_dirty(iconbox);
    return true;
}

void atk_iconbox_set_active(atk_widget_t *iconbox, bool active)
{
    atk_iconbox_priv_t *priv = iconbox_priv_mut(iconbox);
    if (!priv)
    {
        return;
    }
    iconbox->used = active;
    if (priv->scrollbar)
    {
        priv->scrollbar->used = active;
    }
    iconbox_mark_dirty(iconbox);
}

void atk_iconbox_clear(atk_widget_t *iconbox)
{
    atk_iconbox_priv_t *priv = iconbox_priv_mut(iconbox);
    if (!priv)
    {
        return;
    }
    atk_list_clear(&priv->icons, iconbox_destroy_icon);
    priv->scroll_y = 0;
    priv->content_height = iconbox ? iconbox->height : 0;
    priv->layout_dirty = true;
    if (priv->scrollbar)
    {
        atk_scrollbar_set_value(priv->scrollbar, 0);
    }
    iconbox_mark_dirty(iconbox);
}

size_t atk_iconbox_count(const atk_widget_t *iconbox)
{
    const atk_iconbox_priv_t *priv = iconbox_priv(iconbox);
    return priv ? priv->icons.size : 0;
}

void atk_iconbox_relayout(atk_widget_t *iconbox)
{
    atk_iconbox_priv_t *priv = iconbox_priv_mut(iconbox);
    if (!priv)
    {
        return;
    }
    priv->layout_dirty = true;
    iconbox_apply_layout(iconbox, priv);
    iconbox_mark_dirty(iconbox);
}

static void iconbox_destroy_cb(atk_widget_t *widget, void *context)
{
    (void)context;
    atk_iconbox_priv_t *priv = iconbox_priv_mut(widget);
    if (priv)
    {
        atk_iconbox_clear(widget);
        if (priv->scrollbar)
        {
            priv->scrollbar->used = false;
            priv->scrollbar = NULL;
        }
        priv->list_node = NULL;
        priv->drag_icon = NULL;
    }
    atk_widget_destroy(widget);
}

static void iconbox_draw_cb(const atk_state_t *state,
                            const atk_widget_t *widget,
                            int origin_x,
                            int origin_y,
                            void *context)
{
    (void)context;
    atk_iconbox_priv_t *priv = iconbox_priv_mut((atk_widget_t *)widget);
    if (!state || !widget || !widget->used || !priv)
    {
        return;
    }

    if (priv->layout_dirty)
    {
        iconbox_apply_layout((atk_widget_t *)widget, priv);
    }

    atk_state_theme_validate(state, "atk_iconbox_draw");
    const atk_theme_t *theme = &state->theme;

    int box_x = origin_x + widget->x;
    int box_y = origin_y + widget->y;

    video_draw_rect(box_x, box_y, widget->width, widget->height, theme->window_body);

    int button_origin_y = box_y - priv->scroll_y;
    ATK_LIST_FOR_EACH(node, &priv->icons)
    {
        atk_iconbox_icon_t *icon = (atk_iconbox_icon_t *)node->value;
        if (!icon || !icon->button || !icon->button->used)
        {
            continue;
        }

        int tile_height = atk_button_effective_height(icon->button);
        int abs_y = icon->button->y + button_origin_y;
        if (abs_y + tile_height < box_y || abs_y > box_y + widget->height)
        {
            continue;
        }

        atk_button_draw(state, icon->button, box_x, button_origin_y);
    }

    video_draw_rect_outline(box_x, box_y, widget->width, widget->height, theme->window_border);
}

static bool iconbox_hit_test_cb(const atk_widget_t *widget,
                                int origin_x,
                                int origin_y,
                                int px,
                                int py,
                                void *context)
{
    (void)context;
    if (!widget || !widget->used)
    {
        return false;
    }
    int x0 = origin_x + widget->x;
    int y0 = origin_y + widget->y;
    int x1 = x0 + widget->width;
    int y1 = y0 + widget->height;
    return (px >= x0 && px < x1 && py >= y0 && py < y1);
}

static void iconbox_update_drag_target(atk_widget_t *iconbox,
                                       atk_iconbox_priv_t *priv,
                                       const atk_mouse_event_t *event)
{
    if (!iconbox || !priv || !event || !priv->drag_icon)
    {
        return;
    }

    atk_iconbox_icon_t *icon = iconbox_find_icon(priv, priv->drag_icon);
    if (!icon || !icon->button)
    {
        return;
    }

    int target_x = event->local_x - priv->drag_offset_x;
    int target_y = event->local_y + priv->scroll_y - priv->drag_offset_y;

    int min_x = priv->padding;
    int max_x = iconbox->width - priv->scrollbar_size - priv->padding - icon->button->width;
    if (max_x < min_x)
    {
        max_x = min_x;
    }
    if (target_x < min_x)
    {
        target_x = min_x;
    }
    if (target_x > max_x)
    {
        target_x = max_x;
    }

    int min_y = priv->padding;
    if (target_y < min_y)
    {
        target_y = min_y;
    }

    if (icon->button->x != target_x || icon->button->y != target_y)
    {
        icon->button->x = target_x;
        icon->button->y = target_y;
        priv->drag_moved = true;
        iconbox_refresh_content_height(priv);
        iconbox_update_scrollbar(iconbox, priv);
        iconbox_mark_dirty(iconbox);
    }
}

static atk_mouse_response_t iconbox_mouse_cb(atk_widget_t *widget,
                                             const atk_mouse_event_t *event,
                                             void *context)
{
    (void)context;
    atk_iconbox_priv_t *priv = iconbox_priv_mut(widget);
    if (!priv || !event)
    {
        return ATK_MOUSE_RESPONSE_NONE;
    }

    iconbox_sync_layout(widget, priv);

    if (event->pressed_edge)
    {
        atk_iconbox_icon_t *icon = iconbox_icon_at(widget, priv, event->cursor_x, event->cursor_y);
        if (icon && icon->button)
        {
            priv->drag_icon = icon->button;
            priv->drag_offset_x = event->local_x - icon->button->x;
            priv->drag_offset_y = event->local_y + priv->scroll_y - icon->button->y;
            priv->drag_moved = false;
            if (icon->node)
            {
                atk_list_move_to_back(&priv->icons, icon->node);
            }
            iconbox_mark_dirty(widget);
            return ATK_MOUSE_RESPONSE_HANDLED | ATK_MOUSE_RESPONSE_CAPTURE;
        }
    }
    else if (event->released_edge && priv->drag_icon)
    {
        atk_iconbox_icon_t *icon = iconbox_find_icon(priv, priv->drag_icon);
        atk_widget_t *button = priv->drag_icon;
        priv->drag_icon = NULL;
        bool moved = priv->drag_moved;
        priv->drag_moved = false;
        if (icon && button)
        {
            if (moved)
            {
                icon->manual_position = true;
            }
            else
            {
                atk_button_invoke(button);
            }
        }
        return ATK_MOUSE_RESPONSE_HANDLED | ATK_MOUSE_RESPONSE_RELEASE | ATK_MOUSE_RESPONSE_REDRAW;
    }
    else if (event->left_pressed && priv->drag_icon)
    {
        iconbox_update_drag_target(widget, priv, event);
        return ATK_MOUSE_RESPONSE_HANDLED | ATK_MOUSE_RESPONSE_REDRAW;
    }

    return ATK_MOUSE_RESPONSE_NONE;
}
