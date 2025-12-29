#include "atk/atk_tree_view.h"

#include "atk_internal.h"
#include "atk/atk_scrollbar.h"
#include "atk/atk_font.h"
#include "atk_window.h"
#include "video.h"
#include "libc.h"

#define ATK_TREE_VIEW_SCROLLBAR_SIZE 14
#define ATK_TREE_VIEW_PADDING        4
#define ATK_TREE_VIEW_INDENT         (ATK_FONT_WIDTH * 2)
#define ATK_TREE_VIEW_INDICATOR_W    (ATK_FONT_WIDTH + 4)

struct atk_tree_node
{
    char label[ATK_TREE_VIEW_LABEL_MAX];
    void *user;
    struct atk_tree_node *parent;
    atk_list_t children;
    atk_list_node_t *list_node;
    bool expandable;
    bool expanded;
    bool loaded;
};

typedef struct
{
    atk_list_t roots;
    atk_widget_t *scrollbar;
    atk_list_node_t *list_node;
    int scroll_y;
    int row_height;
    int indent;
    int padding;
    int scrollbar_size;
    int content_height;
    bool layout_dirty;
    int last_layout_width;
    int last_layout_height;
    atk_tree_node_t *selected;
    atk_tree_view_select_t on_select;
    void *select_context;
    atk_tree_view_lazy_load_t lazy_load;
    void *lazy_context;
    atk_tree_view_node_destroy_t node_destroy;
    void *destroy_context;
} atk_tree_view_priv_t;

static void tree_view_mark_dirty(const atk_widget_t *tree);
static atk_tree_view_priv_t *tree_view_priv_mut(atk_widget_t *tree);
static const atk_tree_view_priv_t *tree_view_priv(const atk_widget_t *tree);
static void tree_view_destroy_nodes(atk_widget_t *tree, atk_tree_view_priv_t *priv, atk_list_t *list);
static size_t tree_view_count_visible(const atk_tree_node_t *node);
static size_t tree_view_count_visible_list(const atk_list_t *list);
static void tree_view_sync_layout(atk_widget_t *tree, atk_tree_view_priv_t *priv);
static atk_widget_t *tree_view_window(const atk_widget_t *tree);
static void tree_view_scrollbar_changed(atk_widget_t *scrollbar, void *context, int value);
static void tree_view_update_scrollbar(atk_widget_t *tree,
                                       atk_tree_view_priv_t *priv,
                                       bool need_scroll,
                                       int max_scroll,
                                       int client_width);
static int tree_view_node_depth(const atk_tree_node_t *node);
static bool tree_view_find_row(const atk_tree_node_t *node,
                               size_t target,
                               size_t *index,
                               atk_tree_node_t **out);
static atk_tree_node_t *tree_view_node_at_row(const atk_tree_view_priv_t *priv, size_t row);
static bool tree_view_draw_nodes(const atk_state_t *state,
                                 const atk_widget_t *tree,
                                 const atk_tree_view_priv_t *priv,
                                 const atk_list_t *list,
                                 int depth,
                                 size_t *row_index,
                                 int origin_x,
                                 int origin_y,
                                 int client_width);
static void tree_view_request_children(atk_widget_t *tree, atk_tree_view_priv_t *priv, atk_tree_node_t *node);
static void tree_view_select_node(atk_widget_t *tree, atk_tree_view_priv_t *priv, atk_tree_node_t *node);

static void tree_view_destroy_cb(atk_widget_t *widget, void *context);
static void tree_view_draw_cb(const atk_state_t *state,
                              const atk_widget_t *widget,
                              int origin_x,
                              int origin_y,
                              void *context);
static bool tree_view_hit_test_cb(const atk_widget_t *widget,
                                  int origin_x,
                                  int origin_y,
                                  int px,
                                  int py,
                                  void *context);
static atk_mouse_response_t tree_view_mouse_cb(atk_widget_t *widget,
                                               const atk_mouse_event_t *event,
                                               void *context);

static const atk_widget_vtable_t tree_view_vtable = { 0 };
static const atk_widget_ops_t g_tree_view_ops = {
    .destroy = tree_view_destroy_cb,
    .draw = tree_view_draw_cb,
    .hit_test = tree_view_hit_test_cb,
    .on_mouse = tree_view_mouse_cb,
    .on_key = NULL
};

const atk_class_t ATK_TREE_VIEW_CLASS = { "TreeView", &ATK_WIDGET_CLASS, &tree_view_vtable, sizeof(atk_tree_view_priv_t) };

static atk_tree_view_priv_t *tree_view_priv_mut(atk_widget_t *tree)
{
    if (!tree)
    {
        return NULL;
    }
    return (atk_tree_view_priv_t *)atk_widget_priv(tree, &ATK_TREE_VIEW_CLASS);
}

static const atk_tree_view_priv_t *tree_view_priv(const atk_widget_t *tree)
{
    if (!tree)
    {
        return NULL;
    }
    return (const atk_tree_view_priv_t *)atk_widget_priv(tree, &ATK_TREE_VIEW_CLASS);
}

static void tree_view_mark_dirty(const atk_widget_t *tree)
{
    if (!tree)
    {
        return;
    }
    int x = 0;
    int y = 0;
    int w = 0;
    int h = 0;
    atk_widget_absolute_bounds(tree, &x, &y, &w, &h);
    if (w > 0 && h > 0)
    {
        atk_dirty_mark_rect(x, y, w, h);
    }
}

static atk_tree_node_t *tree_view_node_create(const char *label, void *user, atk_tree_node_t *parent)
{
    atk_tree_node_t *node = (atk_tree_node_t *)calloc(1, sizeof(atk_tree_node_t));
    if (!node)
    {
        return NULL;
    }
    if (label)
    {
        size_t len = strlen(label);
        if (len >= ATK_TREE_VIEW_LABEL_MAX)
        {
            len = ATK_TREE_VIEW_LABEL_MAX - 1;
        }
        memcpy(node->label, label, len);
        node->label[len] = '\0';
    }
    else
    {
        node->label[0] = '\0';
    }
    node->user = user;
    node->parent = parent;
    atk_list_init(&node->children);
    node->list_node = NULL;
    node->expandable = false;
    node->expanded = false;
    node->loaded = false;
    return node;
}

static void tree_view_destroy_nodes(atk_widget_t *tree, atk_tree_view_priv_t *priv, atk_list_t *list)
{
    if (!priv || !list)
    {
        return;
    }

    ATK_LIST_FOR_EACH(node, list)
    {
        atk_tree_node_t *child = (atk_tree_node_t *)node->value;
        if (!child)
        {
            continue;
        }
        tree_view_destroy_nodes(tree, priv, &child->children);
        if (priv->node_destroy)
        {
            priv->node_destroy(tree, priv->destroy_context, child);
        }
        free(child);
    }
    atk_list_clear(list, NULL);
}

static size_t tree_view_count_visible(const atk_tree_node_t *node)
{
    if (!node)
    {
        return 0;
    }
    size_t count = 1;
    if (node->expanded)
    {
        ATK_LIST_FOR_EACH(child_node, &node->children)
        {
            atk_tree_node_t *child = (atk_tree_node_t *)child_node->value;
            count += tree_view_count_visible(child);
        }
    }
    return count;
}

static size_t tree_view_count_visible_list(const atk_list_t *list)
{
    if (!list)
    {
        return 0;
    }
    size_t count = 0;
    ATK_LIST_FOR_EACH(node, list)
    {
        atk_tree_node_t *root = (atk_tree_node_t *)node->value;
        count += tree_view_count_visible(root);
    }
    return count;
}

static atk_widget_t *tree_view_window(const atk_widget_t *tree)
{
    atk_widget_t *current = tree ? tree->parent : NULL;
    while (current)
    {
        if (atk_widget_is_a(current, &ATK_WINDOW_CLASS))
        {
            return current;
        }
        current = current->parent;
    }
    return NULL;
}

static void tree_view_scrollbar_changed(atk_widget_t *scrollbar, void *context, int value)
{
    (void)scrollbar;
    atk_widget_t *tree = (atk_widget_t *)context;
    atk_tree_view_priv_t *priv = tree_view_priv_mut(tree);
    if (!priv)
    {
        return;
    }
    if (value < 0)
    {
        value = 0;
    }
    priv->scroll_y = value;
    tree_view_mark_dirty(tree);
}

static void tree_view_update_scrollbar(atk_widget_t *tree,
                                       atk_tree_view_priv_t *priv,
                                       bool need_scroll,
                                       int max_scroll,
                                       int client_width)
{
    atk_widget_t *window = tree_view_window(tree);
    if (!window || !priv)
    {
        if (priv && priv->scrollbar)
        {
            priv->scrollbar->used = false;
        }
        return;
    }

    int window_x = 0;
    int window_y = 0;
    int tree_x = 0;
    int tree_y = 0;
    atk_widget_absolute_position(window, &window_x, &window_y);
    atk_widget_absolute_position(tree, &tree_x, &tree_y);
    int rel_x = tree_x - window_x;
    int rel_y = tree_y - window_y;

    int scrollbar_size = priv->scrollbar_size > 0 ? priv->scrollbar_size : ATK_TREE_VIEW_SCROLLBAR_SIZE;
    if (need_scroll && client_width > 0 && scrollbar_size > 0)
    {
        if (!priv->scrollbar)
        {
            priv->scrollbar = atk_window_add_scrollbar(window,
                                                       rel_x + client_width,
                                                       rel_y,
                                                       scrollbar_size,
                                                       tree->height,
                                                       ATK_SCROLLBAR_VERTICAL);
            if (priv->scrollbar)
            {
                atk_scrollbar_set_change_handler(priv->scrollbar, tree_view_scrollbar_changed, tree);
            }
        }
        if (priv->scrollbar)
        {
            priv->scrollbar->used = true;
            priv->scrollbar->x = rel_x + client_width;
            priv->scrollbar->y = rel_y;
            priv->scrollbar->width = scrollbar_size;
            priv->scrollbar->height = tree->height;
            if (priv->scrollbar->width < 1)
            {
                priv->scrollbar->width = 1;
            }
            if (priv->scrollbar->height < 1)
            {
                priv->scrollbar->height = 1;
            }
            int page = tree->height > 1 ? tree->height : 1;
            atk_scrollbar_set_range(priv->scrollbar, 0, max_scroll, page);
            atk_scrollbar_set_value(priv->scrollbar, priv->scroll_y);
            atk_scrollbar_mark_dirty(priv->scrollbar);
        }
    }
    else if (priv->scrollbar)
    {
        priv->scrollbar->used = false;
        atk_scrollbar_mark_dirty(priv->scrollbar);
        tree_view_mark_dirty(tree);
    }
}

static void tree_view_sync_layout(atk_widget_t *tree, atk_tree_view_priv_t *priv)
{
    if (!tree || !priv)
    {
        return;
    }

    if (!priv->layout_dirty &&
        tree->width == priv->last_layout_width &&
        tree->height == priv->last_layout_height)
    {
        return;
    }

    size_t rows = tree_view_count_visible_list(&priv->roots);
    int padding = priv->padding;
    if (padding < 0)
    {
        padding = 0;
    }
    int content_height = (int)rows * priv->row_height + padding * 2;
    if (content_height < tree->height)
    {
        content_height = tree->height;
    }

    priv->content_height = content_height;
    priv->last_layout_width = tree->width;
    priv->last_layout_height = tree->height;
    priv->layout_dirty = false;

    int max_scroll = content_height - tree->height;
    if (max_scroll < 0)
    {
        max_scroll = 0;
    }
    if (priv->scroll_y > max_scroll)
    {
        priv->scroll_y = max_scroll;
        if (priv->scrollbar)
        {
            atk_scrollbar_set_value(priv->scrollbar, priv->scroll_y);
        }
    }

    bool need_scroll = (content_height > tree->height);
    int scrollbar_size = (need_scroll && priv->scrollbar_size > 0) ? priv->scrollbar_size : 0;
    int client_width = tree->width - scrollbar_size;
    if (client_width < 0)
    {
        client_width = 0;
    }
    tree_view_update_scrollbar(tree, priv, need_scroll, max_scroll, client_width);
}

static int tree_view_node_depth(const atk_tree_node_t *node)
{
    int depth = 0;
    const atk_tree_node_t *cursor = node;
    size_t guard = 0;
    while (cursor && cursor->parent && guard < 128)
    {
        depth++;
        cursor = cursor->parent;
        guard++;
    }
    return depth;
}

static bool tree_view_find_row(const atk_tree_node_t *node,
                               size_t target,
                               size_t *index,
                               atk_tree_node_t **out)
{
    if (!node || !index || !out)
    {
        return false;
    }
    if (*index == target)
    {
        *out = (atk_tree_node_t *)node;
        return true;
    }
    (*index)++;
    if (node->expanded)
    {
        ATK_LIST_FOR_EACH(child_node, &node->children)
        {
            atk_tree_node_t *child = (atk_tree_node_t *)child_node->value;
            if (tree_view_find_row(child, target, index, out))
            {
                return true;
            }
        }
    }
    return false;
}

static atk_tree_node_t *tree_view_node_at_row(const atk_tree_view_priv_t *priv, size_t row)
{
    if (!priv)
    {
        return NULL;
    }
    size_t index = 0;
    atk_tree_node_t *out = NULL;
    ATK_LIST_FOR_EACH(node, &priv->roots)
    {
        atk_tree_node_t *root = (atk_tree_node_t *)node->value;
        if (tree_view_find_row(root, row, &index, &out))
        {
            return out;
        }
    }
    return NULL;
}

static bool tree_view_draw_nodes(const atk_state_t *state,
                                 const atk_widget_t *tree,
                                 const atk_tree_view_priv_t *priv,
                                 const atk_list_t *list,
                                 int depth,
                                 size_t *row_index,
                                 int origin_x,
                                 int origin_y,
                                 int client_width)
{
    if (!state || !tree || !priv || !list || !row_index)
    {
        return true;
    }

    const atk_theme_t *theme = &state->theme;
    video_color_t stripe_colors[2] = { theme->window_body, atk_color_tint(theme->window_body, -6) };
    int row_height = priv->row_height;
    if (row_height <= 0)
    {
        return true;
    }

    int view_top = origin_y;
    int view_bottom = origin_y + tree->height;

    ATK_LIST_FOR_EACH(node, list)
    {
        atk_tree_node_t *entry = (atk_tree_node_t *)node->value;
        if (!entry)
        {
            continue;
        }
        int row_y = origin_y + priv->padding + (int)(*row_index) * row_height - priv->scroll_y;
        if (row_y > view_bottom)
        {
            return false;
        }

        if (row_y + row_height >= view_top && row_y < view_bottom)
        {
            video_color_t row_bg = stripe_colors[(*row_index) % 2];
            video_color_t text_color = theme->button_text;
            if (priv->selected == entry)
            {
                row_bg = theme->menu_bar_highlight;
                text_color = theme->window_title_text;
            }

            if (client_width > 0 && row_height > 0)
            {
                video_draw_rect(origin_x, row_y, client_width, row_height, row_bg);
            }

            int indent = priv->indent > 0 ? priv->indent : ATK_TREE_VIEW_INDENT;
            int indicator_x = origin_x + priv->padding + depth * indent;
            int indicator_w = ATK_TREE_VIEW_INDICATOR_W;
            int text_x = indicator_x + indicator_w + priv->padding;
            int baseline = atk_font_baseline_for_rect(row_y, row_height);
            atk_rect_t clip = { origin_x, row_y, client_width, row_height };

            if (entry->expandable)
            {
                const char *marker = entry->expanded ? "v" : ">";
                atk_font_draw_string_clipped(indicator_x,
                                             baseline,
                                             marker,
                                             text_color,
                                             row_bg,
                                             &clip);
            }

            const char *label = entry->label[0] ? entry->label : "";
            atk_font_draw_string_clipped(text_x, baseline, label, text_color, row_bg, &clip);
        }

        (*row_index)++;
        if (entry->expanded)
        {
            if (!tree_view_draw_nodes(state,
                                      tree,
                                      priv,
                                      &entry->children,
                                      depth + 1,
                                      row_index,
                                      origin_x,
                                      origin_y,
                                      client_width))
            {
                return false;
            }
        }
    }

    return true;
}

static void tree_view_request_children(atk_widget_t *tree, atk_tree_view_priv_t *priv, atk_tree_node_t *node)
{
    if (!tree || !priv || !node || node->loaded || !node->expandable || !priv->lazy_load)
    {
        return;
    }
    if (priv->lazy_load(tree, priv->lazy_context, node))
    {
        node->loaded = true;
    }
}

static void tree_view_select_node(atk_widget_t *tree, atk_tree_view_priv_t *priv, atk_tree_node_t *node)
{
    if (!tree || !priv || !node)
    {
        return;
    }
    priv->selected = node;
    tree_view_mark_dirty(tree);
    if (priv->on_select)
    {
        priv->on_select(tree, priv->select_context, node);
    }
}

static void tree_view_destroy_cb(atk_widget_t *widget, void *context)
{
    (void)context;
    atk_tree_view_destroy(widget);
    atk_widget_destroy(widget);
}

static void tree_view_draw_cb(const atk_state_t *state,
                              const atk_widget_t *widget,
                              int origin_x,
                              int origin_y,
                              void *context)
{
    (void)origin_x;
    (void)origin_y;
    (void)context;
    atk_tree_view_draw(state, widget);
}

static bool tree_view_hit_test_cb(const atk_widget_t *widget,
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

static atk_mouse_response_t tree_view_mouse_cb(atk_widget_t *widget,
                                               const atk_mouse_event_t *event,
                                               void *context)
{
    (void)context;
    if (!widget || !event)
    {
        return ATK_MOUSE_RESPONSE_NONE;
    }

    atk_tree_view_priv_t *priv = tree_view_priv_mut(widget);
    if (!priv)
    {
        return ATK_MOUSE_RESPONSE_NONE;
    }

    tree_view_sync_layout(widget, priv);

    if (!event->released_edge)
    {
        return ATK_MOUSE_RESPONSE_NONE;
    }

    int client_width = widget->width;
    if (priv->scrollbar && priv->scrollbar->used)
    {
        client_width -= priv->scrollbar_size;
    }
    if (client_width < 0)
    {
        client_width = 0;
    }

    if (event->local_x >= client_width)
    {
        return ATK_MOUSE_RESPONSE_NONE;
    }

    int content_y = event->local_y + priv->scroll_y - priv->padding;
    if (content_y < 0 || priv->row_height <= 0)
    {
        return ATK_MOUSE_RESPONSE_NONE;
    }

    size_t row = (size_t)(content_y / priv->row_height);
    atk_tree_node_t *node = tree_view_node_at_row(priv, row);
    if (!node)
    {
        return ATK_MOUSE_RESPONSE_NONE;
    }

    int depth = tree_view_node_depth(node);
    int indent = priv->indent > 0 ? priv->indent : ATK_TREE_VIEW_INDENT;
    int indicator_x = priv->padding + depth * indent;
    int indicator_end = indicator_x + ATK_TREE_VIEW_INDICATOR_W;
    bool toggle = node->expandable && event->local_x >= indicator_x && event->local_x < indicator_end;
    if (toggle)
    {
        atk_tree_view_set_node_expanded(widget, node, !node->expanded);
    }
    else
    {
        tree_view_select_node(widget, priv, node);
    }
    return ATK_MOUSE_RESPONSE_HANDLED | ATK_MOUSE_RESPONSE_REDRAW;
}

atk_widget_t *atk_tree_view_create(void)
{
    atk_widget_t *widget = atk_widget_create(&ATK_TREE_VIEW_CLASS);
    if (!widget)
    {
        return NULL;
    }

    widget->used = true;
    widget->x = 0;
    widget->y = 0;
    widget->width = 0;
    widget->height = 0;
    widget->parent = NULL;
    atk_widget_set_ops(widget, &g_tree_view_ops, NULL);

    atk_tree_view_priv_t *priv = tree_view_priv_mut(widget);
    if (!priv)
    {
        atk_widget_destroy(widget);
        return NULL;
    }

    atk_list_init(&priv->roots);
    priv->scrollbar = NULL;
    priv->list_node = NULL;
    priv->scroll_y = 0;
    priv->row_height = atk_font_line_height() + 4;
    priv->indent = ATK_TREE_VIEW_INDENT;
    priv->padding = ATK_TREE_VIEW_PADDING;
    priv->scrollbar_size = ATK_TREE_VIEW_SCROLLBAR_SIZE;
    priv->content_height = 0;
    priv->layout_dirty = true;
    priv->last_layout_width = -1;
    priv->last_layout_height = -1;
    priv->selected = NULL;
    priv->on_select = NULL;
    priv->select_context = NULL;
    priv->lazy_load = NULL;
    priv->lazy_context = NULL;
    priv->node_destroy = NULL;
    priv->destroy_context = NULL;
    return widget;
}

atk_widget_t *atk_window_add_tree_view(atk_widget_t *window, int x, int y, int width, int height)
{
    if (!window || width <= 0 || height <= 0)
    {
        return NULL;
    }

    atk_window_priv_t *priv = (atk_window_priv_t *)atk_widget_priv(window, &ATK_WINDOW_CLASS);
    if (!priv)
    {
        return NULL;
    }

    atk_widget_t *tree = atk_tree_view_create();
    if (!tree)
    {
        return NULL;
    }

    tree->x = x;
    tree->y = y;
    tree->width = width;
    tree->height = height;
    tree->parent = window;

    atk_list_node_t *child_node = atk_list_push_back(&priv->children, tree);
    if (!child_node)
    {
        atk_tree_view_destroy(tree);
        atk_widget_destroy(tree);
        return NULL;
    }

    atk_tree_view_priv_t *tree_priv = tree_view_priv_mut(tree);
    tree_priv->list_node = child_node;
    return tree;
}

void atk_tree_view_clear(atk_widget_t *tree)
{
    atk_tree_view_priv_t *priv = tree_view_priv_mut(tree);
    if (!priv)
    {
        return;
    }
    tree_view_destroy_nodes(tree, priv, &priv->roots);
    priv->selected = NULL;
    priv->scroll_y = 0;
    priv->content_height = tree ? tree->height : 0;
    priv->layout_dirty = true;
    if (priv->scrollbar)
    {
        atk_scrollbar_set_value(priv->scrollbar, 0);
    }
    tree_view_mark_dirty(tree);
}

atk_tree_node_t *atk_tree_view_add_root(atk_widget_t *tree, const char *label, void *user)
{
    atk_tree_view_priv_t *priv = tree_view_priv_mut(tree);
    if (!priv)
    {
        return NULL;
    }
    atk_tree_node_t *node = tree_view_node_create(label, user, NULL);
    if (!node)
    {
        return NULL;
    }
    node->list_node = atk_list_push_back(&priv->roots, node);
    if (!node->list_node)
    {
        free(node);
        return NULL;
    }
    priv->layout_dirty = true;
    tree_view_mark_dirty(tree);
    return node;
}

atk_tree_node_t *atk_tree_view_add_child(atk_widget_t *tree, atk_tree_node_t *parent, const char *label, void *user)
{
    atk_tree_view_priv_t *priv = tree_view_priv_mut(tree);
    if (!priv || !parent)
    {
        return NULL;
    }
    atk_tree_node_t *node = tree_view_node_create(label, user, parent);
    if (!node)
    {
        return NULL;
    }
    node->list_node = atk_list_push_back(&parent->children, node);
    if (!node->list_node)
    {
        free(node);
        return NULL;
    }
    priv->layout_dirty = true;
    tree_view_mark_dirty(tree);
    return node;
}

const char *atk_tree_view_node_label(const atk_tree_node_t *node)
{
    return node ? node->label : "";
}

void atk_tree_view_set_node_label(atk_tree_node_t *node, const char *label)
{
    if (!node)
    {
        return;
    }
    size_t len = label ? strlen(label) : 0;
    if (len >= ATK_TREE_VIEW_LABEL_MAX)
    {
        len = ATK_TREE_VIEW_LABEL_MAX - 1;
    }
    if (label && len > 0)
    {
        memcpy(node->label, label, len);
        node->label[len] = '\0';
    }
    else
    {
        node->label[0] = '\0';
    }
}

void *atk_tree_view_node_user(const atk_tree_node_t *node)
{
    return node ? node->user : NULL;
}

void atk_tree_view_set_node_user(atk_tree_node_t *node, void *user)
{
    if (!node)
    {
        return;
    }
    node->user = user;
}

atk_tree_node_t *atk_tree_view_node_parent(const atk_tree_node_t *node)
{
    return node ? node->parent : NULL;
}

atk_tree_node_t *atk_tree_view_node_find_child(const atk_tree_node_t *parent, const char *label)
{
    if (!parent || !label)
    {
        return NULL;
    }
    ATK_LIST_FOR_EACH(node, &parent->children)
    {
        atk_tree_node_t *child = (atk_tree_node_t *)node->value;
        if (!child)
        {
            continue;
        }
        if (strcmp(child->label, label) == 0)
        {
            return child;
        }
    }
    return NULL;
}

bool atk_tree_view_node_expandable(const atk_tree_node_t *node)
{
    return node ? node->expandable : false;
}

void atk_tree_view_set_node_expandable(atk_tree_node_t *node, bool expandable)
{
    if (!node)
    {
        return;
    }
    node->expandable = expandable;
}

bool atk_tree_view_node_expanded(const atk_tree_node_t *node)
{
    return node ? node->expanded : false;
}

void atk_tree_view_set_node_expanded(atk_widget_t *tree, atk_tree_node_t *node, bool expanded)
{
    atk_tree_view_priv_t *priv = tree_view_priv_mut(tree);
    if (!priv || !node)
    {
        return;
    }
    if (expanded && !node->expandable)
    {
        return;
    }
    if (node->expanded == expanded)
    {
        return;
    }
    if (expanded)
    {
        tree_view_request_children(tree, priv, node);
    }
    node->expanded = expanded;
    priv->layout_dirty = true;
    tree_view_sync_layout(tree, priv);
    tree_view_mark_dirty(tree);
}

void atk_tree_view_set_selected(atk_widget_t *tree, atk_tree_node_t *node)
{
    atk_tree_view_priv_t *priv = tree_view_priv_mut(tree);
    if (!priv)
    {
        return;
    }
    if (priv->selected != node)
    {
        priv->selected = node;
        tree_view_mark_dirty(tree);
    }
}

atk_tree_node_t *atk_tree_view_selected(const atk_widget_t *tree)
{
    const atk_tree_view_priv_t *priv = tree_view_priv(tree);
    return priv ? priv->selected : NULL;
}

void atk_tree_view_set_select_handler(atk_widget_t *tree, atk_tree_view_select_t handler, void *context)
{
    atk_tree_view_priv_t *priv = tree_view_priv_mut(tree);
    if (!priv)
    {
        return;
    }
    priv->on_select = handler;
    priv->select_context = context;
}

void atk_tree_view_set_lazy_load_handler(atk_widget_t *tree, atk_tree_view_lazy_load_t handler, void *context)
{
    atk_tree_view_priv_t *priv = tree_view_priv_mut(tree);
    if (!priv)
    {
        return;
    }
    priv->lazy_load = handler;
    priv->lazy_context = context;
}

void atk_tree_view_set_node_destroy_handler(atk_widget_t *tree, atk_tree_view_node_destroy_t handler, void *context)
{
    atk_tree_view_priv_t *priv = tree_view_priv_mut(tree);
    if (!priv)
    {
        return;
    }
    priv->node_destroy = handler;
    priv->destroy_context = context;
}

void atk_tree_view_relayout(atk_widget_t *tree)
{
    atk_tree_view_priv_t *priv = tree_view_priv_mut(tree);
    if (!priv)
    {
        return;
    }
    priv->layout_dirty = true;
    tree_view_sync_layout(tree, priv);
    tree_view_mark_dirty(tree);
}

void atk_tree_view_draw(const atk_state_t *state, const atk_widget_t *tree)
{
    if (!state || !tree || !tree->used || tree->width <= 0 || tree->height <= 0)
    {
        return;
    }

    atk_tree_view_priv_t *priv = tree_view_priv_mut((atk_widget_t *)tree);
    if (!priv)
    {
        return;
    }

    atk_state_theme_validate(state, "atk_tree_view_draw");

    int origin_x = 0;
    int origin_y = 0;
    atk_widget_absolute_position(tree, &origin_x, &origin_y);

    const atk_theme_t *theme = &state->theme;
    video_color_t body_top = atk_color_tint(theme->window_body, 4);
    video_color_t body_bottom = atk_color_tint(theme->window_body, -6);
    atk_draw_vertical_gradient(origin_x, origin_y, tree->width, tree->height, body_top, body_bottom);

    tree_view_sync_layout((atk_widget_t *)tree, priv);

    int client_width = tree->width;
    if (priv->scrollbar && priv->scrollbar->used)
    {
        client_width -= priv->scrollbar_size;
    }
    if (client_width < 0)
    {
        client_width = 0;
    }

    size_t row_index = 0;
    tree_view_draw_nodes(state, tree, priv, &priv->roots, 0, &row_index, origin_x, origin_y, client_width);

    atk_draw_bevel_outline(origin_x,
                           origin_y,
                           tree->width,
                           tree->height,
                           atk_color_tint(theme->window_body, 18),
                           atk_color_tint(theme->window_border, -10));
}

void atk_tree_view_destroy(atk_widget_t *tree)
{
    atk_tree_view_priv_t *priv = tree_view_priv_mut(tree);
    if (!priv)
    {
        return;
    }
    if (priv->scrollbar)
    {
        priv->scrollbar->used = false;
    }
    tree_view_destroy_nodes(tree, priv, &priv->roots);
    priv->selected = NULL;
    priv->scroll_y = 0;
    priv->content_height = 0;
    priv->layout_dirty = true;
    priv->on_select = NULL;
    priv->select_context = NULL;
    priv->lazy_load = NULL;
    priv->lazy_context = NULL;
    priv->node_destroy = NULL;
    priv->destroy_context = NULL;
    priv->list_node = NULL;
}
