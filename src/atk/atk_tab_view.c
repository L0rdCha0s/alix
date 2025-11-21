#include "atk/atk_tabs.h"

#include "atk_internal.h"
#include "atk_event_debug.h"
#include "video.h"
#include "libc.h"
#include "serial.h"

#if ATK_DEBUG
#define TAB_LOG(...) serial_printf(__VA_ARGS__)
#else
#define TAB_LOG(...) (void)0
#endif

#define ATK_TAB_VIEW_MIN_WIDTH   (ATK_FONT_WIDTH * 6)

typedef struct
{
    char title[ATK_TAB_TITLE_MAX];
    atk_widget_t *content;
} atk_tab_view_page_t;

typedef struct
{
    atk_list_t pages;
    size_t page_count;
    size_t active_index;
    int tab_height;
    int tab_padding;
    int tab_spacing;
    int content_padding;
    atk_tab_view_change_t change;
    void *change_context;
    atk_list_node_t *list_node;
} atk_tab_view_priv_t;

static atk_tab_view_priv_t *tab_view_priv_mut(atk_widget_t *tab_view);
static const atk_tab_view_priv_t *tab_view_priv(const atk_widget_t *tab_view);
static atk_widget_t *atk_tab_view_create(void);
static void tab_view_free_page(void *value);
static void tab_view_layout_pages(atk_widget_t *tab_view, atk_tab_view_priv_t *priv);
static void tab_view_content_bounds(const atk_widget_t *tab_view,
                                    const atk_tab_view_priv_t *priv,
                                    int *x,
                                    int *y,
                                    int *width,
                                    int *height);
static int tab_view_tab_width(const atk_tab_view_priv_t *priv, const atk_tab_view_page_t *page);
static void tab_view_invalidate(const atk_widget_t *tab_view);
static atk_mouse_response_t tab_view_mouse_cb(atk_widget_t *widget,
                                              const atk_mouse_event_t *event,
                                              void *context);
static bool tab_view_hit_test_cb(const atk_widget_t *widget,
                                 int origin_x,
                                 int origin_y,
                                 int px,
                                 int py,
                                 void *context);
static void tab_view_draw_cb(const atk_state_t *state,
                             const atk_widget_t *widget,
                             int origin_x,
                             int origin_y,
                             void *context);
static void tab_view_destroy_cb(atk_widget_t *widget, void *context);

static const atk_widget_vtable_t tab_view_vtable = { 0 };
static const atk_widget_ops_t g_tab_view_ops = {
    .destroy = tab_view_destroy_cb,
    .draw = tab_view_draw_cb,
    .hit_test = tab_view_hit_test_cb,
    .on_mouse = tab_view_mouse_cb,
    .on_key = NULL
};
const atk_class_t ATK_TAB_VIEW_CLASS = { "TabView", &ATK_WIDGET_CLASS, &tab_view_vtable, sizeof(atk_tab_view_priv_t) };

atk_widget_t *atk_window_add_tab_view(atk_widget_t *window, int x, int y, int width, int height)
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

    atk_widget_t *tab_view = atk_tab_view_create();
    if (!tab_view)
    {
        return NULL;
    }

    tab_view->x = x;
    tab_view->y = y;
    tab_view->width = width;
    tab_view->height = height;
    tab_view->parent = window;

    atk_list_node_t *child_node = atk_list_push_back(&priv->children, tab_view);
    if (!child_node)
    {
        atk_tab_view_destroy(tab_view);
        atk_widget_destroy(tab_view);
        return NULL;
    }

    atk_tab_view_priv_t *tv_priv = tab_view_priv_mut(tab_view);
    tv_priv->list_node = child_node;
    tab_view_layout_pages(tab_view, tv_priv);
    return tab_view;
}

bool atk_tab_view_add_page(atk_widget_t *tab_view, const char *title, atk_widget_t *content)
{
    atk_tab_view_priv_t *priv = tab_view_priv_mut(tab_view);
    if (!priv || !content)
    {
        return false;
    }

    atk_tab_view_page_t *page = (atk_tab_view_page_t *)malloc(sizeof(atk_tab_view_page_t));
    if (!page)
    {
        return false;
    }

    size_t len = title ? strlen(title) : 0;
    if (len >= ATK_TAB_TITLE_MAX)
    {
        len = ATK_TAB_TITLE_MAX - 1;
    }
    if (title && len > 0)
    {
        memcpy(page->title, title, len);
        page->title[len] = '\0';
    }
    else
    {
        page->title[0] = '\0';
    }

    page->content = content;

    atk_list_node_t *node = atk_list_push_back(&priv->pages, page);
    if (!node)
    {
        free(page);
        return false;
    }

    priv->page_count++;
    if (priv->page_count == 1)
    {
        priv->active_index = 0;
    }

    tab_view_layout_pages(tab_view, priv);
    tab_view_invalidate(tab_view);
    return true;
}

void atk_tab_view_set_active(atk_widget_t *tab_view, size_t index)
{
    atk_tab_view_priv_t *priv = tab_view_priv_mut(tab_view);
    if (!priv || priv->page_count == 0)
    {
        return;
    }

    if (index >= priv->page_count)
    {
        index = priv->page_count - 1;
    }
    if (index == priv->active_index)
    {
        return;
    }

    priv->active_index = index;
    if (priv->change)
    {
        priv->change(tab_view, priv->change_context, index);
    }
    tab_view_invalidate(tab_view);
}

size_t atk_tab_view_active(const atk_widget_t *tab_view)
{
    const atk_tab_view_priv_t *priv = tab_view_priv(tab_view);
    if (!priv || priv->page_count == 0)
    {
        return 0;
    }
    if (priv->active_index >= priv->page_count)
    {
        return priv->page_count - 1;
    }
    return priv->active_index;
}

atk_widget_t *atk_tab_view_active_content(const atk_widget_t *tab_view)
{
    const atk_tab_view_priv_t *priv = tab_view_priv(tab_view);
    if (!priv || priv->page_count == 0)
    {
        return NULL;
    }

    size_t index = atk_tab_view_active(tab_view);
    size_t current = 0;
    ATK_LIST_FOR_EACH(node, &priv->pages)
    {
        atk_tab_view_page_t *page = (atk_tab_view_page_t *)node->value;
        if (current == index)
        {
            return page->content;
        }
        current++;
    }
    return NULL;
}

void atk_tab_view_set_change_handler(atk_widget_t *tab_view, atk_tab_view_change_t handler, void *context)
{
    atk_tab_view_priv_t *priv = tab_view_priv_mut(tab_view);
    if (!priv)
    {
        return;
    }
    priv->change = handler;
    priv->change_context = context;
}

void atk_tab_view_relayout(atk_widget_t *tab_view)
{
    atk_tab_view_priv_t *priv = tab_view_priv_mut(tab_view);
    if (!priv)
    {
        return;
    }
    tab_view_layout_pages(tab_view, priv);
}

bool atk_tab_view_contains_point(const atk_widget_t *tab_view, int px, int py)
{
    int x = 0;
    int y = 0;
    int w = 0;
    int h = 0;
    atk_widget_absolute_bounds(tab_view, &x, &y, &w, &h);
    return (px >= x && px < x + w && py >= y && py < y + h);
}

bool atk_tab_view_point_in_tab_bar(const atk_widget_t *tab_view, int px, int py)
{
    const atk_tab_view_priv_t *priv = tab_view_priv(tab_view);
    if (!priv)
    {
        return false;
    }

    int origin_x = 0;
    int origin_y = 0;
    atk_widget_absolute_position(tab_view, &origin_x, &origin_y);

    if (px < origin_x || px >= origin_x + tab_view->width)
    {
        return false;
    }
    return (py >= origin_y && py < origin_y + priv->tab_height);
}

bool atk_tab_view_handle_mouse(atk_widget_t *tab_view, const atk_mouse_event_t *event)
{
    atk_tab_view_priv_t *priv = tab_view_priv_mut(tab_view);
    if (!priv || !event || priv->page_count == 0)
    {
        return false;
    }

    int local_x = event->local_x;
    int local_y = event->local_y;

    if (local_y < 0 || local_y >= priv->tab_height)
    {
        atk_event_debug_tab_miss(event->id, tab_view, local_x, local_y, "outside_tab_bar");
        TAB_LOG("[atk][tab_view] miss outside bar id=%016llX local=(%d,%d) tab_h=%d\r\n",
                (unsigned long long)event->id,
                local_x,
                local_y,
                priv->tab_height);
        return false;
    }

    int tab_x = priv->content_padding;
    int max_x = tab_view->width;
    size_t index = 0;
    ATK_LIST_FOR_EACH(node, &priv->pages)
    {
        atk_tab_view_page_t *page = (atk_tab_view_page_t *)node->value;
        int width = tab_view_tab_width(priv, page);
        if (tab_x >= max_x)
        {
            break;
        }
        if (tab_x + width > max_x)
        {
            width = max_x - tab_x;
            if (width <= 0)
            {
                break;
            }
        }
        int x0 = tab_x;
        int x1 = tab_x + width;
        if (local_x >= x0 && local_x < x1)
        {
            atk_event_debug_tab_hit(event->id, tab_view, index, page->title, priv->active_index);
            if (index != priv->active_index)
            {
                atk_tab_view_set_active(tab_view, index);
            }
            TAB_LOG("[atk][tab_view] hit id=%016llX tab=%llu title=%s\r\n",
                    (unsigned long long)event->id,
                    (unsigned long long)index,
                    page->title[0] ? page->title : "<empty>");
            return true;
        }
        tab_x = x1 + priv->tab_spacing;
        index++;
    }

    atk_event_debug_tab_miss(event->id, tab_view, local_x, local_y, "no_tab_match");
    TAB_LOG("[atk][tab_view] miss no match id=%016llX local=(%d,%d)\r\n",
            (unsigned long long)event->id,
            local_x,
            local_y);
    return false;
}

static atk_mouse_response_t tab_view_mouse_cb(atk_widget_t *widget,
                                              const atk_mouse_event_t *event,
                                              void *context)
{
    (void)context;
    if (!event || !event->pressed_edge)
    {
        return ATK_MOUSE_RESPONSE_NONE;
    }

    TAB_LOG("[atk][tab_view] mouse id=%016llX cursor=(%d,%d) local=(%d,%d) left=%d\r\n",
            (unsigned long long)event->id,
            event->cursor_x,
            event->cursor_y,
            event->local_x,
            event->local_y,
            event->left_pressed ? 1 : 0);

    if (atk_tab_view_handle_mouse(widget, event))
    {
        TAB_LOG("[atk][tab_view] handled id=%016llX\r\n",
                (unsigned long long)event->id);
        return ATK_MOUSE_RESPONSE_HANDLED | ATK_MOUSE_RESPONSE_REDRAW;
    }
    TAB_LOG("[atk][tab_view] ignored id=%016llX\r\n",
            (unsigned long long)event->id);
    return ATK_MOUSE_RESPONSE_NONE;
}

static bool tab_view_hit_test_cb(const atk_widget_t *widget,
                                 int origin_x,
                                 int origin_y,
                                 int px,
                                 int py,
                                 void *context)
{
    (void)origin_x;
    (void)origin_y;
    (void)context;
    return atk_tab_view_contains_point(widget, px, py);
}

static void tab_view_draw_cb(const atk_state_t *state,
                             const atk_widget_t *widget,
                             int origin_x,
                             int origin_y,
                             void *context)
{
    (void)origin_x;
    (void)origin_y;
    (void)context;
    atk_tab_view_draw(state, widget);
}

static void tab_view_destroy_cb(atk_widget_t *widget, void *context)
{
    (void)context;
    atk_tab_view_destroy(widget);
    atk_widget_destroy(widget);
}

void atk_tab_view_draw(const atk_state_t *state, const atk_widget_t *tab_view)
{
    const atk_tab_view_priv_t *priv = tab_view_priv(tab_view);
    if (!state || !tab_view || !tab_view->used || !priv || tab_view->width <= 0 || tab_view->height <= 0)
    {
        return;
    }

    atk_state_theme_validate(state, "atk_tab_view_draw");

    int origin_x = 0;
    int origin_y = 0;
    atk_widget_absolute_position(tab_view, &origin_x, &origin_y);

    const atk_theme_t *theme = &state->theme;
    video_draw_rect(origin_x, origin_y, tab_view->width, tab_view->height, theme->window_body);
    video_draw_rect(origin_x, origin_y, tab_view->width, priv->tab_height, theme->button_face);

    int tab_x = origin_x + priv->content_padding;
    int tab_y = origin_y;
    size_t index = 0;
    ATK_LIST_FOR_EACH(node, &priv->pages)
    {
        const atk_tab_view_page_t *page = (const atk_tab_view_page_t *)node->value;
        int width = tab_view_tab_width(priv, page);
        if (width <= 0)
        {
            continue;
        }
        if (tab_x >= origin_x + tab_view->width)
        {
            break;
        }
        if (tab_x + width > origin_x + tab_view->width)
        {
            width = origin_x + tab_view->width - tab_x;
            if (width <= 0)
            {
                break;
            }
        }

        bool active = (index == priv->active_index);
        uint16_t bg = active ? theme->window_body : theme->button_face;
        uint16_t border = theme->window_border;
        uint16_t text = theme->button_text;

        video_draw_rect(tab_x, tab_y, width, priv->tab_height, bg);
        video_draw_rect_outline(tab_x, tab_y, width, priv->tab_height, border);
        int text_x = tab_x + priv->tab_padding / 2;
        int text_y = tab_y + (priv->tab_height - ATK_FONT_HEIGHT) / 2;
        if (text_y < tab_y)
        {
            text_y = tab_y;
        }
        video_draw_text(text_x, text_y, page->title, text, bg);

        if (active)
        {
            video_draw_rect(tab_x,
                            tab_y + priv->tab_height - 1,
                            width,
                            1,
                            theme->window_body);
        }

        tab_x += width + priv->tab_spacing;
        index++;
    }

    int content_x = 0;
    int content_y = 0;
    int content_w = 0;
    int content_h = 0;
    tab_view_content_bounds(tab_view, priv, &content_x, &content_y, &content_w, &content_h);
    content_x += origin_x;
    content_y += origin_y;
    video_draw_rect(content_x, content_y, content_w, content_h, theme->window_body);
    video_draw_rect_outline(origin_x, origin_y, tab_view->width, tab_view->height, theme->window_border);

    atk_widget_t *content = atk_tab_view_active_content(tab_view);
    if (content && content->used)
    {
        atk_widget_draw_any(state, content);
    }
}

void atk_tab_view_destroy(atk_widget_t *tab_view)
{
    atk_tab_view_priv_t *priv = tab_view_priv_mut(tab_view);
    if (!priv)
    {
        return;
    }
    atk_list_clear(&priv->pages, tab_view_free_page);
    priv->page_count = 0;
    priv->active_index = 0;
    priv->change = NULL;
    priv->change_context = NULL;
    priv->list_node = NULL;
}

static atk_widget_t *atk_tab_view_create(void)
{
    atk_widget_t *widget = atk_widget_create(&ATK_TAB_VIEW_CLASS);
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
    atk_widget_set_ops(widget, &g_tab_view_ops, NULL);

    atk_tab_view_priv_t *priv = tab_view_priv_mut(widget);
    if (!priv)
    {
        atk_widget_destroy(widget);
        return NULL;
    }

    atk_list_init(&priv->pages);
    priv->page_count = 0;
    priv->active_index = 0;
    priv->tab_height = ATK_FONT_HEIGHT + 10;
    priv->tab_padding = 12;
    priv->tab_spacing = 6;
    priv->content_padding = 8;
    priv->change = NULL;
    priv->change_context = NULL;
    priv->list_node = NULL;
    return widget;
}

static atk_tab_view_priv_t *tab_view_priv_mut(atk_widget_t *tab_view)
{
    if (!tab_view)
    {
        return NULL;
    }
    return (atk_tab_view_priv_t *)atk_widget_priv(tab_view, &ATK_TAB_VIEW_CLASS);
}

static const atk_tab_view_priv_t *tab_view_priv(const atk_widget_t *tab_view)
{
    if (!tab_view)
    {
        return NULL;
    }
    return (const atk_tab_view_priv_t *)atk_widget_priv(tab_view, &ATK_TAB_VIEW_CLASS);
}

static void tab_view_content_bounds(const atk_widget_t *tab_view,
                                    const atk_tab_view_priv_t *priv,
                                    int *x,
                                    int *y,
                                    int *width,
                                    int *height)
{
    if (!tab_view || !priv)
    {
        if (x) *x = 0;
        if (y) *y = 0;
        if (width) *width = 0;
        if (height) *height = 0;
        return;
    }

    int local_x = priv->content_padding;
    int local_y = priv->tab_height + priv->content_padding;
    int local_w = tab_view->width - priv->content_padding * 2;
    int local_h = tab_view->height - priv->tab_height - (priv->content_padding * 2);
    if (local_w < 0) local_w = 0;
    if (local_h < 0) local_h = 0;

    if (x) *x = local_x;
    if (y) *y = local_y;
    if (width) *width = local_w;
    if (height) *height = local_h;
}

static void tab_view_layout_pages(atk_widget_t *tab_view, atk_tab_view_priv_t *priv)
{
    if (!tab_view || !priv)
    {
        return;
    }
    int content_x = 0;
    int content_y = 0;
    int content_w = 0;
    int content_h = 0;
    tab_view_content_bounds(tab_view, priv, &content_x, &content_y, &content_w, &content_h);

    ATK_LIST_FOR_EACH(node, &priv->pages)
    {
        atk_tab_view_page_t *page = (atk_tab_view_page_t *)node->value;
        if (page && page->content)
        {
            page->content->x = content_x;
            page->content->y = content_y;
            page->content->width = content_w;
            page->content->height = content_h;
            page->content->parent = tab_view;
        }
    }
}

static int tab_view_tab_width(const atk_tab_view_priv_t *priv, const atk_tab_view_page_t *page)
{
    if (!priv || !page)
    {
        return ATK_TAB_VIEW_MIN_WIDTH;
    }
    size_t len = strlen(page->title);
    int text_width = (int)len * ATK_FONT_WIDTH;
    int width = text_width + priv->tab_padding * 2;
    if (width < ATK_TAB_VIEW_MIN_WIDTH)
    {
        width = ATK_TAB_VIEW_MIN_WIDTH;
    }
    return width;
}

static void tab_view_free_page(void *value)
{
    atk_tab_view_page_t *page = (atk_tab_view_page_t *)value;
    if (!page)
    {
        return;
    }
    if (page->content)
    {
        atk_widget_destroy_any(page->content);
        page->content = NULL;
    }
    free(page);
}

static void tab_view_invalidate(const atk_widget_t *tab_view)
{
    if (!tab_view)
    {
        return;
    }
    int x = 0;
    int y = 0;
    int w = 0;
    int h = 0;
    atk_widget_absolute_bounds(tab_view, &x, &y, &w, &h);
    atk_dirty_mark_rect(x, y, w, h);
}
