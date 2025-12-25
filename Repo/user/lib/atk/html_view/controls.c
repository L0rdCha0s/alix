#include "atk/html_view/html_view_internal.h"
#include "atk/atk_dropdown.h"

typedef struct html_view_radio_group
{
    char *name;
    atk_radio_group_t *group;
    struct html_view_radio_group *next;
} html_view_radio_group_t;

static html_view_control_t *html_view_control_find_by_widget(atk_html_view_priv_t *priv,
                                                             const atk_widget_t *widget)
{
    if (!priv || !widget)
    {
        return NULL;
    }
    for (html_view_control_t *ctrl = priv->controls; ctrl; ctrl = ctrl->next)
    {
        if (ctrl->widget == widget)
        {
            return ctrl;
        }
    }
    return NULL;
}

static void html_view_controls_button_action(atk_widget_t *widget, void *context)
{
    atk_widget_t *view = (atk_widget_t *)context;
    if (!view || !widget)
    {
        return;
    }
    atk_html_view_priv_t *priv = html_view_priv_mut(view);
    if (!priv)
    {
        return;
    }
    html_view_control_t *ctrl = html_view_control_find_by_widget(priv, widget);
    if (!ctrl || !ctrl->node)
    {
        return;
    }
    html_view_js_dispatch_click(view, ctrl->node);
}

static atk_radio_group_t *html_view_radio_group_get(html_view_radio_group_t **head, const char *name)
{
    if (!head)
    {
        return NULL;
    }
    const char *key = (name && name[0] != '\0') ? name : NULL;
    if (!key)
    {
        return NULL;
    }
    for (html_view_radio_group_t *g = *head; g; g = g->next)
    {
        if (g->name && key && strcmp(g->name, key) == 0)
        {
            return g->group;
        }
    }

    atk_radio_group_t *group = atk_radio_group_create();
    if (!group)
    {
        return NULL;
    }

    html_view_radio_group_t *entry = (html_view_radio_group_t *)calloc(1, sizeof(*entry));
    if (!entry)
    {
        atk_radio_group_destroy(group);
        return NULL;
    }
    entry->group = group;
    entry->name = key ? html_view_strdup(key) : NULL;
    entry->next = *head;
    *head = entry;
    return group;
}

static void html_view_radio_groups_free(html_view_radio_group_t *head)
{
    html_view_radio_group_t *g = head;
    while (g)
    {
        html_view_radio_group_t *next = g->next;
        free(g->name);
        /* group lifetime is managed by radio widgets; do not destroy here */
        free(g);
        g = next;
    }
}

static bool html_view_controls_add(atk_html_view_priv_t *priv,
                                  const html_node_t *node,
                                  atk_widget_t *widget,
                                  html_view_control_kind_t kind)
{
    if (!priv || !node || !widget)
    {
        return false;
    }

    html_view_control_t *ctrl = (html_view_control_t *)calloc(1, sizeof(*ctrl));
    if (!ctrl)
    {
        return false;
    }
    ctrl->node = node;
    ctrl->widget = widget;
    ctrl->kind = kind;
    ctrl->next = priv->controls;
    priv->controls = ctrl;
    return true;
}

static void html_view_controls_build_node(atk_widget_t *view,
                                         atk_html_view_priv_t *priv,
                                         const html_node_t *node,
                                         html_view_radio_group_t **radio_groups)
{
    if (!view || !priv || !node)
    {
        return;
    }

    const html_node_t **stack = NULL;
    size_t stack_cap = 0;
    size_t sp = 0;

    const html_node_t *cur = node;
    while (cur)
    {
        if (cur->type == HTML_NODE_ELEMENT && cur->name)
        {
            if (strcmp(cur->name, "input") == 0)
            {
                const char *type = html_attr_get(cur, "type");
                if (!type || type[0] == '\0')
                {
                    type = "text";
                }

                atk_widget_t *w = NULL;
                if (strcasecmp(type, "hidden") == 0)
                {
                    /* Hidden inputs are non-rendered form state. */
                }
                else if (strcasecmp(type, "checkbox") == 0)
                {
                    w = atk_window_add_checkbox(view->parent, "", 0, 0, 24);
                    if (w)
                    {
                        w->used = false;
                        if (html_attr_get(cur, "checked"))
                        {
                            atk_checkbox_set_checked(w, true);
                        }
                        if (!html_view_controls_add(priv, cur, w, HTML_VIEW_CONTROL_CHECKBOX))
                        {
                            html_view_window_remove_widget(view->parent, w);
                        }
                    }
                }
                else if (strcasecmp(type, "radio") == 0)
                {
                    const char *name = html_attr_get(cur, "name");
                    bool ephemeral_group = !(name && name[0] != '\0');
                    atk_radio_group_t *group = ephemeral_group ? atk_radio_group_create()
                                                               : html_view_radio_group_get(radio_groups, name);
                    if (group)
                    {
                        w = atk_window_add_radio_button(view->parent, group, "", 0, 0, 24);
                        if (w)
                        {
                            w->used = false;
                            if (html_attr_get(cur, "checked"))
                            {
                                atk_radio_button_set_selected(w, true);
                            }
                            if (!html_view_controls_add(priv, cur, w, HTML_VIEW_CONTROL_RADIO))
                            {
                                html_view_window_remove_widget(view->parent, w);
                            }
                        }
                        else if (ephemeral_group)
                        {
                            atk_radio_group_destroy(group);
                        }
                    }
                }
                else if (strcasecmp(type, "submit") == 0 ||
                         strcasecmp(type, "button") == 0 ||
                         strcasecmp(type, "reset") == 0)
                {
                    const char *value = html_attr_get(cur, "value");
                    const char *label = (value && value[0] != '\0') ? value :
                                        (strcasecmp(type, "reset") == 0) ? "Reset" :
                                        (strcasecmp(type, "button") == 0) ? "Button" :
                                                                           "Submit";

                    int btn_w = atk_font_text_width(label) + 20;
                    if (btn_w < 80) btn_w = 80;
                    int btn_h = atk_font_line_height() + 8;

                    w = atk_window_add_button(view->parent,
                                              label,
                                              0,
                                              0,
                                              btn_w,
                                              btn_h,
                                              ATK_BUTTON_STYLE_TITLE_INSIDE,
                                              false,
                                              html_view_controls_button_action,
                                              view);
                    if (w)
                    {
                        w->used = false;
                        if (!html_view_controls_add(priv, cur, w, HTML_VIEW_CONTROL_BUTTON))
                        {
                            html_view_window_remove_widget(view->parent, w);
                        }
                    }
                }
                else
                {
                    w = atk_window_add_text_input(view->parent, 0, 0, 200);
                    if (w)
                    {
                        w->used = false;
                        const char *value = html_attr_get(cur, "value");
                        if (value && value[0] != '\0')
                        {
                            atk_text_input_set_text(w, value);
                        }
                        if (!html_view_controls_add(priv, cur, w, HTML_VIEW_CONTROL_INPUT_TEXT))
                        {
                            html_view_window_remove_widget(view->parent, w);
                        }
                    }
                }
            }
            else if (strcmp(cur->name, "select") == 0)
            {
                int height = atk_font_line_height() + 8;
                atk_widget_t *w = atk_window_add_dropdown(view->parent,
                                                          0,
                                                          0,
                                                          160,
                                                          height,
                                                          ATK_DROPDOWN_STYLE_COMBO,
                                                          NULL,
                                                          NULL);
                if (w)
                {
                    w->used = false;
                    size_t option_index = 0;
                    size_t selected_index = (size_t)-1;
                    for (const html_node_t *opt = cur->first_child; opt; opt = opt->next_sibling)
                    {
                        if (opt->type != HTML_NODE_ELEMENT || !opt->name || strcmp(opt->name, "option") != 0)
                        {
                            continue;
                        }
                        char *label = NULL;
                        size_t label_len = 0;
                        size_t label_cap = 0;
                        html_view_collect_text(opt, &label, &label_len, &label_cap);
                        if (label)
                        {
                            html_view_trim_collapse_ws(label);
                        }

                        const char *value = html_attr_get(opt, "value");
                        const char *title = (label && label[0] != '\0') ? label :
                                            (value && value[0] != '\0') ? value : "Option";
                        if (atk_dropdown_add_item(w, title, (uintptr_t)option_index))
                        {
                            if (html_attr_get(opt, "selected"))
                            {
                                selected_index = option_index;
                            }
                            option_index++;
                        }
                        free(label);
                    }

                    if (option_index > 0)
                    {
                        size_t use_index = (selected_index != (size_t)-1) ? selected_index : 0;
                        (void)atk_dropdown_set_selected(w, use_index);
                    }

                    if (!html_view_controls_add(priv, cur, w, HTML_VIEW_CONTROL_SELECT))
                    {
                        html_view_window_remove_widget(view->parent, w);
                    }
                }
            }
            else if (strcmp(cur->name, "textarea") == 0)
            {
                atk_widget_t *w = atk_window_add_text_input(view->parent, 0, 0, 280);
                if (w)
                {
                    w->used = false;
                    atk_text_input_set_multiline(w, true);
                    char *text = NULL;
                    size_t text_len = 0;
                    size_t text_cap = 0;
                    html_view_collect_text(cur, &text, &text_len, &text_cap);
                    if (text)
                    {
                        atk_text_input_set_text(w, text);
                    }
                    free(text);
                    if (!html_view_controls_add(priv, cur, w, HTML_VIEW_CONTROL_TEXTAREA))
                    {
                        html_view_window_remove_widget(view->parent, w);
                    }
                }
            }
            else if (strcmp(cur->name, "button") == 0)
            {
                char *label = NULL;
                size_t label_len = 0;
                size_t label_cap = 0;
                html_view_collect_text(cur, &label, &label_len, &label_cap);
                if (!label)
                {
                    label = html_view_strdup("Button");
                }
                if (label)
                {
                    html_view_trim_collapse_ws(label);
                }

                int btn_w = 100;
                if (label && label[0] != '\0')
                {
                    btn_w = atk_font_text_width(label) + 20;
                    if (btn_w < 80) btn_w = 80;
                }
                int btn_h = atk_font_line_height() + 8;

                atk_widget_t *w = atk_window_add_button(view->parent,
                                                        (label && label[0] != '\0') ? label : "Button",
                                                        0,
                                                        0,
                                                        btn_w,
                                                        btn_h,
                                                        ATK_BUTTON_STYLE_TITLE_INSIDE,
                                                        false,
                                                        html_view_controls_button_action,
                                                        view);
                free(label);
                if (w)
                {
                    w->used = false;
                    if (!html_view_controls_add(priv, cur, w, HTML_VIEW_CONTROL_BUTTON))
                    {
                        html_view_window_remove_widget(view->parent, w);
                    }
                }
            }
        }

        if (cur->first_child)
        {
            if (cur->next_sibling)
            {
                if (sp == stack_cap)
                {
                    size_t new_cap = stack_cap ? (stack_cap * 2) : 64;
                    const html_node_t **new_stack = (const html_node_t **)realloc(stack, new_cap * sizeof(*new_stack));
                    if (!new_stack)
                    {
                        break;
                    }
                    stack = new_stack;
                    stack_cap = new_cap;
                }
                stack[sp++] = cur->next_sibling;
            }
            cur = cur->first_child;
            continue;
        }

        if (cur->next_sibling)
        {
            cur = cur->next_sibling;
            continue;
        }
        if (sp > 0)
        {
            cur = stack[--sp];
            continue;
        }
        break;
    }

    free(stack);
}

void html_view_controls_build(atk_widget_t *view, atk_html_view_priv_t *priv)
{
    if (!view || !priv || !priv->doc || !priv->doc->root)
    {
        return;
    }

    html_view_radio_group_t *radio_groups = NULL;
    html_view_controls_build_node(view, priv, priv->doc->root, &radio_groups);
    html_view_radio_groups_free(radio_groups);
}

html_view_image_t *html_view_image_find(atk_html_view_priv_t *priv, const char *src)
{
    if (!priv || !src || src[0] == '\0')
    {
        return NULL;
    }
    for (html_view_image_t *img = priv->images; img; img = img->next)
    {
        if (!img->src)
        {
            continue;
        }
        if (strcmp(img->src, src) == 0)
        {
            return img;
        }
    }
    return NULL;
}

static void html_view_collect_style_text(const html_node_t *node, char **buf, size_t *len, size_t *cap)
{
    if (!node || !buf || !len || !cap)
    {
        return;
    }

    const html_node_t **stack = NULL;
    size_t stack_cap = 0;
    size_t sp = 0;

    const html_node_t *cur = node->first_child;
    while (cur)
    {
        bool descend = cur->first_child != NULL;
        if (cur->type == HTML_NODE_ELEMENT && cur->name && strcmp(cur->name, "style") == 0)
        {
            for (const html_node_t *txt = cur->first_child; txt; txt = txt->next_sibling)
            {
                if (txt->type == HTML_NODE_TEXT && txt->text)
                {
                    (void)html_view_buf_append(buf, len, cap, txt->text, strlen(txt->text));
                    (void)html_view_buf_append(buf, len, cap, "\n", 1);
                }
            }
            descend = false;
        }

        if (descend)
        {
            if (cur->next_sibling)
            {
                if (sp == stack_cap)
                {
                    size_t new_cap = stack_cap ? (stack_cap * 2) : 64;
                    const html_node_t **new_stack = (const html_node_t **)realloc(stack, new_cap * sizeof(*new_stack));
                    if (!new_stack)
                    {
                        break;
                    }
                    stack = new_stack;
                    stack_cap = new_cap;
                }
                stack[sp++] = cur->next_sibling;
            }
            cur = cur->first_child;
            continue;
        }

        if (cur->next_sibling)
        {
            cur = cur->next_sibling;
            continue;
        }
        if (sp > 0)
        {
            cur = stack[--sp];
            continue;
        }
        break;
    }

    free(stack);
}

void html_view_rebuild_stylesheet(atk_html_view_priv_t *priv)
{
    if (!priv)
    {
        return;
    }
    if (priv->sheet)
    {
        css_stylesheet_destroy(priv->sheet);
        priv->sheet = NULL;
    }
    if (!priv->doc || !priv->doc->root)
    {
        return;
    }

    char *css_text = NULL;
    size_t css_len = 0;
    size_t css_cap = 0;
    html_view_collect_style_text(priv->doc->root, &css_text, &css_len, &css_cap);

    if (priv->external_css && priv->external_css_len > 0)
    {
        if (css_len > 0)
        {
            (void)html_view_buf_append(&css_text, &css_len, &css_cap, "\n", 1);
        }
        (void)html_view_buf_append(&css_text,
                                   &css_len,
                                   &css_cap,
                                   priv->external_css,
                                   priv->external_css_len);
    }

    if (!css_text || css_len == 0)
    {
        free(css_text);
        return;
    }

    priv->sheet = css_parse(css_text);
    free(css_text);
}

const html_node_t *html_view_find_first_element(const html_node_t *root, const char *tag)
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

        for (const html_node_t *child = node->first_child; child; child = child->next_sibling)
        {
            if (sp < (sizeof(stack) / sizeof(stack[0])))
            {
                stack[sp++] = child;
            }
        }
    }

    return NULL;
}
