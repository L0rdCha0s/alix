#include "browser_internal.h"

#include "string.h"
#include "web/url.h"

const html_node_t *browser_dom_find_first_element(const html_node_t *root, const char *tag)
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

const char *browser_dom_first_text_child(const html_node_t *node)
{
    if (!node)
    {
        return NULL;
    }
    for (const html_node_t *child = node->first_child; child; child = child->next_sibling)
    {
        if (child->type == HTML_NODE_TEXT && child->text && child->text[0] != '\0')
        {
            return child->text;
        }
    }
    return NULL;
}

size_t browser_dom_count_nodes(const html_node_t *root, size_t limit)
{
    if (!root)
    {
        return 0;
    }
    if (limit == 0)
    {
        limit = 1;
    }

    const html_node_t *stack[128];
    size_t sp = 0;
    stack[sp++] = root;
    size_t count = 0;

    while (sp > 0 && count < limit)
    {
        const html_node_t *node = stack[--sp];
        count++;
        for (const html_node_t *child = node->last_child; child; child = child->prev_sibling)
        {
            if (sp < sizeof(stack) / sizeof(stack[0]))
            {
                stack[sp++] = child;
            }
        }
    }
    return count;
}

bool browser_is_png_bytes(const uint8_t *data, size_t len)
{
    static const uint8_t signature[8] = {0x89u, 0x50u, 0x4Eu, 0x47u, 0x0Du, 0x0Au, 0x1Au, 0x0Au};
    if (!data || len < sizeof(signature))
    {
        return false;
    }
    return memcmp(data, signature, sizeof(signature)) == 0;
}

void browser_dom_set_attr(html_node_t *node, const char *name, const char *value)
{
    if (!node || node->type != HTML_NODE_ELEMENT || !name || name[0] == '\0' || !value)
    {
        return;
    }

    for (html_attr_t *attr = node->attrs; attr; attr = attr->next)
    {
        if (!attr->name)
        {
            continue;
        }
        if (strcasecmp(attr->name, name) != 0)
        {
            continue;
        }

        char *copy = browser_strdup(value);
        if (!copy)
        {
            return;
        }
        free(attr->value);
        attr->value = copy;
        return;
    }

    html_attr_t *attr = (html_attr_t *)calloc(1, sizeof(*attr));
    if (!attr)
    {
        return;
    }
    attr->name = browser_strdup(name);
    attr->value = browser_strdup(value);
    if (!attr->name || !attr->value)
    {
        free(attr->name);
        free(attr->value);
        free(attr);
        return;
    }
    attr->next = node->attrs;
    node->attrs = attr;
}

void browser_collect_resource_urls(browser_app_t *app,
                                  html_node_t *root,
                                  const browser_url_t *base_url,
                                  char **css_urls,
                                  size_t *css_count_io,
                                  char **img_urls,
                                  size_t *img_count_io,
                                  char **script_urls,
                                  size_t *script_count_io)
{
    if (!app || !root || !base_url || !base_url->host || !css_urls || !css_count_io ||
        !img_urls || !img_count_io || !script_urls || !script_count_io)
    {
        return;
    }

    size_t css_count = 0;
    size_t img_count = 0;
    size_t script_count = 0;

    for (html_node_t *node = root; node;)
    {
        if (node->type == HTML_NODE_ELEMENT && node->name)
        {
            if (css_count < BROWSER_MAX_STYLESHEETS && strcmp(node->name, "link") == 0)
            {
                const char *rel = html_attr_get(node, "rel");
                if (rel && browser_has_token_ci(rel, strlen(rel), "stylesheet"))
                {
                    const char *href = html_attr_get(node, "href");
                    if (href && href[0] != '\0')
                    {
                        char *abs = browser_build_absolute_url(base_url, href, strlen(href));
                        if (abs)
                        {
                            browser_dom_set_attr(node, "href", abs);
                            css_urls[css_count++] = abs;
                            browser_debug_logf(app, "[css] discovered %s", abs);
                        }
                    }
                }
            }
            else if (img_count < BROWSER_MAX_IMAGES && strcmp(node->name, "img") == 0)
            {
                const char *src = html_attr_get(node, "src");
                if (src && src[0] != '\0')
                {
                    char *abs = browser_build_absolute_url(base_url, src, strlen(src));
                    if (abs)
                    {
                        browser_dom_set_attr(node, "src", abs);
                        if (!web_url_is_svg(abs))
                        {
                            img_urls[img_count++] = abs;
                            browser_debug_logf(app, "[img] discovered %s", abs);
                        }
                        else
                        {
                            browser_debug_logf(app, "[img] skipped svg %s", abs);
                            free(abs);
                        }
                    }
                }
            }
            else if (script_count < BROWSER_MAX_SCRIPTS && strcmp(node->name, "script") == 0)
            {
                const char *src = html_attr_get(node, "src");
                if (src && src[0] != '\0')
                {
                    char *abs = browser_build_absolute_url(base_url, src, strlen(src));
                    if (abs)
                    {
                        browser_dom_set_attr(node, "src", abs);
                        script_urls[script_count++] = abs;
                        browser_debug_logf(app, "[js] discovered %s", abs);
                    }
                }
            }
        }

        if (node->first_child)
        {
            node = node->first_child;
            continue;
        }
        while (node && !node->next_sibling)
        {
            node = node->parent;
        }
        if (node)
        {
            node = node->next_sibling;
        }
    }

    *css_count_io = css_count;
    *img_count_io = img_count;
    *script_count_io = script_count;
    if (css_count > 0)
    {
        browser_debug_logf(app, "[css] total stylesheets=%u", (unsigned)css_count);
    }
    if (img_count > 0)
    {
        browser_debug_logf(app, "[img] total images=%u", (unsigned)img_count);
    }
    if (script_count > 0)
    {
        browser_debug_logf(app, "[js] total scripts=%u", (unsigned)script_count);
    }
}
