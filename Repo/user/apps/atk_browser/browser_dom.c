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

bool browser_is_gif_bytes(const uint8_t *data, size_t len)
{
    if (!data || len < 6)
    {
        return false;
    }
    return (memcmp(data, "GIF87a", 6) == 0) || (memcmp(data, "GIF89a", 6) == 0);
}

bool browser_is_svg_bytes(const uint8_t *data, size_t len)
{
    if (!data || len < 4)
    {
        return false;
    }

    size_t limit = len < 512 ? len : 512;
    for (size_t i = 0; i + 4 <= limit; ++i)
    {
        if (data[i] != '<')
        {
            continue;
        }
        size_t j = i + 1;
        while (j < limit)
        {
            char ch = (char)data[j];
            if (ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r')
            {
                ++j;
                continue;
            }
            break;
        }
        if (j + 3 <= limit)
        {
            char c1 = (char)data[j];
            char c2 = (char)data[j + 1];
            char c3 = (char)data[j + 2];
            if (c1 >= 'A' && c1 <= 'Z') c1 = (char)(c1 + 32);
            if (c2 >= 'A' && c2 <= 'Z') c2 = (char)(c2 + 32);
            if (c3 >= 'A' && c3 <= 'Z') c3 = (char)(c3 + 32);
            if (c1 == 's' && c2 == 'v' && c3 == 'g')
            {
                return true;
            }
        }
    }
    return false;
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

size_t browser_collect_resource_urls(browser_app_t *app,
                                     html_node_t *root,
                                     const browser_url_t *base_url,
                                     browser_resource_set_t *requested,
                                     browser_resource_kind_t kind,
                                     uint64_t load_id,
                                     browser_resource_queue_t *queue)
{
    if (!app || !root || !base_url || !base_url->host || !requested)
    {
        return 0;
    }

    const char *tag = NULL;
    const char *attr = NULL;
    const char *log_label = NULL;
    bool check_stylesheet = false;

    switch (kind)
    {
        case BROWSER_RESOURCE_CSS:
            tag = "link";
            attr = "href";
            log_label = "css";
            check_stylesheet = true;
            break;
        case BROWSER_RESOURCE_SCRIPT:
            tag = "script";
            attr = "src";
            log_label = "js";
            break;
        case BROWSER_RESOURCE_IMAGE:
            tag = "img";
            attr = "src";
            log_label = "img";
            break;
        default:
            return 0;
    }

    size_t count = 0;

    for (html_node_t *node = root; node;)
    {
        if (node->type == HTML_NODE_ELEMENT && node->name)
        {
            if (strcmp(node->name, tag) == 0)
            {
                if (check_stylesheet)
                {
                    const char *rel = html_attr_get(node, "rel");
                    if (!rel || !browser_has_token_ci(rel, strlen(rel), "stylesheet"))
                    {
                        goto next_node;
                    }
                }

                const char *value = html_attr_get(node, attr);
                if (value && value[0] != '\0')
                {
                    if (kind == BROWSER_RESOURCE_IMAGE &&
                        strncasecmp(value, "inline-svg:", 11) == 0)
                    {
                        goto next_node;
                    }

                    char *abs = browser_build_absolute_url(base_url, value, strlen(value));
                    if (abs)
                    {
                        browser_dom_set_attr(node, attr, abs);
                        browser_resource_track_t track = browser_resource_set_track(requested, kind, abs);
                        if (track == BROWSER_RESOURCE_TRACK_DUP)
                        {
                            browser_debug_logf(app, "[%s] skip duplicate url=%s", log_label, abs);
                            free(abs);
                        }
                        else
                        {
                            if (track == BROWSER_RESOURCE_TRACK_ERROR)
                            {
                                browser_debug_logf(app, "[%s] track failed url=%s", log_label, abs);
                            }
                            browser_debug_logf(app, "[%s] discovered %s", log_label, abs);
                            if (queue)
                            {
                                browser_resource_job_t *job = (browser_resource_job_t *)calloc(1, sizeof(*job));
                                if (!job)
                                {
                                    browser_debug_logf(app, "[%s] queue failed url=%s", log_label, abs);
                                }
                                else
                                {
                                    job->kind = kind;
                                    job->load_id = load_id;
                                    job->url = abs;
                                    if (queue->tail)
                                    {
                                        queue->tail->next = job;
                                    }
                                    else
                                    {
                                        queue->head = job;
                                    }
                                    queue->tail = job;
                                    queue->count++;
                                    abs = NULL;
                                }
                            }
                            count++;
                            if (abs)
                            {
                                free(abs);
                            }
                        }
                    }
                }
            }
        }

next_node:
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

    return count;
}
