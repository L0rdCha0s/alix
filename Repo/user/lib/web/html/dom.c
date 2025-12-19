#include "web/html/html_internal.h"

#include "libc.h"

html_node_t *html_node_create(html_node_type_t type)
{
    html_node_t *node = (html_node_t *)calloc(1, sizeof(*node));
    if (!node)
    {
        return NULL;
    }
    node->type = type;
    return node;
}

void html_attr_free_list(html_attr_t *attr)
{
    while (attr)
    {
        html_attr_t *next = attr->next;
        free(attr->name);
        free(attr->value);
        free(attr);
        attr = next;
    }
}

void html_node_append_child(html_node_t *parent, html_node_t *child)
{
    if (!parent || !child)
    {
        return;
    }
    child->parent = parent;
    child->prev_sibling = parent->last_child;
    child->next_sibling = NULL;
    if (parent->last_child)
    {
        parent->last_child->next_sibling = child;
    }
    else
    {
        parent->first_child = child;
    }
    parent->last_child = child;
}


void html_document_destroy(html_document_t *doc)
{
    if (!doc)
    {
        return;
    }

    html_node_t *root = doc->root;
    doc->root = NULL;

    typedef struct
    {
        html_node_t *node;
        bool visited;
    } free_entry_t;

    free_entry_t *stack = NULL;
    size_t count = 0;
    size_t cap = 0;

    if (root)
    {
        cap = 64;
        stack = (free_entry_t *)malloc(cap * sizeof(*stack));
        if (stack)
        {
            stack[count++] = (free_entry_t){ .node = root, .visited = false };
        }
    }

    while (count > 0)
    {
        free_entry_t entry = stack[--count];
        html_node_t *node = entry.node;
        if (!node)
        {
            continue;
        }

        if (!entry.visited)
        {
            if (count + 1 >= cap)
            {
                size_t new_cap = cap ? cap * 2u : 64u;
                free_entry_t *new_stack = (free_entry_t *)realloc(stack, new_cap * sizeof(*new_stack));
                if (!new_stack)
                {
                    break;
                }
                stack = new_stack;
                cap = new_cap;
            }
            stack[count++] = (free_entry_t){ .node = node, .visited = true };

            for (html_node_t *child = node->first_child; child; child = child->next_sibling)
            {
                if (count + 1 >= cap)
                {
                    size_t new_cap = cap ? cap * 2u : 64u;
                    free_entry_t *new_stack = (free_entry_t *)realloc(stack, new_cap * sizeof(*new_stack));
                    if (!new_stack)
                    {
                        break;
                    }
                    stack = new_stack;
                    cap = new_cap;
                }
                stack[count++] = (free_entry_t){ .node = child, .visited = false };
            }

            continue;
        }

        html_attr_free_list(node->attrs);
        free(node->name);
        free(node->text);
        free(node);
    }

    free(stack);
    free(doc);
}

const char *html_attr_get(const html_node_t *node, const char *name)
{
    if (!node || node->type != HTML_NODE_ELEMENT || !name || name[0] == '\0')
    {
        return NULL;
    }
    for (html_attr_t *attr = node->attrs; attr; attr = attr->next)
    {
        if (!attr->name)
        {
            continue;
        }
        if (strcasecmp(attr->name, name) == 0)
        {
            return attr->value ? attr->value : "";
        }
    }
    return NULL;
}
