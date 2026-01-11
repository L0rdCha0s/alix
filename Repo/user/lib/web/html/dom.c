#include "web/html/html_internal.h"

#include "libc.h"

typedef struct html_arena_block
{
    struct html_arena_block *next;
    size_t used;
    size_t capacity;
    unsigned char data[];
} html_arena_block_t;

enum
{
    HTML_ARENA_BLOCK_SIZE = 32768
};

void *html_doc_alloc(html_document_t *doc, size_t size)
{
    if (!doc || size == 0)
    {
        return NULL;
    }
    size_t align = sizeof(void *);
    size_t padded = (size + align - 1u) & ~(align - 1u);

    html_arena_block_t *block = (html_arena_block_t *)doc->arena_blocks;
    if (!block || block->capacity - block->used < padded)
    {
        size_t capacity = HTML_ARENA_BLOCK_SIZE;
        if (padded > capacity)
        {
            capacity = padded;
        }
        html_arena_block_t *next = (html_arena_block_t *)malloc(sizeof(*next) + capacity);
        if (!next)
        {
            return NULL;
        }
        next->next = (html_arena_block_t *)doc->arena_blocks;
        next->used = 0;
        next->capacity = capacity;
        doc->arena_blocks = (struct html_arena_block *)next;
        block = next;
    }

    void *ptr = block->data + block->used;
    block->used += padded;
    memset(ptr, 0, size);
    return ptr;
}

html_node_t *html_node_create(html_document_t *doc, html_node_type_t type)
{
    html_node_t *node = (html_node_t *)html_doc_alloc(doc, sizeof(*node));
    if (!node)
    {
        return NULL;
    }
    node->doc = doc;
    node->type = type;
    return node;
}

void html_attr_free_list(html_document_t *doc, html_attr_t *attr)
{
    bool use_arena = doc && doc->arena_blocks;
    while (attr)
    {
        html_attr_t *next = attr->next;
        if (!use_arena)
        {
            free(attr->name);
            free(attr->value);
            free(attr);
        }
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
    bool use_arena = doc->arena_blocks != NULL;

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

        html_attr_free_list(doc, node->attrs);
        if (node->class_tokens)
        {
            if (!use_arena || node->doc == NULL)
            {
                free(node->class_tokens);
            }
            node->class_tokens = NULL;
        }
        if (!use_arena)
        {
            free(node->name);
            free(node->text);
            free(node);
        }
    }

    free(stack);
    if (use_arena)
    {
        html_arena_block_t *block = (html_arena_block_t *)doc->arena_blocks;
        while (block)
        {
            html_arena_block_t *next = block->next;
            free(block);
            block = next;
        }
        doc->arena_blocks = NULL;
    }
    free(doc);
}

const char *html_attr_get(const html_node_t *node, const char *name)
{
    if (!node || node->type != HTML_NODE_ELEMENT || !name || name[0] == '\0')
    {
        return NULL;
    }
    if (node->attr_cache && node->attr_cache->name &&
        strcasecmp(node->attr_cache->name, name) == 0)
    {
        return node->attr_cache->value ? node->attr_cache->value : "";
    }
    for (html_attr_t *attr = node->attrs; attr; attr = attr->next)
    {
        if (!attr->name)
        {
            continue;
        }
        if (strcasecmp(attr->name, name) == 0)
        {
            ((html_node_t *)node)->attr_cache = attr;
            return attr->value ? attr->value : "";
        }
    }
    return NULL;
}
