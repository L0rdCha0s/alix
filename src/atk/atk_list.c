#define ATK_LIST_DISABLE_AUTOTAG
#include "atk/atk_list.h"
#undef ATK_LIST_DISABLE_AUTOTAG

#include <stddef.h>

#include "libc.h"
#include "serial.h"

static bool atk_list_pointer_is_canonical(const void *ptr)
{
    if (!ptr)
    {
        return true;
    }

    uint64_t value = (uint64_t)(uintptr_t)ptr;
    uint64_t top = value >> 47;
    return (top == 0u) || (top == 0x1FFFFu);
}

static void atk_list_log_corruption(const char *what, const void *ptr, const char *tag)
{
    serial_printf("%s", "atk_list");
    if (tag)
    {
        serial_printf("%s", "[");
        serial_printf("%s", tag);
        serial_printf("%s", "]");
    }
    serial_printf("%s", ": corrupted pointer (");
    serial_printf("%s", what ? what : "ptr");
    serial_printf("%s", ")=0x");
    serial_printf("%016llX", (unsigned long long)((uint64_t)(uintptr_t)ptr));
    serial_printf("%s", "\r\n");
}

void atk_list_init(atk_list_t *list)
{
    if (!list)
    {
        return;
    }
    list->head = NULL;
    list->tail = NULL;
    list->size = 0;
}

void atk_list_clear(atk_list_t *list, void (*deleter)(void *value))
{
    atk_list_clear_tag(list, deleter, NULL);
}

void atk_list_clear_tag(atk_list_t *list, void (*deleter)(void *value), const char *tag)
{
    if (!list)
    {
        return;
    }

    atk_list_node_t *node = list->head;
    size_t guard = 0;
    const size_t guard_limit = 4096;

    while (node)
    {
        if (!atk_list_pointer_is_canonical(node))
        {
            atk_list_log_corruption("node", node, tag);
            break;
        }

        atk_list_node_t *next = node->next;
        if (next && !atk_list_pointer_is_canonical(next))
        {
            atk_list_log_corruption("next", next, tag);
            next = NULL;
        }

        if (deleter && node->value)
        {
            deleter(node->value);
        }
        free(node);
        node = next;

        guard++;
        if (guard > guard_limit)
        {
            atk_list_log_corruption("guard", (void *)(uintptr_t)guard, tag);
            break;
        }
    }

    list->head = NULL;
    list->tail = NULL;
    list->size = 0;
}

atk_list_node_t *atk_list_push_back(atk_list_t *list, void *value)
{
    if (!list)
    {
        return NULL;
    }

    atk_list_node_t *node = (atk_list_node_t *)malloc(sizeof(atk_list_node_t));
    if (!node)
    {
        return NULL;
    }

    node->value = value;
    node->next = NULL;
    node->prev = list->tail;

    if (list->tail)
    {
        list->tail->next = node;
    }
    else
    {
        list->head = node;
    }

    list->tail = node;
    list->size++;
    return node;
}

void atk_list_remove(atk_list_t *list, atk_list_node_t *node)
{
    if (!list || !node)
    {
        return;
    }

    if (node->prev)
    {
        node->prev->next = node->next;
    }
    else
    {
        list->head = node->next;
    }

    if (node->next)
    {
        node->next->prev = node->prev;
    }
    else
    {
        list->tail = node->prev;
    }

    if (list->size > 0)
    {
        list->size--;
    }

    free(node);
}

atk_list_node_t *atk_list_find(const atk_list_t *list, const void *value)
{
    if (!list)
    {
        return NULL;
    }

    for (atk_list_node_t *node = list->head; node; node = node->next)
    {
        if (node->value == value)
        {
            return node;
        }
    }
    return NULL;
}

void atk_list_move_to_back(atk_list_t *list, atk_list_node_t *node)
{
    if (!list || !node || list->tail == node)
    {
        return;
    }

    if (node->prev)
    {
        node->prev->next = node->next;
    }
    else
    {
        list->head = node->next;
    }

    if (node->next)
    {
        node->next->prev = node->prev;
    }
    else
    {
        list->tail = node->prev;
    }

    node->prev = list->tail;
    node->next = NULL;

    if (list->tail)
    {
        list->tail->next = node;
    }
    else
    {
        list->head = node;
    }

    list->tail = node;
}
