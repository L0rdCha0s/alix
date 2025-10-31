#include "atk/atk_list.h"

#include <stddef.h>

#include "libc.h"

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
    if (!list)
    {
        return;
    }

    atk_list_node_t *node = list->head;
    while (node)
    {
        atk_list_node_t *next = node->next;
        if (deleter && node->value)
        {
            deleter(node->value);
        }
        free(node);
        node = next;
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
