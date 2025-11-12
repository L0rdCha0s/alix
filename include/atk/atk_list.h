#ifndef ATK_LIST_H
#define ATK_LIST_H

#include "types.h"

typedef struct atk_list_node
{
    struct atk_list_node *prev;
    struct atk_list_node *next;
    void *value;
} atk_list_node_t;

typedef struct
{
    atk_list_node_t *head;
    atk_list_node_t *tail;
    size_t size;
} atk_list_t;

void atk_list_init(atk_list_t *list);
void atk_list_clear(atk_list_t *list, void (*deleter)(void *value));
void atk_list_clear_tag(atk_list_t *list, void (*deleter)(void *value), const char *tag);

#ifndef ATK_LIST_DISABLE_AUTOTAG
#undef atk_list_clear
#define atk_list_clear(list, deleter) \
    atk_list_clear_tag((list), (deleter), __func__)
#endif
atk_list_node_t *atk_list_push_back(atk_list_t *list, void *value);
void atk_list_remove(atk_list_t *list, atk_list_node_t *node);
atk_list_node_t *atk_list_find(const atk_list_t *list, const void *value);
void atk_list_move_to_back(atk_list_t *list, atk_list_node_t *node);

#define ATK_LIST_FOR_EACH(node_var, list_ptr) \
    for (atk_list_node_t *node_var = (list_ptr)->head; node_var; node_var = (node_var)->next)

#define ATK_LIST_FOR_EACH_REVERSE(node_var, list_ptr) \
    for (atk_list_node_t *node_var = (list_ptr)->tail; node_var; node_var = (node_var)->prev)

#endif
