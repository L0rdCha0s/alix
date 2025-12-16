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

/* Initialize a list to the empty state. */
void atk_list_init(atk_list_t *list);

/*
 * Remove all nodes from the list and free them.
 *
 * If `deleter` is non-NULL, it is called on each non-NULL `node->value` before
 * the node is freed.
 */
void atk_list_clear(atk_list_t *list, void (*deleter)(void *value));

/*
 * Same as `atk_list_clear()`, but with an explicit debug `tag`.
 *
 * The tag is used by corruption diagnostics to help identify call sites.
 */
void atk_list_clear_tag(atk_list_t *list, void (*deleter)(void *value), const char *tag);

#ifndef ATK_LIST_DISABLE_AUTOTAG
#undef atk_list_clear
#define atk_list_clear(list, deleter) \
    atk_list_clear_tag((list), (deleter), __func__)
#endif

/*
 * Append `value` to the end of the list.
 *
 * Returns the created node (owned by the list) or NULL on allocation failure.
 */
atk_list_node_t *atk_list_push_back(atk_list_t *list, void *value);

/*
 * Remove and free a node from the list.
 *
 * This does not free `node->value`; callers should clean up the value first if
 * required.
 */
void atk_list_remove(atk_list_t *list, atk_list_node_t *node);

/* Find the first node with `node->value == value` (pointer equality). */
atk_list_node_t *atk_list_find(const atk_list_t *list, const void *value);

/*
 * Move an existing node to the end of the list.
 *
 * Used by ATK to maintain Z-order and focus lists.
 */
void atk_list_move_to_back(atk_list_t *list, atk_list_node_t *node);

#define ATK_LIST_FOR_EACH(node_var, list_ptr) \
    for (atk_list_node_t *node_var = (list_ptr)->head; node_var; node_var = (node_var)->next)

#define ATK_LIST_FOR_EACH_REVERSE(node_var, list_ptr) \
    for (atk_list_node_t *node_var = (list_ptr)->tail; node_var; node_var = (node_var)->prev)

#endif
