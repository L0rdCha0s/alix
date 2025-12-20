#ifndef ATK_TREE_VIEW_H
#define ATK_TREE_VIEW_H

#include "atk/object.h"

#ifdef __cplusplus
extern "C" {
#endif

struct atk_state;

#define ATK_TREE_VIEW_LABEL_MAX 64

typedef struct atk_tree_node atk_tree_node_t;

typedef void (*atk_tree_view_select_t)(atk_widget_t *tree, void *context, atk_tree_node_t *node);
typedef bool (*atk_tree_view_lazy_load_t)(atk_widget_t *tree, void *context, atk_tree_node_t *node);
typedef void (*atk_tree_view_node_destroy_t)(atk_widget_t *tree, void *context, atk_tree_node_t *node);

/* Create a standalone tree view widget. */
atk_widget_t *atk_tree_view_create(void);

/* Create a tree view widget as a child of `window`. */
atk_widget_t *atk_window_add_tree_view(atk_widget_t *window, int x, int y, int width, int height);

/* Remove all nodes from the tree view. */
void atk_tree_view_clear(atk_widget_t *tree);

/* Add a new root node. */
atk_tree_node_t *atk_tree_view_add_root(atk_widget_t *tree, const char *label, void *user);

/* Add a child node under `parent`. */
atk_tree_node_t *atk_tree_view_add_child(atk_widget_t *tree, atk_tree_node_t *parent, const char *label, void *user);

/* Accessors for node label and user data. */
const char *atk_tree_view_node_label(const atk_tree_node_t *node);
void atk_tree_view_set_node_label(atk_tree_node_t *node, const char *label);
void *atk_tree_view_node_user(const atk_tree_node_t *node);
void atk_tree_view_set_node_user(atk_tree_node_t *node, void *user);

/* Node hierarchy helpers. */
atk_tree_node_t *atk_tree_view_node_parent(const atk_tree_node_t *node);
atk_tree_node_t *atk_tree_view_node_find_child(const atk_tree_node_t *parent, const char *label);

/* Expand/collapse flags. */
bool atk_tree_view_node_expandable(const atk_tree_node_t *node);
void atk_tree_view_set_node_expandable(atk_tree_node_t *node, bool expandable);
bool atk_tree_view_node_expanded(const atk_tree_node_t *node);
void atk_tree_view_set_node_expanded(atk_widget_t *tree, atk_tree_node_t *node, bool expanded);

/* Selection helpers. */
void atk_tree_view_set_selected(atk_widget_t *tree, atk_tree_node_t *node);
atk_tree_node_t *atk_tree_view_selected(const atk_widget_t *tree);

/* Register callbacks for selection and lazy-loading. */
void atk_tree_view_set_select_handler(atk_widget_t *tree, atk_tree_view_select_t handler, void *context);
void atk_tree_view_set_lazy_load_handler(atk_widget_t *tree, atk_tree_view_lazy_load_t handler, void *context);
void atk_tree_view_set_node_destroy_handler(atk_widget_t *tree, atk_tree_view_node_destroy_t handler, void *context);

/* Recompute layout after size or content changes. */
void atk_tree_view_relayout(atk_widget_t *tree);

/* Draw/destroy helpers. */
void atk_tree_view_draw(const struct atk_state *state, const atk_widget_t *tree);
void atk_tree_view_destroy(atk_widget_t *tree);

extern const atk_class_t ATK_TREE_VIEW_CLASS;

#ifdef __cplusplus
}
#endif

#endif
