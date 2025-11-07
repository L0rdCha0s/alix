#ifndef ATK_SCROLLBAR_H
#define ATK_SCROLLBAR_H

#include "atk/object.h"

#ifdef __cplusplus
extern "C" {
#endif

struct atk_state;

typedef enum
{
    ATK_SCROLLBAR_VERTICAL = 0,
    ATK_SCROLLBAR_HORIZONTAL = 1
} atk_scrollbar_orientation_t;

typedef void (*atk_scrollbar_change_t)(atk_widget_t *scrollbar, void *context, int value);

atk_widget_t *atk_window_add_scrollbar(atk_widget_t *window,
                                       int x,
                                       int y,
                                       int width,
                                       int height,
                                       atk_scrollbar_orientation_t orientation);

void atk_scrollbar_set_change_handler(atk_widget_t *scrollbar, atk_scrollbar_change_t handler, void *context);
void atk_scrollbar_set_range(atk_widget_t *scrollbar, int min_value, int max_value, int page_size);
void atk_scrollbar_set_value(atk_widget_t *scrollbar, int value);
int atk_scrollbar_value(const atk_widget_t *scrollbar);
bool atk_scrollbar_hit_test(const atk_widget_t *scrollbar, int origin_x, int origin_y, int px, int py);
bool atk_scrollbar_begin_drag(atk_widget_t *scrollbar, int px, int py, bool *value_changed);
bool atk_scrollbar_drag_to(atk_widget_t *scrollbar, int px, int py);
void atk_scrollbar_end_drag(atk_widget_t *scrollbar);
void atk_scrollbar_mark_dirty(const atk_widget_t *scrollbar);
void atk_scrollbar_draw(const struct atk_state *state, const atk_widget_t *scrollbar);
void atk_scrollbar_destroy(atk_widget_t *scrollbar);

extern const atk_class_t ATK_SCROLLBAR_CLASS;

#ifdef __cplusplus
}
#endif

#endif
