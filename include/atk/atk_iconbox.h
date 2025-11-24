#ifndef ATK_ICONBOX_H
#define ATK_ICONBOX_H

#include "atk_button.h"

#ifdef __cplusplus
extern "C" {
#endif

struct atk_state;

atk_widget_t *atk_window_add_iconbox(atk_widget_t *window, int x, int y, int width, int height);
bool atk_iconbox_add_icon(atk_widget_t *iconbox, const char *title, atk_button_action_t action, void *context);
void atk_iconbox_clear(atk_widget_t *iconbox);
void atk_iconbox_relayout(atk_widget_t *iconbox);
size_t atk_iconbox_count(const atk_widget_t *iconbox);

extern const atk_class_t ATK_ICONBOX_CLASS;

#ifdef __cplusplus
}
#endif

#endif
