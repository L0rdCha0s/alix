#ifndef ATK_DROPDOWN_H
#define ATK_DROPDOWN_H

#include "atk/object.h"
#include "types.h"
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum
{
    ATK_DROPDOWN_STYLE_COMBO = 0,
    ATK_DROPDOWN_STYLE_MENU = 1,
} atk_dropdown_style_t;

typedef void (*atk_dropdown_select_t)(atk_widget_t *dropdown,
                                      void *context,
                                      size_t index,
                                      uintptr_t value);

atk_widget_t *atk_window_add_dropdown(atk_widget_t *window,
                                      int x,
                                      int y,
                                      int width,
                                      int height,
                                      atk_dropdown_style_t style,
                                      atk_dropdown_select_t on_select,
                                      void *context);

void atk_dropdown_clear(atk_widget_t *dropdown);
bool atk_dropdown_add_item(atk_widget_t *dropdown, const char *title, uintptr_t value);
size_t atk_dropdown_count(const atk_widget_t *dropdown);

void atk_dropdown_set_title(atk_widget_t *dropdown, const char *title);
const char *atk_dropdown_title(const atk_widget_t *dropdown);

bool atk_dropdown_set_selected(atk_widget_t *dropdown, size_t index);
size_t atk_dropdown_selected(const atk_widget_t *dropdown);
uintptr_t atk_dropdown_selected_value(const atk_widget_t *dropdown);
const char *atk_dropdown_selected_title(const atk_widget_t *dropdown);

bool atk_dropdown_is_open(const atk_widget_t *dropdown);
void atk_dropdown_set_open(atk_widget_t *dropdown, bool open);

#ifdef __cplusplus
}
#endif

#endif

