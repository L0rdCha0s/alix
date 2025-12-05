#ifndef ATK_RICH_TEXT_H
#define ATK_RICH_TEXT_H

#include "atk/object.h"

#ifdef __cplusplus
extern "C" {
#endif

struct atk_state;

typedef void (*atk_rich_text_change_t)(atk_widget_t *editor, void *context);

atk_widget_t *atk_window_add_rich_text(atk_widget_t *window, int x, int y, int width, int height);
void atk_rich_text_focus(struct atk_state *state, atk_widget_t *editor);
void atk_rich_text_set_font_size(atk_widget_t *editor, int size_px);
int atk_rich_text_current_font_size(const atk_widget_t *editor);
void atk_rich_text_set_text(atk_widget_t *editor, const char *text);
void atk_rich_text_append(atk_widget_t *editor, const char *text);
void atk_rich_text_scroll_to_top(atk_widget_t *editor);
void atk_rich_text_scroll_to_bottom(atk_widget_t *editor);
void atk_rich_text_set_change_handler(atk_widget_t *editor, atk_rich_text_change_t handler, void *context);

#ifdef __cplusplus
}
#endif

#endif
