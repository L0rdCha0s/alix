#ifndef ATK_WINDOW_H
#define ATK_WINDOW_H

#include "atk_button.h"

void atk_window_reset_all(atk_state_t *state);
void atk_window_draw_all(const atk_state_t *state, const atk_rect_t *clip);
void atk_window_draw(atk_state_t *state, atk_widget_t *window);
void atk_window_draw_from(atk_state_t *state, atk_widget_t *start_window);
bool atk_window_contains(const atk_state_t *state, const atk_widget_t *window);
bool atk_window_is_topmost(const atk_state_t *state, const atk_widget_t *window);
bool atk_window_bring_to_front(atk_state_t *state, atk_widget_t *window);
atk_widget_t *atk_window_hit_test(const atk_state_t *state, int x, int y);
atk_widget_t *atk_window_title_hit_test(const atk_state_t *state, int x, int y);
atk_widget_t *atk_window_get_button_at(atk_widget_t *window, int px, int py);
void atk_window_mark_dirty(const atk_widget_t *window);
void atk_window_ensure_inside(atk_widget_t *window);
atk_widget_t *atk_window_create_at(atk_state_t *state, int x, int y);
void atk_window_close(atk_state_t *state, atk_widget_t *window);
const char *atk_window_title(const atk_widget_t *window);
void atk_window_set_title_text(atk_widget_t *window, const char *title);
atk_widget_t *atk_window_text_input_at(atk_widget_t *window, int px, int py);
atk_widget_t *atk_window_terminal_at(atk_widget_t *window, int px, int py);
atk_widget_t *atk_window_scrollbar_at(atk_widget_t *window, int px, int py);
atk_widget_t *atk_window_tab_view_at(atk_widget_t *window, int px, int py);
void atk_window_set_context(atk_widget_t *window, void *context, void (*on_destroy)(void *context));
void *atk_window_context(const atk_widget_t *window);
void atk_window_set_chrome_visible(atk_widget_t *window, bool visible);
bool atk_window_is_chrome_visible(const atk_widget_t *window);

#endif
