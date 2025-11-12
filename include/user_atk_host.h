#ifndef USER_ATK_HOST_H
#define USER_ATK_HOST_H

#include "user_atk_defs.h"

struct atk_widget;
struct process;

void user_atk_init(void);
void user_atk_on_process_destroy(struct process *process);

bool user_atk_window_is_remote(const struct atk_widget *window);
bool user_atk_window_is_resizable(const struct atk_widget *window);
void user_atk_focus_window(const struct atk_widget *window);
bool user_atk_route_mouse_event(const struct atk_widget *hover_window,
                                int cursor_x,
                                int cursor_y,
                                bool pressed_edge,
                                bool released_edge,
                                bool left_pressed);
bool user_atk_route_key_event(char ch);
void user_atk_window_resized(const struct atk_widget *window);

int64_t user_atk_sys_create(const user_atk_window_desc_t *desc);
int64_t user_atk_sys_present(uint32_t handle, const uint16_t *pixels, size_t byte_len);
int64_t user_atk_sys_poll_event(uint32_t handle, user_atk_event_t *event_out, uint32_t flags);
int64_t user_atk_sys_close(uint32_t handle);

#endif /* USER_ATK_HOST_H */
