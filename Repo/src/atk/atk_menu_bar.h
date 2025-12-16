#ifndef ATK_MENU_BAR_H
#define ATK_MENU_BAR_H

#include "atk_internal.h"

/*
 * Reset the menu bar state and clear menu entries.
 *
 * Menu entries are global UI elements owned by the ATK state (not by windows).
 */
void atk_menu_bar_reset(atk_state_t *state);

/*
 * Enable/disable menu bar rendering and input.
 *
 * When disabled, `atk_menu_bar_height()` returns 0 and mouse events will not be
 * consumed by the menu bar.
 */
void atk_menu_bar_set_enabled(atk_state_t *state, bool enabled);

/*
 * Return the current menu bar height in pixels (0 when disabled).
 *
 * Callers use this to clip window rendering and to decide whether to draw the
 * menu bar for a given dirty region.
 */
int atk_menu_bar_height(const atk_state_t *state);

/*
 * Populate the default menu bar entries (logo, clock, etc.).
 *
 * This is called during mode entry; apps may rebuild menus by clearing entries
 * and calling this again.
 */
void atk_menu_bar_build_default(atk_state_t *state);

/*
 * Enable periodic clock updates in the menu bar.
 *
 * Kernel builds poll this from the UI loop to keep the clock label fresh
 * without relying on timer IRQ callbacks.
 */
void atk_menu_bar_enable_clock_timer(void);

/*
 * Poll for clock updates.
 *
 * Call this from the video/UI loop; it schedules a redraw when the clock needs
 * refreshing (currently every ~5 seconds).
 */
void atk_menu_bar_poll_clock(void);

/* Draw the menu bar into the current backbuffer. */
void atk_menu_bar_draw(const atk_state_t *state);

/*
 * Handle a mouse event for the menu bar.
 *
 * Returns true if the event was consumed by the menu bar. If `redraw_out` is
 * non-NULL, it is set when the menu bar changed visual state (hover/open).
 */
bool atk_menu_bar_handle_mouse(atk_state_t *state,
                               int cursor_x,
                               int cursor_y,
                               bool pressed_edge,
                               bool released_edge,
                               bool left_pressed,
                               bool *redraw_out);

#endif
