#ifndef ATK_RICH_TEXT_H
#define ATK_RICH_TEXT_H

#include "atk/object.h"

#ifdef __cplusplus
extern "C" {
#endif

struct atk_state;

typedef void (*atk_rich_text_change_t)(atk_widget_t *editor, void *context);

typedef enum
{
    ATK_RICH_TEXT_STYLE_BOLD = (1u << 0),
    ATK_RICH_TEXT_STYLE_ITALIC = (1u << 1),
    ATK_RICH_TEXT_STYLE_UNDERLINE = (1u << 2),
} atk_rich_text_style_t;

#define ATK_RICH_TEXT_PAGE_BREAK_CHAR '\f'

atk_widget_t *atk_window_add_rich_text(atk_widget_t *window, int x, int y, int width, int height);
void atk_rich_text_focus(struct atk_state *state, atk_widget_t *editor);
void atk_rich_text_set_font_size(atk_widget_t *editor, int size_px);
void atk_rich_text_apply_font_size(atk_widget_t *editor, int size_px);
int atk_rich_text_current_font_size(const atk_widget_t *editor);
int atk_rich_text_cursor_font_size(const atk_widget_t *editor);
void atk_rich_text_apply_style(atk_widget_t *editor, uint32_t style_flags, bool enabled);
void atk_rich_text_toggle_style(atk_widget_t *editor, uint32_t style_flags);
uint32_t atk_rich_text_current_style(const atk_widget_t *editor);
uint32_t atk_rich_text_cursor_style(const atk_widget_t *editor);
void atk_rich_text_set_text(atk_widget_t *editor, const char *text);
void atk_rich_text_append(atk_widget_t *editor, const char *text);
void atk_rich_text_insert_page_break(atk_widget_t *editor);
void atk_rich_text_set_pagination_enabled(atk_widget_t *editor, bool enabled);
bool atk_rich_text_pagination_enabled(const atk_widget_t *editor);
size_t atk_rich_text_page_count(const atk_widget_t *editor);
void atk_rich_text_scroll_to_top(atk_widget_t *editor);
void atk_rich_text_scroll_to_bottom(atk_widget_t *editor);
void atk_rich_text_set_change_handler(atk_widget_t *editor, atk_rich_text_change_t handler, void *context);
char *atk_rich_text_copy_text(const atk_widget_t *editor);
bool atk_rich_text_serialize(const atk_widget_t *editor, uint8_t **data_out, size_t *size_out);
bool atk_rich_text_deserialize(atk_widget_t *editor, const uint8_t *data, size_t size);

#ifdef __cplusplus
}
#endif

#endif
