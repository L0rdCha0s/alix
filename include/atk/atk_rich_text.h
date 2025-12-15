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

/*
 * Create a rich text editor widget as a child of `window`.
 *
 * Rich text supports styled spans, cursor/selection, optional pagination, and
 * vertical scrolling.
 */
atk_widget_t *atk_window_add_rich_text(atk_widget_t *window, int x, int y, int width, int height);

/* Focus the rich text editor so it receives key events. */
void atk_rich_text_focus(struct atk_state *state, atk_widget_t *editor);

/* Set the default font size used for new text (in pixels). */
void atk_rich_text_set_font_size(atk_widget_t *editor, int size_px);

/* Apply a font size to the current selection (or next inserted text). */
void atk_rich_text_apply_font_size(atk_widget_t *editor, int size_px);

/* Return the editor's current default font size. */
int atk_rich_text_current_font_size(const atk_widget_t *editor);

/* Return the font size at the cursor position. */
int atk_rich_text_cursor_font_size(const atk_widget_t *editor);

/*
 * Enable/disable style flags on the current selection.
 *
 * `style_flags` is a bitmask of `atk_rich_text_style_t`.
 */
void atk_rich_text_apply_style(atk_widget_t *editor, uint32_t style_flags, bool enabled);

/* Toggle style flags on the current selection. */
void atk_rich_text_toggle_style(atk_widget_t *editor, uint32_t style_flags);

/* Return the editor's current default style flags. */
uint32_t atk_rich_text_current_style(const atk_widget_t *editor);

/* Return the style flags at the cursor position. */
uint32_t atk_rich_text_cursor_style(const atk_widget_t *editor);

/* Replace all text content (clears existing spans) and reset cursor/scroll. */
void atk_rich_text_set_text(atk_widget_t *editor, const char *text);

/* Append plain text to the end of the document. */
void atk_rich_text_append(atk_widget_t *editor, const char *text);

/* Insert a page break marker (`ATK_RICH_TEXT_PAGE_BREAK_CHAR`). */
void atk_rich_text_insert_page_break(atk_widget_t *editor);

/* Enable/disable pagination mode. */
void atk_rich_text_set_pagination_enabled(atk_widget_t *editor, bool enabled);

/* Return whether pagination is currently enabled. */
bool atk_rich_text_pagination_enabled(const atk_widget_t *editor);

/* Return the number of pages in pagination mode. */
size_t atk_rich_text_page_count(const atk_widget_t *editor);

/* Scroll to the start of the document. */
void atk_rich_text_scroll_to_top(atk_widget_t *editor);

/* Scroll to the end of the document. */
void atk_rich_text_scroll_to_bottom(atk_widget_t *editor);

/* Install a callback invoked when the document content changes. */
void atk_rich_text_set_change_handler(atk_widget_t *editor, atk_rich_text_change_t handler, void *context);

/* Enable/disable read-only mode (disables user edits, but still allows programmatic updates). */
void atk_rich_text_set_read_only(atk_widget_t *editor, bool read_only);

/* Return whether read-only mode is enabled. */
bool atk_rich_text_is_read_only(const atk_widget_t *editor);

/*
 * Return a heap-allocated copy of the editor text.
 *
 * Caller owns the returned buffer and must `free()` it.
 */
char *atk_rich_text_copy_text(const atk_widget_t *editor);

/*
 * Serialize the rich text document into a binary format.
 *
 * On success, `*data_out` is heap-allocated and must be `free()`d by the caller.
 */
bool atk_rich_text_serialize(const atk_widget_t *editor, uint8_t **data_out, size_t *size_out);

/*
 * Deserialize a binary rich text document into the editor.
 *
 * Returns false if the input is invalid or allocation fails.
 */
bool atk_rich_text_deserialize(atk_widget_t *editor, const uint8_t *data, size_t size);

#ifdef __cplusplus
}
#endif

#endif
