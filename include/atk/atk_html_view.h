#ifndef ATK_HTML_VIEW_H
#define ATK_HTML_VIEW_H

#include "atk/object.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct html_document html_document_t;
typedef struct html_parse_error html_parse_error_t;

/*
 * Create an HTML view widget as a child of `window`.
 *
 * The HTML view renders a parsed HTML DOM with a small subset of CSS, intended
 * for userland browser experiments.
 */
atk_widget_t *atk_window_add_html_view(atk_widget_t *window, int x, int y, int width, int height);

/*
 * Replace the currently displayed document.
 *
 * The view takes ownership of `doc` and will destroy it when replaced or when
 * the widget is destroyed.
 */
void atk_html_view_set_document(atk_widget_t *view, html_document_t *doc);

/*
 * Convenience: parse `html` and install the resulting document.
 *
 * Returns false if parsing fails.
 */
bool atk_html_view_set_html(atk_widget_t *view, const char *html, html_parse_error_t *error_out);

extern const atk_class_t ATK_HTML_VIEW_CLASS;

#ifdef __cplusplus
}
#endif

#endif /* ATK_HTML_VIEW_H */

