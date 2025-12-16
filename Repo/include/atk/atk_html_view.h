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

/*
 * Replace the external stylesheet text (typically from `<link rel="stylesheet">`).
 *
 * Passing NULL clears any previously set external stylesheet.
 */
void atk_html_view_set_external_stylesheet(atk_widget_t *view, const char *css_text);

/*
 * Add a PNG image resource that can be referenced by `<img src="...">`.
 *
 * `src` should match the `src` attribute value used in the DOM (often an
 * absolute URL after resolution by the browser).
 */
bool atk_html_view_add_image_png(atk_widget_t *view, const char *src, const uint8_t *data, size_t size);

extern const atk_class_t ATK_HTML_VIEW_CLASS;

#ifdef __cplusplus
}
#endif

#endif /* ATK_HTML_VIEW_H */
