#ifndef ATK_HTML_VIEW_H
#define ATK_HTML_VIEW_H

#include "atk/object.h"
#include "video.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct html_document html_document_t;
typedef struct html_parse_error html_parse_error_t;

typedef void (*atk_html_view_link_t)(atk_widget_t *view, const char *href, void *context);

/*
 * Create an HTML view widget as a child of `window`.
 *
 * The HTML view renders a parsed HTML DOM with a small subset of CSS, intended
 * for userland browser experiments.
 */
atk_widget_t *atk_window_add_html_view(atk_widget_t *window, int x, int y, int width, int height);

/*
 * Set a callback invoked when a user clicks an `<a href="...">` link.
 *
 * The callback is invoked from the ATK event path; keep it fast.
 */
void atk_html_view_set_link_handler(atk_widget_t *view, atk_html_view_link_t handler, void *context);

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
 * Non-blocking stylesheet update; returns false if the view is busy.
 *
 * The caller retains ownership of `css_text` regardless of return value.
 */
bool atk_html_view_try_set_external_stylesheet(atk_widget_t *view, const char *css_text);

/*
 * Queue a script body for execution in the HTML view's JS thread.
 *
 * `script_text` is copied by the view.
 */
bool atk_html_view_add_script(atk_widget_t *view, const char *script_text, size_t len);
/*
 * Non-blocking script queue; returns false if the view is busy.
 *
 * The script is copied by the view when queued.
 */
bool atk_html_view_try_add_script(atk_widget_t *view, const char *script_text, size_t len);

/*
 * Stop JS execution and clear queued scripts/listeners for the view.
 */
void atk_html_view_stop_js(atk_widget_t *view);

/*
 * Enable or disable asynchronous render cache builds.
 *
 * When enabled, the view rebuilds its render cache on a worker thread and
 * only draws when a fresh cache is ready.
 */
void atk_html_view_enable_async_render(atk_widget_t *view, bool enabled);

/*
 * Poll for JS-driven DOM changes that require a redraw.
 *
 * Call this from the UI thread (e.g. your main loop tick) to propagate
 * invalidations from the JS thread into the ATK dirty region tracker.
 */
bool atk_html_view_poll_js(atk_widget_t *view);

/*
 * Add a PNG image resource that can be referenced by `<img src="...">`.
 *
 * `src` should match the `src` attribute value used in the DOM (often an
 * absolute URL after resolution by the browser).
 */
bool atk_html_view_add_image_png(atk_widget_t *view, const char *src, const uint8_t *data, size_t size);

/*
 * Add a GIF image resource that can be referenced by `<img src="...">`.
 */
bool atk_html_view_add_image_gif(atk_widget_t *view, const char *src, const uint8_t *data, size_t size);

/*
 * Add an RGBA image resource that can be referenced by `<img src="...">`.
 *
 * The view takes ownership of `pixels`.
 */
bool atk_html_view_add_image_rgba(atk_widget_t *view,
                                  const char *src,
                                  video_color_t *pixels,
                                  int width,
                                  int height,
                                  int stride_bytes);
/*
 * Non-blocking RGBA image registration; returns false if the view is busy.
 *
 * Ownership of `pixels` is transferred only on success.
 */
bool atk_html_view_try_add_image_rgba(atk_widget_t *view,
                                      const char *src,
                                      video_color_t *pixels,
                                      int width,
                                      int height,
                                      int stride_bytes);

extern const atk_class_t ATK_HTML_VIEW_CLASS;

#ifdef __cplusplus
}
#endif

#endif /* ATK_HTML_VIEW_H */
