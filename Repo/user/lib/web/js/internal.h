#ifndef WEB_JS_INTERNAL_H
#define WEB_JS_INTERNAL_H

#include "web/js.h"

#ifdef __cplusplus
extern "C" {
#endif

void js_parse_error_set(js_parse_error_t *err, size_t offset, const char *message);
char *js_strdup_len(const char *src, size_t len);
char *js_strdup(const char *src);
int js_hex_value(char c);

#ifdef __cplusplus
}
#endif

#endif /* WEB_JS_INTERNAL_H */
