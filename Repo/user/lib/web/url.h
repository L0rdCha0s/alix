#ifndef WEB_URL_H
#define WEB_URL_H

#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

bool web_url_has_extension(const char *url, const char *ext);
bool web_url_is_svg(const char *url);

#ifdef __cplusplus
}
#endif

#endif /* WEB_URL_H */
