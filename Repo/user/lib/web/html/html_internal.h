#ifndef WEB_HTML_INTERNAL_H
#define WEB_HTML_INTERNAL_H

#include "web/html.h"

#ifdef __cplusplus
extern "C" {
#endif

void *html_doc_alloc(html_document_t *doc, size_t size);
html_node_t *html_node_create(html_document_t *doc, html_node_type_t type);
void html_attr_free_list(html_document_t *doc, html_attr_t *attr);
void html_node_append_child(html_node_t *parent, html_node_t *child);

char *html_doc_strdup_range(html_document_t *doc, const char *start, const char *end, bool to_lower);
char *html_doc_strdup_decoded_range(html_document_t *doc, const char *start, const char *end);

#ifdef __cplusplus
}
#endif

#endif /* WEB_HTML_INTERNAL_H */
