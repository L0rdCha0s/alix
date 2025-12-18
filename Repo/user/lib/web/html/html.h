#ifndef WEB_HTML_PUBLIC_H
#define WEB_HTML_PUBLIC_H

#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum
{
    HTML_NODE_DOCUMENT = 0,
    HTML_NODE_ELEMENT,
    HTML_NODE_TEXT,
    HTML_NODE_DOCTYPE,
    HTML_NODE_COMMENT
} html_node_type_t;

typedef struct html_attr
{
    char *name;
    char *value;
    struct html_attr *next;
} html_attr_t;

typedef struct html_node
{
    html_node_type_t type;
    char *name;
    char *text;
    html_attr_t *attrs;
    struct html_node *parent;
    struct html_node *first_child;
    struct html_node *last_child;
    struct html_node *prev_sibling;
    struct html_node *next_sibling;
} html_node_t;

typedef struct html_document
{
    html_node_t *root;
} html_document_t;

typedef struct html_parse_error
{
    size_t offset;
    const char *message;
} html_parse_error_t;

html_document_t *html_parse(const char *input, html_parse_error_t *error_out);
void html_document_destroy(html_document_t *doc);

const char *html_attr_get(const html_node_t *node, const char *name);

#ifdef __cplusplus
}
#endif

#endif /* WEB_HTML_PUBLIC_H */
