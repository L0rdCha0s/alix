#include "web/js.h"
#include "web/js/internal.h"
#include "web/js/lexer.h"

#include "ctype.h"
#include "libc.h"

typedef struct
{
    js_lexer_t lexer;
    js_token_t current;
    bool had_error;
    js_parse_error_t *error_out;
    bool in_generator;
    bool in_async;
    js_arena_t arena;
    bool use_arena;
} js_parser_t;

typedef struct
{
    js_stmt_t **items;
    size_t count;
    size_t cap;
} js_stmt_list_t;

typedef struct
{
    js_expr_t **items;
    size_t count;
    size_t cap;
} js_expr_list_t;

typedef struct
{
    js_template_segment_t *items;
    size_t count;
    size_t cap;
} js_template_segment_list_t;

typedef struct
{
    js_param_t *items;
    size_t count;
    size_t cap;
} js_param_list_t;

typedef struct
{
    js_switch_case_t *items;
    size_t count;
    size_t cap;
} js_case_list_t;

typedef struct
{
    js_object_property_t *items;
    size_t count;
    size_t cap;
} js_prop_list_t;

typedef struct
{
    js_var_binding_t *items;
    size_t count;
    size_t cap;
} js_var_list_t;

typedef struct
{
    js_class_method_t *items;
    size_t count;
    size_t cap;
} js_class_method_list_t;

static bool js_token_is_identifier(const js_token_t *tok, const char *text);

static void *js_parser_alloc(js_parser_t *parser, size_t size)
{
    if (!parser || size == 0)
    {
        return NULL;
    }
    if (!parser->use_arena)
    {
        return js_calloc(1, size);
    }
    return js_arena_alloc(&parser->arena, size);
}

static void *js_parser_realloc(js_parser_t *parser,
                               void *items,
                               size_t count,
                               size_t new_cap,
                               size_t elem_size)
{
    if (!parser)
    {
        return NULL;
    }
    size_t bytes = 0;
    if (__builtin_mul_overflow(new_cap, elem_size, &bytes))
    {
        return NULL;
    }
    if (!parser->use_arena)
    {
        return js_realloc(items, bytes);
    }
    void *next = js_arena_alloc(&parser->arena, bytes);
    if (!next)
    {
        return NULL;
    }
    if (items && count)
    {
        memcpy(next, items, count * elem_size);
    }
    return next;
}

static char *js_parser_strdup_len(js_parser_t *parser, const char *src, size_t len)
{
    if (!parser)
    {
        return NULL;
    }
    if (!parser->use_arena)
    {
        return js_strdup_len(src, len);
    }
    return js_arena_strdup_len(&parser->arena, src, len);
}

static char *js_parser_strdup(js_parser_t *parser, const char *src)
{
    if (!src)
    {
        return NULL;
    }
    return js_parser_strdup_len(parser, src, strlen(src));
}

static void js_parser_free(js_parser_t *parser, void *ptr)
{
    if (!ptr)
    {
        return;
    }
    if (parser && parser->use_arena)
    {
        return;
    }
    js_free(ptr);
}

static void js_parser_init(js_parser_t *parser, const char *source, js_parse_error_t *error_out)
{
    if (!parser)
    {
        return;
    }
    if (error_out)
    {
        error_out->message = NULL;
        error_out->offset = 0;
    }
    memset(parser, 0, sizeof(*parser));
    parser->error_out = error_out;
    parser->use_arena = true;
    js_arena_init(&parser->arena);
    js_lexer_init(&parser->lexer, source, &parser->arena);
    if (!js_lexer_next(&parser->lexer, &parser->current, parser->error_out))
    {
        parser->had_error = true;
    }
}

static void js_parser_error(js_parser_t *parser, size_t offset, const char *message)
{
    if (!parser)
    {
        return;
    }
    parser->had_error = true;
    js_parse_error_set(parser->error_out, offset, message);
}

static void js_parser_advance(js_parser_t *parser)
{
    if (!parser)
    {
        return;
    }
    js_token_destroy(&parser->current);
    if (!js_lexer_next(&parser->lexer, &parser->current, parser->error_out))
    {
        parser->had_error = true;
        parser->current.type = JS_TOKEN_EOF;
        parser->current.offset = parser->lexer.offset;
    }
}

static bool js_parser_match(js_parser_t *parser, js_token_type_t type)
{
    if (!parser || parser->current.type != type)
    {
        return false;
    }
    js_parser_advance(parser);
    return true;
}

static bool js_parser_expect(js_parser_t *parser, js_token_type_t type, const char *message)
{
    if (!parser)
    {
        return false;
    }
    if (parser->current.type == type)
    {
        js_parser_advance(parser);
        return true;
    }
    js_parser_error(parser, parser->current.offset, message);
    return false;
}

static bool js_parser_consume_semicolon(js_parser_t *parser)
{
    if (!parser)
    {
        return false;
    }
    if (parser->current.type == JS_TOKEN_SEMICOLON)
    {
        js_parser_advance(parser);
        return true;
    }
    if (parser->current.line_terminator)
    {
        return true;
    }
    if (parser->current.type == JS_TOKEN_EOF || parser->current.type == JS_TOKEN_RBRACE)
    {
        return true;
    }
    js_parser_error(parser, parser->current.offset, "expected ';'");
    return false;
}

static bool js_stmt_list_push(js_parser_t *parser, js_stmt_list_t *list, js_stmt_t *stmt)
{
    if (!parser || !list || !stmt)
    {
        return false;
    }
    if (list->count + 1 > list->cap)
    {
        size_t new_cap = list->cap ? list->cap * 2u : 8u;
        if (new_cap < list->count + 1)
        {
            new_cap = list->count + 1;
        }
        js_stmt_t **new_items =
            (js_stmt_t **)js_parser_realloc(parser,
                                            list->items,
                                            list->count,
                                            new_cap,
                                            sizeof(*new_items));
        if (!new_items)
        {
            return false;
        }
        list->items = new_items;
        list->cap = new_cap;
    }
    list->items[list->count++] = stmt;
    return true;
}

static bool js_expr_list_push(js_parser_t *parser, js_expr_list_t *list, js_expr_t *expr)
{
    if (!parser || !list || !expr)
    {
        return false;
    }
    if (list->count + 1 > list->cap)
    {
        size_t new_cap = list->cap ? list->cap * 2u : 4u;
        if (new_cap < list->count + 1)
        {
            new_cap = list->count + 1;
        }
        js_expr_t **new_items =
            (js_expr_t **)js_parser_realloc(parser,
                                            list->items,
                                            list->count,
                                            new_cap,
                                            sizeof(*new_items));
        if (!new_items)
        {
            return false;
        }
        list->items = new_items;
        list->cap = new_cap;
    }
    list->items[list->count++] = expr;
    return true;
}

static bool js_template_segment_list_push(js_parser_t *parser,
                                          js_template_segment_list_t *list,
                                          const js_template_segment_t *segment)
{
    if (!parser || !list || !segment)
    {
        return false;
    }
    if (list->count + 1 > list->cap)
    {
        size_t new_cap = list->cap ? list->cap * 2u : 4u;
        if (new_cap < list->count + 1)
        {
            new_cap = list->count + 1;
        }
        js_template_segment_t *new_items =
            (js_template_segment_t *)js_parser_realloc(parser,
                                                       list->items,
                                                       list->count,
                                                       new_cap,
                                                       sizeof(*new_items));
        if (!new_items)
        {
            return false;
        }
        list->items = new_items;
        list->cap = new_cap;
    }
    list->items[list->count++] = *segment;
    return true;
}

static bool js_template_buf_append(js_parser_t *parser,
                                   char **buf,
                                   size_t *len,
                                   size_t *cap,
                                   const char *data,
                                   size_t data_len)
{
    if (!parser || !buf || !len || !cap)
    {
        return false;
    }
    if (data_len == 0)
    {
        return true;
    }
    if (!data)
    {
        return false;
    }
    if (*len > SIZE_MAX - data_len)
    {
        return false;
    }
    size_t needed = *len + data_len;
    if (needed + 1 > *cap)
    {
        size_t new_cap = *cap ? *cap * 2u : 32u;
        if (new_cap < needed + 1)
        {
            new_cap = needed + 1;
        }
        char *next = (char *)js_parser_realloc(parser, *buf, *len, new_cap, sizeof(char));
        if (!next)
        {
            return false;
        }
        *buf = next;
        *cap = new_cap;
    }
    memcpy(*buf + *len, data, data_len);
    *len = needed;
    (*buf)[*len] = '\0';
    return true;
}

static bool js_template_buf_append_char(js_parser_t *parser,
                                        char **buf,
                                        size_t *len,
                                        size_t *cap,
                                        char c)
{
    return js_template_buf_append(parser, buf, len, cap, &c, 1);
}

static bool js_template_buf_append_utf8(js_parser_t *parser,
                                        char **buf,
                                        size_t *len,
                                        size_t *cap,
                                        unsigned int code)
{
    char tmp[4];
    size_t tmp_len = 0;
    if (code <= 0x7F)
    {
        tmp[tmp_len++] = (char)code;
    }
    else if (code <= 0x7FF)
    {
        tmp[tmp_len++] = (char)(0xC0 | (code >> 6));
        tmp[tmp_len++] = (char)(0x80 | (code & 0x3F));
    }
    else if (code <= 0xFFFF)
    {
        tmp[tmp_len++] = (char)(0xE0 | (code >> 12));
        tmp[tmp_len++] = (char)(0x80 | ((code >> 6) & 0x3F));
        tmp[tmp_len++] = (char)(0x80 | (code & 0x3F));
    }
    else if (code <= 0x10FFFF)
    {
        tmp[tmp_len++] = (char)(0xF0 | (code >> 18));
        tmp[tmp_len++] = (char)(0x80 | ((code >> 12) & 0x3F));
        tmp[tmp_len++] = (char)(0x80 | ((code >> 6) & 0x3F));
        tmp[tmp_len++] = (char)(0x80 | (code & 0x3F));
    }
    else
    {
        return false;
    }
    return js_template_buf_append(parser, buf, len, cap, tmp, tmp_len);
}

static bool js_template_flush_segment(js_parser_t *parser,
                                      size_t offset,
                                      js_template_segment_list_t *segments,
                                      char **buffer,
                                      size_t *buffer_len)
{
    if (!segments || !buffer || !buffer_len)
    {
        return false;
    }
    char *copy = js_parser_strdup_len(parser, *buffer ? *buffer : "", *buffer_len);
    if (!copy)
    {
        js_parser_error(parser, offset, "allocation failed");
        return false;
    }
    js_template_segment_t segment = {0};
    segment.data = copy;
    segment.len = *buffer_len;
    if (!js_template_segment_list_push(parser, segments, &segment))
    {
        js_parser_free(parser, copy);
        js_parser_error(parser, offset, "allocation failed");
        return false;
    }
    *buffer_len = 0;
    if (*buffer)
    {
        (*buffer)[0] = '\0';
    }
    return true;
}

static bool js_param_list_push(js_parser_t *parser, js_param_list_t *list, const js_param_t *param)
{
    if (!parser || !list || !param)
    {
        return false;
    }
    if (list->count + 1 > list->cap)
    {
        size_t new_cap = list->cap ? list->cap * 2u : 4u;
        if (new_cap < list->count + 1)
        {
            new_cap = list->count + 1;
        }
        js_param_t *new_items =
            (js_param_t *)js_parser_realloc(parser,
                                            list->items,
                                            list->count,
                                            new_cap,
                                            sizeof(*new_items));
        if (!new_items)
        {
            return false;
        }
        list->items = new_items;
        list->cap = new_cap;
    }
    list->items[list->count++] = *param;
    return true;
}

static bool js_case_list_push(js_parser_t *parser, js_case_list_t *list, const js_switch_case_t *item)
{
    if (!parser || !list || !item)
    {
        return false;
    }
    if (list->count + 1 > list->cap)
    {
        size_t new_cap = list->cap ? list->cap * 2u : 4u;
        if (new_cap < list->count + 1)
        {
            new_cap = list->count + 1;
        }
        js_switch_case_t *new_items =
            (js_switch_case_t *)js_parser_realloc(parser,
                                                  list->items,
                                                  list->count,
                                                  new_cap,
                                                  sizeof(*new_items));
        if (!new_items)
        {
            return false;
        }
        list->items = new_items;
        list->cap = new_cap;
    }
    list->items[list->count++] = *item;
    return true;
}

static bool js_prop_list_push(js_parser_t *parser, js_prop_list_t *list, const js_object_property_t *prop)
{
    if (!parser || !list || !prop)
    {
        return false;
    }
    if (list->count + 1 > list->cap)
    {
        size_t new_cap = list->cap ? list->cap * 2u : 4u;
        if (new_cap < list->count + 1)
        {
            new_cap = list->count + 1;
        }
        js_object_property_t *new_items =
            (js_object_property_t *)js_parser_realloc(parser,
                                                      list->items,
                                                      list->count,
                                                      new_cap,
                                                      sizeof(*new_items));
        if (!new_items)
        {
            return false;
        }
        list->items = new_items;
        list->cap = new_cap;
    }
    list->items[list->count++] = *prop;
    return true;
}

static bool js_var_list_push(js_parser_t *parser, js_var_list_t *list, const js_var_binding_t *binding)
{
    if (!parser || !list || !binding)
    {
        return false;
    }
    if (list->count + 1 > list->cap)
    {
        size_t new_cap = list->cap ? list->cap * 2u : 4u;
        if (new_cap < list->count + 1)
        {
            new_cap = list->count + 1;
        }
        js_var_binding_t *new_items =
            (js_var_binding_t *)js_parser_realloc(parser,
                                                  list->items,
                                                  list->count,
                                                  new_cap,
                                                  sizeof(*new_items));
        if (!new_items)
        {
            return false;
        }
        list->items = new_items;
        list->cap = new_cap;
    }
    list->items[list->count++] = *binding;
    return true;
}

static bool js_class_method_list_push(js_parser_t *parser,
                                      js_class_method_list_t *list,
                                      const js_class_method_t *method)
{
    if (!parser || !list || !method)
    {
        return false;
    }
    if (list->count + 1 > list->cap)
    {
        size_t new_cap = list->cap ? list->cap * 2u : 4u;
        if (new_cap < list->count + 1)
        {
            new_cap = list->count + 1;
        }
        js_class_method_t *new_items =
            (js_class_method_t *)js_parser_realloc(parser,
                                                   list->items,
                                                   list->count,
                                                   new_cap,
                                                   sizeof(*new_items));
        if (!new_items)
        {
            return false;
        }
        list->items = new_items;
        list->cap = new_cap;
    }
    list->items[list->count++] = *method;
    return true;
}

static bool js_binding_element_list_push(js_parser_t *parser,
                                         js_binding_element_t **items,
                                         size_t *count,
                                         size_t *cap,
                                         const js_binding_element_t *elem)
{
    if (!parser || !items || !count || !cap || !elem)
    {
        return false;
    }
    if (*count + 1 > *cap)
    {
        size_t new_cap = *cap ? (*cap * 2u) : 4u;
        if (new_cap < *count + 1)
        {
            new_cap = *count + 1;
        }
        js_binding_element_t *new_items =
            (js_binding_element_t *)js_parser_realloc(parser,
                                                      *items,
                                                      *count,
                                                      new_cap,
                                                      sizeof(*new_items));
        if (!new_items)
        {
            return false;
        }
        *items = new_items;
        *cap = new_cap;
    }
    (*items)[(*count)++] = *elem;
    return true;
}

static bool js_binding_prop_list_push(js_parser_t *parser,
                                      js_binding_property_t **items,
                                      size_t *count,
                                      size_t *cap,
                                      const js_binding_property_t *prop)
{
    if (!parser || !items || !count || !cap || !prop)
    {
        return false;
    }
    if (*count + 1 > *cap)
    {
        size_t new_cap = *cap ? (*cap * 2u) : 4u;
        if (new_cap < *count + 1)
        {
            new_cap = *count + 1;
        }
        js_binding_property_t *new_items =
            (js_binding_property_t *)js_parser_realloc(parser,
                                                       *items,
                                                       *count,
                                                       new_cap,
                                                       sizeof(*new_items));
        if (!new_items)
        {
            return false;
        }
        *items = new_items;
        *cap = new_cap;
    }
    (*items)[(*count)++] = *prop;
    return true;
}

static void js_expr_destroy(js_expr_t *expr, bool arena_owned);
static void js_binding_destroy(js_binding_t *binding, bool arena_owned);
static void js_value_destroy_arena(js_value_t *value);

static void js_param_list_destroy(js_param_list_t *params, bool arena_owned)
{
    if (!params)
    {
        return;
    }
    for (size_t i = 0; i < params->count; ++i)
    {
        js_binding_destroy(params->items[i].binding, arena_owned);
        js_expr_destroy(params->items[i].init, arena_owned);
    }
    if (!arena_owned)
    {
        js_free(params->items);
    }
    params->items = NULL;
    params->count = 0;
    params->cap = 0;
}

static js_expr_t *js_new_expr(js_parser_t *parser, js_expr_type_t type)
{
    js_expr_t *expr = (js_expr_t *)js_parser_alloc(parser, sizeof(*expr));
    if (!expr)
    {
        return NULL;
    }
    expr->type = type;
    return expr;
}

static js_stmt_t *js_new_stmt(js_parser_t *parser, js_stmt_type_t type)
{
    js_stmt_t *stmt = (js_stmt_t *)js_parser_alloc(parser, sizeof(*stmt));
    if (!stmt)
    {
        return NULL;
    }
    stmt->type = type;
    return stmt;
}

static void js_binding_destroy(js_binding_t *binding, bool arena_owned)
{
    if (!binding)
    {
        return;
    }
    switch (binding->type)
    {
        case JS_BINDING_IDENTIFIER:
            if (!arena_owned)
            {
                js_free(binding->as.ident.name);
            }
            break;
        case JS_BINDING_ARRAY:
            for (size_t i = 0; i < binding->as.array.count; ++i)
            {
                js_binding_destroy(binding->as.array.elements[i].binding, arena_owned);
                js_expr_destroy(binding->as.array.elements[i].init, arena_owned);
            }
            if (!arena_owned)
            {
                js_free(binding->as.array.elements);
            }
            js_binding_destroy(binding->as.array.rest, arena_owned);
            break;
        case JS_BINDING_OBJECT:
            for (size_t i = 0; i < binding->as.object.count; ++i)
            {
                if (binding->as.object.props[i].computed)
                {
                    js_expr_destroy(binding->as.object.props[i].name_expr, arena_owned);
                }
                else
                {
                    if (!arena_owned)
                    {
                        js_free(binding->as.object.props[i].name);
                    }
                }
                js_binding_destroy(binding->as.object.props[i].binding, arena_owned);
                js_expr_destroy(binding->as.object.props[i].init, arena_owned);
            }
            if (!arena_owned)
            {
                js_free(binding->as.object.props);
                js_free(binding->as.object.rest_name);
            }
            break;
    }
    if (!arena_owned)
    {
        js_free(binding);
    }
}

static void js_stmt_destroy(js_stmt_t *stmt, bool arena_owned)
{
    if (!stmt)
    {
        return;
    }
    switch (stmt->type)
    {
        case JS_STMT_VAR:
            for (size_t i = 0; i < stmt->as.var.count; ++i)
            {
                js_binding_destroy(stmt->as.var.bindings[i].binding, arena_owned);
                js_expr_destroy(stmt->as.var.bindings[i].init, arena_owned);
            }
            if (!arena_owned)
            {
                js_free(stmt->as.var.bindings);
            }
            break;
        case JS_STMT_EXPR:
            js_expr_destroy(stmt->as.expr.expr, arena_owned);
            break;
        case JS_STMT_BLOCK:
            for (size_t i = 0; i < stmt->as.block.count; ++i)
            {
                js_stmt_destroy(stmt->as.block.stmts[i], arena_owned);
            }
            if (!arena_owned)
            {
                js_free(stmt->as.block.stmts);
            }
            break;
        case JS_STMT_RETURN:
            js_expr_destroy(stmt->as.ret.value, arena_owned);
            break;
        case JS_STMT_THROW:
            js_expr_destroy(stmt->as.throw_stmt.expr, arena_owned);
            break;
        case JS_STMT_FUNCTION_DECL:
            if (!arena_owned)
            {
                js_free(stmt->as.func.name);
            }
            for (size_t p = 0; p < stmt->as.func.param_count; ++p)
            {
                js_binding_destroy(stmt->as.func.params[p].binding, arena_owned);
                js_expr_destroy(stmt->as.func.params[p].init, arena_owned);
            }
            if (!arena_owned)
            {
                js_free(stmt->as.func.params);
            }
            for (size_t i = 0; i < stmt->as.func.body.count; ++i)
            {
                js_stmt_destroy(stmt->as.func.body.stmts[i], arena_owned);
            }
            if (!arena_owned)
            {
                js_free(stmt->as.func.body.stmts);
            }
            break;
        case JS_STMT_IF:
            js_expr_destroy(stmt->as.if_stmt.condition, arena_owned);
            js_stmt_destroy(stmt->as.if_stmt.then_branch, arena_owned);
            js_stmt_destroy(stmt->as.if_stmt.else_branch, arena_owned);
            break;
        case JS_STMT_WHILE:
            js_expr_destroy(stmt->as.while_stmt.condition, arena_owned);
            js_stmt_destroy(stmt->as.while_stmt.body, arena_owned);
            break;
        case JS_STMT_DO_WHILE:
            js_stmt_destroy(stmt->as.do_while_stmt.body, arena_owned);
            js_expr_destroy(stmt->as.do_while_stmt.condition, arena_owned);
            break;
        case JS_STMT_FOR:
            js_stmt_destroy(stmt->as.for_stmt.init, arena_owned);
            js_expr_destroy(stmt->as.for_stmt.condition, arena_owned);
            js_expr_destroy(stmt->as.for_stmt.post, arena_owned);
            js_stmt_destroy(stmt->as.for_stmt.body, arena_owned);
            break;
        case JS_STMT_FOR_IN:
        case JS_STMT_FOR_OF:
            js_binding_destroy(stmt->as.for_inof.binding, arena_owned);
            js_expr_destroy(stmt->as.for_inof.target, arena_owned);
            js_expr_destroy(stmt->as.for_inof.expr, arena_owned);
            js_stmt_destroy(stmt->as.for_inof.body, arena_owned);
            break;
        case JS_STMT_SWITCH:
            js_expr_destroy(stmt->as.switch_stmt.expr, arena_owned);
            for (size_t c = 0; c < stmt->as.switch_stmt.case_count; ++c)
            {
                js_switch_case_t *case_stmt = &stmt->as.switch_stmt.cases[c];
                js_expr_destroy(case_stmt->test, arena_owned);
                for (size_t i = 0; i < case_stmt->count; ++i)
                {
                    js_stmt_destroy(case_stmt->stmts[i], arena_owned);
                }
                if (!arena_owned)
                {
                    js_free(case_stmt->stmts);
                }
            }
            if (!arena_owned)
            {
                js_free(stmt->as.switch_stmt.cases);
            }
            break;
        case JS_STMT_TRY:
            for (size_t i = 0; i < stmt->as.try_stmt.try_block.count; ++i)
            {
                js_stmt_destroy(stmt->as.try_stmt.try_block.stmts[i], arena_owned);
            }
            if (!arena_owned)
            {
                js_free(stmt->as.try_stmt.try_block.stmts);
            }
            if (stmt->as.try_stmt.has_catch)
            {
                if (!arena_owned)
                {
                    js_free(stmt->as.try_stmt.catch_name);
                }
                for (size_t i = 0; i < stmt->as.try_stmt.catch_block.count; ++i)
                {
                    js_stmt_destroy(stmt->as.try_stmt.catch_block.stmts[i], arena_owned);
                }
                if (!arena_owned)
                {
                    js_free(stmt->as.try_stmt.catch_block.stmts);
                }
            }
            break;
        case JS_STMT_BREAK:
        case JS_STMT_CONTINUE:
        case JS_STMT_EMPTY:
            break;
    }
    if (!arena_owned)
    {
        js_free(stmt);
    }
}

static void js_value_destroy_arena(js_value_t *value)
{
    if (!value)
    {
        return;
    }
    if (value->type == JS_VALUE_STRING)
    {
        value->as.string.data = NULL;
        value->as.string.len = 0;
        value->type = JS_VALUE_UNDEFINED;
        return;
    }
    js_value_destroy(value);
}

static void js_expr_destroy(js_expr_t *expr, bool arena_owned)
{
    if (!expr)
    {
        return;
    }
    switch (expr->type)
    {
        case JS_EXPR_LITERAL:
            if (arena_owned)
            {
                js_value_destroy_arena(&expr->as.literal.value);
            }
            else
            {
                js_value_destroy(&expr->as.literal.value);
            }
            break;
        case JS_EXPR_IDENTIFIER:
            if (!arena_owned)
            {
                js_free(expr->as.ident.name);
            }
            break;
        case JS_EXPR_THIS:
            break;
        case JS_EXPR_BINARY:
            js_expr_destroy(expr->as.binary.left, arena_owned);
            js_expr_destroy(expr->as.binary.right, arena_owned);
            break;
        case JS_EXPR_UNARY:
            js_expr_destroy(expr->as.unary.expr, arena_owned);
            break;
        case JS_EXPR_UPDATE:
            js_expr_destroy(expr->as.update.target, arena_owned);
            break;
        case JS_EXPR_ASSIGN:
            js_expr_destroy(expr->as.assign.target, arena_owned);
            js_expr_destroy(expr->as.assign.value, arena_owned);
            break;
        case JS_EXPR_NEW:
            js_expr_destroy(expr->as.new_expr.callee, arena_owned);
            for (size_t i = 0; i < expr->as.new_expr.arg_count; ++i)
            {
                js_expr_destroy(expr->as.new_expr.args[i], arena_owned);
            }
            if (!arena_owned)
            {
                js_free(expr->as.new_expr.args);
            }
            break;
        case JS_EXPR_CALL:
            js_expr_destroy(expr->as.call.callee, arena_owned);
            for (size_t i = 0; i < expr->as.call.arg_count; ++i)
            {
                js_expr_destroy(expr->as.call.args[i], arena_owned);
            }
            if (!arena_owned)
            {
                js_free(expr->as.call.args);
            }
            break;
        case JS_EXPR_ARRAY:
            for (size_t i = 0; i < expr->as.array.count; ++i)
            {
                js_expr_destroy(expr->as.array.items[i], arena_owned);
            }
            if (!arena_owned)
            {
                js_free(expr->as.array.items);
            }
            break;
        case JS_EXPR_OBJECT:
            for (size_t i = 0; i < expr->as.object.count; ++i)
            {
                if (expr->as.object.props[i].is_spread)
                {
                    js_expr_destroy(expr->as.object.props[i].value, arena_owned);
                    continue;
                }
                if (expr->as.object.props[i].computed)
                {
                    js_expr_destroy(expr->as.object.props[i].name_expr, arena_owned);
                }
                else if (!arena_owned)
                {
                    js_free(expr->as.object.props[i].name);
                }
                js_expr_destroy(expr->as.object.props[i].value, arena_owned);
            }
            if (!arena_owned)
            {
                js_free(expr->as.object.props);
            }
            break;
        case JS_EXPR_TEMPLATE:
            for (size_t i = 0; i < expr->as.template.segment_count; ++i)
            {
                if (!arena_owned)
                {
                    js_free(expr->as.template.segments[i].data);
                }
            }
            if (!arena_owned)
            {
                js_free(expr->as.template.segments);
            }
            for (size_t i = 0; i < expr->as.template.expr_count; ++i)
            {
                js_expr_destroy(expr->as.template.exprs[i], arena_owned);
            }
            if (!arena_owned)
            {
                js_free(expr->as.template.exprs);
            }
            break;
        case JS_EXPR_MEMBER:
            js_expr_destroy(expr->as.member.object, arena_owned);
            if (expr->as.member.computed)
            {
                js_expr_destroy(expr->as.member.property_expr, arena_owned);
            }
            if (!arena_owned)
            {
                js_free(expr->as.member.property);
            }
            break;
        case JS_EXPR_SPREAD:
            js_expr_destroy(expr->as.spread.expr, arena_owned);
            break;
        case JS_EXPR_CLASS:
            if (!arena_owned)
            {
                js_free(expr->as.class_expr.name);
            }
            js_expr_destroy(expr->as.class_expr.base, arena_owned);
            js_expr_destroy(expr->as.class_expr.constructor, arena_owned);
            for (size_t i = 0; i < expr->as.class_expr.method_count; ++i)
            {
                js_class_method_t *method = &expr->as.class_expr.methods[i];
                if (method->computed)
                {
                    js_expr_destroy(method->name_expr, arena_owned);
                }
                else if (!arena_owned)
                {
                    js_free(method->name);
                }
                js_expr_destroy(method->value, arena_owned);
            }
            if (!arena_owned)
            {
                js_free(expr->as.class_expr.methods);
            }
            break;
        case JS_EXPR_REGEXP_SUBCLASS:
            break;
        case JS_EXPR_TERNARY:
            js_expr_destroy(expr->as.ternary.condition, arena_owned);
            js_expr_destroy(expr->as.ternary.then_expr, arena_owned);
            js_expr_destroy(expr->as.ternary.else_expr, arena_owned);
            break;
        case JS_EXPR_FUNCTION:
            if (!arena_owned)
            {
                js_free(expr->as.func.name);
            }
            for (size_t p = 0; p < expr->as.func.param_count; ++p)
            {
                js_binding_destroy(expr->as.func.params[p].binding, arena_owned);
                js_expr_destroy(expr->as.func.params[p].init, arena_owned);
            }
            if (!arena_owned)
            {
                js_free(expr->as.func.params);
            }
            for (size_t i = 0; i < expr->as.func.body.count; ++i)
            {
                js_stmt_destroy(expr->as.func.body.stmts[i], arena_owned);
            }
            if (!arena_owned)
            {
                js_free(expr->as.func.body.stmts);
            }
            break;
        case JS_EXPR_AWAIT:
            js_expr_destroy(expr->as.await.value, arena_owned);
            break;
        case JS_EXPR_YIELD:
            js_expr_destroy(expr->as.yield.value, arena_owned);
            break;
    }
    if (!arena_owned)
    {
        js_free(expr);
    }
}

void js_program_destroy(js_program_t *program)
{
    if (!program)
    {
        return;
    }
    bool arena_owned = (program->arena_blocks != NULL);
    for (size_t i = 0; i < program->count; ++i)
    {
        js_stmt_destroy(program->statements[i], arena_owned);
    }
    if (arena_owned)
    {
        js_arena_t arena = {0};
        arena.blocks = program->arena_blocks;
        js_arena_release(&arena);
        program->arena_blocks = NULL;
    }
    else
    {
        js_free(program->statements);
    }
    js_free(program);
}

static js_expr_t *js_parse_expression(js_parser_t *parser);
static js_stmt_t *js_parse_statement(js_parser_t *parser, bool allow_return);
static bool js_parse_block(js_parser_t *parser, bool allow_return, js_block_t *out);
static bool js_parse_function_common(js_parser_t *parser,
                                     bool require_name,
                                     js_function_expr_t *out,
                                     bool is_async);
static bool js_parse_function_tail(js_parser_t *parser,
                                   js_function_expr_t *out,
                                   bool is_async);
static js_expr_t *js_parse_arrow_function(js_parser_t *parser, bool is_async);
static js_expr_t *js_parse_member_suffix(js_parser_t *parser, js_expr_t *expr);
static js_binding_t *js_new_binding(js_parser_t *parser, js_binding_type_t type);
static js_binding_t *js_parse_binding_pattern(js_parser_t *parser);
static js_expr_t *js_parse_template_literal(js_parser_t *parser);

static js_expr_t *js_parse_regex_literal(js_parser_t *parser)
{
    if (!parser || parser->current.type != JS_TOKEN_SLASH)
    {
        return NULL;
    }
    size_t offset = parser->current.offset;
    const char *start = parser->lexer.cur;
    const char *cur = start;
    bool escaped = false;
    bool in_class = false;
    while (*cur)
    {
        char c = *cur;
        if (escaped)
        {
            escaped = false;
            ++cur;
            continue;
        }
        if (c == '\\')
        {
            escaped = true;
            ++cur;
            continue;
        }
        if (c == '[')
        {
            in_class = true;
            ++cur;
            continue;
        }
        if (c == ']' && in_class)
        {
            in_class = false;
            ++cur;
            continue;
        }
        if (c == '/' && !in_class)
        {
            break;
        }
        ++cur;
    }
    if (*cur != '/')
    {
        js_parser_error(parser, offset, "unterminated regex");
        return NULL;
    }
    size_t pattern_len = (size_t)(cur - start);
    char *pattern = js_parser_strdup_len(parser, start, pattern_len);
    if (!pattern)
    {
        js_parser_error(parser, offset, "allocation failed");
        return NULL;
    }
    for (size_t i = 0; i < pattern_len; ++i)
    {
        if ((unsigned char)pattern[i] == JS_EVAL_NUL_SENTINEL)
        {
            pattern[i] = '\0';
        }
    }
    ++cur;
    const char *flag_start = cur;
    while (isalpha((unsigned char)*cur) != 0)
    {
        ++cur;
    }
    size_t flag_len = (size_t)(cur - flag_start);
    char *flags = NULL;
    if (flag_len)
    {
        flags = js_parser_strdup_len(parser, flag_start, flag_len);
        if (!flags)
        {
            js_parser_free(parser, pattern);
            js_parser_error(parser, offset, "allocation failed");
            return NULL;
        }
    }

    parser->lexer.cur = cur;
    parser->lexer.offset = (size_t)(cur - parser->lexer.source);
    js_parser_advance(parser);

    js_expr_t *callee = js_new_expr(parser, JS_EXPR_IDENTIFIER);
    if (!callee)
    {
        js_parser_free(parser, pattern);
        js_parser_free(parser, flags);
        js_parser_error(parser, offset, "allocation failed");
        return NULL;
    }
    callee->as.ident.name = js_parser_strdup(parser, "RegExp");
    if (!callee->as.ident.name)
    {
        js_parser_free(parser, pattern);
        js_parser_free(parser, flags);
        js_expr_destroy(callee, parser->use_arena);
        js_parser_error(parser, offset, "allocation failed");
        return NULL;
    }

    js_expr_t *pattern_expr = js_new_expr(parser, JS_EXPR_LITERAL);
    if (!pattern_expr)
    {
        js_parser_free(parser, pattern);
        js_parser_free(parser, flags);
        js_expr_destroy(callee, parser->use_arena);
        js_parser_error(parser, offset, "allocation failed");
        return NULL;
    }
    pattern_expr->as.literal.value.type = JS_VALUE_STRING;
    pattern_expr->as.literal.value.as.string.data = pattern;
    pattern_expr->as.literal.value.as.string.len = pattern_len;

    size_t arg_count = flag_len ? 2 : 1;
    js_expr_t **args = (js_expr_t **)js_parser_alloc(parser, arg_count * sizeof(*args));
    if (!args)
    {
        js_expr_destroy(pattern_expr, parser->use_arena);
        js_expr_destroy(callee, parser->use_arena);
        js_parser_free(parser, flags);
        js_parser_error(parser, offset, "allocation failed");
        return NULL;
    }
    args[0] = pattern_expr;

    if (flag_len)
    {
        js_expr_t *flag_expr = js_new_expr(parser, JS_EXPR_LITERAL);
        if (!flag_expr)
        {
            js_parser_free(parser, flags);
            js_parser_free(parser, args);
            js_expr_destroy(pattern_expr, parser->use_arena);
            js_expr_destroy(callee, parser->use_arena);
            js_parser_error(parser, offset, "allocation failed");
            return NULL;
        }
        flag_expr->as.literal.value.type = JS_VALUE_STRING;
        flag_expr->as.literal.value.as.string.data = flags;
        flag_expr->as.literal.value.as.string.len = flag_len;
        args[1] = flag_expr;
    }

    js_expr_t *call = js_new_expr(parser, JS_EXPR_CALL);
    if (!call)
    {
        for (size_t i = 0; i < arg_count; ++i)
        {
            if (args[i])
            {
                js_expr_destroy(args[i], parser->use_arena);
            }
        }
        js_parser_free(parser, args);
        js_expr_destroy(callee, parser->use_arena);
        js_parser_error(parser, offset, "allocation failed");
        return NULL;
    }
    call->as.call.callee = callee;
    call->as.call.args = args;
    call->as.call.arg_count = arg_count;
    return call;
}

static js_expr_t *js_parse_template_literal(js_parser_t *parser)
{
    if (!parser || parser->current.type != JS_TOKEN_BACKTICK)
    {
        return NULL;
    }
    size_t offset = parser->current.offset;
    const char *cur = parser->lexer.cur;
    js_template_segment_list_t segments = {0};
    js_expr_list_t exprs = {0};
    char *buffer = NULL;
    size_t buffer_len = 0;
    size_t buffer_cap = 0;

    for (;;)
    {
        char c = *cur;
        if (c == '\0')
        {
            js_parser_error(parser, offset, "unterminated template");
            goto error;
        }
        if (c == '`')
        {
            if (!js_template_flush_segment(parser, offset, &segments, &buffer, &buffer_len))
            {
                goto error;
            }
            ++cur;
            break;
        }
        if (c == '$' && cur[1] == '{')
        {
            if (!js_template_flush_segment(parser, offset, &segments, &buffer, &buffer_len))
            {
                goto error;
            }
            cur += 2;
            parser->lexer.cur = cur;
            parser->lexer.offset = (size_t)(cur - parser->lexer.source);
            js_parser_advance(parser);
            js_expr_t *expr = js_parse_expression(parser);
            if (!expr)
            {
                goto error;
            }
            if (parser->current.type != JS_TOKEN_RBRACE)
            {
                js_expr_destroy(expr, parser->use_arena);
                js_parser_error(parser, parser->current.offset, "expected '}'");
                goto error;
            }
            if (!js_expr_list_push(parser, &exprs, expr))
            {
                js_expr_destroy(expr, parser->use_arena);
                js_parser_error(parser, parser->current.offset, "allocation failed");
                goto error;
            }
            cur = parser->lexer.cur;
            continue;
        }
        if (c == '\\')
        {
            ++cur;
            char esc = *cur;
            if (esc == '\0')
            {
                js_parser_error(parser, offset, "unterminated template");
                goto error;
            }
            if (esc == '\n')
            {
                ++cur;
                continue;
            }
            if (esc == '\r')
            {
                ++cur;
                if (*cur == '\n')
                {
                    ++cur;
                }
                continue;
            }
            switch (esc)
            {
                case 'n': c = '\n'; ++cur; break;
                case 'r': c = '\r'; ++cur; break;
                case 't': c = '\t'; ++cur; break;
                case 'b': c = '\b'; ++cur; break;
                case 'f': c = '\f'; ++cur; break;
                case 'v': c = '\v'; ++cur; break;
                case '\\': c = '\\'; ++cur; break;
                case '\'': c = '\''; ++cur; break;
                case '\"': c = '\"'; ++cur; break;
                case '`': c = '`'; ++cur; break;
                case 'x':
                {
                    if (cur[1] == '\0' || cur[2] == '\0')
                    {
                        js_parser_error(parser, offset, "invalid hex escape");
                        goto error;
                    }
                    int hi = js_hex_value(cur[1]);
                    int lo = js_hex_value(cur[2]);
                    if (hi < 0 || lo < 0)
                    {
                        js_parser_error(parser, offset, "invalid hex escape");
                        goto error;
                    }
                    unsigned int value = (unsigned int)((hi << 4) | lo);
                    if (!js_template_buf_append_char(parser, &buffer, &buffer_len, &buffer_cap, (char)value))
                    {
                        js_parser_error(parser, offset, "allocation failed");
                        goto error;
                    }
                    cur += 3;
                    continue;
                }
                case 'u':
                {
                    if (cur[1] == '{')
                    {
                        const char *scan = cur + 2;
                        unsigned int value = 0;
                        size_t digits = 0;
                        while (*scan && *scan != '}')
                        {
                            int hv = js_hex_value(*scan);
                            if (hv < 0)
                            {
                                js_parser_error(parser, offset, "invalid unicode escape");
                                goto error;
                            }
                            value = (value << 4) | (unsigned int)hv;
                            digits++;
                            scan++;
                        }
                        if (*scan != '}' || digits == 0)
                        {
                            js_parser_error(parser, offset, "invalid unicode escape");
                            goto error;
                        }
                        if (!js_template_buf_append_utf8(parser, &buffer, &buffer_len, &buffer_cap, value))
                        {
                            js_parser_error(parser, offset, "allocation failed");
                            goto error;
                        }
                        cur = scan + 1;
                        continue;
                    }
                    if (cur[1] == '\0' || cur[2] == '\0' || cur[3] == '\0' || cur[4] == '\0')
                    {
                        js_parser_error(parser, offset, "invalid unicode escape");
                        goto error;
                    }
                    int v0 = js_hex_value(cur[1]);
                    int v1 = js_hex_value(cur[2]);
                    int v2 = js_hex_value(cur[3]);
                    int v3 = js_hex_value(cur[4]);
                    if (v0 < 0 || v1 < 0 || v2 < 0 || v3 < 0)
                    {
                        js_parser_error(parser, offset, "invalid unicode escape");
                        goto error;
                    }
                    unsigned int value = (unsigned int)((v0 << 12) | (v1 << 8) | (v2 << 4) | v3);
                    if (!js_template_buf_append_utf8(parser, &buffer, &buffer_len, &buffer_cap, value))
                    {
                        js_parser_error(parser, offset, "allocation failed");
                        goto error;
                    }
                    cur += 5;
                    continue;
                }
                default:
                    c = esc;
                    ++cur;
                    break;
            }
            if (!js_template_buf_append_char(parser, &buffer, &buffer_len, &buffer_cap, c))
            {
                js_parser_error(parser, offset, "allocation failed");
                goto error;
            }
            continue;
        }
        if (c == '\r')
        {
            if (cur[1] == '\n')
            {
                ++cur;
            }
            c = '\n';
        }
        if (!js_template_buf_append_char(parser, &buffer, &buffer_len, &buffer_cap, c))
        {
            js_parser_error(parser, offset, "allocation failed");
            goto error;
        }
        ++cur;
    }

    parser->lexer.cur = cur;
    parser->lexer.offset = (size_t)(cur - parser->lexer.source);
    js_parser_advance(parser);

    js_expr_t *expr = js_new_expr(parser, JS_EXPR_TEMPLATE);
    if (!expr)
    {
        js_parser_error(parser, offset, "allocation failed");
        goto error;
    }
    expr->as.template.segments = segments.items;
    expr->as.template.segment_count = segments.count;
    expr->as.template.exprs = exprs.items;
    expr->as.template.expr_count = exprs.count;
    js_parser_free(parser, buffer);
    return expr;

error:
    js_parser_free(parser, buffer);
    for (size_t i = 0; i < segments.count; ++i)
    {
        js_parser_free(parser, segments.items[i].data);
    }
    js_parser_free(parser, segments.items);
    for (size_t i = 0; i < exprs.count; ++i)
    {
        js_expr_destroy(exprs.items[i], parser->use_arena);
    }
    js_parser_free(parser, exprs.items);
    return NULL;
}

static bool js_parser_peek_arrow_after_ident(js_parser_t *parser)
{
    if (!parser || parser->current.type != JS_TOKEN_IDENTIFIER)
    {
        return false;
    }
    js_lexer_t lex = parser->lexer;
    js_parse_error_t err = {0};
    js_token_t next = {0};
    if (!js_lexer_next(&lex, &next, &err))
    {
        js_token_destroy(&next);
        return false;
    }
    bool is_arrow = (next.type == JS_TOKEN_ARROW);
    js_token_destroy(&next);
    return is_arrow;
}

static bool js_parser_peek_async_function(js_parser_t *parser)
{
    if (!parser || !js_token_is_identifier(&parser->current, "async"))
    {
        return false;
    }
    js_lexer_t lex = parser->lexer;
    js_parse_error_t err = {0};
    js_token_t tok = {0};
    if (!js_lexer_next(&lex, &tok, &err))
    {
        js_token_destroy(&tok);
        return false;
    }
    bool ok = (tok.type == JS_TOKEN_KW_FUNCTION);
    js_token_destroy(&tok);
    return ok;
}

static bool js_parser_peek_async_arrow(js_parser_t *parser)
{
    if (!parser || !js_token_is_identifier(&parser->current, "async"))
    {
        return false;
    }
    js_lexer_t lex = parser->lexer;
    js_parse_error_t err = {0};
    js_token_t tok = {0};
    if (!js_lexer_next(&lex, &tok, &err))
    {
        js_token_destroy(&tok);
        return false;
    }
    if (tok.type == JS_TOKEN_IDENTIFIER)
    {
        js_token_t next = {0};
        if (!js_lexer_next(&lex, &next, &err))
        {
            js_token_destroy(&tok);
            js_token_destroy(&next);
            return false;
        }
        bool ok = (next.type == JS_TOKEN_ARROW);
        js_token_destroy(&tok);
        js_token_destroy(&next);
        return ok;
    }
    if (tok.type == JS_TOKEN_LPAREN)
    {
        js_token_destroy(&tok);
        if (!js_lexer_next(&lex, &tok, &err))
        {
            js_token_destroy(&tok);
            return false;
        }
        if (tok.type == JS_TOKEN_RPAREN)
        {
            js_token_destroy(&tok);
            if (!js_lexer_next(&lex, &tok, &err))
            {
                js_token_destroy(&tok);
                return false;
            }
            bool ok = (tok.type == JS_TOKEN_ARROW);
            js_token_destroy(&tok);
            return ok;
        }
        size_t paren_depth = 0;
        size_t brace_depth = 0;
        size_t bracket_depth = 0;
        for (;;)
        {
            if (tok.type == JS_TOKEN_EOF)
            {
                js_token_destroy(&tok);
                return false;
            }
            switch (tok.type)
            {
                case JS_TOKEN_LPAREN:
                    paren_depth++;
                    break;
                case JS_TOKEN_LBRACE:
                    brace_depth++;
                    break;
                case JS_TOKEN_LBRACKET:
                    bracket_depth++;
                    break;
                case JS_TOKEN_RPAREN:
                    if (paren_depth == 0 && brace_depth == 0 && bracket_depth == 0)
                    {
                        js_token_destroy(&tok);
                        if (!js_lexer_next(&lex, &tok, &err))
                        {
                            js_token_destroy(&tok);
                            return false;
                        }
                        bool ok = (tok.type == JS_TOKEN_ARROW);
                        js_token_destroy(&tok);
                        return ok;
                    }
                    if (paren_depth == 0)
                    {
                        js_token_destroy(&tok);
                        return false;
                    }
                    paren_depth--;
                    break;
                case JS_TOKEN_RBRACE:
                    if (brace_depth == 0)
                    {
                        js_token_destroy(&tok);
                        return false;
                    }
                    brace_depth--;
                    break;
                case JS_TOKEN_RBRACKET:
                    if (bracket_depth == 0)
                    {
                        js_token_destroy(&tok);
                        return false;
                    }
                    bracket_depth--;
                    break;
                default:
                    break;
            }
            js_token_destroy(&tok);
            if (!js_lexer_next(&lex, &tok, &err))
            {
                js_token_destroy(&tok);
                return false;
            }
        }
    }
    js_token_destroy(&tok);
    return false;
}

static bool js_parser_peek_arrow_after_paren(js_parser_t *parser)
{
    if (!parser || parser->current.type != JS_TOKEN_LPAREN)
    {
        return false;
    }
    js_lexer_t lex = parser->lexer;
    js_parse_error_t err = {0};
    js_token_t tok = {0};
    if (!js_lexer_next(&lex, &tok, &err))
    {
        js_token_destroy(&tok);
        return false;
    }
    if (tok.type == JS_TOKEN_RPAREN)
    {
        js_token_destroy(&tok);
        if (!js_lexer_next(&lex, &tok, &err))
        {
            js_token_destroy(&tok);
            return false;
        }
        bool ok = (tok.type == JS_TOKEN_ARROW);
        js_token_destroy(&tok);
        return ok;
    }
    size_t paren_depth = 0;
    size_t brace_depth = 0;
    size_t bracket_depth = 0;
    for (;;)
    {
        if (tok.type == JS_TOKEN_EOF)
        {
            js_token_destroy(&tok);
            return false;
        }
        switch (tok.type)
        {
            case JS_TOKEN_LPAREN:
                paren_depth++;
                break;
            case JS_TOKEN_LBRACE:
                brace_depth++;
                break;
            case JS_TOKEN_LBRACKET:
                bracket_depth++;
                break;
            case JS_TOKEN_RPAREN:
                if (paren_depth == 0 && brace_depth == 0 && bracket_depth == 0)
                {
                    js_token_destroy(&tok);
                    if (!js_lexer_next(&lex, &tok, &err))
                    {
                        js_token_destroy(&tok);
                        return false;
                    }
                    bool ok = (tok.type == JS_TOKEN_ARROW);
                    js_token_destroy(&tok);
                    return ok;
                }
                if (paren_depth == 0)
                {
                    js_token_destroy(&tok);
                    return false;
                }
                paren_depth--;
                break;
            case JS_TOKEN_RBRACE:
                if (brace_depth == 0)
                {
                    js_token_destroy(&tok);
                    return false;
                }
                brace_depth--;
                break;
            case JS_TOKEN_RBRACKET:
                if (bracket_depth == 0)
                {
                    js_token_destroy(&tok);
                    return false;
                }
                bracket_depth--;
                break;
            default:
                break;
        }
        js_token_destroy(&tok);
        if (!js_lexer_next(&lex, &tok, &err))
        {
            js_token_destroy(&tok);
            return false;
        }
    }
}

static const char *js_keyword_text(js_token_type_t type)
{
    switch (type)
    {
        case JS_TOKEN_KW_VAR:
            return "var";
        case JS_TOKEN_KW_LET:
            return "let";
        case JS_TOKEN_KW_CONST:
            return "const";
        case JS_TOKEN_KW_FUNCTION:
            return "function";
        case JS_TOKEN_KW_RETURN:
            return "return";
        case JS_TOKEN_KW_THROW:
            return "throw";
        case JS_TOKEN_KW_TRUE:
            return "true";
        case JS_TOKEN_KW_FALSE:
            return "false";
        case JS_TOKEN_KW_NULL:
            return "null";
        case JS_TOKEN_KW_UNDEFINED:
            return "undefined";
        case JS_TOKEN_KW_THIS:
            return "this";
        case JS_TOKEN_KW_TYPEOF:
            return "typeof";
        case JS_TOKEN_KW_IF:
            return "if";
        case JS_TOKEN_KW_ELSE:
            return "else";
        case JS_TOKEN_KW_WHILE:
            return "while";
        case JS_TOKEN_KW_FOR:
            return "for";
        case JS_TOKEN_KW_BREAK:
            return "break";
        case JS_TOKEN_KW_CONTINUE:
            return "continue";
        case JS_TOKEN_KW_SWITCH:
            return "switch";
        case JS_TOKEN_KW_CASE:
            return "case";
        case JS_TOKEN_KW_DEFAULT:
            return "default";
        case JS_TOKEN_KW_DO:
            return "do";
        case JS_TOKEN_KW_TRY:
            return "try";
        case JS_TOKEN_KW_CATCH:
            return "catch";
        case JS_TOKEN_KW_NEW:
            return "new";
        default:
            return NULL;
    }
}

static bool js_token_is_keyword(js_token_type_t type)
{
    return js_keyword_text(type) != NULL;
}

static bool js_parser_peek_accessor(js_parser_t *parser)
{
    if (!parser || parser->current.type != JS_TOKEN_IDENTIFIER || !parser->current.text)
    {
        return false;
    }
    if (strcmp(parser->current.text, "get") != 0 && strcmp(parser->current.text, "set") != 0)
    {
        return false;
    }
    js_lexer_t lex = parser->lexer;
    js_parse_error_t err = {0};
    js_token_t tok = {0};
    if (!js_lexer_next(&lex, &tok, &err))
    {
        js_token_destroy(&tok);
        return false;
    }
    if (tok.type == JS_TOKEN_LBRACKET)
    {
        size_t depth = 0;
        for (;;)
        {
            js_token_destroy(&tok);
            if (!js_lexer_next(&lex, &tok, &err))
            {
                js_token_destroy(&tok);
                return false;
            }
            if (tok.type == JS_TOKEN_EOF)
            {
                js_token_destroy(&tok);
                return false;
            }
            if (tok.type == JS_TOKEN_LBRACKET)
            {
                depth++;
            }
            else if (tok.type == JS_TOKEN_RBRACKET)
            {
                if (depth == 0)
                {
                    break;
                }
                depth--;
            }
        }
        js_token_destroy(&tok);
        if (!js_lexer_next(&lex, &tok, &err))
        {
            js_token_destroy(&tok);
            return false;
        }
        bool ok = (tok.type == JS_TOKEN_LPAREN);
        js_token_destroy(&tok);
        return ok;
    }
    if (tok.type == JS_TOKEN_IDENTIFIER || tok.type == JS_TOKEN_STRING || js_token_is_keyword(tok.type))
    {
        js_token_destroy(&tok);
        if (!js_lexer_next(&lex, &tok, &err))
        {
            js_token_destroy(&tok);
            return false;
        }
        bool ok = (tok.type == JS_TOKEN_LPAREN);
        js_token_destroy(&tok);
        return ok;
    }
    js_token_destroy(&tok);
    return false;
}

static bool js_parser_peek_async_method(js_parser_t *parser)
{
    if (!parser || !js_token_is_identifier(&parser->current, "async"))
    {
        return false;
    }
    js_lexer_t lex = parser->lexer;
    js_parse_error_t err = {0};
    js_token_t tok = {0};
    if (!js_lexer_next(&lex, &tok, &err))
    {
        js_token_destroy(&tok);
        return false;
    }
    if (tok.type == JS_TOKEN_LPAREN)
    {
        js_token_destroy(&tok);
        return false;
    }
    if (tok.type == JS_TOKEN_LBRACKET)
    {
        size_t depth = 0;
        for (;;)
        {
            js_token_destroy(&tok);
            if (!js_lexer_next(&lex, &tok, &err))
            {
                js_token_destroy(&tok);
                return false;
            }
            if (tok.type == JS_TOKEN_EOF)
            {
                js_token_destroy(&tok);
                return false;
            }
            if (tok.type == JS_TOKEN_LBRACKET)
            {
                depth++;
            }
            else if (tok.type == JS_TOKEN_RBRACKET)
            {
                if (depth == 0)
                {
                    break;
                }
                depth--;
            }
        }
        js_token_destroy(&tok);
        if (!js_lexer_next(&lex, &tok, &err))
        {
            js_token_destroy(&tok);
            return false;
        }
        bool ok = (tok.type == JS_TOKEN_LPAREN);
        js_token_destroy(&tok);
        return ok;
    }
    if (tok.type == JS_TOKEN_IDENTIFIER ||
        tok.type == JS_TOKEN_STRING ||
        js_token_is_keyword(tok.type))
    {
        js_token_destroy(&tok);
        if (!js_lexer_next(&lex, &tok, &err))
        {
            js_token_destroy(&tok);
            return false;
        }
        bool ok = (tok.type == JS_TOKEN_LPAREN);
        js_token_destroy(&tok);
        return ok;
    }
    js_token_destroy(&tok);
    return false;
}

static bool js_build_return_block(js_parser_t *parser, js_expr_t *expr, js_block_t *out)
{
    if (!parser || !expr || !out)
    {
        return false;
    }
    js_stmt_t *stmt = js_new_stmt(parser, JS_STMT_RETURN);
    if (!stmt)
    {
        return false;
    }
    stmt->as.ret.value = expr;
    js_stmt_t **stmts = (js_stmt_t **)js_parser_alloc(parser, sizeof(*stmts));
    if (!stmts)
    {
        stmt->as.ret.value = NULL;
        js_stmt_destroy(stmt, parser->use_arena);
        return false;
    }
    stmts[0] = stmt;
    out->stmts = stmts;
    out->count = 1;
    return true;
}

static bool js_parse_param_list_body(js_parser_t *parser, js_param_list_t *params)
{
    if (!parser || !params)
    {
        return false;
    }
    if (parser->current.type == JS_TOKEN_RPAREN)
    {
        return true;
    }
    bool saw_rest = false;
    for (;;)
    {
        js_param_t param;
        memset(&param, 0, sizeof(param));
        if (parser->current.type == JS_TOKEN_ELLIPSIS)
        {
            if (saw_rest)
            {
                js_parser_error(parser, parser->current.offset, "invalid rest parameter");
                js_param_list_destroy(params, parser->use_arena);
                return false;
            }
            saw_rest = true;
            param.is_rest = true;
            js_parser_advance(parser);
            param.binding = js_parse_binding_pattern(parser);
            if (!param.binding)
            {
                js_param_list_destroy(params, parser->use_arena);
                return false;
            }
        }
        else
        {
            param.binding = js_parse_binding_pattern(parser);
            if (!param.binding)
            {
                js_param_list_destroy(params, parser->use_arena);
                return false;
            }
        }
        if (!param.is_rest && parser->current.type == JS_TOKEN_EQUAL)
        {
            js_parser_advance(parser);
            param.init = js_parse_expression(parser);
            if (!param.init)
            {
                js_binding_destroy(param.binding, parser->use_arena);
                js_param_list_destroy(params, parser->use_arena);
                return false;
            }
        }
        else if (param.is_rest && parser->current.type == JS_TOKEN_EQUAL)
        {
            js_binding_destroy(param.binding, parser->use_arena);
            js_parser_error(parser, parser->current.offset, "invalid rest parameter");
            js_param_list_destroy(params, parser->use_arena);
            return false;
        }

        if (!js_param_list_push(parser, params, &param))
        {
            js_binding_destroy(param.binding, parser->use_arena);
            js_expr_destroy(param.init, parser->use_arena);
            js_param_list_destroy(params, parser->use_arena);
            return false;
        }
        if (parser->current.type == JS_TOKEN_COMMA)
        {
            if (saw_rest)
            {
                js_parser_error(parser, parser->current.offset, "expected ')'");
                js_param_list_destroy(params, parser->use_arena);
                return false;
            }
            js_parser_advance(parser);
            continue;
        }
        break;
    }
    return true;
}

static bool js_parse_arrow_params(js_parser_t *parser, js_param_list_t *params)
{
    if (!parser || !params)
    {
        return false;
    }
    if (parser->current.type == JS_TOKEN_IDENTIFIER)
    {
        js_param_t param;
        memset(&param, 0, sizeof(param));
        js_binding_t *binding = js_new_binding(parser, JS_BINDING_IDENTIFIER);
        if (!binding)
        {
            js_parser_error(parser, parser->current.offset, "allocation failed");
            return false;
        }
        binding->as.ident.name = js_token_take_text(&parser->current);
        js_parser_advance(parser);
        param.binding = binding;
        param.is_rest = false;
        if (!js_param_list_push(parser, params, &param))
        {
            js_binding_destroy(binding, parser->use_arena);
            js_param_list_destroy(params, parser->use_arena);
            return false;
        }
        return true;
    }
    if (!js_parser_expect(parser, JS_TOKEN_LPAREN, "expected '('"))
    {
        return false;
    }
    if (!js_parse_param_list_body(parser, params))
    {
        return false;
    }
    return js_parser_expect(parser, JS_TOKEN_RPAREN, "expected ')'");
}

static js_expr_t *js_parse_arrow_function(js_parser_t *parser, bool is_async)
{
    size_t offset = parser ? parser->current.offset : 0;
    js_param_list_t params = {0};
    if (!js_parse_arrow_params(parser, &params))
    {
        return NULL;
    }
    if (!js_parser_expect(parser, JS_TOKEN_ARROW, "expected '=>'"))
    {
        js_param_list_destroy(&params, parser->use_arena);
        return NULL;
    }

    js_block_t body = {0};
    bool prev_in_generator = parser->in_generator;
    bool prev_in_async = parser->in_async;
    parser->in_generator = false;
    parser->in_async = is_async;
    if (parser->current.type == JS_TOKEN_LBRACE)
    {
        if (!js_parse_block(parser, true, &body))
        {
            parser->in_async = prev_in_async;
            parser->in_generator = prev_in_generator;
            js_param_list_destroy(&params, parser->use_arena);
            return NULL;
        }
    }
    else
    {
        js_expr_t *expr = js_parse_expression(parser);
        if (!expr)
        {
            parser->in_generator = prev_in_generator;
            js_param_list_destroy(&params, parser->use_arena);
            return NULL;
        }
        if (!js_build_return_block(parser, expr, &body))
        {
            js_expr_destroy(expr, parser->use_arena);
            parser->in_async = prev_in_async;
            parser->in_generator = prev_in_generator;
            js_param_list_destroy(&params, parser->use_arena);
            js_parser_error(parser, offset, "allocation failed");
            return NULL;
        }
    }
    parser->in_async = prev_in_async;
    parser->in_generator = prev_in_generator;

    js_expr_t *expr = js_new_expr(parser, JS_EXPR_FUNCTION);
    if (!expr)
    {
        js_param_list_destroy(&params, parser->use_arena);
        for (size_t i = 0; i < body.count; ++i)
        {
            js_stmt_destroy(body.stmts[i], parser->use_arena);
        }
        js_parser_free(parser, body.stmts);
        js_parser_error(parser, offset, "allocation failed");
        return NULL;
    }
    expr->as.func.name = NULL;
    expr->as.func.params = params.items;
    expr->as.func.param_count = params.count;
    expr->as.func.body = body;
    expr->as.func.is_arrow = true;
    expr->as.func.is_generator = false;
    expr->as.func.is_async = is_async;
    return expr;
}

static js_binding_t *js_new_binding(js_parser_t *parser, js_binding_type_t type)
{
    js_binding_t *binding = (js_binding_t *)js_parser_alloc(parser, sizeof(*binding));
    if (!binding)
    {
        return NULL;
    }
    binding->type = type;
    return binding;
}

static js_binding_t *js_parse_binding_pattern(js_parser_t *parser);

static void js_binding_prop_cleanup(js_parser_t *parser, js_binding_property_t *prop)
{
    if (!parser || !prop)
    {
        return;
    }
    if (prop->computed)
    {
        js_expr_destroy(prop->name_expr, parser->use_arena);
    }
    else
    {
        js_parser_free(parser, prop->name);
    }
    js_binding_destroy(prop->binding, parser->use_arena);
    js_expr_destroy(prop->init, parser->use_arena);
    memset(prop, 0, sizeof(*prop));
}

static js_binding_t *js_parse_binding_array(js_parser_t *parser)
{
    size_t offset = parser ? parser->current.offset : 0;
    if (!js_parser_expect(parser, JS_TOKEN_LBRACKET, "expected '['"))
    {
        return NULL;
    }

    js_binding_t *binding = js_new_binding(parser, JS_BINDING_ARRAY);
    if (!binding)
    {
        js_parser_error(parser, offset, "allocation failed");
        return NULL;
    }

    js_binding_element_t *elements = NULL;
    size_t count = 0;
    size_t cap = 0;
    js_binding_t *rest = NULL;

    if (parser->current.type != JS_TOKEN_RBRACKET)
    {
        for (;;)
        {
            if (parser->current.type == JS_TOKEN_COMMA)
            {
                js_binding_element_t elem = {0};
                if (!js_binding_element_list_push(parser, &elements, &count, &cap, &elem))
                {
                    js_parser_error(parser, parser->current.offset, "allocation failed");
                    goto error;
                }
                js_parser_advance(parser);
                if (parser->current.type == JS_TOKEN_RBRACKET)
                {
                    break;
                }
                continue;
            }
            if (parser->current.type == JS_TOKEN_ELLIPSIS)
            {
                js_parser_advance(parser);
                rest = js_parse_binding_pattern(parser);
                if (!rest)
                {
                    goto error;
                }
                if (!js_parser_expect(parser, JS_TOKEN_RBRACKET, "expected ']'"))
                {
                    goto error;
                }
                break;
            }

            js_binding_t *item_binding = js_parse_binding_pattern(parser);
            if (!item_binding)
            {
                goto error;
            }
            js_expr_t *init = NULL;
            if (parser->current.type == JS_TOKEN_EQUAL)
            {
                js_parser_advance(parser);
                init = js_parse_expression(parser);
                if (!init)
                {
                    js_binding_destroy(item_binding, parser->use_arena);
                    goto error;
                }
            }
            js_binding_element_t elem = {0};
            elem.binding = item_binding;
            elem.init = init;
            if (!js_binding_element_list_push(parser, &elements, &count, &cap, &elem))
            {
                js_binding_destroy(item_binding, parser->use_arena);
                js_expr_destroy(init, parser->use_arena);
                js_parser_error(parser, parser->current.offset, "allocation failed");
                goto error;
            }
            if (parser->current.type == JS_TOKEN_COMMA)
            {
                js_parser_advance(parser);
                if (parser->current.type == JS_TOKEN_RBRACKET)
                {
                    break;
                }
                continue;
            }
            break;
        }
    }

    if (parser->current.type != JS_TOKEN_RBRACKET)
    {
        js_parser_error(parser, parser->current.offset, "expected ']'");
        goto error;
    }
    js_parser_advance(parser);

    binding->as.array.elements = elements;
    binding->as.array.count = count;
    binding->as.array.rest = rest;
    return binding;

error:
    for (size_t i = 0; i < count; ++i)
    {
        js_binding_destroy(elements[i].binding, parser->use_arena);
        js_expr_destroy(elements[i].init, parser->use_arena);
    }
    js_parser_free(parser, elements);
    js_binding_destroy(rest, parser->use_arena);
    js_binding_destroy(binding, parser->use_arena);
    return NULL;
}

static js_binding_t *js_parse_binding_object(js_parser_t *parser)
{
    size_t offset = parser ? parser->current.offset : 0;
    if (!js_parser_expect(parser, JS_TOKEN_LBRACE, "expected '{'"))
    {
        return NULL;
    }

    js_binding_t *binding = js_new_binding(parser, JS_BINDING_OBJECT);
    if (!binding)
    {
        js_parser_error(parser, offset, "allocation failed");
        return NULL;
    }

    js_binding_property_t *props = NULL;
    size_t count = 0;
    size_t cap = 0;
    char *rest_name = NULL;

    if (parser->current.type != JS_TOKEN_RBRACE)
    {
        for (;;)
        {
            if (parser->current.type == JS_TOKEN_ELLIPSIS)
            {
                if (rest_name)
                {
                    js_parser_error(parser, parser->current.offset, "invalid rest binding");
                    goto error;
                }
                js_parser_advance(parser);
                if (parser->current.type != JS_TOKEN_IDENTIFIER)
                {
                    js_parser_error(parser, parser->current.offset, "expected identifier");
                    goto error;
                }
                rest_name = js_token_take_text(&parser->current);
                js_parser_advance(parser);
                if (parser->current.type == JS_TOKEN_COMMA)
                {
                    js_parser_advance(parser);
                }
                break;
            }

            js_binding_property_t prop;
            memset(&prop, 0, sizeof(prop));

            if (parser->current.type == JS_TOKEN_LBRACKET)
            {
                prop.computed = true;
                js_parser_advance(parser);
                prop.name_expr = js_parse_expression(parser);
                if (!prop.name_expr)
                {
                    js_binding_prop_cleanup(parser, &prop);
                    goto error;
                }
                if (!js_parser_expect(parser, JS_TOKEN_RBRACKET, "expected ']'"))
                {
                    js_binding_prop_cleanup(parser, &prop);
                    goto error;
                }
            }
            else if (parser->current.type == JS_TOKEN_IDENTIFIER)
            {
                prop.name = js_token_take_text(&parser->current);
                js_parser_advance(parser);
            }
            else if (parser->current.type == JS_TOKEN_STRING)
            {
                prop.name = js_token_take_text(&parser->current);
                js_parser_advance(parser);
            }
            else
            {
                js_parser_error(parser, parser->current.offset, "expected property name");
                js_binding_prop_cleanup(parser, &prop);
                goto error;
            }

            if (parser->current.type == JS_TOKEN_COLON)
            {
                js_parser_advance(parser);
                prop.binding = js_parse_binding_pattern(parser);
                if (!prop.binding)
                {
                    js_binding_prop_cleanup(parser, &prop);
                    goto error;
                }
            }
            else
            {
                if (prop.computed || !prop.name)
                {
                    js_parser_error(parser, parser->current.offset, "expected ':'");
                    js_binding_prop_cleanup(parser, &prop);
                    goto error;
                }
                prop.binding = js_new_binding(parser, JS_BINDING_IDENTIFIER);
                if (!prop.binding)
                {
                    js_parser_error(parser, parser->current.offset, "allocation failed");
                    js_binding_prop_cleanup(parser, &prop);
                    goto error;
                }
                prop.binding->as.ident.name = js_parser_strdup(parser, prop.name);
                if (!prop.binding->as.ident.name)
                {
                    js_parser_error(parser, parser->current.offset, "allocation failed");
                    js_binding_prop_cleanup(parser, &prop);
                    goto error;
                }
            }

            if (parser->current.type == JS_TOKEN_EQUAL)
            {
                js_parser_advance(parser);
                prop.init = js_parse_expression(parser);
                if (!prop.init)
                {
                    js_binding_prop_cleanup(parser, &prop);
                    goto error;
                }
            }

            if (!js_binding_prop_list_push(parser, &props, &count, &cap, &prop))
            {
                js_parser_error(parser, parser->current.offset, "allocation failed");
                js_binding_prop_cleanup(parser, &prop);
                goto error;
            }

            if (parser->current.type == JS_TOKEN_COMMA)
            {
                js_parser_advance(parser);
                if (parser->current.type == JS_TOKEN_RBRACE)
                {
                    break;
                }
                continue;
            }
            break;
        }
    }

    if (parser->current.type != JS_TOKEN_RBRACE)
    {
        js_parser_error(parser, parser->current.offset, "expected '}'");
        goto error;
    }
    js_parser_advance(parser);

    binding->as.object.props = props;
    binding->as.object.count = count;
    binding->as.object.rest_name = rest_name;
    return binding;

error:
    for (size_t i = 0; i < count; ++i)
    {
        if (props[i].computed)
        {
            js_expr_destroy(props[i].name_expr, parser->use_arena);
        }
        else
        {
            js_parser_free(parser, props[i].name);
        }
        js_binding_destroy(props[i].binding, parser->use_arena);
        js_expr_destroy(props[i].init, parser->use_arena);
    }
    js_parser_free(parser, props);
    js_parser_free(parser, rest_name);
    js_binding_destroy(binding, parser->use_arena);
    return NULL;
}

static js_binding_t *js_parse_binding_pattern(js_parser_t *parser)
{
    if (!parser)
    {
        return NULL;
    }
    if (parser->current.type == JS_TOKEN_IDENTIFIER)
    {
        js_binding_t *binding = js_new_binding(parser, JS_BINDING_IDENTIFIER);
        if (!binding)
        {
            js_parser_error(parser, parser->current.offset, "allocation failed");
            return NULL;
        }
        binding->as.ident.name = js_token_take_text(&parser->current);
        js_parser_advance(parser);
        return binding;
    }
    if (parser->current.type == JS_TOKEN_LBRACKET)
    {
        return js_parse_binding_array(parser);
    }
    if (parser->current.type == JS_TOKEN_LBRACE)
    {
        return js_parse_binding_object(parser);
    }
    js_parser_error(parser, parser->current.offset, "expected identifier");
    return NULL;
}

static js_expr_t *js_parse_class_common(js_parser_t *parser, bool require_name, char **out_name)
{
    if (!parser)
    {
        return NULL;
    }
    if (out_name)
    {
        *out_name = NULL;
    }
    size_t offset = parser->current.offset;
    if (!js_token_is_identifier(&parser->current, "class"))
    {
        js_parser_error(parser, parser->current.offset, "expected 'class'");
        return NULL;
    }
    js_parser_advance(parser);
    char *name = NULL;
    if (parser->current.type == JS_TOKEN_IDENTIFIER &&
        parser->current.text &&
        strcmp(parser->current.text, "extends") != 0)
    {
        name = js_token_take_text(&parser->current);
        js_parser_advance(parser);
    }
    if (require_name && !name)
    {
        js_parser_error(parser, parser->current.offset, "expected class name");
        return NULL;
    }
    if (out_name && name)
    {
        *out_name = js_parser_strdup(parser, name);
        if (!*out_name)
        {
            js_parser_free(parser, name);
            js_parser_error(parser, offset, "allocation failed");
            return NULL;
        }
    }
    js_expr_t *base = NULL;
    if (js_token_is_identifier(&parser->current, "extends"))
    {
        js_parser_advance(parser);
        base = js_parse_expression(parser);
        if (!base)
        {
            js_parser_free(parser, name);
            return NULL;
        }
    }
    if (!js_parser_expect(parser, JS_TOKEN_LBRACE, "expected '{'") )
    {
        js_expr_destroy(base, parser->use_arena);
        js_parser_free(parser, name);
        return NULL;
    }

    js_class_method_list_t methods = {0};
    js_expr_t *constructor = NULL;
    while (parser->current.type != JS_TOKEN_RBRACE && !parser->had_error)
    {
        if (parser->current.type == JS_TOKEN_SEMICOLON)
        {
            js_parser_advance(parser);
            continue;
        }
        bool is_static = false;
        bool is_accessor = false;
        bool accessor_is_getter = false;
        bool method_async = false;
        if (js_token_is_identifier(&parser->current, "static"))
        {
            is_static = true;
            js_parser_advance(parser);
        }
        if (js_token_is_identifier(&parser->current, "async") &&
            js_parser_peek_async_method(parser))
        {
            method_async = true;
            js_parser_advance(parser);
        }
        if (parser->current.type == JS_TOKEN_IDENTIFIER && js_parser_peek_accessor(parser))
        {
            accessor_is_getter = (strcmp(parser->current.text, "get") == 0);
            is_accessor = true;
            js_parser_advance(parser);
        }

        bool computed = false;
        char *method_name = NULL;
        js_expr_t *name_expr = NULL;
        if (parser->current.type == JS_TOKEN_LBRACKET)
        {
            computed = true;
            js_parser_advance(parser);
            name_expr = js_parse_expression(parser);
            if (!name_expr)
            {
                break;
            }
            if (!js_parser_expect(parser, JS_TOKEN_RBRACKET, "expected ']'"))
            {
                js_expr_destroy(name_expr, parser->use_arena);
                break;
            }
        }
        else if (parser->current.type == JS_TOKEN_IDENTIFIER)
        {
            method_name = js_token_take_text(&parser->current);
            js_parser_advance(parser);
        }
        else if (parser->current.type == JS_TOKEN_STRING)
        {
            method_name = js_token_take_text(&parser->current);
            js_parser_advance(parser);
        }
        else if (js_token_is_keyword(parser->current.type))
        {
            const char *kw = js_keyword_text(parser->current.type);
            if (!kw)
            {
                js_parser_error(parser, parser->current.offset, "expected property name");
                break;
            }
            method_name = js_parser_strdup(parser, kw);
            if (!method_name)
            {
                js_parser_error(parser, parser->current.offset, "allocation failed");
                break;
            }
            js_parser_advance(parser);
        }
        else
        {
            js_parser_error(parser, parser->current.offset, "expected property name");
            break;
        }

        js_function_expr_t func = {0};
        if (!js_parse_function_tail(parser, &func, method_async))
        {
            js_expr_destroy(name_expr, parser->use_arena);
            js_parser_free(parser, method_name);
            break;
        }
        js_expr_t *fn_expr = js_new_expr(parser, JS_EXPR_FUNCTION);
        if (!fn_expr)
        {
            js_expr_destroy(name_expr, parser->use_arena);
            js_parser_free(parser, method_name);
            for (size_t p = 0; p < func.param_count; ++p)
            {
                js_binding_destroy(func.params[p].binding, parser->use_arena);
                js_expr_destroy(func.params[p].init, parser->use_arena);
            }
            js_parser_free(parser, func.params);
            for (size_t i = 0; i < func.body.count; ++i)
            {
                js_stmt_destroy(func.body.stmts[i], parser->use_arena);
            }
            js_parser_free(parser, func.body.stmts);
            js_parser_error(parser, parser->current.offset, "allocation failed");
            break;
        }
        fn_expr->as.func = func;
        fn_expr->as.func.is_arrow = false;

        bool is_constructor = !computed && !is_static && !is_accessor &&
                              method_name && strcmp(method_name, "constructor") == 0;
        if (is_constructor)
        {
            if (constructor)
            {
                js_expr_destroy(constructor, parser->use_arena);
            }
            constructor = fn_expr;
            js_expr_destroy(name_expr, parser->use_arena);
            js_parser_free(parser, method_name);
        }
        else
        {
            js_class_method_t method = {0};
            method.computed = computed;
            method.is_static = is_static;
            method.is_getter = is_accessor && accessor_is_getter;
            method.is_setter = is_accessor && !accessor_is_getter;
            method.name = method_name;
            method.name_expr = name_expr;
            method.value = fn_expr;
            if (!js_class_method_list_push(parser, &methods, &method))
            {
                js_expr_destroy(name_expr, parser->use_arena);
                js_parser_free(parser, method_name);
                js_expr_destroy(fn_expr, parser->use_arena);
                js_parser_error(parser, parser->current.offset, "allocation failed");
                break;
            }
        }
        if (parser->current.type == JS_TOKEN_SEMICOLON)
        {
            js_parser_advance(parser);
        }
    }
    if (parser->had_error || !js_parser_expect(parser, JS_TOKEN_RBRACE, "expected '}'"))
    {
        js_expr_destroy(base, parser->use_arena);
        js_parser_free(parser, name);
        js_expr_destroy(constructor, parser->use_arena);
        for (size_t i = 0; i < methods.count; ++i)
        {
            if (methods.items[i].computed)
            {
                js_expr_destroy(methods.items[i].name_expr, parser->use_arena);
            }
            else
            {
                js_parser_free(parser, methods.items[i].name);
            }
            js_expr_destroy(methods.items[i].value, parser->use_arena);
        }
        js_parser_free(parser, methods.items);
        return NULL;
    }

    if (!constructor)
    {
        js_expr_t *default_ctor = js_new_expr(parser, JS_EXPR_FUNCTION);
        if (!default_ctor)
        {
            js_expr_destroy(base, parser->use_arena);
            js_parser_free(parser, name);
            for (size_t i = 0; i < methods.count; ++i)
            {
                if (methods.items[i].computed)
                {
                    js_expr_destroy(methods.items[i].name_expr, parser->use_arena);
                }
                else
                {
                    js_parser_free(parser, methods.items[i].name);
                }
                js_expr_destroy(methods.items[i].value, parser->use_arena);
            }
            js_parser_free(parser, methods.items);
            js_parser_error(parser, offset, "allocation failed");
            return NULL;
        }
        memset(&default_ctor->as.func, 0, sizeof(default_ctor->as.func));
        default_ctor->as.func.is_arrow = false;
        default_ctor->as.func.is_generator = false;
        constructor = default_ctor;
    }

    js_expr_t *expr = js_new_expr(parser, JS_EXPR_CLASS);
    if (!expr)
    {
        js_expr_destroy(base, parser->use_arena);
        js_parser_free(parser, name);
        js_expr_destroy(constructor, parser->use_arena);
        for (size_t i = 0; i < methods.count; ++i)
        {
            if (methods.items[i].computed)
            {
                js_expr_destroy(methods.items[i].name_expr, parser->use_arena);
            }
            else
            {
                js_parser_free(parser, methods.items[i].name);
            }
            js_expr_destroy(methods.items[i].value, parser->use_arena);
        }
        js_parser_free(parser, methods.items);
        js_parser_error(parser, offset, "allocation failed");
        return NULL;
    }
    expr->as.class_expr.name = name;
    expr->as.class_expr.base = base;
    expr->as.class_expr.constructor = constructor;
    expr->as.class_expr.methods = methods.items;
    expr->as.class_expr.method_count = methods.count;
    return expr;
}

static js_expr_t *js_parse_class_expression(js_parser_t *parser)
{
    return js_parse_class_common(parser, false, NULL);
}

static js_stmt_t *js_parse_class_decl(js_parser_t *parser)
{
    if (!parser)
    {
        return NULL;
    }
    size_t offset = parser->current.offset;
    char *binding_name = NULL;
    js_expr_t *init = js_parse_class_common(parser, true, &binding_name);
    if (!init)
    {
        return NULL;
    }
    if (!js_parser_consume_semicolon(parser))
    {
        js_expr_destroy(init, parser->use_arena);
        js_parser_free(parser, binding_name);
        return NULL;
    }
    if (!binding_name)
    {
        js_expr_destroy(init, parser->use_arena);
        js_parser_error(parser, offset, "expected class name");
        return NULL;
    }
    js_binding_t *binding = js_new_binding(parser, JS_BINDING_IDENTIFIER);
    if (!binding)
    {
        js_expr_destroy(init, parser->use_arena);
        js_parser_free(parser, binding_name);
        js_parser_error(parser, offset, "allocation failed");
        return NULL;
    }
    binding->as.ident.name = binding_name;

    js_var_binding_t entry = {0};
    entry.binding = binding;
    entry.init = init;

    js_var_list_t list = {0};
    if (!js_var_list_push(parser, &list, &entry))
    {
        js_expr_destroy(init, parser->use_arena);
        js_binding_destroy(binding, parser->use_arena);
        js_parser_error(parser, offset, "allocation failed");
        return NULL;
    }
    js_stmt_t *stmt = js_new_stmt(parser, JS_STMT_VAR);
    if (!stmt)
    {
        for (size_t i = 0; i < list.count; ++i)
        {
            js_binding_destroy(list.items[i].binding, parser->use_arena);
            js_expr_destroy(list.items[i].init, parser->use_arena);
        }
        js_parser_free(parser, list.items);
        js_parser_error(parser, offset, "allocation failed");
        return NULL;
    }
    stmt->as.var.kind = JS_VAR_LET;
    stmt->as.var.bindings = list.items;
    stmt->as.var.count = list.count;
    return stmt;
}

static js_expr_t *js_parse_primary(js_parser_t *parser)
{
    if (!parser)
    {
        return NULL;
    }
    if (js_token_is_identifier(&parser->current, "async") &&
        js_parser_peek_async_arrow(parser))
    {
        js_parser_advance(parser);
        return js_parse_arrow_function(parser, true);
    }
    if (parser->current.type == JS_TOKEN_IDENTIFIER && js_parser_peek_arrow_after_ident(parser))
    {
        return js_parse_arrow_function(parser, false);
    }
    if (parser->current.type == JS_TOKEN_IDENTIFIER &&
        parser->current.text &&
        strcmp(parser->current.text, "class") == 0)
    {
        return js_parse_class_expression(parser);
    }
    if (parser->current.type == JS_TOKEN_LPAREN && js_parser_peek_arrow_after_paren(parser))
    {
        return js_parse_arrow_function(parser, false);
    }
    if (js_token_is_identifier(&parser->current, "async") &&
        js_parser_peek_async_function(parser))
    {
        size_t offset = parser->current.offset;
        js_parser_advance(parser);
        if (!js_parser_expect(parser, JS_TOKEN_KW_FUNCTION, "expected 'function'"))
        {
            return NULL;
        }
        js_function_expr_t func = {0};
        if (!js_parse_function_common(parser, false, &func, true))
        {
            return NULL;
        }
        js_expr_t *expr = js_new_expr(parser, JS_EXPR_FUNCTION);
        if (!expr)
        {
            js_parser_free(parser, func.name);
            for (size_t p = 0; p < func.param_count; ++p)
            {
                js_binding_destroy(func.params[p].binding, parser->use_arena);
                js_expr_destroy(func.params[p].init, parser->use_arena);
            }
            js_parser_free(parser, func.params);
            for (size_t i = 0; i < func.body.count; ++i)
            {
                js_stmt_destroy(func.body.stmts[i], parser->use_arena);
            }
            js_parser_free(parser, func.body.stmts);
            js_parser_error(parser, offset, "allocation failed");
            return NULL;
        }
        expr->as.func = func;
        return expr;
    }
    switch (parser->current.type)
    {
        case JS_TOKEN_SLASH:
        {
            return js_parse_regex_literal(parser);
        }
        case JS_TOKEN_NUMBER:
        {
            js_expr_t *expr = js_new_expr(parser, JS_EXPR_LITERAL);
            if (!expr)
            {
                js_parser_error(parser, parser->current.offset, "allocation failed");
                return NULL;
            }
            expr->as.literal.value = js_value_make_number(parser->current.number);
            js_parser_advance(parser);
            return expr;
        }
        case JS_TOKEN_BIGINT:
        {
            js_expr_t *expr = js_new_expr(parser, JS_EXPR_LITERAL);
            if (!expr)
            {
                js_parser_error(parser, parser->current.offset, "allocation failed");
                return NULL;
            }
            char *text = js_token_take_text(&parser->current);
            bool ok = false;
            if (text)
            {
                const char *digits = text;
                int base = 10;
                if (digits[0] == '0' && (digits[1] == 'x' || digits[1] == 'X'))
                {
                    base = 16;
                    digits += 2;
                }
                else if (digits[0] == '0' && (digits[1] == 'b' || digits[1] == 'B'))
                {
                    base = 2;
                    digits += 2;
                }
                else if (digits[0] == '0' && (digits[1] == 'o' || digits[1] == 'O'))
                {
                    base = 8;
                    digits += 2;
                }
                ok = js_value_make_bigint(&expr->as.literal.value, digits, base);
            }
            js_parser_free(parser, text);
            if (!ok)
            {
                js_expr_destroy(expr, parser->use_arena);
                js_parser_error(parser, parser->current.offset, "invalid bigint literal");
                return NULL;
            }
            js_parser_advance(parser);
            return expr;
        }
        case JS_TOKEN_STRING:
        {
            js_expr_t *expr = js_new_expr(parser, JS_EXPR_LITERAL);
            if (!expr)
            {
                js_parser_error(parser, parser->current.offset, "allocation failed");
                return NULL;
            }
            size_t len = parser->current.length;
            char *text = js_token_take_text(&parser->current);
            expr->as.literal.value.type = JS_VALUE_STRING;
            expr->as.literal.value.as.string.data = text;
            expr->as.literal.value.as.string.len = len;
            js_parser_advance(parser);
            return expr;
        }
        case JS_TOKEN_BACKTICK:
        {
            return js_parse_template_literal(parser);
        }
        case JS_TOKEN_KW_TRUE:
        case JS_TOKEN_KW_FALSE:
        {
            js_expr_t *expr = js_new_expr(parser, JS_EXPR_LITERAL);
            if (!expr)
            {
                js_parser_error(parser, parser->current.offset, "allocation failed");
                return NULL;
            }
            bool value = (parser->current.type == JS_TOKEN_KW_TRUE);
            expr->as.literal.value = js_value_make_bool(value);
            js_parser_advance(parser);
            return expr;
        }
        case JS_TOKEN_KW_NULL:
        {
            js_expr_t *expr = js_new_expr(parser, JS_EXPR_LITERAL);
            if (!expr)
            {
                js_parser_error(parser, parser->current.offset, "allocation failed");
                return NULL;
            }
            expr->as.literal.value = js_value_make_null();
            js_parser_advance(parser);
            return expr;
        }
        case JS_TOKEN_KW_UNDEFINED:
        {
            js_expr_t *expr = js_new_expr(parser, JS_EXPR_LITERAL);
            if (!expr)
            {
                js_parser_error(parser, parser->current.offset, "allocation failed");
                return NULL;
            }
            expr->as.literal.value = js_value_make_undefined();
            js_parser_advance(parser);
            return expr;
        }
        case JS_TOKEN_KW_THIS:
        {
            js_expr_t *expr = js_new_expr(parser, JS_EXPR_THIS);
            if (!expr)
            {
                js_parser_error(parser, parser->current.offset, "allocation failed");
                return NULL;
            }
            js_parser_advance(parser);
            return expr;
        }
        case JS_TOKEN_IDENTIFIER:
        {
            js_expr_t *expr = js_new_expr(parser, JS_EXPR_IDENTIFIER);
            if (!expr)
            {
                js_parser_error(parser, parser->current.offset, "allocation failed");
                return NULL;
            }
            expr->as.ident.name = js_token_take_text(&parser->current);
            js_parser_advance(parser);
            return expr;
        }
        case JS_TOKEN_LBRACKET:
        {
            size_t offset = parser->current.offset;
            js_parser_advance(parser);
            js_expr_list_t items = {0};
            if (parser->current.type != JS_TOKEN_RBRACKET)
            {
                for (;;)
                {
                    js_expr_t *item = js_parse_expression(parser);
                    if (!item)
                    {
                        for (size_t i = 0; i < items.count; ++i)
                        {
                            js_expr_destroy(items.items[i], parser->use_arena);
                        }
                        js_parser_free(parser, items.items);
                        return NULL;
                    }
                    if (!js_expr_list_push(parser, &items, item))
                    {
                        js_expr_destroy(item, parser->use_arena);
                        for (size_t i = 0; i < items.count; ++i)
                        {
                            js_expr_destroy(items.items[i], parser->use_arena);
                        }
                        js_parser_free(parser, items.items);
                        js_parser_error(parser, parser->current.offset, "allocation failed");
                        return NULL;
                    }
                    if (parser->current.type == JS_TOKEN_COMMA)
                    {
                        js_parser_advance(parser);
                        if (parser->current.type == JS_TOKEN_RBRACKET)
                        {
                            break;
                        }
                        continue;
                    }
                    break;
                }
            }
            if (!js_parser_expect(parser, JS_TOKEN_RBRACKET, "expected ']'") )
            {
                for (size_t i = 0; i < items.count; ++i)
                {
                    js_expr_destroy(items.items[i], parser->use_arena);
                }
                js_parser_free(parser, items.items);
                return NULL;
            }
            js_expr_t *expr = js_new_expr(parser, JS_EXPR_ARRAY);
            if (!expr)
            {
                for (size_t i = 0; i < items.count; ++i)
                {
                    js_expr_destroy(items.items[i], parser->use_arena);
                }
                js_parser_free(parser, items.items);
                js_parser_error(parser, offset, "allocation failed");
                return NULL;
            }
            expr->as.array.items = items.items;
            expr->as.array.count = items.count;
            return expr;
        }
        case JS_TOKEN_LBRACE:
        {
            size_t offset = parser->current.offset;
            js_parser_advance(parser);
            js_prop_list_t props = {0};
            if (parser->current.type != JS_TOKEN_RBRACE)
            {
                for (;;)
                {
                    js_object_property_t prop = {0};
                    bool is_accessor = false;
                    bool accessor_is_getter = false;
                    bool method_async = false;
                    bool allow_shorthand = false;
                    bool parsed = false;
                    if (parser->current.type == JS_TOKEN_ELLIPSIS)
                    {
                        js_parser_advance(parser);
                        js_expr_t *spread_expr = js_parse_expression(parser);
                        if (!spread_expr)
                        {
                            break;
                        }
                        prop.is_spread = true;
                        prop.value = spread_expr;
                        parsed = true;
                    }
                    if (!parsed &&
                        js_token_is_identifier(&parser->current, "async") &&
                        js_parser_peek_async_method(parser))
                    {
                        method_async = true;
                        js_parser_advance(parser);
                    }
                    if (!parsed &&
                        parser->current.type == JS_TOKEN_IDENTIFIER &&
                        js_parser_peek_accessor(parser))
                    {
                        accessor_is_getter = (strcmp(parser->current.text, "get") == 0);
                        is_accessor = true;
                        js_parser_advance(parser);
                    }
                    if (parsed)
                    {
                        if (!js_prop_list_push(parser, &props, &prop))
                        {
                            js_expr_destroy(prop.value, parser->use_arena);
                            js_parser_error(parser, parser->current.offset, "allocation failed");
                            break;
                        }
                        if (parser->current.type == JS_TOKEN_COMMA)
                        {
                            js_parser_advance(parser);
                            if (parser->current.type == JS_TOKEN_RBRACE)
                            {
                                break;
                            }
                            continue;
                        }
                        break;
                    }
                    if (parser->current.type == JS_TOKEN_LBRACKET)
                    {
                        prop.computed = true;
                        js_parser_advance(parser);
                        js_expr_t *name_expr = js_parse_expression(parser);
                        if (!name_expr)
                        {
                            break;
                        }
                        if (!js_parser_expect(parser, JS_TOKEN_RBRACKET, "expected ']'"))
                        {
                            js_expr_destroy(name_expr, parser->use_arena);
                            break;
                        }
                        prop.name_expr = name_expr;
                    }
                    else if (parser->current.type == JS_TOKEN_IDENTIFIER)
                    {
                        prop.name = js_token_take_text(&parser->current);
                        allow_shorthand = true;
                        js_parser_advance(parser);
                    }
                    else if (parser->current.type == JS_TOKEN_STRING)
                    {
                        prop.name = js_token_take_text(&parser->current);
                        js_parser_advance(parser);
                    }
                    else if (js_token_is_keyword(parser->current.type))
                    {
                        const char *kw = js_keyword_text(parser->current.type);
                        if (!kw)
                        {
                            js_parser_error(parser, parser->current.offset, "expected property name");
                            break;
                        }
                        prop.name = js_parser_strdup(parser, kw);
                        if (!prop.name)
                        {
                            js_parser_error(parser, parser->current.offset, "allocation failed");
                            break;
                        }
                        js_parser_advance(parser);
                    }
                    else
                    {
                        js_parser_error(parser, parser->current.offset, "expected property name");
                        break;
                    }

                    if (is_accessor)
                    {
                        js_function_expr_t func = {0};
                        if (!js_parse_function_tail(parser, &func, method_async))
                        {
                            if (prop.computed)
                            {
                                js_expr_destroy(prop.name_expr, parser->use_arena);
                            }
                            else
                            {
                                js_parser_free(parser, prop.name);
                            }
                            break;
                        }
                        js_expr_t *fn_expr = js_new_expr(parser, JS_EXPR_FUNCTION);
                        if (!fn_expr)
                        {
                            if (prop.computed)
                            {
                                js_expr_destroy(prop.name_expr, parser->use_arena);
                            }
                            else
                            {
                                js_parser_free(parser, prop.name);
                            }
                            for (size_t p = 0; p < func.param_count; ++p)
                            {
                                js_binding_destroy(func.params[p].binding, parser->use_arena);
                                js_expr_destroy(func.params[p].init, parser->use_arena);
                            }
                            js_parser_free(parser, func.params);
                            for (size_t i = 0; i < func.body.count; ++i)
                            {
                                js_stmt_destroy(func.body.stmts[i], parser->use_arena);
                            }
                            js_parser_free(parser, func.body.stmts);
                            js_parser_error(parser, parser->current.offset, "allocation failed");
                            break;
                        }
                        fn_expr->as.func = func;
                        fn_expr->as.func.is_arrow = false;
                        prop.value = fn_expr;
                        prop.is_getter = accessor_is_getter;
                        prop.is_setter = !accessor_is_getter;
                    }
                    else if (parser->current.type == JS_TOKEN_LPAREN)
                    {
                        js_function_expr_t func = {0};
                        if (!js_parse_function_tail(parser, &func, method_async))
                        {
                            if (prop.computed)
                            {
                                js_expr_destroy(prop.name_expr, parser->use_arena);
                            }
                            else
                            {
                                js_parser_free(parser, prop.name);
                            }
                            break;
                        }
                        js_expr_t *fn_expr = js_new_expr(parser, JS_EXPR_FUNCTION);
                        if (!fn_expr)
                        {
                            if (prop.computed)
                            {
                                js_expr_destroy(prop.name_expr, parser->use_arena);
                            }
                            else
                            {
                                js_parser_free(parser, prop.name);
                            }
                            for (size_t p = 0; p < func.param_count; ++p)
                            {
                                js_binding_destroy(func.params[p].binding, parser->use_arena);
                                js_expr_destroy(func.params[p].init, parser->use_arena);
                            }
                            js_parser_free(parser, func.params);
                            for (size_t i = 0; i < func.body.count; ++i)
                            {
                                js_stmt_destroy(func.body.stmts[i], parser->use_arena);
                            }
                            js_parser_free(parser, func.body.stmts);
                            js_parser_error(parser, parser->current.offset, "allocation failed");
                            break;
                        }
                        fn_expr->as.func = func;
                        fn_expr->as.func.is_arrow = false;
                        prop.value = fn_expr;
                    }
                    else if (parser->current.type == JS_TOKEN_COLON)
                    {
                        js_parser_advance(parser);
                        js_expr_t *value = js_parse_expression(parser);
                        if (!value)
                        {
                            if (prop.computed)
                            {
                                js_expr_destroy(prop.name_expr, parser->use_arena);
                            }
                            else
                            {
                                js_parser_free(parser, prop.name);
                            }
                            break;
                        }
                        prop.value = value;
                    }
                    else if (!prop.computed && prop.name &&
                             allow_shorthand &&
                             (parser->current.type == JS_TOKEN_COMMA ||
                              parser->current.type == JS_TOKEN_RBRACE))
                    {
                        js_expr_t *value = js_new_expr(parser, JS_EXPR_IDENTIFIER);
                        if (!value)
                        {
                            js_parser_free(parser, prop.name);
                            js_parser_error(parser, parser->current.offset, "allocation failed");
                            break;
                        }
                        value->as.ident.name = js_parser_strdup(parser, prop.name);
                        if (!value->as.ident.name)
                        {
                            js_expr_destroy(value, parser->use_arena);
                            js_parser_free(parser, prop.name);
                            js_parser_error(parser, parser->current.offset, "allocation failed");
                            break;
                        }
                        prop.value = value;
                    }
                    else
                    {
                        js_parser_error(parser, parser->current.offset, "expected ':'");
                        if (prop.computed)
                        {
                            js_expr_destroy(prop.name_expr, parser->use_arena);
                        }
                        else
                        {
                            js_parser_free(parser, prop.name);
                        }
                        break;
                    }

                    if (!js_prop_list_push(parser, &props, &prop))
                    {
                        if (prop.computed)
                        {
                            js_expr_destroy(prop.name_expr, parser->use_arena);
                        }
                        else
                        {
                            js_parser_free(parser, prop.name);
                        }
                        js_expr_destroy(prop.value, parser->use_arena);
                        js_parser_error(parser, parser->current.offset, "allocation failed");
                        break;
                    }
                    if (parser->current.type == JS_TOKEN_COMMA)
                    {
                        js_parser_advance(parser);
                        if (parser->current.type == JS_TOKEN_RBRACE)
                        {
                            break;
                        }
                        continue;
                    }
                    break;
                }
            }
            if (parser->had_error || !js_parser_expect(parser, JS_TOKEN_RBRACE, "expected '}'"))
            {
                for (size_t i = 0; i < props.count; ++i)
                {
                    if (props.items[i].computed)
                    {
                        js_expr_destroy(props.items[i].name_expr, parser->use_arena);
                    }
                    else
                    {
                        js_parser_free(parser, props.items[i].name);
                    }
                    js_expr_destroy(props.items[i].value, parser->use_arena);
                }
                js_parser_free(parser, props.items);
                return NULL;
            }
            js_expr_t *expr = js_new_expr(parser, JS_EXPR_OBJECT);
            if (!expr)
            {
                for (size_t i = 0; i < props.count; ++i)
                {
                    if (props.items[i].computed)
                    {
                        js_expr_destroy(props.items[i].name_expr, parser->use_arena);
                    }
                    else
                    {
                        js_parser_free(parser, props.items[i].name);
                    }
                    js_expr_destroy(props.items[i].value, parser->use_arena);
                }
                js_parser_free(parser, props.items);
                js_parser_error(parser, offset, "allocation failed");
                return NULL;
            }
            expr->as.object.props = props.items;
            expr->as.object.count = props.count;
            return expr;
        }
        case JS_TOKEN_KW_FUNCTION:
        {
            size_t offset = parser->current.offset;
            js_parser_advance(parser);
            js_function_expr_t func = {0};
            if (!js_parse_function_common(parser, false, &func, false))
            {
                return NULL;
            }
            js_expr_t *expr = js_new_expr(parser, JS_EXPR_FUNCTION);
            if (!expr)
            {
                js_parser_free(parser, func.name);
                for (size_t p = 0; p < func.param_count; ++p)
                {
                    js_binding_destroy(func.params[p].binding, parser->use_arena);
                    js_expr_destroy(func.params[p].init, parser->use_arena);
                }
                js_parser_free(parser, func.params);
                for (size_t i = 0; i < func.body.count; ++i)
                {
                    js_stmt_destroy(func.body.stmts[i], parser->use_arena);
                }
                js_parser_free(parser, func.body.stmts);
                js_parser_error(parser, offset, "allocation failed");
                return NULL;
            }
            expr->as.func = func;
            return expr;
        }
        case JS_TOKEN_LPAREN:
        {
            js_parser_advance(parser);
            js_expr_t *expr = js_parse_expression(parser);
            if (!expr)
            {
                return NULL;
            }
            if (!js_parser_expect(parser, JS_TOKEN_RPAREN, "expected ')'") )
            {
                js_expr_destroy(expr, parser->use_arena);
                return NULL;
            }
            return expr;
        }
        default:
            js_parser_error(parser, parser->current.offset, "expected expression");
            return NULL;
    }
}

static js_expr_t *js_parse_member_suffix(js_parser_t *parser, js_expr_t *expr)
{
    if (!parser || !expr)
    {
        return NULL;
    }
    for (;;)
    {
        if (js_parser_match(parser, JS_TOKEN_DOT))
        {
            if (parser->current.type != JS_TOKEN_IDENTIFIER)
            {
                js_expr_destroy(expr, parser->use_arena);
                js_parser_error(parser, parser->current.offset, "expected property name");
                return NULL;
            }
            char *name = js_token_take_text(&parser->current);
            js_parser_advance(parser);
            js_expr_t *member = js_new_expr(parser, JS_EXPR_MEMBER);
            if (!member)
            {
                js_parser_free(parser, name);
                js_expr_destroy(expr, parser->use_arena);
                js_parser_error(parser, parser->current.offset, "allocation failed");
                return NULL;
            }
            member->as.member.object = expr;
            member->as.member.computed = false;
            member->as.member.optional = false;
            member->as.member.property = name;
            member->as.member.property_expr = NULL;
            expr = member;
            continue;
        }

        if (js_parser_match(parser, JS_TOKEN_LBRACKET))
        {
            js_expr_t *prop_expr = js_parse_expression(parser);
            if (!prop_expr)
            {
                js_expr_destroy(expr, parser->use_arena);
                return NULL;
            }
            if (!js_parser_expect(parser, JS_TOKEN_RBRACKET, "expected ']'") )
            {
                js_expr_destroy(prop_expr, parser->use_arena);
                js_expr_destroy(expr, parser->use_arena);
                return NULL;
            }
            js_expr_t *member = js_new_expr(parser, JS_EXPR_MEMBER);
            if (!member)
            {
                js_expr_destroy(prop_expr, parser->use_arena);
                js_expr_destroy(expr, parser->use_arena);
                js_parser_error(parser, parser->current.offset, "allocation failed");
                return NULL;
            }
            member->as.member.object = expr;
            member->as.member.computed = true;
            member->as.member.optional = false;
            member->as.member.property = NULL;
            member->as.member.property_expr = prop_expr;
            expr = member;
            continue;
        }

        if (js_parser_match(parser, JS_TOKEN_QDOT))
        {
            if (js_parser_match(parser, JS_TOKEN_LBRACKET))
            {
                js_expr_t *prop_expr = js_parse_expression(parser);
                if (!prop_expr)
                {
                    js_expr_destroy(expr, parser->use_arena);
                    return NULL;
                }
                if (!js_parser_expect(parser, JS_TOKEN_RBRACKET, "expected ']'"))
                {
                    js_expr_destroy(prop_expr, parser->use_arena);
                    js_expr_destroy(expr, parser->use_arena);
                    return NULL;
                }
                js_expr_t *member = js_new_expr(parser, JS_EXPR_MEMBER);
                if (!member)
                {
                    js_expr_destroy(prop_expr, parser->use_arena);
                    js_expr_destroy(expr, parser->use_arena);
                    js_parser_error(parser, parser->current.offset, "allocation failed");
                    return NULL;
                }
                member->as.member.object = expr;
                member->as.member.computed = true;
                member->as.member.optional = true;
                member->as.member.property = NULL;
                member->as.member.property_expr = prop_expr;
                expr = member;
                continue;
            }

            if (parser->current.type != JS_TOKEN_IDENTIFIER)
            {
                js_expr_destroy(expr, parser->use_arena);
                js_parser_error(parser, parser->current.offset, "expected property name");
                return NULL;
            }
            char *name = js_token_take_text(&parser->current);
            js_parser_advance(parser);
            js_expr_t *member = js_new_expr(parser, JS_EXPR_MEMBER);
            if (!member)
            {
                js_parser_free(parser, name);
                js_expr_destroy(expr, parser->use_arena);
                js_parser_error(parser, parser->current.offset, "allocation failed");
                return NULL;
            }
            member->as.member.object = expr;
            member->as.member.computed = false;
            member->as.member.optional = true;
            member->as.member.property = name;
            member->as.member.property_expr = NULL;
            expr = member;
            continue;
        }

        break;
    }

    return expr;
}

static js_expr_t *js_parse_call(js_parser_t *parser)
{
    js_expr_t *expr = js_parse_primary(parser);
    if (!expr)
    {
        return NULL;
    }

    for (;;)
    {
        if (js_parser_match(parser, JS_TOKEN_DOT))
        {
            if (parser->current.type != JS_TOKEN_IDENTIFIER)
            {
                js_expr_destroy(expr, parser->use_arena);
                js_parser_error(parser, parser->current.offset, "expected property name");
                return NULL;
            }
            char *name = js_token_take_text(&parser->current);
            js_parser_advance(parser);
            js_expr_t *member = js_new_expr(parser, JS_EXPR_MEMBER);
            if (!member)
            {
                js_parser_free(parser, name);
                js_expr_destroy(expr, parser->use_arena);
                js_parser_error(parser, parser->current.offset, "allocation failed");
                return NULL;
            }
            member->as.member.object = expr;
            member->as.member.computed = false;
            member->as.member.optional = false;
            member->as.member.property = name;
            member->as.member.property_expr = NULL;
            expr = member;
            continue;
        }

        if (js_parser_match(parser, JS_TOKEN_LBRACKET))
        {
            js_expr_t *prop_expr = js_parse_expression(parser);
            if (!prop_expr)
            {
                js_expr_destroy(expr, parser->use_arena);
                return NULL;
            }
            if (!js_parser_expect(parser, JS_TOKEN_RBRACKET, "expected ']'"))
            {
                js_expr_destroy(prop_expr, parser->use_arena);
                js_expr_destroy(expr, parser->use_arena);
                return NULL;
            }
            js_expr_t *member = js_new_expr(parser, JS_EXPR_MEMBER);
            if (!member)
            {
                js_expr_destroy(prop_expr, parser->use_arena);
                js_expr_destroy(expr, parser->use_arena);
                js_parser_error(parser, parser->current.offset, "allocation failed");
                return NULL;
            }
            member->as.member.object = expr;
            member->as.member.computed = true;
            member->as.member.optional = false;
            member->as.member.property = NULL;
            member->as.member.property_expr = prop_expr;
            expr = member;
            continue;
        }

        if (js_parser_match(parser, JS_TOKEN_LPAREN))
        {
            js_expr_list_t args = {0};
            if (parser->current.type != JS_TOKEN_RPAREN)
            {
                for (;;)
                {
                    js_expr_t *arg = js_parse_expression(parser);
                    if (!arg)
                    {
                        for (size_t i = 0; i < args.count; ++i)
                        {
                            js_expr_destroy(args.items[i], parser->use_arena);
                        }
                        js_parser_free(parser, args.items);
                        js_expr_destroy(expr, parser->use_arena);
                        return NULL;
                    }
                    if (!js_expr_list_push(parser, &args, arg))
                    {
                        js_expr_destroy(arg, parser->use_arena);
                        for (size_t i = 0; i < args.count; ++i)
                        {
                            js_expr_destroy(args.items[i], parser->use_arena);
                        }
                        js_parser_free(parser, args.items);
                        js_expr_destroy(expr, parser->use_arena);
                        js_parser_error(parser, parser->current.offset, "allocation failed");
                        return NULL;
                    }
                    if (parser->current.type == JS_TOKEN_COMMA)
                    {
                        js_parser_advance(parser);
                        continue;
                    }
                    break;
                }
            }

            if (!js_parser_expect(parser, JS_TOKEN_RPAREN, "expected ')'"))
            {
                for (size_t i = 0; i < args.count; ++i)
                {
                    js_expr_destroy(args.items[i], parser->use_arena);
                }
                js_parser_free(parser, args.items);
                js_expr_destroy(expr, parser->use_arena);
                return NULL;
            }

            js_expr_t *call = js_new_expr(parser, JS_EXPR_CALL);
            if (!call)
            {
                for (size_t i = 0; i < args.count; ++i)
                {
                    js_expr_destroy(args.items[i], parser->use_arena);
                }
                js_parser_free(parser, args.items);
                js_expr_destroy(expr, parser->use_arena);
                js_parser_error(parser, parser->current.offset, "allocation failed");
                return NULL;
            }
            call->as.call.callee = expr;
            call->as.call.args = args.items;
            call->as.call.arg_count = args.count;
            call->as.call.optional = false;
            expr = call;
            continue;
        }

        if (js_parser_match(parser, JS_TOKEN_QDOT))
        {
            if (parser->current.type == JS_TOKEN_LPAREN)
            {
                js_parser_advance(parser);
                js_expr_list_t args = {0};
                if (parser->current.type != JS_TOKEN_RPAREN)
                {
                    for (;;)
                    {
                        js_expr_t *arg = js_parse_expression(parser);
                        if (!arg)
                        {
                            for (size_t i = 0; i < args.count; ++i)
                            {
                                js_expr_destroy(args.items[i], parser->use_arena);
                            }
                            js_parser_free(parser, args.items);
                            js_expr_destroy(expr, parser->use_arena);
                            return NULL;
                        }
                        if (!js_expr_list_push(parser, &args, arg))
                        {
                            js_expr_destroy(arg, parser->use_arena);
                            for (size_t i = 0; i < args.count; ++i)
                            {
                                js_expr_destroy(args.items[i], parser->use_arena);
                            }
                            js_parser_free(parser, args.items);
                            js_expr_destroy(expr, parser->use_arena);
                            js_parser_error(parser, parser->current.offset, "allocation failed");
                            return NULL;
                        }
                        if (parser->current.type == JS_TOKEN_COMMA)
                        {
                            js_parser_advance(parser);
                            continue;
                        }
                        break;
                    }
                }

                if (!js_parser_expect(parser, JS_TOKEN_RPAREN, "expected ')'"))
                {
                    for (size_t i = 0; i < args.count; ++i)
                    {
                        js_expr_destroy(args.items[i], parser->use_arena);
                    }
                    js_parser_free(parser, args.items);
                    js_expr_destroy(expr, parser->use_arena);
                    return NULL;
                }

                js_expr_t *call = js_new_expr(parser, JS_EXPR_CALL);
                if (!call)
                {
                    for (size_t i = 0; i < args.count; ++i)
                    {
                        js_expr_destroy(args.items[i], parser->use_arena);
                    }
                    js_parser_free(parser, args.items);
                    js_expr_destroy(expr, parser->use_arena);
                    js_parser_error(parser, parser->current.offset, "allocation failed");
                    return NULL;
                }
                call->as.call.callee = expr;
                call->as.call.args = args.items;
                call->as.call.arg_count = args.count;
                call->as.call.optional = true;
                expr = call;
                continue;
            }

            if (parser->current.type == JS_TOKEN_LBRACKET)
            {
                js_parser_advance(parser);
                js_expr_t *prop_expr = js_parse_expression(parser);
                if (!prop_expr)
                {
                    js_expr_destroy(expr, parser->use_arena);
                    return NULL;
                }
                if (!js_parser_expect(parser, JS_TOKEN_RBRACKET, "expected ']'"))
                {
                    js_expr_destroy(prop_expr, parser->use_arena);
                    js_expr_destroy(expr, parser->use_arena);
                    return NULL;
                }
                js_expr_t *member = js_new_expr(parser, JS_EXPR_MEMBER);
                if (!member)
                {
                    js_expr_destroy(prop_expr, parser->use_arena);
                    js_expr_destroy(expr, parser->use_arena);
                    js_parser_error(parser, parser->current.offset, "allocation failed");
                    return NULL;
                }
                member->as.member.object = expr;
                member->as.member.computed = true;
                member->as.member.optional = true;
                member->as.member.property = NULL;
                member->as.member.property_expr = prop_expr;
                expr = member;
                continue;
            }

            if (parser->current.type != JS_TOKEN_IDENTIFIER)
            {
                js_expr_destroy(expr, parser->use_arena);
                js_parser_error(parser, parser->current.offset, "expected property name");
                return NULL;
            }
            char *name = js_token_take_text(&parser->current);
            js_parser_advance(parser);
            js_expr_t *member = js_new_expr(parser, JS_EXPR_MEMBER);
            if (!member)
            {
                js_parser_free(parser, name);
                js_expr_destroy(expr, parser->use_arena);
                js_parser_error(parser, parser->current.offset, "allocation failed");
                return NULL;
            }
            member->as.member.object = expr;
            member->as.member.computed = false;
            member->as.member.optional = true;
            member->as.member.property = name;
            member->as.member.property_expr = NULL;
            expr = member;
            continue;
        }
        break;
    }

    return expr;
}

static js_expr_t *js_parse_unary(js_parser_t *parser)
{
    if (!parser)
    {
        return NULL;
    }
    if (parser->in_async && js_token_is_identifier(&parser->current, "await"))
    {
        size_t offset = parser->current.offset;
        js_parser_advance(parser);
        js_expr_t *value = js_parse_unary(parser);
        if (!value)
        {
            return NULL;
        }
        js_expr_t *expr = js_new_expr(parser, JS_EXPR_AWAIT);
        if (!expr)
        {
            js_expr_destroy(value, parser->use_arena);
            js_parser_error(parser, offset, "allocation failed");
            return NULL;
        }
        expr->as.await.value = value;
        return expr;
    }
    if (parser->current.type == JS_TOKEN_PLUS_PLUS ||
        parser->current.type == JS_TOKEN_MINUS_MINUS)
    {
        bool increment = (parser->current.type == JS_TOKEN_PLUS_PLUS);
        size_t offset = parser->current.offset;
        js_parser_advance(parser);
        js_expr_t *target = js_parse_unary(parser);
        if (!target)
        {
            return NULL;
        }
        js_expr_t *expr = js_new_expr(parser, JS_EXPR_UPDATE);
        if (!expr)
        {
            js_expr_destroy(target, parser->use_arena);
            js_parser_error(parser, offset, "allocation failed");
            return NULL;
        }
        expr->as.update.is_prefix = true;
        expr->as.update.is_increment = increment;
        expr->as.update.target = target;
        return expr;
    }
    if (parser->current.type == JS_TOKEN_KW_NEW)
    {
        size_t offset = parser->current.offset;
        js_parser_advance(parser);
        js_expr_t *callee = js_parse_primary(parser);
        if (!callee)
        {
            return NULL;
        }
        callee = js_parse_member_suffix(parser, callee);
        if (!callee)
        {
            return NULL;
        }
        js_expr_list_t args = {0};
        if (js_parser_match(parser, JS_TOKEN_LPAREN))
        {
            if (parser->current.type != JS_TOKEN_RPAREN)
            {
                for (;;)
                {
                    js_expr_t *arg = js_parse_expression(parser);
                    if (!arg)
                    {
                        for (size_t i = 0; i < args.count; ++i)
                        {
                            js_expr_destroy(args.items[i], parser->use_arena);
                        }
                        js_parser_free(parser, args.items);
                        js_expr_destroy(callee, parser->use_arena);
                        return NULL;
                    }
                    if (!js_expr_list_push(parser, &args, arg))
                    {
                        js_expr_destroy(arg, parser->use_arena);
                        for (size_t i = 0; i < args.count; ++i)
                        {
                            js_expr_destroy(args.items[i], parser->use_arena);
                        }
                        js_parser_free(parser, args.items);
                        js_expr_destroy(callee, parser->use_arena);
                        js_parser_error(parser, parser->current.offset, "allocation failed");
                        return NULL;
                    }
                    if (parser->current.type == JS_TOKEN_COMMA)
                    {
                        js_parser_advance(parser);
                        continue;
                    }
                    break;
                }
            }
            if (!js_parser_expect(parser, JS_TOKEN_RPAREN, "expected ')'") )
            {
                for (size_t i = 0; i < args.count; ++i)
                {
                    js_expr_destroy(args.items[i], parser->use_arena);
                }
                js_parser_free(parser, args.items);
                js_expr_destroy(callee, parser->use_arena);
                return NULL;
            }
        }
        js_expr_t *expr = js_new_expr(parser, JS_EXPR_NEW);
        if (!expr)
        {
            for (size_t i = 0; i < args.count; ++i)
            {
                js_expr_destroy(args.items[i], parser->use_arena);
            }
            js_parser_free(parser, args.items);
            js_expr_destroy(callee, parser->use_arena);
            js_parser_error(parser, offset, "allocation failed");
            return NULL;
        }
        expr->as.new_expr.callee = callee;
        expr->as.new_expr.args = args.items;
        expr->as.new_expr.arg_count = args.count;
        expr = js_parse_member_suffix(parser, expr);
        if (!expr)
        {
            return NULL;
        }
        for (;;)
        {
            if (!js_parser_match(parser, JS_TOKEN_LPAREN))
            {
                break;
            }
            js_expr_list_t call_args = {0};
            if (parser->current.type != JS_TOKEN_RPAREN)
            {
                for (;;)
                {
                    js_expr_t *arg = js_parse_expression(parser);
                    if (!arg)
                    {
                        for (size_t i = 0; i < call_args.count; ++i)
                        {
                            js_expr_destroy(call_args.items[i], parser->use_arena);
                        }
                        js_parser_free(parser, call_args.items);
                        js_expr_destroy(expr, parser->use_arena);
                        return NULL;
                    }
                    if (!js_expr_list_push(parser, &call_args, arg))
                    {
                        js_expr_destroy(arg, parser->use_arena);
                        for (size_t i = 0; i < call_args.count; ++i)
                        {
                            js_expr_destroy(call_args.items[i], parser->use_arena);
                        }
                        js_parser_free(parser, call_args.items);
                        js_expr_destroy(expr, parser->use_arena);
                        js_parser_error(parser, parser->current.offset, "allocation failed");
                        return NULL;
                    }
                    if (parser->current.type == JS_TOKEN_COMMA)
                    {
                        js_parser_advance(parser);
                        continue;
                    }
                    break;
                }
            }
            if (!js_parser_expect(parser, JS_TOKEN_RPAREN, "expected ')'") )
            {
                for (size_t i = 0; i < call_args.count; ++i)
                {
                    js_expr_destroy(call_args.items[i], parser->use_arena);
                }
                js_parser_free(parser, call_args.items);
                js_expr_destroy(expr, parser->use_arena);
                return NULL;
            }
            js_expr_t *call = js_new_expr(parser, JS_EXPR_CALL);
            if (!call)
            {
                for (size_t i = 0; i < call_args.count; ++i)
                {
                    js_expr_destroy(call_args.items[i], parser->use_arena);
                }
                js_parser_free(parser, call_args.items);
                js_expr_destroy(expr, parser->use_arena);
                js_parser_error(parser, parser->current.offset, "allocation failed");
                return NULL;
            }
            call->as.call.callee = expr;
            call->as.call.args = call_args.items;
            call->as.call.arg_count = call_args.count;
            expr = call;
            expr = js_parse_member_suffix(parser, expr);
            if (!expr)
            {
                return NULL;
            }
        }
        return expr;
    }
    if (parser->current.type == JS_TOKEN_BANG ||
        parser->current.type == JS_TOKEN_MINUS ||
        parser->current.type == JS_TOKEN_PLUS ||
        parser->current.type == JS_TOKEN_KW_TYPEOF)
    {
        js_unary_op_t op = JS_UNARY_NOT;
        if (parser->current.type == JS_TOKEN_MINUS)
        {
            op = JS_UNARY_NEGATE;
        }
        else if (parser->current.type == JS_TOKEN_PLUS)
        {
            op = JS_UNARY_POSITIVE;
        }
        else if (parser->current.type == JS_TOKEN_KW_TYPEOF)
        {
            op = JS_UNARY_TYPEOF;
        }
        size_t offset = parser->current.offset;
        js_parser_advance(parser);
        js_expr_t *right = js_parse_unary(parser);
        if (!right)
        {
            return NULL;
        }
        js_expr_t *expr = js_new_expr(parser, JS_EXPR_UNARY);
        if (!expr)
        {
            js_expr_destroy(right, parser->use_arena);
            js_parser_error(parser, offset, "allocation failed");
            return NULL;
        }
        expr->as.unary.op = op;
        expr->as.unary.expr = right;
        return expr;
    }
    js_expr_t *expr = js_parse_call(parser);
    if (!expr)
    {
        return NULL;
    }
    if (parser->current.type == JS_TOKEN_PLUS_PLUS ||
        parser->current.type == JS_TOKEN_MINUS_MINUS)
    {
        bool increment = (parser->current.type == JS_TOKEN_PLUS_PLUS);
        size_t offset = parser->current.offset;
        js_parser_advance(parser);
        js_expr_t *update = js_new_expr(parser, JS_EXPR_UPDATE);
        if (!update)
        {
            js_expr_destroy(expr, parser->use_arena);
            js_parser_error(parser, offset, "allocation failed");
            return NULL;
        }
        update->as.update.is_prefix = false;
        update->as.update.is_increment = increment;
        update->as.update.target = expr;
        return update;
    }
    return expr;
}

static js_expr_t *js_parse_exponent(js_parser_t *parser)
{
    js_expr_t *expr = js_parse_unary(parser);
    if (!expr)
    {
        return NULL;
    }
    if (parser->current.type == JS_TOKEN_STAR_STAR)
    {
        size_t offset = parser->current.offset;
        js_parser_advance(parser);
        js_expr_t *right = js_parse_exponent(parser);
        if (!right)
        {
            js_expr_destroy(expr, parser->use_arena);
            return NULL;
        }
        js_expr_t *binary = js_new_expr(parser, JS_EXPR_BINARY);
        if (!binary)
        {
            js_expr_destroy(expr, parser->use_arena);
            js_expr_destroy(right, parser->use_arena);
            js_parser_error(parser, offset, "allocation failed");
            return NULL;
        }
        binary->as.binary.op = JS_BINARY_EXP;
        binary->as.binary.left = expr;
        binary->as.binary.right = right;
        return binary;
    }
    return expr;
}

static js_expr_t *js_parse_factor(js_parser_t *parser)
{
    js_expr_t *expr = js_parse_exponent(parser);
    if (!expr)
    {
        return NULL;
    }
    for (;;)
    {
        js_binary_op_t op;
        if (parser->current.type == JS_TOKEN_STAR)
        {
            op = JS_BINARY_MUL;
        }
        else if (parser->current.type == JS_TOKEN_SLASH)
        {
            op = JS_BINARY_DIV;
        }
        else if (parser->current.type == JS_TOKEN_PERCENT)
        {
            op = JS_BINARY_MOD;
        }
        else
        {
            break;
        }
        size_t offset = parser->current.offset;
        js_parser_advance(parser);
        js_expr_t *right = js_parse_exponent(parser);
        if (!right)
        {
            js_expr_destroy(expr, parser->use_arena);
            return NULL;
        }
        js_expr_t *binary = js_new_expr(parser, JS_EXPR_BINARY);
        if (!binary)
        {
            js_expr_destroy(expr, parser->use_arena);
            js_expr_destroy(right, parser->use_arena);
            js_parser_error(parser, offset, "allocation failed");
            return NULL;
        }
        binary->as.binary.op = op;
        binary->as.binary.left = expr;
        binary->as.binary.right = right;
        expr = binary;
    }
    return expr;
}

static js_expr_t *js_parse_term(js_parser_t *parser)
{
    js_expr_t *expr = js_parse_factor(parser);
    if (!expr)
    {
        return NULL;
    }
    for (;;)
    {
        js_binary_op_t op;
        if (parser->current.type == JS_TOKEN_PLUS)
        {
            op = JS_BINARY_ADD;
        }
        else if (parser->current.type == JS_TOKEN_MINUS)
        {
            op = JS_BINARY_SUB;
        }
        else
        {
            break;
        }
        size_t offset = parser->current.offset;
        js_parser_advance(parser);
        js_expr_t *right = js_parse_factor(parser);
        if (!right)
        {
            js_expr_destroy(expr, parser->use_arena);
            return NULL;
        }
        js_expr_t *binary = js_new_expr(parser, JS_EXPR_BINARY);
        if (!binary)
        {
            js_expr_destroy(expr, parser->use_arena);
            js_expr_destroy(right, parser->use_arena);
            js_parser_error(parser, offset, "allocation failed");
            return NULL;
        }
        binary->as.binary.op = op;
        binary->as.binary.left = expr;
        binary->as.binary.right = right;
        expr = binary;
    }
    return expr;
}

static js_expr_t *js_parse_relational(js_parser_t *parser)
{
    js_expr_t *expr = js_parse_term(parser);
    if (!expr)
    {
        return NULL;
    }
    for (;;)
    {
        js_binary_op_t op;
        if (parser->current.type == JS_TOKEN_LT)
        {
            op = JS_BINARY_LT;
        }
        else if (parser->current.type == JS_TOKEN_LTE)
        {
            op = JS_BINARY_LTE;
        }
        else if (parser->current.type == JS_TOKEN_GT)
        {
            op = JS_BINARY_GT;
        }
        else if (parser->current.type == JS_TOKEN_GTE)
        {
            op = JS_BINARY_GTE;
        }
        else if (parser->current.type == JS_TOKEN_KW_INSTANCEOF)
        {
            op = JS_BINARY_INSTANCEOF;
        }
        else
        {
            break;
        }
        size_t offset = parser->current.offset;
        js_parser_advance(parser);
        js_expr_t *right = js_parse_term(parser);
        if (!right)
        {
            js_expr_destroy(expr, parser->use_arena);
            return NULL;
        }
        js_expr_t *binary = js_new_expr(parser, JS_EXPR_BINARY);
        if (!binary)
        {
            js_expr_destroy(expr, parser->use_arena);
            js_expr_destroy(right, parser->use_arena);
            js_parser_error(parser, offset, "allocation failed");
            return NULL;
        }
        binary->as.binary.op = op;
        binary->as.binary.left = expr;
        binary->as.binary.right = right;
        expr = binary;
    }
    return expr;
}

static js_expr_t *js_parse_equality(js_parser_t *parser)
{
    js_expr_t *expr = js_parse_relational(parser);
    if (!expr)
    {
        return NULL;
    }
    for (;;)
    {
        js_binary_op_t op;
        if (parser->current.type == JS_TOKEN_EQUAL_EQUAL)
        {
            op = JS_BINARY_EQ;
        }
        else if (parser->current.type == JS_TOKEN_BANG_EQUAL)
        {
            op = JS_BINARY_NEQ;
        }
        else if (parser->current.type == JS_TOKEN_EQUAL_EQUAL_EQUAL)
        {
            op = JS_BINARY_STRICT_EQ;
        }
        else if (parser->current.type == JS_TOKEN_BANG_EQUAL_EQUAL)
        {
            op = JS_BINARY_STRICT_NEQ;
        }
        else
        {
            break;
        }
        size_t offset = parser->current.offset;
        js_parser_advance(parser);
        js_expr_t *right = js_parse_relational(parser);
        if (!right)
        {
            js_expr_destroy(expr, parser->use_arena);
            return NULL;
        }
        js_expr_t *binary = js_new_expr(parser, JS_EXPR_BINARY);
        if (!binary)
        {
            js_expr_destroy(expr, parser->use_arena);
            js_expr_destroy(right, parser->use_arena);
            js_parser_error(parser, offset, "allocation failed");
            return NULL;
        }
        binary->as.binary.op = op;
        binary->as.binary.left = expr;
        binary->as.binary.right = right;
        expr = binary;
    }
    return expr;
}

static js_expr_t *js_parse_logical_and(js_parser_t *parser)
{
    js_expr_t *expr = js_parse_equality(parser);
    if (!expr)
    {
        return NULL;
    }
    while (parser->current.type == JS_TOKEN_AND_AND)
    {
        size_t offset = parser->current.offset;
        js_parser_advance(parser);
        js_expr_t *right = js_parse_equality(parser);
        if (!right)
        {
            js_expr_destroy(expr, parser->use_arena);
            return NULL;
        }
        js_expr_t *binary = js_new_expr(parser, JS_EXPR_BINARY);
        if (!binary)
        {
            js_expr_destroy(expr, parser->use_arena);
            js_expr_destroy(right, parser->use_arena);
            js_parser_error(parser, offset, "allocation failed");
            return NULL;
        }
        binary->as.binary.op = JS_BINARY_AND;
        binary->as.binary.left = expr;
        binary->as.binary.right = right;
        expr = binary;
    }
    return expr;
}

static js_expr_t *js_parse_logical_or(js_parser_t *parser)
{
    js_expr_t *expr = js_parse_logical_and(parser);
    if (!expr)
    {
        return NULL;
    }
    while (parser->current.type == JS_TOKEN_OR_OR)
    {
        size_t offset = parser->current.offset;
        js_parser_advance(parser);
        js_expr_t *right = js_parse_logical_and(parser);
        if (!right)
        {
            js_expr_destroy(expr, parser->use_arena);
            return NULL;
        }
        js_expr_t *binary = js_new_expr(parser, JS_EXPR_BINARY);
        if (!binary)
        {
            js_expr_destroy(expr, parser->use_arena);
            js_expr_destroy(right, parser->use_arena);
            js_parser_error(parser, offset, "allocation failed");
            return NULL;
        }
        binary->as.binary.op = JS_BINARY_OR;
        binary->as.binary.left = expr;
        binary->as.binary.right = right;
        expr = binary;
    }
    return expr;
}

static js_expr_t *js_parse_nullish(js_parser_t *parser)
{
    js_expr_t *expr = js_parse_logical_or(parser);
    if (!expr)
    {
        return NULL;
    }
    while (parser->current.type == JS_TOKEN_NULLISH)
    {
        size_t offset = parser->current.offset;
        js_parser_advance(parser);
        js_expr_t *right = js_parse_logical_or(parser);
        if (!right)
        {
            js_expr_destroy(expr, parser->use_arena);
            return NULL;
        }
        js_expr_t *binary = js_new_expr(parser, JS_EXPR_BINARY);
        if (!binary)
        {
            js_expr_destroy(expr, parser->use_arena);
            js_expr_destroy(right, parser->use_arena);
            js_parser_error(parser, offset, "allocation failed");
            return NULL;
        }
        binary->as.binary.op = JS_BINARY_NULLISH;
        binary->as.binary.left = expr;
        binary->as.binary.right = right;
        expr = binary;
    }
    return expr;
}

static js_expr_t *js_parse_ternary(js_parser_t *parser)
{
    js_expr_t *expr = js_parse_nullish(parser);
    if (!expr)
    {
        return NULL;
    }
    if (parser->current.type == JS_TOKEN_QUESTION)
    {
        size_t offset = parser->current.offset;
        js_parser_advance(parser);
        js_expr_t *then_expr = js_parse_expression(parser);
        if (!then_expr)
        {
            js_expr_destroy(expr, parser->use_arena);
            return NULL;
        }
        if (!js_parser_expect(parser, JS_TOKEN_COLON, "expected ':'"))
        {
            js_expr_destroy(expr, parser->use_arena);
            js_expr_destroy(then_expr, parser->use_arena);
            return NULL;
        }
        js_expr_t *else_expr = js_parse_ternary(parser);
        if (!else_expr)
        {
            js_expr_destroy(expr, parser->use_arena);
            js_expr_destroy(then_expr, parser->use_arena);
            return NULL;
        }
        js_expr_t *ternary = js_new_expr(parser, JS_EXPR_TERNARY);
        if (!ternary)
        {
            js_expr_destroy(expr, parser->use_arena);
            js_expr_destroy(then_expr, parser->use_arena);
            js_expr_destroy(else_expr, parser->use_arena);
            js_parser_error(parser, offset, "allocation failed");
            return NULL;
        }
        ternary->as.ternary.condition = expr;
        ternary->as.ternary.then_expr = then_expr;
        ternary->as.ternary.else_expr = else_expr;
        return ternary;
    }
    return expr;
}

static js_expr_t *js_parse_yield(js_parser_t *parser);

static js_expr_t *js_parse_assignment(js_parser_t *parser)
{
    if (parser && parser->in_generator && js_token_is_identifier(&parser->current, "yield"))
    {
        return js_parse_yield(parser);
    }
    js_expr_t *expr = js_parse_ternary(parser);
    if (!expr)
    {
        return NULL;
    }
    if (parser->current.type == JS_TOKEN_EQUAL ||
        parser->current.type == JS_TOKEN_PLUS_EQUAL ||
        parser->current.type == JS_TOKEN_NULLISH_EQUAL)
    {
        js_token_type_t assign_type = parser->current.type;
        size_t offset = parser->current.offset;
        js_parser_advance(parser);
        if (expr->type != JS_EXPR_IDENTIFIER && expr->type != JS_EXPR_MEMBER)
        {
            js_expr_destroy(expr, parser->use_arena);
            js_parser_error(parser, offset, "invalid assignment target");
            return NULL;
        }
        if (expr->type == JS_EXPR_MEMBER && expr->as.member.optional)
        {
            js_expr_destroy(expr, parser->use_arena);
            js_parser_error(parser, offset, "invalid assignment target");
            return NULL;
        }
        js_expr_t *value = js_parse_assignment(parser);
        if (!value)
        {
            js_expr_destroy(expr, parser->use_arena);
            return NULL;
        }
        js_expr_t *assign = js_new_expr(parser, JS_EXPR_ASSIGN);
        if (!assign)
        {
            js_expr_destroy(value, parser->use_arena);
            js_expr_destroy(expr, parser->use_arena);
            js_parser_error(parser, offset, "allocation failed");
            return NULL;
        }
        assign->as.assign.target = expr;
        assign->as.assign.value = value;
        if (assign_type == JS_TOKEN_PLUS_EQUAL)
        {
            assign->as.assign.op = JS_ASSIGN_ADD;
        }
        else if (assign_type == JS_TOKEN_NULLISH_EQUAL)
        {
            assign->as.assign.op = JS_ASSIGN_NULLISH;
        }
        else
        {
            assign->as.assign.op = JS_ASSIGN_SET;
        }
        return assign;
    }
    return expr;
}

static js_expr_t *js_parse_expression(js_parser_t *parser)
{
    return js_parse_assignment(parser);
}

static js_expr_t *js_parse_yield(js_parser_t *parser)
{
    if (!parser || !js_token_is_identifier(&parser->current, "yield"))
    {
        return NULL;
    }
    size_t offset = parser->current.offset;
    js_parser_advance(parser);
    js_expr_t *value = NULL;
    if (parser->current.type != JS_TOKEN_SEMICOLON &&
        parser->current.type != JS_TOKEN_RPAREN &&
        parser->current.type != JS_TOKEN_RBRACE &&
        parser->current.type != JS_TOKEN_RBRACKET &&
        parser->current.type != JS_TOKEN_COMMA &&
        parser->current.type != JS_TOKEN_EOF)
    {
        value = js_parse_ternary(parser);
        if (!value)
        {
            return NULL;
        }
    }
    js_expr_t *expr = js_new_expr(parser, JS_EXPR_YIELD);
    if (!expr)
    {
        js_expr_destroy(value, parser->use_arena);
        js_parser_error(parser, offset, "allocation failed");
        return NULL;
    }
    expr->as.yield.value = value;
    return expr;
}

static js_stmt_t *js_parse_var_decl_impl(js_parser_t *parser, js_var_kind_t kind, bool consume_semi)
{
    if (!parser)
    {
        return NULL;
    }
    js_var_list_t bindings = {0};
    for (;;)
    {
        js_binding_t *pattern = js_parse_binding_pattern(parser);
        if (!pattern)
        {
            break;
        }
        js_expr_t *init = NULL;
        if (parser->current.type == JS_TOKEN_EQUAL)
        {
            js_parser_advance(parser);
            init = js_parse_expression(parser);
            if (!init)
            {
                js_binding_destroy(pattern, parser->use_arena);
                break;
            }
        }
        if (kind == JS_VAR_CONST && !init)
        {
            js_parser_error(parser, parser->current.offset, "const requires initializer");
            js_binding_destroy(pattern, parser->use_arena);
            break;
        }
        if (!init && pattern->type != JS_BINDING_IDENTIFIER)
        {
            js_parser_error(parser, parser->current.offset, "missing initializer");
            js_binding_destroy(pattern, parser->use_arena);
            break;
        }
        js_var_binding_t entry = {0};
        entry.binding = pattern;
        entry.init = init;
        if (!js_var_list_push(parser, &bindings, &entry))
        {
            js_expr_destroy(init, parser->use_arena);
            js_binding_destroy(pattern, parser->use_arena);
            js_parser_error(parser, parser->current.offset, "allocation failed");
            break;
        }
        if (parser->current.type == JS_TOKEN_COMMA)
        {
            js_parser_advance(parser);
            continue;
        }
        break;
    }
    if (parser->had_error)
    {
        for (size_t i = 0; i < bindings.count; ++i)
        {
            js_binding_destroy(bindings.items[i].binding, parser->use_arena);
            js_expr_destroy(bindings.items[i].init, parser->use_arena);
        }
        js_parser_free(parser, bindings.items);
        return NULL;
    }
    if (consume_semi)
    {
        if (!js_parser_consume_semicolon(parser))
        {
            for (size_t i = 0; i < bindings.count; ++i)
            {
                js_binding_destroy(bindings.items[i].binding, parser->use_arena);
                js_expr_destroy(bindings.items[i].init, parser->use_arena);
            }
            js_parser_free(parser, bindings.items);
            return NULL;
        }
    }
    js_stmt_t *stmt = js_new_stmt(parser, JS_STMT_VAR);
    if (!stmt)
    {
        for (size_t i = 0; i < bindings.count; ++i)
        {
            js_binding_destroy(bindings.items[i].binding, parser->use_arena);
            js_expr_destroy(bindings.items[i].init, parser->use_arena);
        }
        js_parser_free(parser, bindings.items);
        js_parser_error(parser, parser->current.offset, "allocation failed");
        return NULL;
    }
    stmt->as.var.kind = kind;
    stmt->as.var.bindings = bindings.items;
    stmt->as.var.count = bindings.count;
    return stmt;
}

static bool js_parse_block(js_parser_t *parser, bool allow_return, js_block_t *out)
{
    if (!parser || !out)
    {
        return false;
    }
    if (!js_parser_expect(parser, JS_TOKEN_LBRACE, "expected '{'") )
    {
        return false;
    }
    js_stmt_list_t list = {0};
    while (parser->current.type != JS_TOKEN_EOF && parser->current.type != JS_TOKEN_RBRACE)
    {
        js_stmt_t *stmt = js_parse_statement(parser, allow_return);
        if (!stmt)
        {
            for (size_t i = 0; i < list.count; ++i)
            {
                js_stmt_destroy(list.items[i], parser->use_arena);
            }
            js_parser_free(parser, list.items);
            return false;
        }
        if (!js_stmt_list_push(parser, &list, stmt))
        {
            js_stmt_destroy(stmt, parser->use_arena);
            for (size_t i = 0; i < list.count; ++i)
            {
                js_stmt_destroy(list.items[i], parser->use_arena);
            }
            js_parser_free(parser, list.items);
            js_parser_error(parser, parser->current.offset, "allocation failed");
            return false;
        }
    }
    if (parser->current.type != JS_TOKEN_RBRACE)
    {
        for (size_t i = 0; i < list.count; ++i)
        {
            js_stmt_destroy(list.items[i], parser->use_arena);
        }
        js_parser_free(parser, list.items);
        js_parser_error(parser, parser->current.offset, "expected '}'");
        return false;
    }
    js_parser_advance(parser);
    out->stmts = list.items;
    out->count = list.count;
    return true;
}

static bool js_parse_function_tail(js_parser_t *parser,
                                   js_function_expr_t *out,
                                   bool is_async)
{
    if (!parser || !out)
    {
        return false;
    }
    memset(out, 0, sizeof(*out));
    out->is_async = is_async;

    if (!js_parser_expect(parser, JS_TOKEN_LPAREN, "expected '('") )
    {
        return false;
    }

    js_param_list_t params = {0};
    if (!js_parse_param_list_body(parser, &params))
    {
        return false;
    }

    if (parser->had_error || !js_parser_expect(parser, JS_TOKEN_RPAREN, "expected ')'") )
    {
        js_param_list_destroy(&params, parser->use_arena);
        return false;
    }

    js_block_t body = {0};
    bool prev_in_generator = parser->in_generator;
    bool prev_in_async = parser->in_async;
    parser->in_generator = false;
    parser->in_async = is_async;
    if (!js_parse_block(parser, true, &body))
    {
        parser->in_async = prev_in_async;
        parser->in_generator = prev_in_generator;
        js_param_list_destroy(&params, parser->use_arena);
        js_parser_error(parser, parser->current.offset, "invalid function body");
        return false;
    }
    parser->in_async = prev_in_async;
    parser->in_generator = prev_in_generator;

    out->params = params.items;
    out->param_count = params.count;
    out->body = body;
    return true;
}

static bool js_parse_function_common(js_parser_t *parser,
                                     bool require_name,
                                     js_function_expr_t *out,
                                     bool is_async)
{
    if (!parser || !out)
    {
        return false;
    }
    memset(out, 0, sizeof(*out));
    out->is_async = is_async;

    if (parser->current.type == JS_TOKEN_STAR)
    {
        out->is_generator = true;
        js_parser_advance(parser);
    }

    if (parser->current.type == JS_TOKEN_IDENTIFIER)
    {
        out->name = js_token_take_text(&parser->current);
        js_parser_advance(parser);
    }
    else if (require_name)
    {
        js_parser_error(parser, parser->current.offset, "expected function name");
        return false;
    }

    if (!js_parser_expect(parser, JS_TOKEN_LPAREN, "expected '('") )
    {
        js_parser_free(parser, out->name);
        out->name = NULL;
        return false;
    }

    js_param_list_t params = {0};
    if (!js_parse_param_list_body(parser, &params))
    {
        js_parser_free(parser, out->name);
        out->name = NULL;
        return false;
    }

    if (parser->had_error || !js_parser_expect(parser, JS_TOKEN_RPAREN, "expected ')'") )
    {
        js_param_list_destroy(&params, parser->use_arena);
        js_parser_free(parser, out->name);
        out->name = NULL;
        return false;
    }

    js_block_t body = {0};
    bool prev_in_generator = parser->in_generator;
    bool prev_in_async = parser->in_async;
    parser->in_generator = out->is_generator;
    parser->in_async = is_async;
    if (!js_parse_block(parser, true, &body))
    {
        parser->in_async = prev_in_async;
        parser->in_generator = prev_in_generator;
        js_param_list_destroy(&params, parser->use_arena);
        js_parser_free(parser, out->name);
        out->name = NULL;
        js_parser_error(parser, parser->current.offset, "invalid function body");
        return false;
    }
    parser->in_async = prev_in_async;
    parser->in_generator = prev_in_generator;

    out->params = params.items;
    out->param_count = params.count;
    out->body = body;
    return true;
}

static js_stmt_t *js_parse_function_decl(js_parser_t *parser, bool is_async)
{
    if (!parser)
    {
        return NULL;
    }
    size_t offset = parser->current.offset;
    js_function_expr_t func = {0};
    if (!js_parse_function_common(parser, true, &func, is_async))
    {
        return NULL;
    }

    js_stmt_t *stmt = js_new_stmt(parser, JS_STMT_FUNCTION_DECL);
    if (!stmt)
    {
        js_parser_free(parser, func.name);
        for (size_t p = 0; p < func.param_count; ++p)
        {
            js_binding_destroy(func.params[p].binding, parser->use_arena);
            js_expr_destroy(func.params[p].init, parser->use_arena);
        }
        js_parser_free(parser, func.params);
        for (size_t i = 0; i < func.body.count; ++i)
        {
            js_stmt_destroy(func.body.stmts[i], parser->use_arena);
        }
        js_parser_free(parser, func.body.stmts);
        js_parser_error(parser, offset, "allocation failed");
        return NULL;
    }
    stmt->as.func.name = func.name;
    stmt->as.func.params = func.params;
    stmt->as.func.param_count = func.param_count;
    stmt->as.func.body = func.body;
    stmt->as.func.is_arrow = false;
    stmt->as.func.is_generator = func.is_generator;
    stmt->as.func.is_async = func.is_async;
    return stmt;
}

static js_stmt_t *js_parse_return(js_parser_t *parser, bool allow_return)
{
    if (!parser)
    {
        return NULL;
    }
    size_t offset = parser->current.offset;
    if (!allow_return)
    {
        js_parser_error(parser, offset, "return not allowed here");
        return NULL;
    }
    js_parser_advance(parser);
    js_expr_t *value = NULL;
    if (parser->current.type != JS_TOKEN_SEMICOLON &&
        parser->current.type != JS_TOKEN_RBRACE &&
        parser->current.type != JS_TOKEN_EOF)
    {
        value = js_parse_expression(parser);
        if (!value)
        {
            return NULL;
        }
    }
    if (!js_parser_consume_semicolon(parser))
    {
        js_expr_destroy(value, parser->use_arena);
        return NULL;
    }
    js_stmt_t *stmt = js_new_stmt(parser, JS_STMT_RETURN);
    if (!stmt)
    {
        js_expr_destroy(value, parser->use_arena);
        js_parser_error(parser, offset, "allocation failed");
        return NULL;
    }
    stmt->as.ret.value = value;
    return stmt;
}

static js_stmt_t *js_parse_throw(js_parser_t *parser)
{
    if (!parser)
    {
        return NULL;
    }
    size_t offset = parser->current.offset;
    js_parser_advance(parser);
    js_expr_t *expr = js_parse_expression(parser);
    if (!expr)
    {
        return NULL;
    }
    if (!js_parser_consume_semicolon(parser))
    {
        js_expr_destroy(expr, parser->use_arena);
        return NULL;
    }
    js_stmt_t *stmt = js_new_stmt(parser, JS_STMT_THROW);
    if (!stmt)
    {
        js_expr_destroy(expr, parser->use_arena);
        js_parser_error(parser, offset, "allocation failed");
        return NULL;
    }
    stmt->as.throw_stmt.expr = expr;
    return stmt;
}

static js_stmt_t *js_parse_if_statement(js_parser_t *parser, bool allow_return)
{
    if (!parser)
    {
        return NULL;
    }
    if (!js_parser_expect(parser, JS_TOKEN_LPAREN, "expected '('") )
    {
        return NULL;
    }
    js_expr_t *condition = js_parse_expression(parser);
    if (!condition)
    {
        return NULL;
    }
    if (!js_parser_expect(parser, JS_TOKEN_RPAREN, "expected ')'") )
    {
        js_expr_destroy(condition, parser->use_arena);
        return NULL;
    }
    js_stmt_t *then_branch = js_parse_statement(parser, allow_return);
    if (!then_branch)
    {
        js_expr_destroy(condition, parser->use_arena);
        return NULL;
    }
    js_stmt_t *else_branch = NULL;
    if (parser->current.type == JS_TOKEN_KW_ELSE)
    {
        js_parser_advance(parser);
        else_branch = js_parse_statement(parser, allow_return);
        if (!else_branch)
        {
            js_expr_destroy(condition, parser->use_arena);
            js_stmt_destroy(then_branch, parser->use_arena);
            return NULL;
        }
    }
    js_stmt_t *stmt = js_new_stmt(parser, JS_STMT_IF);
    if (!stmt)
    {
        js_expr_destroy(condition, parser->use_arena);
        js_stmt_destroy(then_branch, parser->use_arena);
        js_stmt_destroy(else_branch, parser->use_arena);
        js_parser_error(parser, parser->current.offset, "allocation failed");
        return NULL;
    }
    stmt->as.if_stmt.condition = condition;
    stmt->as.if_stmt.then_branch = then_branch;
    stmt->as.if_stmt.else_branch = else_branch;
    return stmt;
}

static js_stmt_t *js_parse_while_statement(js_parser_t *parser, bool allow_return)
{
    if (!parser)
    {
        return NULL;
    }
    if (!js_parser_expect(parser, JS_TOKEN_LPAREN, "expected '('") )
    {
        return NULL;
    }
    js_expr_t *condition = js_parse_expression(parser);
    if (!condition)
    {
        return NULL;
    }
    if (!js_parser_expect(parser, JS_TOKEN_RPAREN, "expected ')'") )
    {
        js_expr_destroy(condition, parser->use_arena);
        return NULL;
    }
    js_stmt_t *body = js_parse_statement(parser, allow_return);
    if (!body)
    {
        js_expr_destroy(condition, parser->use_arena);
        return NULL;
    }
    js_stmt_t *stmt = js_new_stmt(parser, JS_STMT_WHILE);
    if (!stmt)
    {
        js_expr_destroy(condition, parser->use_arena);
        js_stmt_destroy(body, parser->use_arena);
        js_parser_error(parser, parser->current.offset, "allocation failed");
        return NULL;
    }
    stmt->as.while_stmt.condition = condition;
    stmt->as.while_stmt.body = body;
    return stmt;
}

static js_stmt_t *js_parse_do_while_statement(js_parser_t *parser, bool allow_return)
{
    if (!parser)
    {
        return NULL;
    }
    js_stmt_t *body = js_parse_statement(parser, allow_return);
    if (!body)
    {
        return NULL;
    }
    if (!js_parser_expect(parser, JS_TOKEN_KW_WHILE, "expected 'while'") )
    {
        js_stmt_destroy(body, parser->use_arena);
        return NULL;
    }
    if (!js_parser_expect(parser, JS_TOKEN_LPAREN, "expected '('") )
    {
        js_stmt_destroy(body, parser->use_arena);
        return NULL;
    }
    js_expr_t *condition = js_parse_expression(parser);
    if (!condition)
    {
        js_stmt_destroy(body, parser->use_arena);
        return NULL;
    }
    if (!js_parser_expect(parser, JS_TOKEN_RPAREN, "expected ')'") )
    {
        js_expr_destroy(condition, parser->use_arena);
        js_stmt_destroy(body, parser->use_arena);
        return NULL;
    }
    if (!js_parser_consume_semicolon(parser))
    {
        js_expr_destroy(condition, parser->use_arena);
        js_stmt_destroy(body, parser->use_arena);
        return NULL;
    }
    js_stmt_t *stmt = js_new_stmt(parser, JS_STMT_DO_WHILE);
    if (!stmt)
    {
        js_expr_destroy(condition, parser->use_arena);
        js_stmt_destroy(body, parser->use_arena);
        js_parser_error(parser, parser->current.offset, "allocation failed");
        return NULL;
    }
    stmt->as.do_while_stmt.body = body;
    stmt->as.do_while_stmt.condition = condition;
    return stmt;
}

static bool js_token_is_identifier(const js_token_t *tok, const char *text)
{
    return tok && tok->type == JS_TOKEN_IDENTIFIER && tok->text && strcmp(tok->text, text) == 0;
}

static js_stmt_t *js_parse_for_statement(js_parser_t *parser, bool allow_return)
{
    if (!parser)
    {
        return NULL;
    }
    if (!js_parser_expect(parser, JS_TOKEN_LPAREN, "expected '('") )
    {
        return NULL;
    }

    js_stmt_t *init = NULL;
    js_binding_t *for_binding = NULL;
    js_expr_t *for_target = NULL;
    js_expr_t *for_expr = NULL;
    js_var_kind_t for_kind = JS_VAR_VAR;
    bool for_is_decl = false;
    bool for_is_of = false;
    bool for_inof = false;
    if (parser->current.type != JS_TOKEN_SEMICOLON)
    {
        if (parser->current.type == JS_TOKEN_KW_VAR ||
            parser->current.type == JS_TOKEN_KW_LET ||
            parser->current.type == JS_TOKEN_KW_CONST)
        {
            js_var_kind_t kind = JS_VAR_VAR;
            if (parser->current.type == JS_TOKEN_KW_LET)
            {
                kind = JS_VAR_LET;
            }
            else if (parser->current.type == JS_TOKEN_KW_CONST)
            {
                kind = JS_VAR_CONST;
            }
            js_parser_advance(parser);
            js_binding_t *pattern = js_parse_binding_pattern(parser);
            if (!pattern)
            {
                return NULL;
            }
            js_expr_t *init_expr = NULL;
            if (parser->current.type == JS_TOKEN_EQUAL)
            {
                js_parser_advance(parser);
                init_expr = js_parse_expression(parser);
                if (!init_expr)
                {
                    js_binding_destroy(pattern, parser->use_arena);
                    return NULL;
                }
            }

            if (js_token_is_identifier(&parser->current, "in") ||
                js_token_is_identifier(&parser->current, "of"))
            {
                if (init_expr)
                {
                    js_expr_destroy(init_expr, parser->use_arena);
                    js_binding_destroy(pattern, parser->use_arena);
                    js_parser_error(parser, parser->current.offset, "invalid for-in/of initializer");
                    return NULL;
                }
                for_is_decl = true;
                for_is_of = js_token_is_identifier(&parser->current, "of");
                for_inof = true;
                for_kind = kind;
                for_binding = pattern;
                js_parser_advance(parser);
                for_expr = js_parse_expression(parser);
                if (!for_expr)
                {
                    js_binding_destroy(for_binding, parser->use_arena);
                    return NULL;
                }
            }
            else
            {
                if (kind == JS_VAR_CONST && !init_expr)
                {
                    js_parser_error(parser, parser->current.offset, "const requires initializer");
                    js_binding_destroy(pattern, parser->use_arena);
                    return NULL;
                }
                if (!init_expr && pattern->type != JS_BINDING_IDENTIFIER)
                {
                    js_parser_error(parser, parser->current.offset, "missing initializer");
                    js_binding_destroy(pattern, parser->use_arena);
                    return NULL;
                }
                js_var_list_t list = {0};
                js_var_binding_t entry = {0};
                entry.binding = pattern;
                entry.init = init_expr;
                if (!js_var_list_push(parser, &list, &entry))
                {
                    js_expr_destroy(init_expr, parser->use_arena);
                    js_binding_destroy(pattern, parser->use_arena);
                    js_parser_error(parser, parser->current.offset, "allocation failed");
                    return NULL;
                }

                while (parser->current.type == JS_TOKEN_COMMA)
                {
                    js_parser_advance(parser);
                    js_binding_t *next = js_parse_binding_pattern(parser);
                    if (!next)
                    {
                        for (size_t i = 0; i < list.count; ++i)
                        {
                            js_binding_destroy(list.items[i].binding, parser->use_arena);
                            js_expr_destroy(list.items[i].init, parser->use_arena);
                        }
                        js_parser_free(parser, list.items);
                        return NULL;
                    }
                    js_expr_t *next_init = NULL;
                    if (parser->current.type == JS_TOKEN_EQUAL)
                    {
                        js_parser_advance(parser);
                        next_init = js_parse_expression(parser);
                        if (!next_init)
                        {
                            js_binding_destroy(next, parser->use_arena);
                            for (size_t i = 0; i < list.count; ++i)
                            {
                                js_binding_destroy(list.items[i].binding, parser->use_arena);
                                js_expr_destroy(list.items[i].init, parser->use_arena);
                            }
                            js_parser_free(parser, list.items);
                            return NULL;
                        }
                    }
                    if (kind == JS_VAR_CONST && !next_init)
                    {
                        js_parser_error(parser, parser->current.offset, "const requires initializer");
                        js_binding_destroy(next, parser->use_arena);
                        for (size_t i = 0; i < list.count; ++i)
                        {
                            js_binding_destroy(list.items[i].binding, parser->use_arena);
                            js_expr_destroy(list.items[i].init, parser->use_arena);
                        }
                        js_parser_free(parser, list.items);
                        return NULL;
                    }
                    if (!next_init && next->type != JS_BINDING_IDENTIFIER)
                    {
                        js_parser_error(parser, parser->current.offset, "missing initializer");
                        js_binding_destroy(next, parser->use_arena);
                        for (size_t i = 0; i < list.count; ++i)
                        {
                            js_binding_destroy(list.items[i].binding, parser->use_arena);
                            js_expr_destroy(list.items[i].init, parser->use_arena);
                        }
                        js_parser_free(parser, list.items);
                        return NULL;
                    }
                    js_var_binding_t next_entry = {0};
                    next_entry.binding = next;
                    next_entry.init = next_init;
                    if (!js_var_list_push(parser, &list, &next_entry))
                    {
                        js_expr_destroy(next_init, parser->use_arena);
                        js_binding_destroy(next, parser->use_arena);
                        for (size_t i = 0; i < list.count; ++i)
                        {
                            js_binding_destroy(list.items[i].binding, parser->use_arena);
                            js_expr_destroy(list.items[i].init, parser->use_arena);
                        }
                        js_parser_free(parser, list.items);
                        js_parser_error(parser, parser->current.offset, "allocation failed");
                        return NULL;
                    }
                }

                init = js_new_stmt(parser, JS_STMT_VAR);
                if (!init)
                {
                    for (size_t i = 0; i < list.count; ++i)
                    {
                        js_binding_destroy(list.items[i].binding, parser->use_arena);
                        js_expr_destroy(list.items[i].init, parser->use_arena);
                    }
                    js_parser_free(parser, list.items);
                    js_parser_error(parser, parser->current.offset, "allocation failed");
                    return NULL;
                }
                init->as.var.kind = kind;
                init->as.var.bindings = list.items;
                init->as.var.count = list.count;
            }
        }
        else
        {
            js_expr_t *expr = js_parse_expression(parser);
            if (!expr)
            {
                return NULL;
            }
            if (js_token_is_identifier(&parser->current, "in") ||
                js_token_is_identifier(&parser->current, "of"))
            {
                if (expr->type != JS_EXPR_IDENTIFIER && expr->type != JS_EXPR_MEMBER)
                {
                    js_expr_destroy(expr, parser->use_arena);
                    js_parser_error(parser, parser->current.offset, "invalid for-in/of target");
                    return NULL;
                }
                for_inof = true;
                for_is_of = js_token_is_identifier(&parser->current, "of");
                for_target = expr;
                js_parser_advance(parser);
                for_expr = js_parse_expression(parser);
                if (!for_expr)
                {
                    js_expr_destroy(for_target, parser->use_arena);
                    return NULL;
                }
            }
            else
            {
                init = js_new_stmt(parser, JS_STMT_EXPR);
                if (!init)
                {
                    js_expr_destroy(expr, parser->use_arena);
                    js_parser_error(parser, parser->current.offset, "allocation failed");
                    return NULL;
                }
                init->as.expr.expr = expr;
            }
        }
    }

    if (for_inof)
    {
        if (!js_parser_expect(parser, JS_TOKEN_RPAREN, "expected ')'") )
        {
            js_stmt_destroy(init, parser->use_arena);
            js_binding_destroy(for_binding, parser->use_arena);
            js_expr_destroy(for_target, parser->use_arena);
            js_expr_destroy(for_expr, parser->use_arena);
            return NULL;
        }
        js_stmt_t *body = js_parse_statement(parser, allow_return);
        if (!body)
        {
            js_stmt_destroy(init, parser->use_arena);
            js_binding_destroy(for_binding, parser->use_arena);
            js_expr_destroy(for_target, parser->use_arena);
            js_expr_destroy(for_expr, parser->use_arena);
            return NULL;
        }
        js_stmt_t *stmt = js_new_stmt(parser, for_is_of ? JS_STMT_FOR_OF : JS_STMT_FOR_IN);
        if (!stmt)
        {
            js_stmt_destroy(init, parser->use_arena);
            js_binding_destroy(for_binding, parser->use_arena);
            js_expr_destroy(for_target, parser->use_arena);
            js_expr_destroy(for_expr, parser->use_arena);
            js_stmt_destroy(body, parser->use_arena);
            js_parser_error(parser, parser->current.offset, "allocation failed");
            return NULL;
        }
        stmt->as.for_inof.is_decl = for_is_decl;
        stmt->as.for_inof.kind = for_kind;
        stmt->as.for_inof.binding = for_binding;
        stmt->as.for_inof.target = for_target;
        stmt->as.for_inof.expr = for_expr;
        stmt->as.for_inof.body = body;
        return stmt;
    }

    if (!js_parser_expect(parser, JS_TOKEN_SEMICOLON, "expected ';'") )
    {
        js_stmt_destroy(init, parser->use_arena);
        return NULL;
    }

    js_expr_t *condition = NULL;
    if (parser->current.type != JS_TOKEN_SEMICOLON)
    {
        condition = js_parse_expression(parser);
        if (!condition)
        {
            js_stmt_destroy(init, parser->use_arena);
            return NULL;
        }
    }
    if (!js_parser_expect(parser, JS_TOKEN_SEMICOLON, "expected ';'") )
    {
        js_stmt_destroy(init, parser->use_arena);
        js_expr_destroy(condition, parser->use_arena);
        return NULL;
    }

    js_expr_t *post = NULL;
    if (parser->current.type != JS_TOKEN_RPAREN)
    {
        post = js_parse_expression(parser);
        if (!post)
        {
            js_stmt_destroy(init, parser->use_arena);
            js_expr_destroy(condition, parser->use_arena);
            return NULL;
        }
    }
    if (!js_parser_expect(parser, JS_TOKEN_RPAREN, "expected ')'") )
    {
        js_stmt_destroy(init, parser->use_arena);
        js_expr_destroy(condition, parser->use_arena);
        js_expr_destroy(post, parser->use_arena);
        return NULL;
    }

    js_stmt_t *body = js_parse_statement(parser, allow_return);
    if (!body)
    {
        js_stmt_destroy(init, parser->use_arena);
        js_expr_destroy(condition, parser->use_arena);
        js_expr_destroy(post, parser->use_arena);
        return NULL;
    }

    js_stmt_t *stmt = js_new_stmt(parser, JS_STMT_FOR);
    if (!stmt)
    {
        js_stmt_destroy(init, parser->use_arena);
        js_expr_destroy(condition, parser->use_arena);
        js_expr_destroy(post, parser->use_arena);
        js_stmt_destroy(body, parser->use_arena);
        js_parser_error(parser, parser->current.offset, "allocation failed");
        return NULL;
    }
    stmt->as.for_stmt.init = init;
    stmt->as.for_stmt.condition = condition;
    stmt->as.for_stmt.post = post;
    stmt->as.for_stmt.body = body;
    return stmt;
}

static js_stmt_t *js_parse_switch_statement(js_parser_t *parser, bool allow_return)
{
    if (!parser)
    {
        return NULL;
    }
    if (!js_parser_expect(parser, JS_TOKEN_LPAREN, "expected '('") )
    {
        return NULL;
    }
    js_expr_t *expr = js_parse_expression(parser);
    if (!expr)
    {
        return NULL;
    }
    if (!js_parser_expect(parser, JS_TOKEN_RPAREN, "expected ')'") )
    {
        js_expr_destroy(expr, parser->use_arena);
        return NULL;
    }
    if (!js_parser_expect(parser, JS_TOKEN_LBRACE, "expected '{'") )
    {
        js_expr_destroy(expr, parser->use_arena);
        return NULL;
    }

    js_case_list_t cases = {0};
    while (parser->current.type != JS_TOKEN_RBRACE &&
           parser->current.type != JS_TOKEN_EOF)
    {
        js_switch_case_t case_stmt;
        js_stmt_list_t stmts = {0};
        memset(&case_stmt, 0, sizeof(case_stmt));

        if (parser->current.type == JS_TOKEN_KW_CASE)
        {
            js_parser_advance(parser);
            case_stmt.test = js_parse_expression(parser);
            if (!case_stmt.test)
            {
                goto switch_error;
            }
        }
        else if (parser->current.type == JS_TOKEN_KW_DEFAULT)
        {
            js_parser_advance(parser);
            case_stmt.test = NULL;
        }
        else
        {
            js_parser_error(parser, parser->current.offset, "expected case or default");
            goto switch_error;
        }

        if (!js_parser_expect(parser, JS_TOKEN_COLON, "expected ':'") )
        {
            goto switch_error;
        }

        while (parser->current.type != JS_TOKEN_KW_CASE &&
               parser->current.type != JS_TOKEN_KW_DEFAULT &&
               parser->current.type != JS_TOKEN_RBRACE &&
               parser->current.type != JS_TOKEN_EOF)
        {
            js_stmt_t *stmt = js_parse_statement(parser, allow_return);
            if (!stmt)
            {
                goto switch_error_stmts;
            }
            if (!js_stmt_list_push(parser, &stmts, stmt))
            {
                js_stmt_destroy(stmt, parser->use_arena);
                js_parser_error(parser, parser->current.offset, "allocation failed");
                goto switch_error_stmts;
            }
        }
        case_stmt.stmts = stmts.items;
        case_stmt.count = stmts.count;

        if (!js_case_list_push(parser, &cases, &case_stmt))
        {
            js_parser_error(parser, parser->current.offset, "allocation failed");
            goto switch_error;
        }
        continue;

switch_error_stmts:
        for (size_t i = 0; i < stmts.count; ++i)
        {
            js_stmt_destroy(stmts.items[i], parser->use_arena);
        }
        js_parser_free(parser, stmts.items);

switch_error:
        js_expr_destroy(case_stmt.test, parser->use_arena);
        for (size_t i = 0; i < case_stmt.count; ++i)
        {
            js_stmt_destroy(case_stmt.stmts[i], parser->use_arena);
        }
        js_parser_free(parser, case_stmt.stmts);
        for (size_t c = 0; c < cases.count; ++c)
        {
            js_expr_destroy(cases.items[c].test, parser->use_arena);
            for (size_t i = 0; i < cases.items[c].count; ++i)
            {
                js_stmt_destroy(cases.items[c].stmts[i], parser->use_arena);
            }
            js_parser_free(parser, cases.items[c].stmts);
        }
        js_parser_free(parser, cases.items);
        js_expr_destroy(expr, parser->use_arena);
        return NULL;
    }

    if (!js_parser_expect(parser, JS_TOKEN_RBRACE, "expected '}'") )
    {
        for (size_t c = 0; c < cases.count; ++c)
        {
            js_expr_destroy(cases.items[c].test, parser->use_arena);
            for (size_t i = 0; i < cases.items[c].count; ++i)
            {
                js_stmt_destroy(cases.items[c].stmts[i], parser->use_arena);
            }
            js_parser_free(parser, cases.items[c].stmts);
        }
        js_parser_free(parser, cases.items);
        js_expr_destroy(expr, parser->use_arena);
        return NULL;
    }

    js_stmt_t *stmt = js_new_stmt(parser, JS_STMT_SWITCH);
    if (!stmt)
    {
        for (size_t c = 0; c < cases.count; ++c)
        {
            js_expr_destroy(cases.items[c].test, parser->use_arena);
            for (size_t i = 0; i < cases.items[c].count; ++i)
            {
                js_stmt_destroy(cases.items[c].stmts[i], parser->use_arena);
            }
            js_parser_free(parser, cases.items[c].stmts);
        }
        js_parser_free(parser, cases.items);
        js_expr_destroy(expr, parser->use_arena);
        js_parser_error(parser, parser->current.offset, "allocation failed");
        return NULL;
    }
    stmt->as.switch_stmt.expr = expr;
    stmt->as.switch_stmt.cases = cases.items;
    stmt->as.switch_stmt.case_count = cases.count;
    return stmt;
}

static js_stmt_t *js_parse_try_statement(js_parser_t *parser, bool allow_return)
{
    if (!parser)
    {
        return NULL;
    }
    js_block_t try_block = {0};
    if (!js_parse_block(parser, allow_return, &try_block))
    {
        return NULL;
    }

    if (parser->current.type != JS_TOKEN_KW_CATCH)
    {
        for (size_t i = 0; i < try_block.count; ++i)
        {
            js_stmt_destroy(try_block.stmts[i], parser->use_arena);
        }
        js_parser_free(parser, try_block.stmts);
        js_parser_error(parser, parser->current.offset, "expected catch");
        return NULL;
    }

    js_parser_advance(parser);
    if (!js_parser_expect(parser, JS_TOKEN_LPAREN, "expected '('") )
    {
        for (size_t i = 0; i < try_block.count; ++i)
        {
            js_stmt_destroy(try_block.stmts[i], parser->use_arena);
        }
        js_parser_free(parser, try_block.stmts);
        return NULL;
    }
    if (parser->current.type != JS_TOKEN_IDENTIFIER)
    {
        for (size_t i = 0; i < try_block.count; ++i)
        {
            js_stmt_destroy(try_block.stmts[i], parser->use_arena);
        }
        js_parser_free(parser, try_block.stmts);
        js_parser_error(parser, parser->current.offset, "expected catch identifier");
        return NULL;
    }
    char *catch_name = js_token_take_text(&parser->current);
    js_parser_advance(parser);
    if (!js_parser_expect(parser, JS_TOKEN_RPAREN, "expected ')'") )
    {
        js_parser_free(parser, catch_name);
        for (size_t i = 0; i < try_block.count; ++i)
        {
            js_stmt_destroy(try_block.stmts[i], parser->use_arena);
        }
        js_parser_free(parser, try_block.stmts);
        return NULL;
    }

    js_block_t catch_block = {0};
    if (!js_parse_block(parser, allow_return, &catch_block))
    {
        js_parser_free(parser, catch_name);
        for (size_t i = 0; i < try_block.count; ++i)
        {
            js_stmt_destroy(try_block.stmts[i], parser->use_arena);
        }
        js_parser_free(parser, try_block.stmts);
        return NULL;
    }

    js_stmt_t *stmt = js_new_stmt(parser, JS_STMT_TRY);
    if (!stmt)
    {
        js_parser_free(parser, catch_name);
        for (size_t i = 0; i < try_block.count; ++i)
        {
            js_stmt_destroy(try_block.stmts[i], parser->use_arena);
        }
        js_parser_free(parser, try_block.stmts);
        for (size_t i = 0; i < catch_block.count; ++i)
        {
            js_stmt_destroy(catch_block.stmts[i], parser->use_arena);
        }
        js_parser_free(parser, catch_block.stmts);
        js_parser_error(parser, parser->current.offset, "allocation failed");
        return NULL;
    }
    stmt->as.try_stmt.try_block = try_block;
    stmt->as.try_stmt.catch_name = catch_name;
    stmt->as.try_stmt.catch_block = catch_block;
    stmt->as.try_stmt.has_catch = true;
    return stmt;
}

static js_stmt_t *js_parse_expression_stmt(js_parser_t *parser)
{
    js_expr_t *expr = js_parse_expression(parser);
    if (!expr)
    {
        return NULL;
    }
    if (!js_parser_consume_semicolon(parser))
    {
        js_expr_destroy(expr, parser->use_arena);
        return NULL;
    }
    js_stmt_t *stmt = js_new_stmt(parser, JS_STMT_EXPR);
    if (!stmt)
    {
        js_expr_destroy(expr, parser->use_arena);
        js_parser_error(parser, parser->current.offset, "allocation failed");
        return NULL;
    }
    stmt->as.expr.expr = expr;
    return stmt;
}

static js_stmt_t *js_parse_statement(js_parser_t *parser, bool allow_return)
{
    if (!parser)
    {
        return NULL;
    }
    if (js_token_is_identifier(&parser->current, "class"))
    {
        return js_parse_class_decl(parser);
    }
    if (js_token_is_identifier(&parser->current, "async") &&
        js_parser_peek_async_function(parser))
    {
        js_parser_advance(parser);
        if (!js_parser_expect(parser, JS_TOKEN_KW_FUNCTION, "expected 'function'"))
        {
            return NULL;
        }
        return js_parse_function_decl(parser, true);
    }
    switch (parser->current.type)
    {
        case JS_TOKEN_SEMICOLON:
        {
            js_parser_advance(parser);
            return js_new_stmt(parser, JS_STMT_EMPTY);
        }
        case JS_TOKEN_KW_VAR:
        {
            js_parser_advance(parser);
            return js_parse_var_decl_impl(parser, JS_VAR_VAR, true);
        }
        case JS_TOKEN_KW_LET:
        {
            js_parser_advance(parser);
            return js_parse_var_decl_impl(parser, JS_VAR_LET, true);
        }
        case JS_TOKEN_KW_CONST:
        {
            js_parser_advance(parser);
            return js_parse_var_decl_impl(parser, JS_VAR_CONST, true);
        }
        case JS_TOKEN_KW_FUNCTION:
            js_parser_advance(parser);
            return js_parse_function_decl(parser, false);
        case JS_TOKEN_KW_RETURN:
            return js_parse_return(parser, allow_return);
        case JS_TOKEN_KW_THROW:
            return js_parse_throw(parser);
        case JS_TOKEN_KW_IF:
            js_parser_advance(parser);
            return js_parse_if_statement(parser, allow_return);
        case JS_TOKEN_KW_WHILE:
            js_parser_advance(parser);
            return js_parse_while_statement(parser, allow_return);
        case JS_TOKEN_KW_DO:
            js_parser_advance(parser);
            return js_parse_do_while_statement(parser, allow_return);
        case JS_TOKEN_KW_FOR:
            js_parser_advance(parser);
            return js_parse_for_statement(parser, allow_return);
        case JS_TOKEN_KW_SWITCH:
            js_parser_advance(parser);
            return js_parse_switch_statement(parser, allow_return);
        case JS_TOKEN_KW_TRY:
            js_parser_advance(parser);
            return js_parse_try_statement(parser, allow_return);
        case JS_TOKEN_KW_BREAK:
        {
            js_parser_advance(parser);
            if (!js_parser_consume_semicolon(parser))
            {
                return NULL;
            }
            return js_new_stmt(parser, JS_STMT_BREAK);
        }
        case JS_TOKEN_KW_CONTINUE:
        {
            js_parser_advance(parser);
            if (!js_parser_consume_semicolon(parser))
            {
                return NULL;
            }
            return js_new_stmt(parser, JS_STMT_CONTINUE);
        }
        case JS_TOKEN_LBRACE:
        {
            js_block_t body = {0};
            if (!js_parse_block(parser, allow_return, &body))
            {
                return NULL;
            }
            js_stmt_t *stmt = js_new_stmt(parser, JS_STMT_BLOCK);
            if (!stmt)
            {
                for (size_t i = 0; i < body.count; ++i)
                {
                    js_stmt_destroy(body.stmts[i], parser->use_arena);
                }
                js_parser_free(parser, body.stmts);
                js_parser_error(parser, parser->current.offset, "allocation failed");
                return NULL;
            }
            stmt->as.block = body;
            return stmt;
        }
        case JS_TOKEN_KW_CASE:
        case JS_TOKEN_KW_DEFAULT:
        case JS_TOKEN_KW_CATCH:
            js_parser_error(parser, parser->current.offset, "unexpected keyword");
            return NULL;
        default:
            return js_parse_expression_stmt(parser);
    }
}

js_program_t *js_parse(const char *source, js_parse_error_t *error_out)
{
    js_parser_t parser;
    js_parser_init(&parser, source, error_out);
    if (parser.had_error)
    {
        js_token_destroy(&parser.current);
        js_arena_release(&parser.arena);
        return NULL;
    }

    js_stmt_list_t list = {0};
    while (parser.current.type != JS_TOKEN_EOF && !parser.had_error)
    {
        js_stmt_t *stmt = js_parse_statement(&parser, false);
        if (!stmt)
        {
            break;
        }
        if (!js_stmt_list_push(&parser, &list, stmt))
        {
            js_stmt_destroy(stmt, parser.use_arena);
            js_parser_error(&parser, parser.current.offset, "allocation failed");
            break;
        }
    }

    if (parser.had_error)
    {
        for (size_t i = 0; i < list.count; ++i)
        {
            js_stmt_destroy(list.items[i], parser.use_arena);
        }
        js_parser_free(&parser, list.items);
        js_token_destroy(&parser.current);
        js_arena_release(&parser.arena);
        return NULL;
    }

    js_program_t *program = (js_program_t *)js_calloc(1, sizeof(*program));
    if (!program)
    {
        for (size_t i = 0; i < list.count; ++i)
        {
            js_stmt_destroy(list.items[i], parser.use_arena);
        }
        js_parser_free(&parser, list.items);
        js_parse_error_set(error_out, parser.current.offset, "allocation failed");
        js_token_destroy(&parser.current);
        js_arena_release(&parser.arena);
        return NULL;
    }
    program->statements = list.items;
    program->count = list.count;
    program->arena_blocks = parser.arena.blocks;
    parser.arena.blocks = NULL;

    js_token_destroy(&parser.current);
    return program;
}
