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

static bool js_token_is_identifier(const js_token_t *tok, const char *text);

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
    js_lexer_init(&parser->lexer, source);
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

static bool js_stmt_list_push(js_stmt_list_t *list, js_stmt_t *stmt)
{
    if (!list || !stmt)
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
        js_stmt_t **new_items = (js_stmt_t **)realloc(list->items, new_cap * sizeof(*new_items));
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

static bool js_expr_list_push(js_expr_list_t *list, js_expr_t *expr)
{
    if (!list || !expr)
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
        js_expr_t **new_items = (js_expr_t **)realloc(list->items, new_cap * sizeof(*new_items));
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

static bool js_param_list_push(js_param_list_t *list, const js_param_t *param)
{
    if (!list || !param)
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
        js_param_t *new_items = (js_param_t *)realloc(list->items, new_cap * sizeof(*new_items));
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

static bool js_case_list_push(js_case_list_t *list, const js_switch_case_t *item)
{
    if (!list || !item)
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
        js_switch_case_t *new_items = (js_switch_case_t *)realloc(list->items, new_cap * sizeof(*new_items));
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

static bool js_prop_list_push(js_prop_list_t *list, const js_object_property_t *prop)
{
    if (!list || !prop)
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
        js_object_property_t *new_items = (js_object_property_t *)realloc(list->items, new_cap * sizeof(*new_items));
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

static bool js_var_list_push(js_var_list_t *list, const js_var_binding_t *binding)
{
    if (!list || !binding)
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
        js_var_binding_t *new_items = (js_var_binding_t *)realloc(list->items, new_cap * sizeof(*new_items));
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

static bool js_binding_element_list_push(js_binding_element_t **items,
                                         size_t *count,
                                         size_t *cap,
                                         const js_binding_element_t *elem)
{
    if (!items || !count || !cap || !elem)
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
            (js_binding_element_t *)realloc(*items, new_cap * sizeof(*new_items));
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

static bool js_binding_prop_list_push(js_binding_property_t **items,
                                      size_t *count,
                                      size_t *cap,
                                      const js_binding_property_t *prop)
{
    if (!items || !count || !cap || !prop)
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
            (js_binding_property_t *)realloc(*items, new_cap * sizeof(*new_items));
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

static void js_expr_destroy(js_expr_t *expr);
static void js_binding_destroy(js_binding_t *binding);

static void js_param_list_destroy(js_param_list_t *params)
{
    if (!params)
    {
        return;
    }
    for (size_t i = 0; i < params->count; ++i)
    {
        js_binding_destroy(params->items[i].binding);
        js_expr_destroy(params->items[i].init);
    }
    free(params->items);
    params->items = NULL;
    params->count = 0;
    params->cap = 0;
}

static js_expr_t *js_new_expr(js_expr_type_t type)
{
    js_expr_t *expr = (js_expr_t *)calloc(1, sizeof(*expr));
    if (!expr)
    {
        return NULL;
    }
    expr->type = type;
    return expr;
}

static js_stmt_t *js_new_stmt(js_stmt_type_t type)
{
    js_stmt_t *stmt = (js_stmt_t *)calloc(1, sizeof(*stmt));
    if (!stmt)
    {
        return NULL;
    }
    stmt->type = type;
    return stmt;
}

static void js_binding_destroy(js_binding_t *binding)
{
    if (!binding)
    {
        return;
    }
    switch (binding->type)
    {
        case JS_BINDING_IDENTIFIER:
            free(binding->as.ident.name);
            break;
        case JS_BINDING_ARRAY:
            for (size_t i = 0; i < binding->as.array.count; ++i)
            {
                js_binding_destroy(binding->as.array.elements[i].binding);
                js_expr_destroy(binding->as.array.elements[i].init);
            }
            free(binding->as.array.elements);
            js_binding_destroy(binding->as.array.rest);
            break;
        case JS_BINDING_OBJECT:
            for (size_t i = 0; i < binding->as.object.count; ++i)
            {
                if (binding->as.object.props[i].computed)
                {
                    js_expr_destroy(binding->as.object.props[i].name_expr);
                }
                else
                {
                    free(binding->as.object.props[i].name);
                }
                js_binding_destroy(binding->as.object.props[i].binding);
                js_expr_destroy(binding->as.object.props[i].init);
            }
            free(binding->as.object.props);
            free(binding->as.object.rest_name);
            break;
    }
    free(binding);
}

static void js_stmt_destroy(js_stmt_t *stmt)
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
                js_binding_destroy(stmt->as.var.bindings[i].binding);
                js_expr_destroy(stmt->as.var.bindings[i].init);
            }
            free(stmt->as.var.bindings);
            break;
        case JS_STMT_EXPR:
            js_expr_destroy(stmt->as.expr.expr);
            break;
        case JS_STMT_BLOCK:
            for (size_t i = 0; i < stmt->as.block.count; ++i)
            {
                js_stmt_destroy(stmt->as.block.stmts[i]);
            }
            free(stmt->as.block.stmts);
            break;
        case JS_STMT_RETURN:
            js_expr_destroy(stmt->as.ret.value);
            break;
        case JS_STMT_THROW:
            js_expr_destroy(stmt->as.throw_stmt.expr);
            break;
        case JS_STMT_FUNCTION_DECL:
            free(stmt->as.func.name);
            for (size_t p = 0; p < stmt->as.func.param_count; ++p)
            {
                js_binding_destroy(stmt->as.func.params[p].binding);
                js_expr_destroy(stmt->as.func.params[p].init);
            }
            free(stmt->as.func.params);
            for (size_t i = 0; i < stmt->as.func.body.count; ++i)
            {
                js_stmt_destroy(stmt->as.func.body.stmts[i]);
            }
            free(stmt->as.func.body.stmts);
            break;
        case JS_STMT_IF:
            js_expr_destroy(stmt->as.if_stmt.condition);
            js_stmt_destroy(stmt->as.if_stmt.then_branch);
            js_stmt_destroy(stmt->as.if_stmt.else_branch);
            break;
        case JS_STMT_WHILE:
            js_expr_destroy(stmt->as.while_stmt.condition);
            js_stmt_destroy(stmt->as.while_stmt.body);
            break;
        case JS_STMT_DO_WHILE:
            js_stmt_destroy(stmt->as.do_while_stmt.body);
            js_expr_destroy(stmt->as.do_while_stmt.condition);
            break;
        case JS_STMT_FOR:
            js_stmt_destroy(stmt->as.for_stmt.init);
            js_expr_destroy(stmt->as.for_stmt.condition);
            js_expr_destroy(stmt->as.for_stmt.post);
            js_stmt_destroy(stmt->as.for_stmt.body);
            break;
        case JS_STMT_FOR_IN:
        case JS_STMT_FOR_OF:
            js_binding_destroy(stmt->as.for_inof.binding);
            js_expr_destroy(stmt->as.for_inof.target);
            js_expr_destroy(stmt->as.for_inof.expr);
            js_stmt_destroy(stmt->as.for_inof.body);
            break;
        case JS_STMT_SWITCH:
            js_expr_destroy(stmt->as.switch_stmt.expr);
            for (size_t c = 0; c < stmt->as.switch_stmt.case_count; ++c)
            {
                js_switch_case_t *case_stmt = &stmt->as.switch_stmt.cases[c];
                js_expr_destroy(case_stmt->test);
                for (size_t i = 0; i < case_stmt->count; ++i)
                {
                    js_stmt_destroy(case_stmt->stmts[i]);
                }
                free(case_stmt->stmts);
            }
            free(stmt->as.switch_stmt.cases);
            break;
        case JS_STMT_TRY:
            for (size_t i = 0; i < stmt->as.try_stmt.try_block.count; ++i)
            {
                js_stmt_destroy(stmt->as.try_stmt.try_block.stmts[i]);
            }
            free(stmt->as.try_stmt.try_block.stmts);
            if (stmt->as.try_stmt.has_catch)
            {
                free(stmt->as.try_stmt.catch_name);
                for (size_t i = 0; i < stmt->as.try_stmt.catch_block.count; ++i)
                {
                    js_stmt_destroy(stmt->as.try_stmt.catch_block.stmts[i]);
                }
                free(stmt->as.try_stmt.catch_block.stmts);
            }
            break;
        case JS_STMT_BREAK:
        case JS_STMT_CONTINUE:
        case JS_STMT_EMPTY:
            break;
    }
    free(stmt);
}

static void js_expr_destroy(js_expr_t *expr)
{
    if (!expr)
    {
        return;
    }
    switch (expr->type)
    {
        case JS_EXPR_LITERAL:
            js_value_destroy(&expr->as.literal.value);
            break;
        case JS_EXPR_IDENTIFIER:
            free(expr->as.ident.name);
            break;
        case JS_EXPR_THIS:
            break;
        case JS_EXPR_BINARY:
            js_expr_destroy(expr->as.binary.left);
            js_expr_destroy(expr->as.binary.right);
            break;
        case JS_EXPR_UNARY:
            js_expr_destroy(expr->as.unary.expr);
            break;
        case JS_EXPR_UPDATE:
            js_expr_destroy(expr->as.update.target);
            break;
        case JS_EXPR_ASSIGN:
            js_expr_destroy(expr->as.assign.target);
            js_expr_destroy(expr->as.assign.value);
            break;
        case JS_EXPR_NEW:
            js_expr_destroy(expr->as.new_expr.callee);
            for (size_t i = 0; i < expr->as.new_expr.arg_count; ++i)
            {
                js_expr_destroy(expr->as.new_expr.args[i]);
            }
            free(expr->as.new_expr.args);
            break;
        case JS_EXPR_CALL:
            js_expr_destroy(expr->as.call.callee);
            for (size_t i = 0; i < expr->as.call.arg_count; ++i)
            {
                js_expr_destroy(expr->as.call.args[i]);
            }
            free(expr->as.call.args);
            break;
        case JS_EXPR_ARRAY:
            for (size_t i = 0; i < expr->as.array.count; ++i)
            {
                js_expr_destroy(expr->as.array.items[i]);
            }
            free(expr->as.array.items);
            break;
        case JS_EXPR_OBJECT:
            for (size_t i = 0; i < expr->as.object.count; ++i)
            {
                if (expr->as.object.props[i].computed)
                {
                    js_expr_destroy(expr->as.object.props[i].name_expr);
                }
                else
                {
                    free(expr->as.object.props[i].name);
                }
                js_expr_destroy(expr->as.object.props[i].value);
            }
            free(expr->as.object.props);
            break;
        case JS_EXPR_MEMBER:
            js_expr_destroy(expr->as.member.object);
            if (expr->as.member.computed)
            {
                js_expr_destroy(expr->as.member.property_expr);
            }
            free(expr->as.member.property);
            break;
        case JS_EXPR_REGEXP_SUBCLASS:
            break;
        case JS_EXPR_TERNARY:
            js_expr_destroy(expr->as.ternary.condition);
            js_expr_destroy(expr->as.ternary.then_expr);
            js_expr_destroy(expr->as.ternary.else_expr);
            break;
        case JS_EXPR_FUNCTION:
            free(expr->as.func.name);
            for (size_t p = 0; p < expr->as.func.param_count; ++p)
            {
                js_binding_destroy(expr->as.func.params[p].binding);
                js_expr_destroy(expr->as.func.params[p].init);
            }
            free(expr->as.func.params);
            for (size_t i = 0; i < expr->as.func.body.count; ++i)
            {
                js_stmt_destroy(expr->as.func.body.stmts[i]);
            }
            free(expr->as.func.body.stmts);
            break;
        case JS_EXPR_YIELD:
            js_expr_destroy(expr->as.yield.value);
            break;
    }
    free(expr);
}

void js_program_destroy(js_program_t *program)
{
    if (!program)
    {
        return;
    }
    for (size_t i = 0; i < program->count; ++i)
    {
        js_stmt_destroy(program->statements[i]);
    }
    free(program->statements);
    free(program);
}

static js_expr_t *js_parse_expression(js_parser_t *parser);
static js_stmt_t *js_parse_statement(js_parser_t *parser, bool allow_return);
static bool js_parse_block(js_parser_t *parser, bool allow_return, js_block_t *out);
static bool js_parse_function_common(js_parser_t *parser, bool require_name, js_function_expr_t *out);
static bool js_parse_function_tail(js_parser_t *parser, js_function_expr_t *out);
static js_expr_t *js_parse_arrow_function(js_parser_t *parser);
static js_expr_t *js_parse_member_suffix(js_parser_t *parser, js_expr_t *expr);
static js_binding_t *js_new_binding(js_binding_type_t type);
static js_binding_t *js_parse_binding_pattern(js_parser_t *parser);

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
    char *pattern = js_strdup_len(start, pattern_len);
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
        flags = js_strdup_len(flag_start, flag_len);
        if (!flags)
        {
            free(pattern);
            js_parser_error(parser, offset, "allocation failed");
            return NULL;
        }
    }

    parser->lexer.cur = cur;
    parser->lexer.offset = (size_t)(cur - parser->lexer.source);
    js_parser_advance(parser);

    js_expr_t *callee = js_new_expr(JS_EXPR_IDENTIFIER);
    if (!callee)
    {
        free(pattern);
        free(flags);
        js_parser_error(parser, offset, "allocation failed");
        return NULL;
    }
    callee->as.ident.name = js_strdup("RegExp");
    if (!callee->as.ident.name)
    {
        free(pattern);
        free(flags);
        js_expr_destroy(callee);
        js_parser_error(parser, offset, "allocation failed");
        return NULL;
    }

    js_expr_t *pattern_expr = js_new_expr(JS_EXPR_LITERAL);
    if (!pattern_expr)
    {
        free(pattern);
        free(flags);
        js_expr_destroy(callee);
        js_parser_error(parser, offset, "allocation failed");
        return NULL;
    }
    pattern_expr->as.literal.value.type = JS_VALUE_STRING;
    pattern_expr->as.literal.value.as.string.data = pattern;
    pattern_expr->as.literal.value.as.string.len = pattern_len;

    size_t arg_count = flag_len ? 2 : 1;
    js_expr_t **args = (js_expr_t **)calloc(arg_count, sizeof(*args));
    if (!args)
    {
        js_expr_destroy(pattern_expr);
        js_expr_destroy(callee);
        free(flags);
        js_parser_error(parser, offset, "allocation failed");
        return NULL;
    }
    args[0] = pattern_expr;

    if (flag_len)
    {
        js_expr_t *flag_expr = js_new_expr(JS_EXPR_LITERAL);
        if (!flag_expr)
        {
            free(flags);
            free(args);
            js_expr_destroy(pattern_expr);
            js_expr_destroy(callee);
            js_parser_error(parser, offset, "allocation failed");
            return NULL;
        }
        flag_expr->as.literal.value.type = JS_VALUE_STRING;
        flag_expr->as.literal.value.as.string.data = flags;
        flag_expr->as.literal.value.as.string.len = flag_len;
        args[1] = flag_expr;
    }

    js_expr_t *call = js_new_expr(JS_EXPR_CALL);
    if (!call)
    {
        for (size_t i = 0; i < arg_count; ++i)
        {
            if (args[i])
            {
                js_expr_destroy(args[i]);
            }
        }
        free(args);
        js_expr_destroy(callee);
        js_parser_error(parser, offset, "allocation failed");
        return NULL;
    }
    call->as.call.callee = callee;
    call->as.call.args = args;
    call->as.call.arg_count = arg_count;
    return call;
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

static bool js_build_return_block(js_expr_t *expr, js_block_t *out)
{
    if (!expr || !out)
    {
        return false;
    }
    js_stmt_t *stmt = js_new_stmt(JS_STMT_RETURN);
    if (!stmt)
    {
        return false;
    }
    stmt->as.ret.value = expr;
    js_stmt_t **stmts = (js_stmt_t **)calloc(1, sizeof(*stmts));
    if (!stmts)
    {
        stmt->as.ret.value = NULL;
        js_stmt_destroy(stmt);
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
                js_param_list_destroy(params);
                return false;
            }
            saw_rest = true;
            param.is_rest = true;
            js_parser_advance(parser);
            param.binding = js_parse_binding_pattern(parser);
            if (!param.binding)
            {
                js_param_list_destroy(params);
                return false;
            }
        }
        else
        {
            param.binding = js_parse_binding_pattern(parser);
            if (!param.binding)
            {
                js_param_list_destroy(params);
                return false;
            }
        }
        if (!param.is_rest && parser->current.type == JS_TOKEN_EQUAL)
        {
            js_parser_advance(parser);
            param.init = js_parse_expression(parser);
            if (!param.init)
            {
                js_binding_destroy(param.binding);
                js_param_list_destroy(params);
                return false;
            }
        }
        else if (param.is_rest && parser->current.type == JS_TOKEN_EQUAL)
        {
            js_binding_destroy(param.binding);
            js_parser_error(parser, parser->current.offset, "invalid rest parameter");
            js_param_list_destroy(params);
            return false;
        }

        if (!js_param_list_push(params, &param))
        {
            js_binding_destroy(param.binding);
            js_expr_destroy(param.init);
            js_param_list_destroy(params);
            return false;
        }
        if (parser->current.type == JS_TOKEN_COMMA)
        {
            if (saw_rest)
            {
                js_parser_error(parser, parser->current.offset, "expected ')'");
                js_param_list_destroy(params);
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
        js_binding_t *binding = js_new_binding(JS_BINDING_IDENTIFIER);
        if (!binding)
        {
            js_parser_error(parser, parser->current.offset, "allocation failed");
            return false;
        }
        binding->as.ident.name = js_token_take_text(&parser->current);
        js_parser_advance(parser);
        param.binding = binding;
        param.is_rest = false;
        if (!js_param_list_push(params, &param))
        {
            js_binding_destroy(binding);
            js_param_list_destroy(params);
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

static js_expr_t *js_parse_arrow_function(js_parser_t *parser)
{
    size_t offset = parser ? parser->current.offset : 0;
    js_param_list_t params = {0};
    if (!js_parse_arrow_params(parser, &params))
    {
        return NULL;
    }
    if (!js_parser_expect(parser, JS_TOKEN_ARROW, "expected '=>'"))
    {
        js_param_list_destroy(&params);
        return NULL;
    }

    js_block_t body = {0};
    bool prev_in_generator = parser->in_generator;
    parser->in_generator = false;
    if (parser->current.type == JS_TOKEN_LBRACE)
    {
        if (!js_parse_block(parser, true, &body))
        {
            parser->in_generator = prev_in_generator;
            js_param_list_destroy(&params);
            return NULL;
        }
    }
    else
    {
        js_expr_t *expr = js_parse_expression(parser);
        if (!expr)
        {
            parser->in_generator = prev_in_generator;
            js_param_list_destroy(&params);
            return NULL;
        }
        if (!js_build_return_block(expr, &body))
        {
            js_expr_destroy(expr);
            parser->in_generator = prev_in_generator;
            js_param_list_destroy(&params);
            js_parser_error(parser, offset, "allocation failed");
            return NULL;
        }
    }
    parser->in_generator = prev_in_generator;

    js_expr_t *expr = js_new_expr(JS_EXPR_FUNCTION);
    if (!expr)
    {
        js_param_list_destroy(&params);
        for (size_t i = 0; i < body.count; ++i)
        {
            js_stmt_destroy(body.stmts[i]);
        }
        free(body.stmts);
        js_parser_error(parser, offset, "allocation failed");
        return NULL;
    }
    expr->as.func.name = NULL;
    expr->as.func.params = params.items;
    expr->as.func.param_count = params.count;
    expr->as.func.body = body;
    expr->as.func.is_arrow = true;
    expr->as.func.is_generator = false;
    return expr;
}

static js_binding_t *js_new_binding(js_binding_type_t type)
{
    js_binding_t *binding = (js_binding_t *)calloc(1, sizeof(*binding));
    if (!binding)
    {
        return NULL;
    }
    binding->type = type;
    return binding;
}

static js_binding_t *js_parse_binding_pattern(js_parser_t *parser);

static void js_binding_prop_cleanup(js_binding_property_t *prop)
{
    if (!prop)
    {
        return;
    }
    if (prop->computed)
    {
        js_expr_destroy(prop->name_expr);
    }
    else
    {
        free(prop->name);
    }
    js_binding_destroy(prop->binding);
    js_expr_destroy(prop->init);
    memset(prop, 0, sizeof(*prop));
}

static js_binding_t *js_parse_binding_array(js_parser_t *parser)
{
    size_t offset = parser ? parser->current.offset : 0;
    if (!js_parser_expect(parser, JS_TOKEN_LBRACKET, "expected '['"))
    {
        return NULL;
    }

    js_binding_t *binding = js_new_binding(JS_BINDING_ARRAY);
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
                if (!js_binding_element_list_push(&elements, &count, &cap, &elem))
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
                    js_binding_destroy(item_binding);
                    goto error;
                }
            }
            js_binding_element_t elem = {0};
            elem.binding = item_binding;
            elem.init = init;
            if (!js_binding_element_list_push(&elements, &count, &cap, &elem))
            {
                js_binding_destroy(item_binding);
                js_expr_destroy(init);
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
        js_binding_destroy(elements[i].binding);
        js_expr_destroy(elements[i].init);
    }
    free(elements);
    js_binding_destroy(rest);
    js_binding_destroy(binding);
    return NULL;
}

static js_binding_t *js_parse_binding_object(js_parser_t *parser)
{
    size_t offset = parser ? parser->current.offset : 0;
    if (!js_parser_expect(parser, JS_TOKEN_LBRACE, "expected '{'"))
    {
        return NULL;
    }

    js_binding_t *binding = js_new_binding(JS_BINDING_OBJECT);
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
                    js_binding_prop_cleanup(&prop);
                    goto error;
                }
                if (!js_parser_expect(parser, JS_TOKEN_RBRACKET, "expected ']'"))
                {
                    js_binding_prop_cleanup(&prop);
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
                js_binding_prop_cleanup(&prop);
                goto error;
            }

            if (parser->current.type == JS_TOKEN_COLON)
            {
                js_parser_advance(parser);
                prop.binding = js_parse_binding_pattern(parser);
                if (!prop.binding)
                {
                    js_binding_prop_cleanup(&prop);
                    goto error;
                }
            }
            else
            {
                if (prop.computed || !prop.name)
                {
                    js_parser_error(parser, parser->current.offset, "expected ':'");
                    js_binding_prop_cleanup(&prop);
                    goto error;
                }
                prop.binding = js_new_binding(JS_BINDING_IDENTIFIER);
                if (!prop.binding)
                {
                    js_parser_error(parser, parser->current.offset, "allocation failed");
                    js_binding_prop_cleanup(&prop);
                    goto error;
                }
                prop.binding->as.ident.name = js_strdup(prop.name);
                if (!prop.binding->as.ident.name)
                {
                    js_parser_error(parser, parser->current.offset, "allocation failed");
                    js_binding_prop_cleanup(&prop);
                    goto error;
                }
            }

            if (parser->current.type == JS_TOKEN_EQUAL)
            {
                js_parser_advance(parser);
                prop.init = js_parse_expression(parser);
                if (!prop.init)
                {
                    js_binding_prop_cleanup(&prop);
                    goto error;
                }
            }

            if (!js_binding_prop_list_push(&props, &count, &cap, &prop))
            {
                js_parser_error(parser, parser->current.offset, "allocation failed");
                js_binding_prop_cleanup(&prop);
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
            js_expr_destroy(props[i].name_expr);
        }
        else
        {
            free(props[i].name);
        }
        js_binding_destroy(props[i].binding);
        js_expr_destroy(props[i].init);
    }
    free(props);
    free(rest_name);
    js_binding_destroy(binding);
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
        js_binding_t *binding = js_new_binding(JS_BINDING_IDENTIFIER);
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

static js_expr_t *js_parse_class_expression(js_parser_t *parser)
{
    if (!parser)
    {
        return NULL;
    }
    size_t offset = parser->current.offset;
    char *class_kw = js_token_take_text(&parser->current);
    free(class_kw);
    js_parser_advance(parser);
    if (parser->current.type == JS_TOKEN_IDENTIFIER &&
        parser->current.text &&
        strcmp(parser->current.text, "extends") != 0)
    {
        char *name = js_token_take_text(&parser->current);
        free(name);
        js_parser_advance(parser);
    }
    if (!(parser->current.type == JS_TOKEN_IDENTIFIER &&
          parser->current.text &&
          strcmp(parser->current.text, "extends") == 0))
    {
        js_parser_error(parser, parser->current.offset, "expected 'extends'");
        return NULL;
    }
    char *extends_kw = js_token_take_text(&parser->current);
    free(extends_kw);
    js_parser_advance(parser);
    if (parser->current.type != JS_TOKEN_IDENTIFIER || !parser->current.text)
    {
        js_parser_error(parser, parser->current.offset, "expected base class");
        return NULL;
    }
    char *base = js_token_take_text(&parser->current);
    js_parser_advance(parser);
    bool is_regexp = base && strcmp(base, "RegExp") == 0;
    free(base);
    if (!is_regexp)
    {
        js_parser_error(parser, offset, "unsupported class base");
        return NULL;
    }
    if (!js_parser_expect(parser, JS_TOKEN_LBRACE, "expected '{'") )
    {
        return NULL;
    }
    if (!js_parser_expect(parser, JS_TOKEN_RBRACE, "expected '}'") )
    {
        return NULL;
    }
    js_expr_t *expr = js_new_expr(JS_EXPR_REGEXP_SUBCLASS);
    if (!expr)
    {
        js_parser_error(parser, offset, "allocation failed");
        return NULL;
    }
    return expr;
}

static js_expr_t *js_parse_primary(js_parser_t *parser)
{
    if (!parser)
    {
        return NULL;
    }
    if (parser->current.type == JS_TOKEN_IDENTIFIER && js_parser_peek_arrow_after_ident(parser))
    {
        return js_parse_arrow_function(parser);
    }
    if (parser->current.type == JS_TOKEN_IDENTIFIER &&
        parser->current.text &&
        strcmp(parser->current.text, "class") == 0)
    {
        return js_parse_class_expression(parser);
    }
    if (parser->current.type == JS_TOKEN_LPAREN && js_parser_peek_arrow_after_paren(parser))
    {
        return js_parse_arrow_function(parser);
    }
    switch (parser->current.type)
    {
        case JS_TOKEN_SLASH:
        {
            return js_parse_regex_literal(parser);
        }
        case JS_TOKEN_NUMBER:
        {
            js_expr_t *expr = js_new_expr(JS_EXPR_LITERAL);
            if (!expr)
            {
                js_parser_error(parser, parser->current.offset, "allocation failed");
                return NULL;
            }
            expr->as.literal.value = js_value_make_number(parser->current.number);
            js_parser_advance(parser);
            return expr;
        }
        case JS_TOKEN_STRING:
        {
            js_expr_t *expr = js_new_expr(JS_EXPR_LITERAL);
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
        case JS_TOKEN_KW_TRUE:
        case JS_TOKEN_KW_FALSE:
        {
            js_expr_t *expr = js_new_expr(JS_EXPR_LITERAL);
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
            js_expr_t *expr = js_new_expr(JS_EXPR_LITERAL);
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
            js_expr_t *expr = js_new_expr(JS_EXPR_LITERAL);
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
            js_expr_t *expr = js_new_expr(JS_EXPR_THIS);
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
            js_expr_t *expr = js_new_expr(JS_EXPR_IDENTIFIER);
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
                            js_expr_destroy(items.items[i]);
                        }
                        free(items.items);
                        return NULL;
                    }
                    if (!js_expr_list_push(&items, item))
                    {
                        js_expr_destroy(item);
                        for (size_t i = 0; i < items.count; ++i)
                        {
                            js_expr_destroy(items.items[i]);
                        }
                        free(items.items);
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
                    js_expr_destroy(items.items[i]);
                }
                free(items.items);
                return NULL;
            }
            js_expr_t *expr = js_new_expr(JS_EXPR_ARRAY);
            if (!expr)
            {
                for (size_t i = 0; i < items.count; ++i)
                {
                    js_expr_destroy(items.items[i]);
                }
                free(items.items);
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
                    bool allow_shorthand = false;
                    if (parser->current.type == JS_TOKEN_IDENTIFIER && js_parser_peek_accessor(parser))
                    {
                        accessor_is_getter = (strcmp(parser->current.text, "get") == 0);
                        is_accessor = true;
                        js_parser_advance(parser);
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
                            js_expr_destroy(name_expr);
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
                        prop.name = js_strdup(kw);
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
                        if (!js_parse_function_tail(parser, &func))
                        {
                            if (prop.computed)
                            {
                                js_expr_destroy(prop.name_expr);
                            }
                            else
                            {
                                free(prop.name);
                            }
                            break;
                        }
                        js_expr_t *fn_expr = js_new_expr(JS_EXPR_FUNCTION);
                        if (!fn_expr)
                        {
                            if (prop.computed)
                            {
                                js_expr_destroy(prop.name_expr);
                            }
                            else
                            {
                                free(prop.name);
                            }
                            for (size_t p = 0; p < func.param_count; ++p)
                            {
                                js_binding_destroy(func.params[p].binding);
                                js_expr_destroy(func.params[p].init);
                            }
                            free(func.params);
                            for (size_t i = 0; i < func.body.count; ++i)
                            {
                                js_stmt_destroy(func.body.stmts[i]);
                            }
                            free(func.body.stmts);
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
                        if (!js_parse_function_tail(parser, &func))
                        {
                            if (prop.computed)
                            {
                                js_expr_destroy(prop.name_expr);
                            }
                            else
                            {
                                free(prop.name);
                            }
                            break;
                        }
                        js_expr_t *fn_expr = js_new_expr(JS_EXPR_FUNCTION);
                        if (!fn_expr)
                        {
                            if (prop.computed)
                            {
                                js_expr_destroy(prop.name_expr);
                            }
                            else
                            {
                                free(prop.name);
                            }
                            for (size_t p = 0; p < func.param_count; ++p)
                            {
                                js_binding_destroy(func.params[p].binding);
                                js_expr_destroy(func.params[p].init);
                            }
                            free(func.params);
                            for (size_t i = 0; i < func.body.count; ++i)
                            {
                                js_stmt_destroy(func.body.stmts[i]);
                            }
                            free(func.body.stmts);
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
                                js_expr_destroy(prop.name_expr);
                            }
                            else
                            {
                                free(prop.name);
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
                        js_expr_t *value = js_new_expr(JS_EXPR_IDENTIFIER);
                        if (!value)
                        {
                            free(prop.name);
                            js_parser_error(parser, parser->current.offset, "allocation failed");
                            break;
                        }
                        value->as.ident.name = js_strdup(prop.name);
                        if (!value->as.ident.name)
                        {
                            js_expr_destroy(value);
                            free(prop.name);
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
                            js_expr_destroy(prop.name_expr);
                        }
                        else
                        {
                            free(prop.name);
                        }
                        break;
                    }

                    if (!js_prop_list_push(&props, &prop))
                    {
                        if (prop.computed)
                        {
                            js_expr_destroy(prop.name_expr);
                        }
                        else
                        {
                            free(prop.name);
                        }
                        js_expr_destroy(prop.value);
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
                        js_expr_destroy(props.items[i].name_expr);
                    }
                    else
                    {
                        free(props.items[i].name);
                    }
                    js_expr_destroy(props.items[i].value);
                }
                free(props.items);
                return NULL;
            }
            js_expr_t *expr = js_new_expr(JS_EXPR_OBJECT);
            if (!expr)
            {
                for (size_t i = 0; i < props.count; ++i)
                {
                    if (props.items[i].computed)
                    {
                        js_expr_destroy(props.items[i].name_expr);
                    }
                    else
                    {
                        free(props.items[i].name);
                    }
                    js_expr_destroy(props.items[i].value);
                }
                free(props.items);
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
            if (!js_parse_function_common(parser, false, &func))
            {
                return NULL;
            }
            js_expr_t *expr = js_new_expr(JS_EXPR_FUNCTION);
            if (!expr)
            {
                free(func.name);
                for (size_t p = 0; p < func.param_count; ++p)
                {
                    js_binding_destroy(func.params[p].binding);
                    js_expr_destroy(func.params[p].init);
                }
                free(func.params);
                for (size_t i = 0; i < func.body.count; ++i)
                {
                    js_stmt_destroy(func.body.stmts[i]);
                }
                free(func.body.stmts);
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
                js_expr_destroy(expr);
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
                js_expr_destroy(expr);
                js_parser_error(parser, parser->current.offset, "expected property name");
                return NULL;
            }
            char *name = js_token_take_text(&parser->current);
            js_parser_advance(parser);
            js_expr_t *member = js_new_expr(JS_EXPR_MEMBER);
            if (!member)
            {
                free(name);
                js_expr_destroy(expr);
                js_parser_error(parser, parser->current.offset, "allocation failed");
                return NULL;
            }
            member->as.member.object = expr;
            member->as.member.computed = false;
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
                js_expr_destroy(expr);
                return NULL;
            }
            if (!js_parser_expect(parser, JS_TOKEN_RBRACKET, "expected ']'") )
            {
                js_expr_destroy(prop_expr);
                js_expr_destroy(expr);
                return NULL;
            }
            js_expr_t *member = js_new_expr(JS_EXPR_MEMBER);
            if (!member)
            {
                js_expr_destroy(prop_expr);
                js_expr_destroy(expr);
                js_parser_error(parser, parser->current.offset, "allocation failed");
                return NULL;
            }
            member->as.member.object = expr;
            member->as.member.computed = true;
            member->as.member.property = NULL;
            member->as.member.property_expr = prop_expr;
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
    expr = js_parse_member_suffix(parser, expr);
    if (!expr)
    {
        return NULL;
    }

    for (;;)
    {
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
                            js_expr_destroy(args.items[i]);
                        }
                        free(args.items);
                        js_expr_destroy(expr);
                        return NULL;
                    }
                    if (!js_expr_list_push(&args, arg))
                    {
                        js_expr_destroy(arg);
                        for (size_t i = 0; i < args.count; ++i)
                        {
                            js_expr_destroy(args.items[i]);
                        }
                        free(args.items);
                        js_expr_destroy(expr);
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
                    js_expr_destroy(args.items[i]);
                }
                free(args.items);
                js_expr_destroy(expr);
                return NULL;
            }

            js_expr_t *call = js_new_expr(JS_EXPR_CALL);
            if (!call)
            {
                for (size_t i = 0; i < args.count; ++i)
                {
                    js_expr_destroy(args.items[i]);
                }
                free(args.items);
                js_expr_destroy(expr);
                js_parser_error(parser, parser->current.offset, "allocation failed");
                return NULL;
            }
            call->as.call.callee = expr;
            call->as.call.args = args.items;
            call->as.call.arg_count = args.count;
            expr = call;
            expr = js_parse_member_suffix(parser, expr);
            if (!expr)
            {
                return NULL;
            }
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
        js_expr_t *expr = js_new_expr(JS_EXPR_UPDATE);
        if (!expr)
        {
            js_expr_destroy(target);
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
                            js_expr_destroy(args.items[i]);
                        }
                        free(args.items);
                        js_expr_destroy(callee);
                        return NULL;
                    }
                    if (!js_expr_list_push(&args, arg))
                    {
                        js_expr_destroy(arg);
                        for (size_t i = 0; i < args.count; ++i)
                        {
                            js_expr_destroy(args.items[i]);
                        }
                        free(args.items);
                        js_expr_destroy(callee);
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
                    js_expr_destroy(args.items[i]);
                }
                free(args.items);
                js_expr_destroy(callee);
                return NULL;
            }
        }
        js_expr_t *expr = js_new_expr(JS_EXPR_NEW);
        if (!expr)
        {
            for (size_t i = 0; i < args.count; ++i)
            {
                js_expr_destroy(args.items[i]);
            }
            free(args.items);
            js_expr_destroy(callee);
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
                            js_expr_destroy(call_args.items[i]);
                        }
                        free(call_args.items);
                        js_expr_destroy(expr);
                        return NULL;
                    }
                    if (!js_expr_list_push(&call_args, arg))
                    {
                        js_expr_destroy(arg);
                        for (size_t i = 0; i < call_args.count; ++i)
                        {
                            js_expr_destroy(call_args.items[i]);
                        }
                        free(call_args.items);
                        js_expr_destroy(expr);
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
                    js_expr_destroy(call_args.items[i]);
                }
                free(call_args.items);
                js_expr_destroy(expr);
                return NULL;
            }
            js_expr_t *call = js_new_expr(JS_EXPR_CALL);
            if (!call)
            {
                for (size_t i = 0; i < call_args.count; ++i)
                {
                    js_expr_destroy(call_args.items[i]);
                }
                free(call_args.items);
                js_expr_destroy(expr);
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
        js_expr_t *expr = js_new_expr(JS_EXPR_UNARY);
        if (!expr)
        {
            js_expr_destroy(right);
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
        js_expr_t *update = js_new_expr(JS_EXPR_UPDATE);
        if (!update)
        {
            js_expr_destroy(expr);
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

static js_expr_t *js_parse_factor(js_parser_t *parser)
{
    js_expr_t *expr = js_parse_unary(parser);
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
        js_expr_t *right = js_parse_unary(parser);
        if (!right)
        {
            js_expr_destroy(expr);
            return NULL;
        }
        js_expr_t *binary = js_new_expr(JS_EXPR_BINARY);
        if (!binary)
        {
            js_expr_destroy(expr);
            js_expr_destroy(right);
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
            js_expr_destroy(expr);
            return NULL;
        }
        js_expr_t *binary = js_new_expr(JS_EXPR_BINARY);
        if (!binary)
        {
            js_expr_destroy(expr);
            js_expr_destroy(right);
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
        else
        {
            break;
        }
        size_t offset = parser->current.offset;
        js_parser_advance(parser);
        js_expr_t *right = js_parse_term(parser);
        if (!right)
        {
            js_expr_destroy(expr);
            return NULL;
        }
        js_expr_t *binary = js_new_expr(JS_EXPR_BINARY);
        if (!binary)
        {
            js_expr_destroy(expr);
            js_expr_destroy(right);
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
            js_expr_destroy(expr);
            return NULL;
        }
        js_expr_t *binary = js_new_expr(JS_EXPR_BINARY);
        if (!binary)
        {
            js_expr_destroy(expr);
            js_expr_destroy(right);
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
            js_expr_destroy(expr);
            return NULL;
        }
        js_expr_t *binary = js_new_expr(JS_EXPR_BINARY);
        if (!binary)
        {
            js_expr_destroy(expr);
            js_expr_destroy(right);
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
            js_expr_destroy(expr);
            return NULL;
        }
        js_expr_t *binary = js_new_expr(JS_EXPR_BINARY);
        if (!binary)
        {
            js_expr_destroy(expr);
            js_expr_destroy(right);
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

static js_expr_t *js_parse_ternary(js_parser_t *parser)
{
    js_expr_t *expr = js_parse_logical_or(parser);
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
            js_expr_destroy(expr);
            return NULL;
        }
        if (!js_parser_expect(parser, JS_TOKEN_COLON, "expected ':'"))
        {
            js_expr_destroy(expr);
            js_expr_destroy(then_expr);
            return NULL;
        }
        js_expr_t *else_expr = js_parse_ternary(parser);
        if (!else_expr)
        {
            js_expr_destroy(expr);
            js_expr_destroy(then_expr);
            return NULL;
        }
        js_expr_t *ternary = js_new_expr(JS_EXPR_TERNARY);
        if (!ternary)
        {
            js_expr_destroy(expr);
            js_expr_destroy(then_expr);
            js_expr_destroy(else_expr);
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
    if (parser->current.type == JS_TOKEN_EQUAL || parser->current.type == JS_TOKEN_PLUS_EQUAL)
    {
        js_token_type_t assign_type = parser->current.type;
        size_t offset = parser->current.offset;
        js_parser_advance(parser);
        if (expr->type != JS_EXPR_IDENTIFIER && expr->type != JS_EXPR_MEMBER)
        {
            js_expr_destroy(expr);
            js_parser_error(parser, offset, "invalid assignment target");
            return NULL;
        }
        js_expr_t *value = js_parse_assignment(parser);
        if (!value)
        {
            js_expr_destroy(expr);
            return NULL;
        }
        js_expr_t *assign = js_new_expr(JS_EXPR_ASSIGN);
        if (!assign)
        {
            js_expr_destroy(value);
            js_expr_destroy(expr);
            js_parser_error(parser, offset, "allocation failed");
            return NULL;
        }
        assign->as.assign.target = expr;
        assign->as.assign.value = value;
        assign->as.assign.op = (assign_type == JS_TOKEN_PLUS_EQUAL) ? JS_ASSIGN_ADD : JS_ASSIGN_SET;
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
    js_expr_t *expr = js_new_expr(JS_EXPR_YIELD);
    if (!expr)
    {
        js_expr_destroy(value);
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
                js_binding_destroy(pattern);
                break;
            }
        }
        if (kind == JS_VAR_CONST && !init)
        {
            js_parser_error(parser, parser->current.offset, "const requires initializer");
            js_binding_destroy(pattern);
            break;
        }
        if (!init && pattern->type != JS_BINDING_IDENTIFIER)
        {
            js_parser_error(parser, parser->current.offset, "missing initializer");
            js_binding_destroy(pattern);
            break;
        }
        js_var_binding_t entry = {0};
        entry.binding = pattern;
        entry.init = init;
        if (!js_var_list_push(&bindings, &entry))
        {
            js_expr_destroy(init);
            js_binding_destroy(pattern);
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
            js_binding_destroy(bindings.items[i].binding);
            js_expr_destroy(bindings.items[i].init);
        }
        free(bindings.items);
        return NULL;
    }
    if (consume_semi)
    {
        if (!js_parser_consume_semicolon(parser))
        {
            for (size_t i = 0; i < bindings.count; ++i)
            {
                js_binding_destroy(bindings.items[i].binding);
                js_expr_destroy(bindings.items[i].init);
            }
            free(bindings.items);
            return NULL;
        }
    }
    js_stmt_t *stmt = js_new_stmt(JS_STMT_VAR);
    if (!stmt)
    {
        for (size_t i = 0; i < bindings.count; ++i)
        {
            js_binding_destroy(bindings.items[i].binding);
            js_expr_destroy(bindings.items[i].init);
        }
        free(bindings.items);
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
                js_stmt_destroy(list.items[i]);
            }
            free(list.items);
            return false;
        }
        if (!js_stmt_list_push(&list, stmt))
        {
            js_stmt_destroy(stmt);
            for (size_t i = 0; i < list.count; ++i)
            {
                js_stmt_destroy(list.items[i]);
            }
            free(list.items);
            js_parser_error(parser, parser->current.offset, "allocation failed");
            return false;
        }
    }
    if (parser->current.type != JS_TOKEN_RBRACE)
    {
        for (size_t i = 0; i < list.count; ++i)
        {
            js_stmt_destroy(list.items[i]);
        }
        free(list.items);
        js_parser_error(parser, parser->current.offset, "expected '}'");
        return false;
    }
    js_parser_advance(parser);
    out->stmts = list.items;
    out->count = list.count;
    return true;
}

static bool js_parse_function_tail(js_parser_t *parser, js_function_expr_t *out)
{
    if (!parser || !out)
    {
        return false;
    }
    memset(out, 0, sizeof(*out));

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
        js_param_list_destroy(&params);
        return false;
    }

    js_block_t body = {0};
    bool prev_in_generator = parser->in_generator;
    parser->in_generator = false;
    if (!js_parse_block(parser, true, &body))
    {
        parser->in_generator = prev_in_generator;
        js_param_list_destroy(&params);
        js_parser_error(parser, parser->current.offset, "invalid function body");
        return false;
    }
    parser->in_generator = prev_in_generator;

    out->params = params.items;
    out->param_count = params.count;
    out->body = body;
    return true;
}

static bool js_parse_function_common(js_parser_t *parser, bool require_name, js_function_expr_t *out)
{
    if (!parser || !out)
    {
        return false;
    }
    memset(out, 0, sizeof(*out));

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
        free(out->name);
        out->name = NULL;
        return false;
    }

    js_param_list_t params = {0};
    if (!js_parse_param_list_body(parser, &params))
    {
        free(out->name);
        out->name = NULL;
        return false;
    }

    if (parser->had_error || !js_parser_expect(parser, JS_TOKEN_RPAREN, "expected ')'") )
    {
        js_param_list_destroy(&params);
        free(out->name);
        out->name = NULL;
        return false;
    }

    js_block_t body = {0};
    bool prev_in_generator = parser->in_generator;
    parser->in_generator = out->is_generator;
    if (!js_parse_block(parser, true, &body))
    {
        parser->in_generator = prev_in_generator;
        js_param_list_destroy(&params);
        free(out->name);
        out->name = NULL;
        js_parser_error(parser, parser->current.offset, "invalid function body");
        return false;
    }
    parser->in_generator = prev_in_generator;

    out->params = params.items;
    out->param_count = params.count;
    out->body = body;
    return true;
}

static js_stmt_t *js_parse_function_decl(js_parser_t *parser)
{
    if (!parser)
    {
        return NULL;
    }
    size_t offset = parser->current.offset;
    js_function_expr_t func = {0};
    if (!js_parse_function_common(parser, true, &func))
    {
        return NULL;
    }

    js_stmt_t *stmt = js_new_stmt(JS_STMT_FUNCTION_DECL);
    if (!stmt)
    {
        free(func.name);
        for (size_t p = 0; p < func.param_count; ++p)
        {
            js_binding_destroy(func.params[p].binding);
            js_expr_destroy(func.params[p].init);
        }
        free(func.params);
        for (size_t i = 0; i < func.body.count; ++i)
        {
            js_stmt_destroy(func.body.stmts[i]);
        }
        free(func.body.stmts);
        js_parser_error(parser, offset, "allocation failed");
        return NULL;
    }
    stmt->as.func.name = func.name;
    stmt->as.func.params = func.params;
    stmt->as.func.param_count = func.param_count;
    stmt->as.func.body = func.body;
    stmt->as.func.is_arrow = false;
    stmt->as.func.is_generator = func.is_generator;
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
        js_expr_destroy(value);
        return NULL;
    }
    js_stmt_t *stmt = js_new_stmt(JS_STMT_RETURN);
    if (!stmt)
    {
        js_expr_destroy(value);
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
        js_expr_destroy(expr);
        return NULL;
    }
    js_stmt_t *stmt = js_new_stmt(JS_STMT_THROW);
    if (!stmt)
    {
        js_expr_destroy(expr);
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
        js_expr_destroy(condition);
        return NULL;
    }
    js_stmt_t *then_branch = js_parse_statement(parser, allow_return);
    if (!then_branch)
    {
        js_expr_destroy(condition);
        return NULL;
    }
    js_stmt_t *else_branch = NULL;
    if (parser->current.type == JS_TOKEN_KW_ELSE)
    {
        js_parser_advance(parser);
        else_branch = js_parse_statement(parser, allow_return);
        if (!else_branch)
        {
            js_expr_destroy(condition);
            js_stmt_destroy(then_branch);
            return NULL;
        }
    }
    js_stmt_t *stmt = js_new_stmt(JS_STMT_IF);
    if (!stmt)
    {
        js_expr_destroy(condition);
        js_stmt_destroy(then_branch);
        js_stmt_destroy(else_branch);
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
        js_expr_destroy(condition);
        return NULL;
    }
    js_stmt_t *body = js_parse_statement(parser, allow_return);
    if (!body)
    {
        js_expr_destroy(condition);
        return NULL;
    }
    js_stmt_t *stmt = js_new_stmt(JS_STMT_WHILE);
    if (!stmt)
    {
        js_expr_destroy(condition);
        js_stmt_destroy(body);
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
        js_stmt_destroy(body);
        return NULL;
    }
    if (!js_parser_expect(parser, JS_TOKEN_LPAREN, "expected '('") )
    {
        js_stmt_destroy(body);
        return NULL;
    }
    js_expr_t *condition = js_parse_expression(parser);
    if (!condition)
    {
        js_stmt_destroy(body);
        return NULL;
    }
    if (!js_parser_expect(parser, JS_TOKEN_RPAREN, "expected ')'") )
    {
        js_expr_destroy(condition);
        js_stmt_destroy(body);
        return NULL;
    }
    if (!js_parser_consume_semicolon(parser))
    {
        js_expr_destroy(condition);
        js_stmt_destroy(body);
        return NULL;
    }
    js_stmt_t *stmt = js_new_stmt(JS_STMT_DO_WHILE);
    if (!stmt)
    {
        js_expr_destroy(condition);
        js_stmt_destroy(body);
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
                    js_binding_destroy(pattern);
                    return NULL;
                }
            }

            if (js_token_is_identifier(&parser->current, "in") ||
                js_token_is_identifier(&parser->current, "of"))
            {
                if (init_expr)
                {
                    js_expr_destroy(init_expr);
                    js_binding_destroy(pattern);
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
                    js_binding_destroy(for_binding);
                    return NULL;
                }
            }
            else
            {
                if (kind == JS_VAR_CONST && !init_expr)
                {
                    js_parser_error(parser, parser->current.offset, "const requires initializer");
                    js_binding_destroy(pattern);
                    return NULL;
                }
                if (!init_expr && pattern->type != JS_BINDING_IDENTIFIER)
                {
                    js_parser_error(parser, parser->current.offset, "missing initializer");
                    js_binding_destroy(pattern);
                    return NULL;
                }
                js_var_list_t list = {0};
                js_var_binding_t entry = {0};
                entry.binding = pattern;
                entry.init = init_expr;
                if (!js_var_list_push(&list, &entry))
                {
                    js_expr_destroy(init_expr);
                    js_binding_destroy(pattern);
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
                            js_binding_destroy(list.items[i].binding);
                            js_expr_destroy(list.items[i].init);
                        }
                        free(list.items);
                        return NULL;
                    }
                    js_expr_t *next_init = NULL;
                    if (parser->current.type == JS_TOKEN_EQUAL)
                    {
                        js_parser_advance(parser);
                        next_init = js_parse_expression(parser);
                        if (!next_init)
                        {
                            js_binding_destroy(next);
                            for (size_t i = 0; i < list.count; ++i)
                            {
                                js_binding_destroy(list.items[i].binding);
                                js_expr_destroy(list.items[i].init);
                            }
                            free(list.items);
                            return NULL;
                        }
                    }
                    if (kind == JS_VAR_CONST && !next_init)
                    {
                        js_parser_error(parser, parser->current.offset, "const requires initializer");
                        js_binding_destroy(next);
                        for (size_t i = 0; i < list.count; ++i)
                        {
                            js_binding_destroy(list.items[i].binding);
                            js_expr_destroy(list.items[i].init);
                        }
                        free(list.items);
                        return NULL;
                    }
                    if (!next_init && next->type != JS_BINDING_IDENTIFIER)
                    {
                        js_parser_error(parser, parser->current.offset, "missing initializer");
                        js_binding_destroy(next);
                        for (size_t i = 0; i < list.count; ++i)
                        {
                            js_binding_destroy(list.items[i].binding);
                            js_expr_destroy(list.items[i].init);
                        }
                        free(list.items);
                        return NULL;
                    }
                    js_var_binding_t next_entry = {0};
                    next_entry.binding = next;
                    next_entry.init = next_init;
                    if (!js_var_list_push(&list, &next_entry))
                    {
                        js_expr_destroy(next_init);
                        js_binding_destroy(next);
                        for (size_t i = 0; i < list.count; ++i)
                        {
                            js_binding_destroy(list.items[i].binding);
                            js_expr_destroy(list.items[i].init);
                        }
                        free(list.items);
                        js_parser_error(parser, parser->current.offset, "allocation failed");
                        return NULL;
                    }
                }

                init = js_new_stmt(JS_STMT_VAR);
                if (!init)
                {
                    for (size_t i = 0; i < list.count; ++i)
                    {
                        js_binding_destroy(list.items[i].binding);
                        js_expr_destroy(list.items[i].init);
                    }
                    free(list.items);
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
                    js_expr_destroy(expr);
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
                    js_expr_destroy(for_target);
                    return NULL;
                }
            }
            else
            {
                init = js_new_stmt(JS_STMT_EXPR);
                if (!init)
                {
                    js_expr_destroy(expr);
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
            js_stmt_destroy(init);
            js_binding_destroy(for_binding);
            js_expr_destroy(for_target);
            js_expr_destroy(for_expr);
            return NULL;
        }
        js_stmt_t *body = js_parse_statement(parser, allow_return);
        if (!body)
        {
            js_stmt_destroy(init);
            js_binding_destroy(for_binding);
            js_expr_destroy(for_target);
            js_expr_destroy(for_expr);
            return NULL;
        }
        js_stmt_t *stmt = js_new_stmt(for_is_of ? JS_STMT_FOR_OF : JS_STMT_FOR_IN);
        if (!stmt)
        {
            js_stmt_destroy(init);
            js_binding_destroy(for_binding);
            js_expr_destroy(for_target);
            js_expr_destroy(for_expr);
            js_stmt_destroy(body);
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
        js_stmt_destroy(init);
        return NULL;
    }

    js_expr_t *condition = NULL;
    if (parser->current.type != JS_TOKEN_SEMICOLON)
    {
        condition = js_parse_expression(parser);
        if (!condition)
        {
            js_stmt_destroy(init);
            return NULL;
        }
    }
    if (!js_parser_expect(parser, JS_TOKEN_SEMICOLON, "expected ';'") )
    {
        js_stmt_destroy(init);
        js_expr_destroy(condition);
        return NULL;
    }

    js_expr_t *post = NULL;
    if (parser->current.type != JS_TOKEN_RPAREN)
    {
        post = js_parse_expression(parser);
        if (!post)
        {
            js_stmt_destroy(init);
            js_expr_destroy(condition);
            return NULL;
        }
    }
    if (!js_parser_expect(parser, JS_TOKEN_RPAREN, "expected ')'") )
    {
        js_stmt_destroy(init);
        js_expr_destroy(condition);
        js_expr_destroy(post);
        return NULL;
    }

    js_stmt_t *body = js_parse_statement(parser, allow_return);
    if (!body)
    {
        js_stmt_destroy(init);
        js_expr_destroy(condition);
        js_expr_destroy(post);
        return NULL;
    }

    js_stmt_t *stmt = js_new_stmt(JS_STMT_FOR);
    if (!stmt)
    {
        js_stmt_destroy(init);
        js_expr_destroy(condition);
        js_expr_destroy(post);
        js_stmt_destroy(body);
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
        js_expr_destroy(expr);
        return NULL;
    }
    if (!js_parser_expect(parser, JS_TOKEN_LBRACE, "expected '{'") )
    {
        js_expr_destroy(expr);
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
            if (!js_stmt_list_push(&stmts, stmt))
            {
                js_stmt_destroy(stmt);
                js_parser_error(parser, parser->current.offset, "allocation failed");
                goto switch_error_stmts;
            }
        }
        case_stmt.stmts = stmts.items;
        case_stmt.count = stmts.count;

        if (!js_case_list_push(&cases, &case_stmt))
        {
            js_parser_error(parser, parser->current.offset, "allocation failed");
            goto switch_error;
        }
        continue;

switch_error_stmts:
        for (size_t i = 0; i < stmts.count; ++i)
        {
            js_stmt_destroy(stmts.items[i]);
        }
        free(stmts.items);

switch_error:
        js_expr_destroy(case_stmt.test);
        for (size_t i = 0; i < case_stmt.count; ++i)
        {
            js_stmt_destroy(case_stmt.stmts[i]);
        }
        free(case_stmt.stmts);
        for (size_t c = 0; c < cases.count; ++c)
        {
            js_expr_destroy(cases.items[c].test);
            for (size_t i = 0; i < cases.items[c].count; ++i)
            {
                js_stmt_destroy(cases.items[c].stmts[i]);
            }
            free(cases.items[c].stmts);
        }
        free(cases.items);
        js_expr_destroy(expr);
        return NULL;
    }

    if (!js_parser_expect(parser, JS_TOKEN_RBRACE, "expected '}'") )
    {
        for (size_t c = 0; c < cases.count; ++c)
        {
            js_expr_destroy(cases.items[c].test);
            for (size_t i = 0; i < cases.items[c].count; ++i)
            {
                js_stmt_destroy(cases.items[c].stmts[i]);
            }
            free(cases.items[c].stmts);
        }
        free(cases.items);
        js_expr_destroy(expr);
        return NULL;
    }

    js_stmt_t *stmt = js_new_stmt(JS_STMT_SWITCH);
    if (!stmt)
    {
        for (size_t c = 0; c < cases.count; ++c)
        {
            js_expr_destroy(cases.items[c].test);
            for (size_t i = 0; i < cases.items[c].count; ++i)
            {
                js_stmt_destroy(cases.items[c].stmts[i]);
            }
            free(cases.items[c].stmts);
        }
        free(cases.items);
        js_expr_destroy(expr);
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
            js_stmt_destroy(try_block.stmts[i]);
        }
        free(try_block.stmts);
        js_parser_error(parser, parser->current.offset, "expected catch");
        return NULL;
    }

    js_parser_advance(parser);
    if (!js_parser_expect(parser, JS_TOKEN_LPAREN, "expected '('") )
    {
        for (size_t i = 0; i < try_block.count; ++i)
        {
            js_stmt_destroy(try_block.stmts[i]);
        }
        free(try_block.stmts);
        return NULL;
    }
    if (parser->current.type != JS_TOKEN_IDENTIFIER)
    {
        for (size_t i = 0; i < try_block.count; ++i)
        {
            js_stmt_destroy(try_block.stmts[i]);
        }
        free(try_block.stmts);
        js_parser_error(parser, parser->current.offset, "expected catch identifier");
        return NULL;
    }
    char *catch_name = js_token_take_text(&parser->current);
    js_parser_advance(parser);
    if (!js_parser_expect(parser, JS_TOKEN_RPAREN, "expected ')'") )
    {
        free(catch_name);
        for (size_t i = 0; i < try_block.count; ++i)
        {
            js_stmt_destroy(try_block.stmts[i]);
        }
        free(try_block.stmts);
        return NULL;
    }

    js_block_t catch_block = {0};
    if (!js_parse_block(parser, allow_return, &catch_block))
    {
        free(catch_name);
        for (size_t i = 0; i < try_block.count; ++i)
        {
            js_stmt_destroy(try_block.stmts[i]);
        }
        free(try_block.stmts);
        return NULL;
    }

    js_stmt_t *stmt = js_new_stmt(JS_STMT_TRY);
    if (!stmt)
    {
        free(catch_name);
        for (size_t i = 0; i < try_block.count; ++i)
        {
            js_stmt_destroy(try_block.stmts[i]);
        }
        free(try_block.stmts);
        for (size_t i = 0; i < catch_block.count; ++i)
        {
            js_stmt_destroy(catch_block.stmts[i]);
        }
        free(catch_block.stmts);
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
        js_expr_destroy(expr);
        return NULL;
    }
    js_stmt_t *stmt = js_new_stmt(JS_STMT_EXPR);
    if (!stmt)
    {
        js_expr_destroy(expr);
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
    switch (parser->current.type)
    {
        case JS_TOKEN_SEMICOLON:
        {
            js_parser_advance(parser);
            return js_new_stmt(JS_STMT_EMPTY);
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
            return js_parse_function_decl(parser);
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
            return js_new_stmt(JS_STMT_BREAK);
        }
        case JS_TOKEN_KW_CONTINUE:
        {
            js_parser_advance(parser);
            if (!js_parser_consume_semicolon(parser))
            {
                return NULL;
            }
            return js_new_stmt(JS_STMT_CONTINUE);
        }
        case JS_TOKEN_LBRACE:
        {
            js_block_t body = {0};
            if (!js_parse_block(parser, allow_return, &body))
            {
                return NULL;
            }
            js_stmt_t *stmt = js_new_stmt(JS_STMT_BLOCK);
            if (!stmt)
            {
                for (size_t i = 0; i < body.count; ++i)
                {
                    js_stmt_destroy(body.stmts[i]);
                }
                free(body.stmts);
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
        if (!js_stmt_list_push(&list, stmt))
        {
            js_stmt_destroy(stmt);
            js_parser_error(&parser, parser.current.offset, "allocation failed");
            break;
        }
    }

    if (parser.had_error)
    {
        for (size_t i = 0; i < list.count; ++i)
        {
            js_stmt_destroy(list.items[i]);
        }
        free(list.items);
        js_token_destroy(&parser.current);
        return NULL;
    }

    js_program_t *program = (js_program_t *)calloc(1, sizeof(*program));
    if (!program)
    {
        for (size_t i = 0; i < list.count; ++i)
        {
            js_stmt_destroy(list.items[i]);
        }
        free(list.items);
        js_parse_error_set(error_out, parser.current.offset, "allocation failed");
        js_token_destroy(&parser.current);
        return NULL;
    }
    program->statements = list.items;
    program->count = list.count;

    js_token_destroy(&parser.current);
    return program;
}
