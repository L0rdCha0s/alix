#ifndef WEB_JS_PUBLIC_H
#define WEB_JS_PUBLIC_H

#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct js_runtime js_runtime_t;
typedef struct js_function js_function_t;
typedef struct js_value js_value_t;
typedef struct js_array js_array_t;
typedef struct js_object js_object_t;

typedef bool (*js_native_fn_t)(js_runtime_t *rt,
                               size_t argc,
                               const js_value_t *argv,
                               void *user_data,
                               js_value_t *out,
                               char **error_message);
typedef bool (*js_host_get_fn_t)(js_runtime_t *rt,
                                 void *user_data,
                                 const char *name,
                                 js_value_t *out,
                                 char **error_message);
typedef bool (*js_host_set_fn_t)(js_runtime_t *rt,
                                 void *user_data,
                                 const char *name,
                                 const js_value_t *value,
                                 char **error_message);
typedef void (*js_host_finalize_fn_t)(void *user_data);

typedef enum
{
    JS_VALUE_UNDEFINED = 0,
    JS_VALUE_NULL,
    JS_VALUE_BOOL,
    JS_VALUE_NUMBER,
    JS_VALUE_STRING,
    JS_VALUE_ARRAY,
    JS_VALUE_OBJECT,
    JS_VALUE_NATIVE_FN,
    JS_VALUE_FUNCTION
} js_value_type_t;

struct js_value
{
    js_value_type_t type;
    union
    {
        bool boolean;
        double number;
        struct
        {
            char *data;
            size_t len;
        } string;
        js_array_t *array;
        js_object_t *object;
        struct
        {
            js_native_fn_t fn;
            void *user_data;
        } native;
        js_function_t *function;
    } as;
};

js_value_t js_value_make_undefined(void);
js_value_t js_value_make_null(void);
js_value_t js_value_make_bool(bool value);
js_value_t js_value_make_number(double value);
bool js_value_make_string(js_value_t *out, const char *data, size_t len);
bool js_value_make_cstring(js_value_t *out, const char *text);
bool js_value_make_array(js_value_t *out);
bool js_value_make_host_object(js_value_t *out,
                               js_host_get_fn_t get_fn,
                               js_host_set_fn_t set_fn,
                               js_host_finalize_fn_t finalize_fn,
                               void *user_data);
bool js_value_array_set(js_value_t *array_value, size_t index, const js_value_t *value);
bool js_value_array_push(js_value_t *array_value, const js_value_t *value);
void js_value_destroy(js_value_t *value);

typedef struct
{
    size_t offset;
    const char *message;
} js_parse_error_t;

typedef enum
{
    JS_VAR_VAR = 0,
    JS_VAR_LET,
    JS_VAR_CONST
} js_var_kind_t;

typedef enum
{
    JS_STMT_VAR = 0,
    JS_STMT_EXPR,
    JS_STMT_BLOCK,
    JS_STMT_RETURN,
    JS_STMT_FUNCTION_DECL,
    JS_STMT_IF,
    JS_STMT_WHILE,
    JS_STMT_DO_WHILE,
    JS_STMT_FOR,
    JS_STMT_SWITCH,
    JS_STMT_TRY,
    JS_STMT_BREAK,
    JS_STMT_CONTINUE,
    JS_STMT_EMPTY
} js_stmt_type_t;

typedef enum
{
    JS_EXPR_LITERAL = 0,
    JS_EXPR_IDENTIFIER,
    JS_EXPR_BINARY,
    JS_EXPR_UNARY,
    JS_EXPR_ASSIGN,
    JS_EXPR_NEW,
    JS_EXPR_CALL,
    JS_EXPR_TERNARY,
    JS_EXPR_ARRAY,
    JS_EXPR_MEMBER,
    JS_EXPR_FUNCTION
} js_expr_type_t;

typedef enum
{
    JS_LITERAL_NUMBER = 0,
    JS_LITERAL_STRING,
    JS_LITERAL_BOOL,
    JS_LITERAL_NULL,
    JS_LITERAL_UNDEFINED
} js_literal_type_t;

typedef enum
{
    JS_BINARY_ADD = 0,
    JS_BINARY_SUB,
    JS_BINARY_MUL,
    JS_BINARY_DIV,
    JS_BINARY_MOD,
    JS_BINARY_EQ,
    JS_BINARY_NEQ,
    JS_BINARY_STRICT_EQ,
    JS_BINARY_STRICT_NEQ,
    JS_BINARY_LT,
    JS_BINARY_LTE,
    JS_BINARY_GT,
    JS_BINARY_GTE,
    JS_BINARY_AND,
    JS_BINARY_OR
} js_binary_op_t;

typedef enum
{
    JS_UNARY_NEGATE = 0,
    JS_UNARY_NOT,
    JS_UNARY_POSITIVE
} js_unary_op_t;

typedef struct js_expr js_expr_t;
typedef struct js_stmt js_stmt_t;

typedef struct
{
    js_var_kind_t kind;
    char *name;
    js_expr_t *init;
} js_var_decl_t;

typedef struct
{
    js_expr_t *expr;
} js_expr_stmt_t;

typedef struct
{
    js_stmt_t **stmts;
    size_t count;
} js_block_t;

typedef struct
{
    js_expr_t *value;
} js_return_stmt_t;

typedef struct
{
    char *name;
    char **params;
    size_t param_count;
    js_block_t body;
} js_function_decl_t;

typedef struct
{
    char *name;
    char **params;
    size_t param_count;
    js_block_t body;
    bool is_arrow;
} js_function_expr_t;

typedef struct
{
    js_expr_t *condition;
    js_stmt_t *then_branch;
    js_stmt_t *else_branch;
} js_if_stmt_t;

typedef struct
{
    js_expr_t *condition;
    js_stmt_t *body;
} js_while_stmt_t;

typedef struct
{
    js_stmt_t *init;
    js_expr_t *condition;
    js_expr_t *post;
    js_stmt_t *body;
} js_for_stmt_t;

typedef struct
{
    js_stmt_t *body;
    js_expr_t *condition;
} js_do_while_stmt_t;

typedef struct
{
    js_expr_t *test;
    js_stmt_t **stmts;
    size_t count;
} js_switch_case_t;

typedef struct
{
    js_expr_t *expr;
    js_switch_case_t *cases;
    size_t case_count;
} js_switch_stmt_t;

typedef struct
{
    js_block_t try_block;
    char *catch_name;
    js_block_t catch_block;
    bool has_catch;
} js_try_stmt_t;

struct js_stmt
{
    js_stmt_type_t type;
    union
    {
        js_var_decl_t var;
        js_expr_stmt_t expr;
        js_block_t block;
        js_return_stmt_t ret;
        js_function_decl_t func;
        js_if_stmt_t if_stmt;
        js_while_stmt_t while_stmt;
        js_for_stmt_t for_stmt;
        js_do_while_stmt_t do_while_stmt;
        js_switch_stmt_t switch_stmt;
        js_try_stmt_t try_stmt;
    } as;
};

typedef struct
{
    js_value_t value;
} js_literal_expr_t;

typedef struct
{
    char *name;
} js_identifier_expr_t;

typedef struct
{
    js_binary_op_t op;
    js_expr_t *left;
    js_expr_t *right;
} js_binary_expr_t;

typedef struct
{
    js_unary_op_t op;
    js_expr_t *expr;
} js_unary_expr_t;

typedef struct
{
    js_expr_t *target;
    js_expr_t *value;
} js_assign_expr_t;

typedef struct
{
    js_expr_t *callee;
    js_expr_t **args;
    size_t arg_count;
} js_new_expr_t;

typedef struct
{
    js_expr_t *callee;
    js_expr_t **args;
    size_t arg_count;
} js_call_expr_t;

typedef struct
{
    js_expr_t **items;
    size_t count;
} js_array_expr_t;

typedef struct
{
    js_expr_t *object;
    bool computed;
    char *property;
    js_expr_t *property_expr;
} js_member_expr_t;

typedef struct
{
    js_expr_t *condition;
    js_expr_t *then_expr;
    js_expr_t *else_expr;
} js_ternary_expr_t;

struct js_expr
{
    js_expr_type_t type;
    union
    {
        js_literal_expr_t literal;
        js_identifier_expr_t ident;
        js_binary_expr_t binary;
        js_unary_expr_t unary;
        js_assign_expr_t assign;
        js_new_expr_t new_expr;
        js_call_expr_t call;
        js_ternary_expr_t ternary;
        js_array_expr_t array;
        js_member_expr_t member;
        js_function_expr_t func;
    } as;
};

typedef struct
{
    js_stmt_t **statements;
    size_t count;
} js_program_t;

js_program_t *js_parse(const char *source, js_parse_error_t *error_out);
void js_program_destroy(js_program_t *program);

typedef struct
{
    bool ok;
    js_value_t value;
    size_t error_offset;
    char *error_message;
} js_exec_result_t;

js_runtime_t *js_runtime_create(void);
void js_runtime_destroy(js_runtime_t *rt);

bool js_runtime_set_global(js_runtime_t *rt, const char *name, const js_value_t *value);
bool js_runtime_set_native(js_runtime_t *rt, const char *name, js_native_fn_t fn, void *user_data);

js_exec_result_t js_execute(js_runtime_t *rt, const js_program_t *program);
js_exec_result_t js_eval(js_runtime_t *rt, const char *source);
void js_exec_result_destroy(js_exec_result_t *result);

#ifdef __cplusplus
}
#endif

#endif /* WEB_JS_PUBLIC_H */
