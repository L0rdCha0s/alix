#ifndef WEB_JS_RUNTIME_INTERNAL_H
#define WEB_JS_RUNTIME_INTERNAL_H

#include "web/js/internal.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct js_env js_env_t;
typedef struct js_var js_var_t;
typedef struct js_program_node js_program_node_t;
typedef struct js_native_meta js_native_meta_t;

struct js_array
{
    int refcount;
    js_value_t *items;
    size_t length;
    size_t capacity;
};

struct js_object
{
    int refcount;
    js_host_get_fn_t get_fn;
    js_host_set_fn_t set_fn;
    js_host_finalize_fn_t finalize_fn;
    void *user_data;
};

struct js_function
{
    int refcount;
    const js_function_decl_t *decl;
    const js_function_expr_t *expr;
    bool is_expr;
    bool is_constructible;
    js_env_t *closure;
};

struct js_native_meta
{
    js_native_fn_t fn;
    void *user_data;
    const char *name;
    bool is_constructor;
    js_native_meta_t *next;
};

struct js_runtime
{
    js_env_t *global;
    js_program_node_t *programs;
    js_native_meta_t *native_meta;
};

typedef struct
{
    char *data;
    size_t len;
    bool owned;
} js_temp_string_t;

js_value_t js_value_make_undefined_internal(void);
bool js_value_copy(js_value_t *out, const js_value_t *in);

double js_nan(void);
bool js_is_nan(double value);

bool js_value_is_truthy(const js_value_t *value);
double js_value_to_number(const js_value_t *value, bool *ok_out);
bool js_value_strict_equal(const js_value_t *a, const js_value_t *b);
bool js_value_loose_equal(const js_value_t *a, const js_value_t *b);

bool js_temp_string_from_value(const js_value_t *value, js_temp_string_t *out);
void js_temp_string_release(js_temp_string_t *temp);

bool js_parse_number_text(const char *text, double *out);

js_array_t *js_array_create(void);
void js_array_retain(js_array_t *array);
void js_array_release(js_array_t *array);
bool js_array_set(js_array_t *array, size_t index, const js_value_t *value);
bool js_array_get(const js_array_t *array, size_t index, js_value_t *out);

void js_object_retain(js_object_t *object);
void js_object_release(js_object_t *object);

js_function_t *js_function_create(const js_function_decl_t *decl,
                                  const js_function_expr_t *expr,
                                  js_env_t *closure,
                                  bool is_constructible);
void js_function_retain(js_function_t *fn);
void js_function_release(js_function_t *fn);

js_env_t *js_env_create(js_env_t *parent, bool is_function);
void js_env_retain(js_env_t *env);
void js_env_release(js_env_t *env);
bool js_env_define_local(js_env_t *env,
                         const char *name,
                         const js_value_t *value,
                         bool is_const,
                         bool allow_redeclare);
bool js_env_define_if_absent(js_env_t *env, const char *name, const js_value_t *value, bool is_const);
js_env_t *js_env_find_var_scope(js_env_t *env);
bool js_env_assign(js_env_t *env, const char *name, const js_value_t *value);
bool js_env_get(js_env_t *env, const char *name, js_value_t *out);

bool js_runtime_track_program(js_runtime_t *rt, js_program_t *program);
bool js_value_is_constructor(js_runtime_t *rt, const js_value_t *value);
const char *js_value_native_name(js_runtime_t *rt, const js_value_t *value);

bool js_call_value(js_runtime_t *rt,
                   const js_value_t *callee,
                   size_t argc,
                   const js_value_t *argv,
                   js_value_t *out,
                   char **error_message);

bool js_builtin_number(js_runtime_t *rt,
                       size_t argc,
                       const js_value_t *argv,
                       void *user_data,
                       js_value_t *out,
                       char **error_message);
bool js_builtin_escape(js_runtime_t *rt,
                       size_t argc,
                       const js_value_t *argv,
                       void *user_data,
                       js_value_t *out,
                       char **error_message);
bool js_builtin_type_error(js_runtime_t *rt,
                           size_t argc,
                           const js_value_t *argv,
                           void *user_data,
                           js_value_t *out,
                           char **error_message);

#ifdef __cplusplus
}
#endif

#endif /* WEB_JS_RUNTIME_INTERNAL_H */
