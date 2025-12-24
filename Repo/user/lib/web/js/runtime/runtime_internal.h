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
typedef struct js_property js_property_t;
typedef struct js_bound_fn js_bound_fn_t;

struct js_array
{
    int refcount;
    js_value_t *items;
    size_t length;
    size_t capacity;
    js_property_t *properties;
};

struct js_object
{
    int refcount;
    js_host_get_fn_t get_fn;
    js_host_set_fn_t set_fn;
    js_host_finalize_fn_t finalize_fn;
    void *user_data;
    js_property_t *properties;
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
    size_t length;
    js_native_meta_t *next;
};

struct js_property
{
    char *name;
    js_value_t value;
    js_value_t getter;
    js_value_t setter;
    bool writable;
    bool enumerable;
    bool configurable;
    bool is_accessor;
    js_property_t *next;
};

struct js_runtime
{
    js_env_t *global;
    js_program_node_t *programs;
    js_native_meta_t *native_meta;
    js_object_t *global_object;
    js_object_t *object_proto;
    js_object_t *function_proto;
    js_object_t *array_proto;
    js_object_t *math_object;
    js_object_t *iterator_proto;
    js_object_t *set_iterator_proto;
    js_array_t *yield_array;
    size_t yield_limit;
    size_t yield_count;
    js_bound_fn_t *bound_functions;
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

bool js_temp_string_from_value(js_runtime_t *rt,
                               const js_value_t *value,
                               js_temp_string_t *out,
                               char **error_message);
void js_temp_string_release(js_temp_string_t *temp);

bool js_parse_number_text(const char *text, double *out);

js_array_t *js_array_create(void);
void js_array_retain(js_array_t *array);
void js_array_release(js_array_t *array);
bool js_array_set(js_array_t *array, size_t index, const js_value_t *value);
bool js_array_get(const js_array_t *array, size_t index, js_value_t *out);
bool js_array_get_property(js_runtime_t *rt, js_array_t *array, const char *name, js_value_t *out, char **error_message);
bool js_array_set_property(js_array_t *array, const char *name, const js_value_t *value);
bool js_array_set_length(js_array_t *array, size_t new_length);
bool js_array_has_property(js_array_t *array, const char *name);
js_property_t *js_array_find_property(js_array_t *array, const char *name);

void js_object_retain(js_object_t *object);
void js_object_release(js_object_t *object);
bool js_object_get_slot(js_object_t *object, const char *name, js_value_t *out);
bool js_object_set_slot(js_object_t *object, const char *name, const js_value_t *value);
bool js_object_has_slot(js_object_t *object, const char *name);
bool js_object_has_property(js_runtime_t *rt, js_object_t *object, const char *name);
bool js_object_is_symbol(const js_object_t *object);
js_property_t *js_object_find_property(js_object_t *object, const char *name);
bool js_object_get_property(js_runtime_t *rt,
                            js_object_t *object,
                            const char *name,
                            js_value_t *out,
                            char **error_message);

bool js_value_make_symbol(js_value_t *out, const char *description);

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
bool js_value_native_length(js_runtime_t *rt, const js_value_t *value, size_t *out_len);
bool js_native_needs_this(js_native_fn_t fn);

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
bool js_builtin_string(js_runtime_t *rt,
                       size_t argc,
                       const js_value_t *argv,
                       void *user_data,
                       js_value_t *out,
                       char **error_message);
bool js_builtin_string_from_char_code(js_runtime_t *rt,
                                      size_t argc,
                                      const js_value_t *argv,
                                      void *user_data,
                                      js_value_t *out,
                                      char **error_message);
bool js_builtin_regexp(js_runtime_t *rt,
                       size_t argc,
                       const js_value_t *argv,
                       void *user_data,
                       js_value_t *out,
                       char **error_message);
bool js_builtin_regexp_subclass(js_runtime_t *rt,
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
bool js_builtin_unescape(js_runtime_t *rt,
                         size_t argc,
                         const js_value_t *argv,
                         void *user_data,
                         js_value_t *out,
                         char **error_message);
bool js_builtin_eval(js_runtime_t *rt,
                     size_t argc,
                     const js_value_t *argv,
                     void *user_data,
                     js_value_t *out,
                     char **error_message);
bool js_builtin_symbol(js_runtime_t *rt,
                       size_t argc,
                       const js_value_t *argv,
                       void *user_data,
                       js_value_t *out,
                       char **error_message);
bool js_builtin_set(js_runtime_t *rt,
                    size_t argc,
                    const js_value_t *argv,
                    void *user_data,
                    js_value_t *out,
                    char **error_message);
bool js_set_iterator(js_runtime_t *rt,
                     size_t argc,
                     const js_value_t *argv,
                     void *user_data,
                     js_value_t *out,
                     char **error_message);
bool js_regexp_compile(js_runtime_t *rt,
                       size_t argc,
                       const js_value_t *argv,
                       void *user_data,
                       js_value_t *out,
                       char **error_message);
bool js_regexp_exec(js_runtime_t *rt,
                    size_t argc,
                    const js_value_t *argv,
                    void *user_data,
                    js_value_t *out,
                    char **error_message);
bool js_regexp_compile_proto(js_runtime_t *rt,
                             size_t argc,
                             const js_value_t *argv,
                             void *user_data,
                             js_value_t *out,
                             char **error_message);
bool js_builtin_is_html_dda(js_runtime_t *rt,
                            size_t argc,
                            const js_value_t *argv,
                            void *user_data,
                            js_value_t *out,
                            char **error_message);
bool js_builtin_create_realm(js_runtime_t *rt,
                             size_t argc,
                             const js_value_t *argv,
                             void *user_data,
                             js_value_t *out,
                             char **error_message);
bool js_builtin_test_with_typed_array_constructors(js_runtime_t *rt,
                                                   size_t argc,
                                                   const js_value_t *argv,
                                                   void *user_data,
                                                   js_value_t *out,
                                                   char **error_message);
bool js_builtin_string_match(js_runtime_t *rt,
                             size_t argc,
                             const js_value_t *argv,
                             void *user_data,
                             js_value_t *out,
                             char **error_message);
bool js_builtin_number_to_string(js_runtime_t *rt,
                                 size_t argc,
                                 const js_value_t *argv,
                                 void *user_data,
                                 js_value_t *out,
                                 char **error_message);
bool js_builtin_define_property(js_runtime_t *rt,
                                size_t argc,
                                const js_value_t *argv,
                                void *user_data,
                                js_value_t *out,
                                char **error_message);
bool js_builtin_define_properties(js_runtime_t *rt,
                                  size_t argc,
                                  const js_value_t *argv,
                                  void *user_data,
                                  js_value_t *out,
                                  char **error_message);
bool js_builtin_object_get_prototype_of(js_runtime_t *rt,
                                        size_t argc,
                                        const js_value_t *argv,
                                        void *user_data,
                                        js_value_t *out,
                                        char **error_message);
bool js_builtin_object_get_own_property_descriptor(js_runtime_t *rt,
                                                   size_t argc,
                                                   const js_value_t *argv,
                                                   void *user_data,
                                                   js_value_t *out,
                                                   char **error_message);
bool js_builtin_object_get_own_property_names(js_runtime_t *rt,
                                              size_t argc,
                                              const js_value_t *argv,
                                              void *user_data,
                                              js_value_t *out,
                                              char **error_message);
bool js_builtin_object_get_own_property_descriptors(js_runtime_t *rt,
                                                    size_t argc,
                                                    const js_value_t *argv,
                                                    void *user_data,
                                                    js_value_t *out,
                                                    char **error_message);
bool js_builtin_object_has_own_property(js_runtime_t *rt,
                                        size_t argc,
                                        const js_value_t *argv,
                                        void *user_data,
                                        js_value_t *out,
                                        char **error_message);
bool js_builtin_object_property_is_enumerable(js_runtime_t *rt,
                                              size_t argc,
                                              const js_value_t *argv,
                                              void *user_data,
                                              js_value_t *out,
                                              char **error_message);
bool js_builtin_object_to_string(js_runtime_t *rt,
                                 size_t argc,
                                 const js_value_t *argv,
                                 void *user_data,
                                 js_value_t *out,
                                 char **error_message);
js_object_t *js_get_object_proto(js_runtime_t *rt);
bool js_builtin_function_call(js_runtime_t *rt,
                              size_t argc,
                              const js_value_t *argv,
                              void *user_data,
                              js_value_t *out,
                              char **error_message);
bool js_builtin_function_bind(js_runtime_t *rt,
                              size_t argc,
                              const js_value_t *argv,
                              void *user_data,
                              js_value_t *out,
                              char **error_message);
bool js_builtin_function(js_runtime_t *rt,
                         size_t argc,
                         const js_value_t *argv,
                         void *user_data,
                         js_value_t *out,
                         char **error_message);
bool js_builtin_function_stub(js_runtime_t *rt,
                              size_t argc,
                              const js_value_t *argv,
                              void *user_data,
                              js_value_t *out,
                              char **error_message);
js_object_t *js_get_function_proto(js_runtime_t *rt);
bool js_builtin_object(js_runtime_t *rt,
                       size_t argc,
                       const js_value_t *argv,
                       void *user_data,
                       js_value_t *out,
                       char **error_message);
bool js_builtin_array(js_runtime_t *rt,
                      size_t argc,
                      const js_value_t *argv,
                      void *user_data,
                      js_value_t *out,
                      char **error_message);
bool js_builtin_array_is_array(js_runtime_t *rt,
                               size_t argc,
                               const js_value_t *argv,
                               void *user_data,
                               js_value_t *out,
                               char **error_message);
bool js_builtin_array_join(js_runtime_t *rt,
                           size_t argc,
                           const js_value_t *argv,
                           void *user_data,
                           js_value_t *out,
                           char **error_message);
bool js_builtin_array_push(js_runtime_t *rt,
                           size_t argc,
                           const js_value_t *argv,
                           void *user_data,
                           js_value_t *out,
                           char **error_message);
bool js_builtin_array_map(js_runtime_t *rt,
                          size_t argc,
                          const js_value_t *argv,
                          void *user_data,
                          js_value_t *out,
                          char **error_message);
js_object_t *js_get_array_proto(js_runtime_t *rt);
bool js_builtin_math_pow(js_runtime_t *rt,
                         size_t argc,
                         const js_value_t *argv,
                         void *user_data,
                         js_value_t *out,
                         char **error_message);
bool js_builtin_iterator(js_runtime_t *rt,
                         size_t argc,
                         const js_value_t *argv,
                         void *user_data,
                         js_value_t *out,
                         char **error_message);
bool js_builtin_iterator_map(js_runtime_t *rt,
                             size_t argc,
                             const js_value_t *argv,
                             void *user_data,
                             js_value_t *out,
                             char **error_message);
js_object_t *js_get_iterator_proto(js_runtime_t *rt);
js_object_t *js_get_math_object(js_runtime_t *rt);
void js_release_bound_functions(js_runtime_t *rt);
bool js_builtin_type_error(js_runtime_t *rt,
                           size_t argc,
                           const js_value_t *argv,
                           void *user_data,
                           js_value_t *out,
                           char **error_message);
bool js_builtin_range_error(js_runtime_t *rt,
                            size_t argc,
                            const js_value_t *argv,
                            void *user_data,
                            js_value_t *out,
                            char **error_message);
bool js_builtin_syntax_error(js_runtime_t *rt,
                             size_t argc,
                             const js_value_t *argv,
                             void *user_data,
                             js_value_t *out,
                             char **error_message);
bool js_builtin_test262_error(js_runtime_t *rt,
                              size_t argc,
                              const js_value_t *argv,
                              void *user_data,
                              js_value_t *out,
                              char **error_message);
bool js_builtin_verify_property(js_runtime_t *rt,
                                size_t argc,
                                const js_value_t *argv,
                                void *user_data,
                                js_value_t *out,
                                char **error_message);

#ifdef __cplusplus
}
#endif

#endif /* WEB_JS_RUNTIME_INTERNAL_H */
