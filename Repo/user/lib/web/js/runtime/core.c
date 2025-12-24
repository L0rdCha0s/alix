#include "web/js/runtime/runtime_internal.h"

#include "libc.h"

struct js_program_node
{
    js_program_t *program;
    struct js_program_node *next;
};

static js_native_meta_t *js_native_meta_find(js_runtime_t *rt, const js_value_t *value)
{
    if (!rt || !value || value->type != JS_VALUE_NATIVE_FN)
    {
        return NULL;
    }
    for (js_native_meta_t *meta = rt->native_meta; meta; meta = meta->next)
    {
        if (meta->fn == value->as.native.fn && meta->user_data == value->as.native.user_data)
        {
            return meta;
        }
    }
    return NULL;
}

static bool js_global_object_get(js_runtime_t *rt,
                                 void *user_data,
                                 const char *name,
                                 js_value_t *out,
                                 char **error_message)
{
    (void)rt;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    if (!name)
    {
        *out = js_value_make_undefined_internal();
        return true;
    }
    js_env_t *env = (js_env_t *)user_data;
    if (!js_env_get(env, name, out))
    {
        *out = js_value_make_undefined_internal();
    }
    return true;
}

static bool js_global_object_set(js_runtime_t *rt,
                                 void *user_data,
                                 const char *name,
                                 const js_value_t *value,
                                 char **error_message)
{
    (void)rt;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!name || !value)
    {
        return false;
    }
    js_env_t *env = (js_env_t *)user_data;
    if (!js_env_assign(env, name, value))
    {
        if (!js_env_define_local(env, name, value, false, true))
        {
            if (error_message)
            {
                *error_message = js_strdup("global assignment failed");
            }
            return false;
        }
    }
    return true;
}

static bool js_runtime_register_native(js_runtime_t *rt,
                                       const char *name,
                                       js_native_fn_t fn,
                                       void *user_data,
                                       bool is_constructor,
                                       size_t length)
{
    if (!rt || !rt->global || !name || !fn)
    {
        return false;
    }
    js_native_meta_t *meta = (js_native_meta_t *)calloc(1, sizeof(*meta));
    if (!meta)
    {
        return false;
    }
    meta->fn = fn;
    meta->user_data = user_data;
    meta->name = name;
    meta->is_constructor = is_constructor;
    meta->length = length;

    js_value_t value;
    memset(&value, 0, sizeof(value));
    value.type = JS_VALUE_NATIVE_FN;
    value.as.native.fn = fn;
    value.as.native.user_data = user_data;
    if (!js_env_define_local(rt->global, name, &value, true, true))
    {
        free(meta);
        return false;
    }
    meta->next = rt->native_meta;
    rt->native_meta = meta;
    return true;
}

bool js_runtime_track_program(js_runtime_t *rt, js_program_t *program)
{
    if (!rt || !program)
    {
        return false;
    }
    js_program_node_t *node = (js_program_node_t *)calloc(1, sizeof(*node));
    if (!node)
    {
        return false;
    }
    node->program = program;
    node->next = rt->programs;
    rt->programs = node;
    return true;
}

js_runtime_t *js_runtime_create(void)
{
    js_runtime_t *rt = (js_runtime_t *)calloc(1, sizeof(*rt));
    if (!rt)
    {
        return NULL;
    }
    rt->global = js_env_create(NULL, true);
    if (!rt->global)
    {
        free(rt);
        return NULL;
    }
    rt->programs = NULL;
    rt->native_meta = NULL;
    rt->global_object = NULL;
    js_value_t global_obj;
    if (!js_value_make_host_object(&global_obj, js_global_object_get, js_global_object_set, NULL, rt->global))
    {
        js_runtime_destroy(rt);
        return NULL;
    }
    rt->global_object = global_obj.as.object;
    if (!js_runtime_register_native(rt, "Number", js_builtin_number, NULL, true, 1))
    {
        js_runtime_destroy(rt);
        return NULL;
    }
    if (!js_runtime_register_native(rt, "String", js_builtin_string, NULL, true, 1))
    {
        js_runtime_destroy(rt);
        return NULL;
    }
    if (!js_runtime_register_native(rt, "TypeError", js_builtin_type_error, NULL, true, 1))
    {
        js_runtime_destroy(rt);
        return NULL;
    }
    if (!js_runtime_register_native(rt, "RangeError", js_builtin_range_error, NULL, true, 1))
    {
        js_runtime_destroy(rt);
        return NULL;
    }
    if (!js_runtime_register_native(rt, "SyntaxError", js_builtin_syntax_error, NULL, true, 1))
    {
        js_runtime_destroy(rt);
        return NULL;
    }
    if (!js_runtime_register_native(rt, "Test262Error", js_builtin_test262_error, NULL, true, 1))
    {
        js_runtime_destroy(rt);
        return NULL;
    }
    if (!js_runtime_register_native(rt, "RegExp", js_builtin_regexp, NULL, true, 2))
    {
        js_runtime_destroy(rt);
        return NULL;
    }
    if (!js_runtime_register_native(rt, "Object", js_builtin_object, NULL, true, 1))
    {
        js_runtime_destroy(rt);
        return NULL;
    }
    if (!js_runtime_register_native(rt, "Function", js_builtin_function, NULL, true, 1))
    {
        js_runtime_destroy(rt);
        return NULL;
    }
    if (!js_runtime_register_native(rt, "Array", js_builtin_array, NULL, true, 1))
    {
        js_runtime_destroy(rt);
        return NULL;
    }
    if (!js_runtime_register_native(rt, "Set", js_builtin_set, NULL, true, 0))
    {
        js_runtime_destroy(rt);
        return NULL;
    }
    if (!js_runtime_register_native(rt, "Iterator", js_builtin_iterator, NULL, false, 0))
    {
        js_runtime_destroy(rt);
        return NULL;
    }
    if (!js_runtime_register_native(rt, "escape", js_builtin_escape, NULL, false, 1))
    {
        js_runtime_destroy(rt);
        return NULL;
    }
    if (!js_runtime_register_native(rt, "unescape", js_builtin_unescape, NULL, false, 1))
    {
        js_runtime_destroy(rt);
        return NULL;
    }
    if (!js_runtime_register_native(rt, "eval", js_builtin_eval, NULL, false, 1))
    {
        js_runtime_destroy(rt);
        return NULL;
    }
    if (!js_runtime_register_native(rt, "verifyProperty", js_builtin_verify_property, NULL, false, 3))
    {
        js_runtime_destroy(rt);
        return NULL;
    }
    if (!js_runtime_register_native(rt, "Symbol", js_builtin_symbol, NULL, false, 0))
    {
        js_runtime_destroy(rt);
        return NULL;
    }
    js_object_t *math_obj = js_get_math_object(rt);
    if (!math_obj)
    {
        js_runtime_destroy(rt);
        return NULL;
    }
    js_value_t math_val;
    memset(&math_val, 0, sizeof(math_val));
    math_val.type = JS_VALUE_OBJECT;
    math_val.as.object = math_obj;
    js_object_retain(math_obj);
    if (!js_runtime_set_global(rt, "Math", &math_val))
    {
        js_value_destroy(&math_val);
        js_runtime_destroy(rt);
        return NULL;
    }
    js_value_destroy(&math_val);
    if (!js_runtime_register_native(rt, "testWithTypedArrayConstructors",
                                    js_builtin_test_with_typed_array_constructors,
                                    NULL,
                                    false,
                                    2))
    {
        js_runtime_destroy(rt);
        return NULL;
    }
    js_value_t host_helpers;
    if (!js_value_make_host_object(&host_helpers, NULL, NULL, NULL, NULL))
    {
        js_runtime_destroy(rt);
        return NULL;
    }
    js_value_t is_html_dda;
    memset(&is_html_dda, 0, sizeof(is_html_dda));
    is_html_dda.type = JS_VALUE_NATIVE_FN;
    is_html_dda.as.native.fn = js_builtin_is_html_dda;
    is_html_dda.as.native.user_data = NULL;
    if (!js_object_set_slot(host_helpers.as.object, "IsHTMLDDA", &is_html_dda))
    {
        js_value_destroy(&host_helpers);
        js_runtime_destroy(rt);
        return NULL;
    }
    js_value_t create_realm;
    memset(&create_realm, 0, sizeof(create_realm));
    create_realm.type = JS_VALUE_NATIVE_FN;
    create_realm.as.native.fn = js_builtin_create_realm;
    create_realm.as.native.user_data = NULL;
    if (!js_object_set_slot(host_helpers.as.object, "createRealm", &create_realm))
    {
        js_value_destroy(&host_helpers);
        js_runtime_destroy(rt);
        return NULL;
    }
    if (!js_runtime_set_global(rt, "$262", &host_helpers))
    {
        js_value_destroy(&host_helpers);
        js_runtime_destroy(rt);
        return NULL;
    }
    js_value_destroy(&host_helpers);
    js_value_t nan_value = js_value_make_number(js_nan());
    if (!js_runtime_set_global(rt, "NaN", &nan_value))
    {
        js_runtime_destroy(rt);
        return NULL;
    }
    double inf_value = 1.0 / 0.0;
    js_value_t inf = js_value_make_number(inf_value);
    if (!js_runtime_set_global(rt, "Infinity", &inf))
    {
        js_runtime_destroy(rt);
        return NULL;
    }
    return rt;
}

void js_runtime_destroy(js_runtime_t *rt)
{
    if (!rt)
    {
        return;
    }
    js_release_bound_functions(rt);
    if (rt->global_object)
    {
        js_object_release(rt->global_object);
        rt->global_object = NULL;
    }
    js_program_node_t *node = rt->programs;
    while (node)
    {
        js_program_node_t *next = node->next;
        if (node->program)
        {
            js_program_destroy(node->program);
        }
        free(node);
        node = next;
    }
    js_native_meta_t *meta = rt->native_meta;
    while (meta)
    {
        js_native_meta_t *next = meta->next;
        free(meta);
        meta = next;
    }
    js_env_release(rt->global);
    if (rt->math_object)
    {
        js_object_release(rt->math_object);
        rt->math_object = NULL;
    }
    if (rt->iterator_proto)
    {
        js_object_release(rt->iterator_proto);
        rt->iterator_proto = NULL;
    }
    if (rt->set_iterator_proto)
    {
        js_object_release(rt->set_iterator_proto);
        rt->set_iterator_proto = NULL;
    }
    if (rt->function_proto)
    {
        js_object_release(rt->function_proto);
        rt->function_proto = NULL;
    }
    if (rt->array_proto)
    {
        js_object_release(rt->array_proto);
        rt->array_proto = NULL;
    }
    if (rt->object_proto)
    {
        js_object_release(rt->object_proto);
        rt->object_proto = NULL;
    }
    free(rt);
}

bool js_runtime_set_global(js_runtime_t *rt, const char *name, const js_value_t *value)
{
    if (!rt || !rt->global)
    {
        return false;
    }
    return js_env_define_local(rt->global, name, value, false, true);
}

bool js_runtime_set_native(js_runtime_t *rt, const char *name, js_native_fn_t fn, void *user_data)
{
    return js_runtime_register_native(rt, name, fn, user_data, false, 0);
}

bool js_value_is_constructor(js_runtime_t *rt, const js_value_t *value)
{
    if (!rt || !value)
    {
        return false;
    }
    if (value->type == JS_VALUE_FUNCTION)
    {
        return value->as.function && value->as.function->is_constructible;
    }
    if (value->type == JS_VALUE_NATIVE_FN)
    {
        js_native_meta_t *meta = js_native_meta_find(rt, value);
        if (meta)
        {
            return meta->is_constructor;
        }
        if (value->as.native.fn == js_builtin_regexp ||
            value->as.native.fn == js_builtin_regexp_subclass)
        {
            return true;
        }
        return false;
    }
    return false;
}

const char *js_value_native_name(js_runtime_t *rt, const js_value_t *value)
{
    js_native_meta_t *meta = js_native_meta_find(rt, value);
    if (meta)
    {
        return meta->name;
    }
    if (value && value->type == JS_VALUE_NATIVE_FN)
    {
        if (value->as.native.fn == js_builtin_iterator)
        {
            return "Iterator";
        }
        if (value->as.native.fn == js_builtin_iterator_map)
        {
            return "map";
        }
        if (value->as.native.fn == js_regexp_compile ||
            value->as.native.fn == js_regexp_compile_proto)
        {
            return "compile";
        }
        if (value->as.native.fn == js_regexp_exec)
        {
            return "exec";
        }
        if (value->as.native.fn == js_builtin_string_from_char_code)
        {
            return "fromCharCode";
        }
        if (value->as.native.fn == js_builtin_define_property)
        {
            return "defineProperty";
        }
        if (value->as.native.fn == js_builtin_define_properties)
        {
            return "defineProperties";
        }
        if (value->as.native.fn == js_builtin_object_get_own_property_descriptor)
        {
            return "getOwnPropertyDescriptor";
        }
        if (value->as.native.fn == js_builtin_object_get_own_property_names)
        {
            return "getOwnPropertyNames";
        }
        if (value->as.native.fn == js_builtin_object_get_own_property_descriptors)
        {
            return "getOwnPropertyDescriptors";
        }
        if (value->as.native.fn == js_builtin_object_get_prototype_of)
        {
            return "getPrototypeOf";
        }
        if (value->as.native.fn == js_builtin_object_has_own_property)
        {
            return "hasOwnProperty";
        }
        if (value->as.native.fn == js_builtin_object_property_is_enumerable)
        {
            return "propertyIsEnumerable";
        }
        if (value->as.native.fn == js_set_iterator)
        {
            return "values";
        }
        if (value->as.native.fn == js_builtin_number_to_string)
        {
            return "toString";
        }
        if (value->as.native.fn == js_builtin_object_to_string)
        {
            return "toString";
        }
        if (value->as.native.fn == js_builtin_function_call)
        {
            return "call";
        }
        if (value->as.native.fn == js_builtin_function_bind)
        {
            return "bind";
        }
        if (value->as.native.fn == js_builtin_function_stub)
        {
            return "anonymous";
        }
        if (value->as.native.fn == js_builtin_array_is_array)
        {
            return "isArray";
        }
        if (value->as.native.fn == js_builtin_array_join)
        {
            return "join";
        }
        if (value->as.native.fn == js_builtin_array_push)
        {
            return "push";
        }
        if (value->as.native.fn == js_builtin_array_map)
        {
            return "map";
        }
        if (value->as.native.fn == js_builtin_math_pow)
        {
            return "pow";
        }
    }
    return NULL;
}

bool js_value_native_length(js_runtime_t *rt, const js_value_t *value, size_t *out_len)
{
    if (out_len)
    {
        *out_len = 0;
    }
    js_native_meta_t *meta = js_native_meta_find(rt, value);
    if (!meta)
    {
        if (value && value->type == JS_VALUE_NATIVE_FN &&
            value->as.native.fn == js_builtin_iterator)
        {
            if (out_len)
            {
                *out_len = 0;
            }
            return true;
        }
        if (value && value->type == JS_VALUE_NATIVE_FN &&
            value->as.native.fn == js_builtin_iterator_map)
        {
            if (out_len)
            {
                *out_len = 1;
            }
            return true;
        }
        if (value && value->type == JS_VALUE_NATIVE_FN &&
            (value->as.native.fn == js_regexp_compile || value->as.native.fn == js_regexp_compile_proto))
        {
            if (out_len)
            {
                *out_len = 2;
            }
            return true;
        }
        if (value && value->type == JS_VALUE_NATIVE_FN &&
            value->as.native.fn == js_regexp_exec)
        {
            if (out_len)
            {
                *out_len = 1;
            }
            return true;
        }
        if (value && value->type == JS_VALUE_NATIVE_FN &&
            value->as.native.fn == js_builtin_string_from_char_code)
        {
            if (out_len)
            {
                *out_len = 1;
            }
            return true;
        }
        if (value && value->type == JS_VALUE_NATIVE_FN &&
            value->as.native.fn == js_builtin_define_property)
        {
            if (out_len)
            {
                *out_len = 3;
            }
            return true;
        }
        if (value && value->type == JS_VALUE_NATIVE_FN &&
            value->as.native.fn == js_builtin_define_properties)
        {
            if (out_len)
            {
                *out_len = 2;
            }
            return true;
        }
        if (value && value->type == JS_VALUE_NATIVE_FN &&
            value->as.native.fn == js_builtin_object_get_prototype_of)
        {
            if (out_len)
            {
                *out_len = 1;
            }
            return true;
        }
        if (value && value->type == JS_VALUE_NATIVE_FN &&
            value->as.native.fn == js_builtin_object_get_own_property_descriptor)
        {
            if (out_len)
            {
                *out_len = 2;
            }
            return true;
        }
        if (value && value->type == JS_VALUE_NATIVE_FN &&
            value->as.native.fn == js_builtin_object_get_own_property_names)
        {
            if (out_len)
            {
                *out_len = 1;
            }
            return true;
        }
        if (value && value->type == JS_VALUE_NATIVE_FN &&
            value->as.native.fn == js_builtin_object_get_own_property_descriptors)
        {
            if (out_len)
            {
                *out_len = 1;
            }
            return true;
        }
        if (value && value->type == JS_VALUE_NATIVE_FN &&
            value->as.native.fn == js_builtin_object_has_own_property)
        {
            if (out_len)
            {
                *out_len = 1;
            }
            return true;
        }
        if (value && value->type == JS_VALUE_NATIVE_FN &&
            value->as.native.fn == js_builtin_object_property_is_enumerable)
        {
            if (out_len)
            {
                *out_len = 1;
            }
            return true;
        }
        if (value && value->type == JS_VALUE_NATIVE_FN &&
            value->as.native.fn == js_builtin_object_to_string)
        {
            if (out_len)
            {
                *out_len = 0;
            }
            return true;
        }
        if (value && value->type == JS_VALUE_NATIVE_FN &&
            value->as.native.fn == js_builtin_function_call)
        {
            if (out_len)
            {
                *out_len = 1;
            }
            return true;
        }
        if (value && value->type == JS_VALUE_NATIVE_FN &&
            value->as.native.fn == js_builtin_function_bind)
        {
            if (out_len)
            {
                *out_len = 1;
            }
            return true;
        }
        if (value && value->type == JS_VALUE_NATIVE_FN &&
            value->as.native.fn == js_builtin_function_stub)
        {
            if (out_len)
            {
                *out_len = 0;
            }
            return true;
        }
        if (value && value->type == JS_VALUE_NATIVE_FN &&
            value->as.native.fn == js_builtin_array_is_array)
        {
            if (out_len)
            {
                *out_len = 1;
            }
            return true;
        }
        if (value && value->type == JS_VALUE_NATIVE_FN &&
            value->as.native.fn == js_builtin_array_join)
        {
            if (out_len)
            {
                *out_len = 1;
            }
            return true;
        }
        if (value && value->type == JS_VALUE_NATIVE_FN &&
            value->as.native.fn == js_builtin_array_push)
        {
            if (out_len)
            {
                *out_len = 1;
            }
            return true;
        }
        if (value && value->type == JS_VALUE_NATIVE_FN &&
            value->as.native.fn == js_builtin_array_map)
        {
            if (out_len)
            {
                *out_len = 1;
            }
            return true;
        }
        if (value && value->type == JS_VALUE_NATIVE_FN &&
            value->as.native.fn == js_builtin_math_pow)
        {
            if (out_len)
            {
                *out_len = 2;
            }
            return true;
        }
        if (value && value->type == JS_VALUE_NATIVE_FN &&
            value->as.native.fn == js_set_iterator)
        {
            if (out_len)
            {
                *out_len = 0;
            }
            return true;
        }
        if (value && value->type == JS_VALUE_NATIVE_FN &&
            value->as.native.fn == js_builtin_number_to_string)
        {
            if (out_len)
            {
                *out_len = 1;
            }
            return true;
        }
        return false;
    }
    if (out_len)
    {
        *out_len = meta->length;
    }
    return true;
}
