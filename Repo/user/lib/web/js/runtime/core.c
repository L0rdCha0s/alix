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
    if (!js_runtime_register_native(rt, "Number", js_builtin_number, NULL, true, 1))
    {
        js_runtime_destroy(rt);
        return NULL;
    }
    if (!js_runtime_register_native(rt, "TypeError", js_builtin_type_error, NULL, true, 1))
    {
        js_runtime_destroy(rt);
        return NULL;
    }
    if (!js_runtime_register_native(rt, "Test262Error", js_builtin_test262_error, NULL, true, 1))
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
    if (!js_runtime_register_native(rt, "verifyProperty", js_builtin_verify_property, NULL, false, 3))
    {
        js_runtime_destroy(rt);
        return NULL;
    }
    js_value_t symbol_obj;
    if (!js_value_make_host_object(&symbol_obj, NULL, NULL, NULL, NULL))
    {
        js_runtime_destroy(rt);
        return NULL;
    }
    js_value_t to_prim;
    if (!js_value_make_cstring(&to_prim, "Symbol.toPrimitive"))
    {
        js_value_destroy(&symbol_obj);
        js_runtime_destroy(rt);
        return NULL;
    }
    if (!js_object_set_slot(symbol_obj.as.object, "toPrimitive", &to_prim))
    {
        js_value_destroy(&to_prim);
        js_value_destroy(&symbol_obj);
        js_runtime_destroy(rt);
        return NULL;
    }
    js_value_destroy(&to_prim);
    if (!js_runtime_set_global(rt, "Symbol", &symbol_obj))
    {
        js_value_destroy(&symbol_obj);
        js_runtime_destroy(rt);
        return NULL;
    }
    js_value_destroy(&symbol_obj);
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
        return meta ? meta->is_constructor : false;
    }
    return false;
}

const char *js_value_native_name(js_runtime_t *rt, const js_value_t *value)
{
    js_native_meta_t *meta = js_native_meta_find(rt, value);
    return meta ? meta->name : NULL;
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
        return false;
    }
    if (out_len)
    {
        *out_len = meta->length;
    }
    return true;
}
