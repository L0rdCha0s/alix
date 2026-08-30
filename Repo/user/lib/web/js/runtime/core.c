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
    js_native_meta_t *meta = (js_native_meta_t *)js_calloc(1, sizeof(*meta));
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
        js_free(meta);
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
    js_program_node_t *node = (js_program_node_t *)js_calloc(1, sizeof(*node));
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
    js_runtime_t *rt = (js_runtime_t *)js_calloc(1, sizeof(*rt));
    if (!rt)
    {
        return NULL;
    }
    rt->global = js_env_create(NULL, true);
    if (!rt->global)
    {
        js_free(rt);
        return NULL;
    }
    rt->programs = NULL;
    rt->native_meta = NULL;
    rt->global_object = NULL;
    rt->microtask_head = NULL;
    rt->microtask_tail = NULL;
    rt->interrupt_fn = NULL;
    rt->interrupt_user_data = NULL;
    rt->interrupt_poll_count = 0;
    js_value_t global_obj;
    if (!js_value_make_host_object(&global_obj, js_global_object_get, js_global_object_set, NULL, rt->global))
    {
        js_runtime_destroy(rt);
        return NULL;
    }
    rt->global_object = global_obj.as.object;
    js_value_t global_val;
    memset(&global_val, 0, sizeof(global_val));
    global_val.type = JS_VALUE_OBJECT;
    global_val.as.object = rt->global_object;
    js_object_retain(rt->global_object);
    if (!js_runtime_set_global(rt, "globalThis", &global_val))
    {
        js_value_destroy(&global_val);
        js_runtime_destroy(rt);
        return NULL;
    }
    js_value_destroy(&global_val);
    if (!js_runtime_register_native(rt, "Number", js_builtin_number, NULL, true, 1))
    {
        js_runtime_destroy(rt);
        return NULL;
    }
    if (!js_runtime_register_native(rt, "BigInt", js_builtin_bigint, NULL, false, 1))
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
    if (!js_runtime_register_native(rt, "Date", js_builtin_date, NULL, true, 7))
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
    if (!js_runtime_register_native(rt, "Promise", js_builtin_promise, NULL, true, 1))
    {
        js_runtime_destroy(rt);
        return NULL;
    }
    if (!js_runtime_register_native(rt, "queueMicrotask", js_builtin_queue_microtask, NULL, false, 1))
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
    js_value_t reflect_obj;
    if (!js_value_make_host_object(&reflect_obj, NULL, NULL, NULL, NULL))
    {
        js_runtime_destroy(rt);
        return NULL;
    }
    js_value_t reflect_get;
    memset(&reflect_get, 0, sizeof(reflect_get));
    reflect_get.type = JS_VALUE_NATIVE_FN;
    reflect_get.as.native.fn = js_builtin_reflect_get;
    reflect_get.as.native.user_data = NULL;
    if (!js_object_set_slot(reflect_obj.as.object, "get", &reflect_get))
    {
        js_value_destroy(&reflect_obj);
        js_runtime_destroy(rt);
        return NULL;
    }
    js_value_t reflect_set;
    memset(&reflect_set, 0, sizeof(reflect_set));
    reflect_set.type = JS_VALUE_NATIVE_FN;
    reflect_set.as.native.fn = js_builtin_reflect_set;
    reflect_set.as.native.user_data = NULL;
    if (!js_object_set_slot(reflect_obj.as.object, "set", &reflect_set))
    {
        js_value_destroy(&reflect_obj);
        js_runtime_destroy(rt);
        return NULL;
    }
    if (!js_runtime_set_global(rt, "Reflect", &reflect_obj))
    {
        js_value_destroy(&reflect_obj);
        js_runtime_destroy(rt);
        return NULL;
    }
    js_value_destroy(&reflect_obj);
    js_object_t *temporal_obj = js_get_temporal_object(rt);
    if (!temporal_obj)
    {
        js_runtime_destroy(rt);
        return NULL;
    }
    js_value_t temporal_val;
    memset(&temporal_val, 0, sizeof(temporal_val));
    temporal_val.type = JS_VALUE_OBJECT;
    temporal_val.as.object = temporal_obj;
    js_object_retain(temporal_obj);
    if (!js_runtime_set_global(rt, "Temporal", &temporal_val))
    {
        js_value_destroy(&temporal_val);
        js_runtime_destroy(rt);
        return NULL;
    }
    js_value_destroy(&temporal_val);
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
    if (!js_value_make_host_object(&is_html_dda, NULL, NULL, NULL, NULL))
    {
        js_value_destroy(&host_helpers);
        js_runtime_destroy(rt);
        return NULL;
    }
    if (is_html_dda.type == JS_VALUE_OBJECT && is_html_dda.as.object)
    {
        is_html_dda.as.object->is_html_dda = true;
        js_object_t *obj_proto = js_get_object_proto(rt);
        if (obj_proto)
        {
            js_value_t proto_val;
            memset(&proto_val, 0, sizeof(proto_val));
            proto_val.type = JS_VALUE_OBJECT;
            proto_val.as.object = obj_proto;
            (void)js_object_set_slot(is_html_dda.as.object, "__proto__", &proto_val);
        }
    }
    if (!js_object_set_slot(host_helpers.as.object, "IsHTMLDDA", &is_html_dda))
    {
        js_value_destroy(&is_html_dda);
        js_value_destroy(&host_helpers);
        js_runtime_destroy(rt);
        return NULL;
    }
    js_value_destroy(&is_html_dda);
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
    while (rt->microtask_head)
    {
        if (js_runtime_interrupt_requested(rt))
        {
            break;
        }
        js_microtask_t *task = rt->microtask_head;
        rt->microtask_head = task->next;
        js_value_destroy(&task->callback);
        for (size_t i = 0; i < task->argc; ++i)
        {
            js_value_destroy(&task->argv[i]);
        }
        js_free(task->argv);
        js_free(task);
    }
    rt->microtask_tail = NULL;
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
        js_free(node);
        node = next;
    }
    js_native_meta_t *meta = rt->native_meta;
    while (meta)
    {
        js_native_meta_t *next = meta->next;
        js_free(meta);
        meta = next;
    }
    js_env_release(rt->global);
    if (rt->math_object)
    {
        js_object_release(rt->math_object);
        rt->math_object = NULL;
    }
    if (rt->date_proto)
    {
        js_object_release(rt->date_proto);
        rt->date_proto = NULL;
    }
    if (rt->number_proto)
    {
        js_object_release(rt->number_proto);
        rt->number_proto = NULL;
    }
    if (rt->string_proto)
    {
        js_object_release(rt->string_proto);
        rt->string_proto = NULL;
    }
    if (rt->symbol_proto)
    {
        js_object_release(rt->symbol_proto);
        rt->symbol_proto = NULL;
    }
    if (rt->temporal_plain_month_day_proto)
    {
        js_object_release(rt->temporal_plain_month_day_proto);
        rt->temporal_plain_month_day_proto = NULL;
    }
    if (rt->temporal_plain_year_month_proto)
    {
        js_object_release(rt->temporal_plain_year_month_proto);
        rt->temporal_plain_year_month_proto = NULL;
    }
    if (rt->temporal_zoned_date_time_proto)
    {
        js_object_release(rt->temporal_zoned_date_time_proto);
        rt->temporal_zoned_date_time_proto = NULL;
    }
    if (rt->temporal_plain_date_time_proto)
    {
        js_object_release(rt->temporal_plain_date_time_proto);
        rt->temporal_plain_date_time_proto = NULL;
    }
    if (rt->temporal_plain_time_proto)
    {
        js_object_release(rt->temporal_plain_time_proto);
        rt->temporal_plain_time_proto = NULL;
    }
    if (rt->temporal_plain_date_proto)
    {
        js_object_release(rt->temporal_plain_date_proto);
        rt->temporal_plain_date_proto = NULL;
    }
    if (rt->temporal_instant_proto)
    {
        js_object_release(rt->temporal_instant_proto);
        rt->temporal_instant_proto = NULL;
    }
    if (rt->temporal_duration_proto)
    {
        js_object_release(rt->temporal_duration_proto);
        rt->temporal_duration_proto = NULL;
    }
    if (rt->temporal_now_object)
    {
        js_object_release(rt->temporal_now_object);
        rt->temporal_now_object = NULL;
    }
    if (rt->temporal_object)
    {
        js_object_release(rt->temporal_object);
        rt->temporal_object = NULL;
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
    js_free(rt);
}

bool js_runtime_set_global(js_runtime_t *rt, const char *name, const js_value_t *value)
{
    if (!rt || !rt->global)
    {
        return false;
    }
    return js_env_define_local(rt->global, name, value, false, true);
}

bool js_runtime_get_global(js_runtime_t *rt, const char *name, js_value_t *out)
{
    if (!out)
    {
        return false;
    }
    if (!rt || !rt->global || !name)
    {
        *out = js_value_make_undefined_internal();
        return true;
    }
    if (!js_env_get(rt->global, name, out))
    {
        *out = js_value_make_undefined_internal();
    }
    return true;
}

void js_runtime_set_interrupt_handler(js_runtime_t *rt,
                                      js_interrupt_fn_t handler,
                                      void *user_data)
{
    if (!rt)
    {
        return;
    }
    rt->interrupt_fn = handler;
    rt->interrupt_user_data = user_data;
    rt->interrupt_poll_count = 0;
}

bool js_runtime_interrupt_requested(js_runtime_t *rt)
{
    if (!rt || !rt->interrupt_fn)
    {
        return false;
    }
    rt->interrupt_poll_count++;
    if ((rt->interrupt_poll_count & 0xFFu) != 0u)
    {
        return false;
    }
    return rt->interrupt_fn(rt->interrupt_user_data);
}

bool js_runtime_queue_microtask(js_runtime_t *rt,
                                const js_value_t *callback,
                                size_t argc,
                                const js_value_t *argv)
{
    if (!rt || !callback)
    {
        return false;
    }
    js_microtask_t *task = (js_microtask_t *)js_calloc(1, sizeof(*task));
    if (!task)
    {
        return false;
    }
    if (!js_value_copy(&task->callback, callback))
    {
        js_free(task);
        return false;
    }
    if (argc)
    {
        task->argv = (js_value_t *)js_calloc(argc, sizeof(*task->argv));
        if (!task->argv)
        {
            js_value_destroy(&task->callback);
            js_free(task);
            return false;
        }
        for (size_t i = 0; i < argc; ++i)
        {
            if (!js_value_copy(&task->argv[i], &argv[i]))
            {
                for (size_t j = 0; j < i; ++j)
                {
                    js_value_destroy(&task->argv[j]);
                }
                js_free(task->argv);
                js_value_destroy(&task->callback);
                js_free(task);
                return false;
            }
        }
    }
    task->argc = argc;
    task->next = NULL;
    if (rt->microtask_tail)
    {
        rt->microtask_tail->next = task;
    }
    else
    {
        rt->microtask_head = task;
    }
    rt->microtask_tail = task;
    return true;
}

void js_runtime_run_microtasks(js_runtime_t *rt)
{
    if (!rt)
    {
        return;
    }
    while (rt->microtask_head)
    {
        js_microtask_t *task = rt->microtask_head;
        rt->microtask_head = task->next;
        if (!rt->microtask_head)
        {
            rt->microtask_tail = NULL;
        }
        js_value_t result = js_value_make_undefined_internal();
        char *err = NULL;
        (void)js_call_value(rt, &task->callback, task->argc, task->argv, &result, &err);
        js_free(err);
        js_value_destroy(&result);
        js_value_destroy(&task->callback);
        for (size_t i = 0; i < task->argc; ++i)
        {
            js_value_destroy(&task->argv[i]);
        }
        js_free(task->argv);
        js_free(task);
    }
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
        if (value->as.native.fn == js_builtin_temporal_duration ||
            value->as.native.fn == js_builtin_temporal_instant ||
            value->as.native.fn == js_builtin_temporal_plain_date ||
            value->as.native.fn == js_builtin_temporal_plain_time ||
            value->as.native.fn == js_builtin_temporal_plain_date_time ||
            value->as.native.fn == js_builtin_temporal_zoned_date_time ||
            value->as.native.fn == js_builtin_temporal_plain_year_month ||
            value->as.native.fn == js_builtin_temporal_plain_month_day)
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
        if (value->as.native.fn == js_string_proto_anchor)
        {
            return "anchor";
        }
        if (value->as.native.fn == js_string_proto_big)
        {
            return "big";
        }
        if (value->as.native.fn == js_string_proto_blink)
        {
            return "blink";
        }
        if (value->as.native.fn == js_string_proto_bold)
        {
            return "bold";
        }
        if (value->as.native.fn == js_string_proto_fixed)
        {
            return "fixed";
        }
        if (value->as.native.fn == js_string_proto_fontcolor)
        {
            return "fontcolor";
        }
        if (value->as.native.fn == js_string_proto_fontsize)
        {
            return "fontsize";
        }
        if (value->as.native.fn == js_string_proto_italics)
        {
            return "italics";
        }
        if (value->as.native.fn == js_string_proto_link)
        {
            return "link";
        }
        if (value->as.native.fn == js_string_proto_match_all)
        {
            return "matchAll";
        }
        if (value->as.native.fn == js_string_proto_replace)
        {
            return "replace";
        }
        if (value->as.native.fn == js_string_proto_replace_all)
        {
            return "replaceAll";
        }
        if (value->as.native.fn == js_string_proto_search)
        {
            return "search";
        }
        if (value->as.native.fn == js_string_proto_small)
        {
            return "small";
        }
        if (value->as.native.fn == js_string_proto_split)
        {
            return "split";
        }
        if (value->as.native.fn == js_string_proto_strike)
        {
            return "strike";
        }
        if (value->as.native.fn == js_string_proto_sub)
        {
            return "sub";
        }
        if (value->as.native.fn == js_string_proto_substr)
        {
            return "substr";
        }
        if (value->as.native.fn == js_string_proto_sup)
        {
            return "sup";
        }
        if (value->as.native.fn == js_builtin_string_match)
        {
            return "match";
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
        if (value->as.native.fn == js_builtin_array_for_each)
        {
            return "forEach";
        }
        if (value->as.native.fn == js_builtin_array_from)
        {
            return "from";
        }
        if (value->as.native.fn == js_builtin_reflect_get)
        {
            return "get";
        }
        if (value->as.native.fn == js_builtin_reflect_set)
        {
            return "set";
        }
        if (value->as.native.fn == js_builtin_define_property)
        {
            return "defineProperty";
        }
        if (value->as.native.fn == js_builtin_define_properties)
        {
            return "defineProperties";
        }
        if (value->as.native.fn == js_builtin_object_is)
        {
            return "is";
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
        if (value->as.native.fn == js_builtin_bigint_to_string)
        {
            return "toString";
        }
        if (value->as.native.fn == js_builtin_bigint_value_of)
        {
            return "valueOf";
        }
        if (value->as.native.fn == js_builtin_temporal_duration)
        {
            return "Duration";
        }
        if (value->as.native.fn == js_builtin_temporal_instant)
        {
            return "Instant";
        }
        if (value->as.native.fn == js_builtin_temporal_plain_date)
        {
            return "PlainDate";
        }
        if (value->as.native.fn == js_builtin_temporal_plain_time)
        {
            return "PlainTime";
        }
        if (value->as.native.fn == js_builtin_temporal_plain_date_time)
        {
            return "PlainDateTime";
        }
        if (value->as.native.fn == js_builtin_temporal_zoned_date_time)
        {
            return "ZonedDateTime";
        }
        if (value->as.native.fn == js_builtin_temporal_plain_year_month)
        {
            return "PlainYearMonth";
        }
        if (value->as.native.fn == js_builtin_temporal_plain_month_day)
        {
            return "PlainMonthDay";
        }
        if (value->as.native.fn == js_temporal_duration_negated)
        {
            return "negated";
        }
        if (value->as.native.fn == js_temporal_duration_abs)
        {
            return "abs";
        }
        if (value->as.native.fn == js_temporal_duration_to_string)
        {
            return "toString";
        }
        if (value->as.native.fn == js_temporal_duration_to_json)
        {
            return "toJSON";
        }
        if (value->as.native.fn == js_temporal_duration_to_locale_string)
        {
            return "toLocaleString";
        }
        if (value->as.native.fn == js_temporal_duration_value_of)
        {
            return "valueOf";
        }
        if (value->as.native.fn == js_temporal_duration_with)
        {
            return "with";
        }
        if (value->as.native.fn == js_temporal_duration_add)
        {
            return "add";
        }
        if (value->as.native.fn == js_temporal_duration_subtract)
        {
            return "subtract";
        }
        if (value->as.native.fn == js_temporal_duration_round)
        {
            return "round";
        }
        if (value->as.native.fn == js_temporal_duration_total)
        {
            return "total";
        }
        if (value->as.native.fn == js_temporal_instant_to_string)
        {
            return "toString";
        }
        if (value->as.native.fn == js_temporal_instant_to_json)
        {
            return "toJSON";
        }
        if (value->as.native.fn == js_temporal_instant_to_locale_string)
        {
            return "toLocaleString";
        }
        if (value->as.native.fn == js_temporal_instant_value_of)
        {
            return "valueOf";
        }
        if (value->as.native.fn == js_temporal_instant_add)
        {
            return "add";
        }
        if (value->as.native.fn == js_temporal_instant_subtract)
        {
            return "subtract";
        }
        if (value->as.native.fn == js_temporal_instant_since)
        {
            return "since";
        }
        if (value->as.native.fn == js_temporal_instant_until)
        {
            return "until";
        }
        if (value->as.native.fn == js_temporal_instant_round)
        {
            return "round";
        }
        if (value->as.native.fn == js_temporal_instant_equals)
        {
            return "equals";
        }
        if (value->as.native.fn == js_temporal_instant_to_zoned_date_time_iso)
        {
            return "toZonedDateTimeISO";
        }
        if (value->as.native.fn == js_temporal_now_instant)
        {
            return "instant";
        }
        if (value->as.native.fn == js_temporal_now_plain_date_iso)
        {
            return "plainDateISO";
        }
        if (value->as.native.fn == js_temporal_now_plain_time_iso)
        {
            return "plainTimeISO";
        }
        if (value->as.native.fn == js_temporal_now_plain_date_time_iso)
        {
            return "plainDateTimeISO";
        }
        if (value->as.native.fn == js_temporal_now_zoned_date_time_iso)
        {
            return "zonedDateTimeISO";
        }
        if (value->as.native.fn == js_temporal_now_time_zone_id)
        {
            return "timeZoneId";
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
        if (value->as.native.fn == js_builtin_array_from)
        {
            return "from";
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
        if (value->as.native.fn == js_builtin_date_now)
        {
            return "now";
        }
        if (value->as.native.fn == js_builtin_date_parse)
        {
            return "parse";
        }
        if (value->as.native.fn == js_builtin_date_utc)
        {
            return "UTC";
        }
        if (value->as.native.fn == js_date_proto_to_string)
        {
            return "toString";
        }
        if (value->as.native.fn == js_date_proto_to_date_string)
        {
            return "toDateString";
        }
        if (value->as.native.fn == js_date_proto_to_time_string)
        {
            return "toTimeString";
        }
        if (value->as.native.fn == js_date_proto_to_utc_string)
        {
            return "toUTCString";
        }
        if (value->as.native.fn == js_date_proto_to_gmt_string)
        {
            return "toGMTString";
        }
        if (value->as.native.fn == js_date_proto_to_iso_string)
        {
            return "toISOString";
        }
        if (value->as.native.fn == js_date_proto_to_json)
        {
            return "toJSON";
        }
        if (value->as.native.fn == js_date_proto_value_of)
        {
            return "valueOf";
        }
        if (value->as.native.fn == js_date_proto_get_time)
        {
            return "getTime";
        }
        if (value->as.native.fn == js_date_proto_get_full_year)
        {
            return "getFullYear";
        }
        if (value->as.native.fn == js_date_proto_get_utc_full_year)
        {
            return "getUTCFullYear";
        }
        if (value->as.native.fn == js_date_proto_get_month)
        {
            return "getMonth";
        }
        if (value->as.native.fn == js_date_proto_get_utc_month)
        {
            return "getUTCMonth";
        }
        if (value->as.native.fn == js_date_proto_get_date)
        {
            return "getDate";
        }
        if (value->as.native.fn == js_date_proto_get_utc_date)
        {
            return "getUTCDate";
        }
        if (value->as.native.fn == js_date_proto_get_day)
        {
            return "getDay";
        }
        if (value->as.native.fn == js_date_proto_get_utc_day)
        {
            return "getUTCDay";
        }
        if (value->as.native.fn == js_date_proto_get_hours)
        {
            return "getHours";
        }
        if (value->as.native.fn == js_date_proto_get_utc_hours)
        {
            return "getUTCHours";
        }
        if (value->as.native.fn == js_date_proto_get_minutes)
        {
            return "getMinutes";
        }
        if (value->as.native.fn == js_date_proto_get_utc_minutes)
        {
            return "getUTCMinutes";
        }
        if (value->as.native.fn == js_date_proto_get_seconds)
        {
            return "getSeconds";
        }
        if (value->as.native.fn == js_date_proto_get_utc_seconds)
        {
            return "getUTCSeconds";
        }
        if (value->as.native.fn == js_date_proto_get_milliseconds)
        {
            return "getMilliseconds";
        }
        if (value->as.native.fn == js_date_proto_get_utc_milliseconds)
        {
            return "getUTCMilliseconds";
        }
        if (value->as.native.fn == js_date_proto_get_timezone_offset)
        {
            return "getTimezoneOffset";
        }
        if (value->as.native.fn == js_date_proto_set_time)
        {
            return "setTime";
        }
        if (value->as.native.fn == js_date_proto_set_full_year)
        {
            return "setFullYear";
        }
        if (value->as.native.fn == js_date_proto_set_utc_full_year)
        {
            return "setUTCFullYear";
        }
        if (value->as.native.fn == js_date_proto_set_month)
        {
            return "setMonth";
        }
        if (value->as.native.fn == js_date_proto_set_utc_month)
        {
            return "setUTCMonth";
        }
        if (value->as.native.fn == js_date_proto_set_date)
        {
            return "setDate";
        }
        if (value->as.native.fn == js_date_proto_set_utc_date)
        {
            return "setUTCDate";
        }
        if (value->as.native.fn == js_date_proto_set_hours)
        {
            return "setHours";
        }
        if (value->as.native.fn == js_date_proto_set_utc_hours)
        {
            return "setUTCHours";
        }
        if (value->as.native.fn == js_date_proto_set_minutes)
        {
            return "setMinutes";
        }
        if (value->as.native.fn == js_date_proto_set_utc_minutes)
        {
            return "setUTCMinutes";
        }
        if (value->as.native.fn == js_date_proto_set_seconds)
        {
            return "setSeconds";
        }
        if (value->as.native.fn == js_date_proto_set_utc_seconds)
        {
            return "setUTCSeconds";
        }
        if (value->as.native.fn == js_date_proto_set_milliseconds)
        {
            return "setMilliseconds";
        }
        if (value->as.native.fn == js_date_proto_set_utc_milliseconds)
        {
            return "setUTCMilliseconds";
        }
        if (value->as.native.fn == js_date_proto_get_year)
        {
            return "getYear";
        }
        if (value->as.native.fn == js_date_proto_set_year)
        {
            return "setYear";
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
            (value->as.native.fn == js_string_proto_anchor ||
             value->as.native.fn == js_string_proto_link ||
             value->as.native.fn == js_string_proto_fontcolor ||
             value->as.native.fn == js_string_proto_fontsize))
        {
            if (out_len)
            {
                *out_len = 1;
            }
            return true;
        }
        if (value && value->type == JS_VALUE_NATIVE_FN &&
            (value->as.native.fn == js_string_proto_match_all ||
             value->as.native.fn == js_string_proto_search ||
             value->as.native.fn == js_builtin_string_match))
        {
            if (out_len)
            {
                *out_len = 1;
            }
            return true;
        }
        if (value && value->type == JS_VALUE_NATIVE_FN &&
            (value->as.native.fn == js_string_proto_replace ||
             value->as.native.fn == js_string_proto_replace_all ||
             value->as.native.fn == js_string_proto_split ||
             value->as.native.fn == js_string_proto_substr))
        {
            if (out_len)
            {
                *out_len = 2;
            }
            return true;
        }
        if (value && value->type == JS_VALUE_NATIVE_FN &&
            (value->as.native.fn == js_string_proto_big ||
             value->as.native.fn == js_string_proto_blink ||
             value->as.native.fn == js_string_proto_bold ||
             value->as.native.fn == js_string_proto_fixed ||
             value->as.native.fn == js_string_proto_italics ||
             value->as.native.fn == js_string_proto_small ||
             value->as.native.fn == js_string_proto_strike ||
             value->as.native.fn == js_string_proto_sub ||
             value->as.native.fn == js_string_proto_sup))
        {
            if (out_len)
            {
                *out_len = 0;
            }
            return true;
        }
        if (value && value->type == JS_VALUE_NATIVE_FN &&
            (value->as.native.fn == js_builtin_array_join ||
             value->as.native.fn == js_builtin_array_push ||
             value->as.native.fn == js_builtin_array_map ||
             value->as.native.fn == js_builtin_array_for_each ||
             value->as.native.fn == js_builtin_array_from))
        {
            if (out_len)
            {
                *out_len = 1;
            }
            return true;
        }
        if (value && value->type == JS_VALUE_NATIVE_FN &&
            value->as.native.fn == js_builtin_reflect_get)
        {
            if (out_len)
            {
                *out_len = 2;
            }
            return true;
        }
        if (value && value->type == JS_VALUE_NATIVE_FN &&
            value->as.native.fn == js_builtin_reflect_set)
        {
            if (out_len)
            {
                *out_len = 3;
            }
            return true;
        }
        if (value && value->type == JS_VALUE_NATIVE_FN &&
            value->as.native.fn == js_regexp_legacy_getter)
        {
            if (out_len)
            {
                *out_len = 0;
            }
            return true;
        }
        if (value && value->type == JS_VALUE_NATIVE_FN &&
            value->as.native.fn == js_regexp_legacy_setter)
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
            value->as.native.fn == js_builtin_object_is)
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
            value->as.native.fn == js_builtin_temporal_duration)
        {
            if (out_len)
            {
                *out_len = 0;
            }
            return true;
        }
        if (value && value->type == JS_VALUE_NATIVE_FN &&
            value->as.native.fn == js_builtin_temporal_instant)
        {
            if (out_len)
            {
                *out_len = 1;
            }
            return true;
        }
        if (value && value->type == JS_VALUE_NATIVE_FN &&
            (value->as.native.fn == js_builtin_temporal_plain_date ||
             value->as.native.fn == js_builtin_temporal_plain_time ||
             value->as.native.fn == js_builtin_temporal_plain_date_time ||
             value->as.native.fn == js_builtin_temporal_zoned_date_time ||
             value->as.native.fn == js_builtin_temporal_plain_year_month ||
             value->as.native.fn == js_builtin_temporal_plain_month_day))
        {
            if (out_len)
            {
                *out_len = 0;
            }
            return true;
        }
        if (value && value->type == JS_VALUE_NATIVE_FN &&
            (value->as.native.fn == js_temporal_duration_negated ||
             value->as.native.fn == js_temporal_duration_abs ||
             value->as.native.fn == js_temporal_duration_to_string ||
             value->as.native.fn == js_temporal_duration_to_json ||
             value->as.native.fn == js_temporal_duration_to_locale_string ||
             value->as.native.fn == js_temporal_duration_value_of))
        {
            if (out_len)
            {
                *out_len = 0;
            }
            return true;
        }
        if (value && value->type == JS_VALUE_NATIVE_FN &&
            (value->as.native.fn == js_temporal_duration_with ||
             value->as.native.fn == js_temporal_duration_add ||
             value->as.native.fn == js_temporal_duration_subtract ||
             value->as.native.fn == js_temporal_duration_round ||
             value->as.native.fn == js_temporal_duration_total))
        {
            if (out_len)
            {
                *out_len = 1;
            }
            return true;
        }
        if (value && value->type == JS_VALUE_NATIVE_FN &&
            (value->as.native.fn == js_temporal_instant_to_string ||
             value->as.native.fn == js_temporal_instant_to_json ||
             value->as.native.fn == js_temporal_instant_to_locale_string ||
             value->as.native.fn == js_temporal_instant_value_of))
        {
            if (out_len)
            {
                *out_len = 0;
            }
            return true;
        }
        if (value && value->type == JS_VALUE_NATIVE_FN &&
            (value->as.native.fn == js_temporal_instant_add ||
             value->as.native.fn == js_temporal_instant_subtract ||
             value->as.native.fn == js_temporal_instant_since ||
             value->as.native.fn == js_temporal_instant_until ||
             value->as.native.fn == js_temporal_instant_round ||
             value->as.native.fn == js_temporal_instant_equals ||
             value->as.native.fn == js_temporal_instant_to_zoned_date_time_iso))
        {
            if (out_len)
            {
                *out_len = 1;
            }
            return true;
        }
        if (value && value->type == JS_VALUE_NATIVE_FN &&
            (value->as.native.fn == js_temporal_now_instant ||
             value->as.native.fn == js_temporal_now_plain_date_iso ||
             value->as.native.fn == js_temporal_now_plain_time_iso ||
             value->as.native.fn == js_temporal_now_plain_date_time_iso ||
             value->as.native.fn == js_temporal_now_zoned_date_time_iso ||
             value->as.native.fn == js_temporal_now_time_zone_id))
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
            value->as.native.fn == js_builtin_array_from)
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
        if (value && value->type == JS_VALUE_NATIVE_FN &&
            value->as.native.fn == js_builtin_bigint_to_string)
        {
            if (out_len)
            {
                *out_len = 1;
            }
            return true;
        }
        if (value && value->type == JS_VALUE_NATIVE_FN &&
            value->as.native.fn == js_builtin_bigint_value_of)
        {
            if (out_len)
            {
                *out_len = 0;
            }
            return true;
        }
        if (value && value->type == JS_VALUE_NATIVE_FN &&
            value->as.native.fn == js_builtin_date_now)
        {
            if (out_len)
            {
                *out_len = 0;
            }
            return true;
        }
        if (value && value->type == JS_VALUE_NATIVE_FN &&
            value->as.native.fn == js_builtin_date_parse)
        {
            if (out_len)
            {
                *out_len = 1;
            }
            return true;
        }
        if (value && value->type == JS_VALUE_NATIVE_FN &&
            value->as.native.fn == js_builtin_date_utc)
        {
            if (out_len)
            {
                *out_len = 7;
            }
            return true;
        }
        if (value && value->type == JS_VALUE_NATIVE_FN &&
            (value->as.native.fn == js_date_proto_to_string ||
             value->as.native.fn == js_date_proto_to_date_string ||
             value->as.native.fn == js_date_proto_to_time_string ||
             value->as.native.fn == js_date_proto_to_utc_string ||
             value->as.native.fn == js_date_proto_to_gmt_string ||
             value->as.native.fn == js_date_proto_to_iso_string ||
             value->as.native.fn == js_date_proto_value_of ||
             value->as.native.fn == js_date_proto_get_time ||
             value->as.native.fn == js_date_proto_get_full_year ||
             value->as.native.fn == js_date_proto_get_utc_full_year ||
             value->as.native.fn == js_date_proto_get_month ||
             value->as.native.fn == js_date_proto_get_utc_month ||
             value->as.native.fn == js_date_proto_get_date ||
             value->as.native.fn == js_date_proto_get_utc_date ||
             value->as.native.fn == js_date_proto_get_day ||
             value->as.native.fn == js_date_proto_get_utc_day ||
             value->as.native.fn == js_date_proto_get_hours ||
             value->as.native.fn == js_date_proto_get_utc_hours ||
             value->as.native.fn == js_date_proto_get_minutes ||
             value->as.native.fn == js_date_proto_get_utc_minutes ||
             value->as.native.fn == js_date_proto_get_seconds ||
             value->as.native.fn == js_date_proto_get_utc_seconds ||
             value->as.native.fn == js_date_proto_get_milliseconds ||
             value->as.native.fn == js_date_proto_get_utc_milliseconds ||
             value->as.native.fn == js_date_proto_get_timezone_offset ||
             value->as.native.fn == js_date_proto_get_year))
        {
            if (out_len)
            {
                *out_len = 0;
            }
            return true;
        }
        if (value && value->type == JS_VALUE_NATIVE_FN &&
            value->as.native.fn == js_date_proto_to_json)
        {
            if (out_len)
            {
                *out_len = 1;
            }
            return true;
        }
        if (value && value->type == JS_VALUE_NATIVE_FN &&
            (value->as.native.fn == js_date_proto_set_time ||
             value->as.native.fn == js_date_proto_set_date ||
             value->as.native.fn == js_date_proto_set_utc_date ||
             value->as.native.fn == js_date_proto_set_milliseconds ||
             value->as.native.fn == js_date_proto_set_utc_milliseconds ||
             value->as.native.fn == js_date_proto_set_year))
        {
            if (out_len)
            {
                *out_len = 1;
            }
            return true;
        }
        if (value && value->type == JS_VALUE_NATIVE_FN &&
            (value->as.native.fn == js_date_proto_set_month ||
             value->as.native.fn == js_date_proto_set_utc_month ||
             value->as.native.fn == js_date_proto_set_seconds ||
             value->as.native.fn == js_date_proto_set_utc_seconds))
        {
            if (out_len)
            {
                *out_len = 2;
            }
            return true;
        }
        if (value && value->type == JS_VALUE_NATIVE_FN &&
            (value->as.native.fn == js_date_proto_set_full_year ||
             value->as.native.fn == js_date_proto_set_utc_full_year ||
             value->as.native.fn == js_date_proto_set_minutes ||
             value->as.native.fn == js_date_proto_set_utc_minutes))
        {
            if (out_len)
            {
                *out_len = 3;
            }
            return true;
        }
        if (value && value->type == JS_VALUE_NATIVE_FN &&
            (value->as.native.fn == js_date_proto_set_hours ||
             value->as.native.fn == js_date_proto_set_utc_hours))
        {
            if (out_len)
            {
                *out_len = 4;
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
