#include "web/js/runtime/runtime_internal.h"

#include "ctype.h"
#include "libc.h"
#include "math.h"
#include "stdio.h"

typedef enum
{
    JS_CTRL_NONE = 0,
    JS_CTRL_RETURN,
    JS_CTRL_BREAK,
    JS_CTRL_CONTINUE
} js_control_t;

typedef struct
{
    bool ok;
    js_control_t control;
    js_value_t value;
    char *error_message;
} js_eval_result_t;

static bool js_parse_index_key(const char *text, size_t *out_index);
static bool js_make_single_char_string(js_value_t *out, char c);
static const char *js_function_name(const js_function_t *fn);
static bool js_string_builder_append(char **buf, size_t *len, size_t *cap, const char *data, size_t data_len);

static double js_trunc(double value)
{
    return (value < 0.0) ? ceil(value) : floor(value);
}

static bool js_string_builder_append(char **buf, size_t *len, size_t *cap, const char *data, size_t data_len)
{
    if (!buf || !len || !cap)
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
        size_t new_cap = *cap ? *cap * 2u : 64u;
        if (new_cap < needed + 1)
        {
            new_cap = needed + 1;
        }
        char *next = (char *)realloc(*buf, new_cap);
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

static bool js_string_equals_len(const char *data, size_t len, const char *text)
{
    if (!text)
    {
        return false;
    }
    size_t text_len = strlen(text);
    if (len != text_len)
    {
        return false;
    }
    if (len == 0)
    {
        return true;
    }
    return data && memcmp(data, text, len) == 0;
}

static bool js_value_is_length_key(const js_value_t *value)
{
    if (!value || value->type != JS_VALUE_STRING)
    {
        return false;
    }
    return js_string_equals_len(value->as.string.data, value->as.string.len, "length");
}

static bool js_value_to_index(const js_value_t *value, size_t *out_index)
{
    if (!value || !out_index)
    {
        return false;
    }
    double num = 0.0;
    if (value->type == JS_VALUE_NUMBER)
    {
        num = value->as.number;
    }
    else if (value->type == JS_VALUE_STRING)
    {
        if (!js_parse_number_text(value->as.string.data ? value->as.string.data : "", &num))
        {
            return false;
        }
    }
    else
    {
        return false;
    }

    if (js_is_nan(num) || num < 0.0)
    {
        return false;
    }
    double trunc = js_trunc(num);
    if (trunc != num)
    {
        return false;
    }
    if (num >= 4294967295.0)
    {
        return false;
    }
    if (num > (double)SIZE_MAX)
    {
        return false;
    }
    *out_index = (size_t)num;
    return true;
}

static bool js_value_to_array_length(const js_value_t *value, size_t *out_length)
{
    if (!value || !out_length)
    {
        return false;
    }
    bool ok = true;
    double num = js_value_to_number(value, &ok);
    if (!ok || js_is_nan(num))
    {
        return false;
    }
    if (num < 0.0 || num >= 4294967296.0)
    {
        return false;
    }
    double trunc = js_trunc(num);
    if (trunc != num)
    {
        return false;
    }
    if (num > (double)SIZE_MAX)
    {
        return false;
    }
    *out_length = (size_t)num;
    return true;
}

static const char *js_typeof_name(const js_value_t *value)
{
    if (!value)
    {
        return "undefined";
    }
    switch (value->type)
    {
        case JS_VALUE_UNDEFINED:
            return "undefined";
        case JS_VALUE_NULL:
            return "object";
        case JS_VALUE_BOOL:
            return "boolean";
        case JS_VALUE_NUMBER:
            return "number";
        case JS_VALUE_BIGINT:
            return "bigint";
        case JS_VALUE_STRING:
            return "string";
        case JS_VALUE_FUNCTION:
        case JS_VALUE_NATIVE_FN:
            return "function";
        case JS_VALUE_ARRAY:
        case JS_VALUE_OBJECT:
            return "object";
    }
    return "undefined";
}

static js_eval_result_t js_eval_error(const char *message);
static js_eval_result_t js_eval_ok(js_value_t value);
static size_t js_function_length(const js_function_t *fn);

static js_eval_result_t js_eval_add_values(js_runtime_t *rt, const js_value_t *left, const js_value_t *right)
{
    if (!left || !right)
    {
        return js_eval_error("invalid add");
    }
    if (left->type == JS_VALUE_STRING || right->type == JS_VALUE_STRING)
    {
        js_temp_string_t ltemp;
        js_temp_string_t rtemp;
        char *err = NULL;
        if (!js_temp_string_from_value(rt, left, &ltemp, &err))
        {
            js_temp_string_release(&ltemp);
            if (err)
            {
                js_eval_result_t res = js_eval_error(err);
                free(err);
                return res;
            }
            return js_eval_error("allocation failed");
        }
        if (!js_temp_string_from_value(rt, right, &rtemp, &err))
        {
            js_temp_string_release(&ltemp);
            js_temp_string_release(&rtemp);
            if (err)
            {
                js_eval_result_t res = js_eval_error(err);
                free(err);
                return res;
            }
            return js_eval_error("allocation failed");
        }
        if (ltemp.len > SIZE_MAX - rtemp.len - 1)
        {
            js_temp_string_release(&ltemp);
            js_temp_string_release(&rtemp);
            return js_eval_error("string too large");
        }
        size_t total = ltemp.len + rtemp.len;
        char *joined = (char *)malloc(total + 1);
        if (!joined)
        {
            js_temp_string_release(&ltemp);
            js_temp_string_release(&rtemp);
            return js_eval_error("allocation failed");
        }
        if (ltemp.len)
        {
            memcpy(joined, ltemp.data, ltemp.len);
        }
        if (rtemp.len)
        {
            memcpy(joined + ltemp.len, rtemp.data, rtemp.len);
        }
        joined[total] = '\0';
        js_temp_string_release(&ltemp);
        js_temp_string_release(&rtemp);
        js_value_t result;
        result.type = JS_VALUE_STRING;
        result.as.string.data = joined;
        result.as.string.len = total;
        return js_eval_ok(result);
    }
    if (left->type == JS_VALUE_BIGINT || right->type == JS_VALUE_BIGINT)
    {
        if (left->type != JS_VALUE_BIGINT || right->type != JS_VALUE_BIGINT)
        {
            return js_eval_error("TypeError: cannot mix BigInt and other types");
        }
        js_bigint_t *sum = js_bigint_add(left->as.bigint, right->as.bigint);
        if (!sum)
        {
            return js_eval_error("allocation failed");
        }
        js_value_t result;
        memset(&result, 0, sizeof(result));
        result.type = JS_VALUE_BIGINT;
        result.as.bigint = sum;
        return js_eval_ok(result);
    }

    bool ok_left = true;
    bool ok_right = true;
    double ln = js_value_to_number(left, &ok_left);
    double rn = js_value_to_number(right, &ok_right);
    if (!ok_left || !ok_right || js_is_nan(ln) || js_is_nan(rn))
    {
        return js_eval_error("expected number");
    }
    return js_eval_ok(js_value_make_number(ln + rn));
}

static js_eval_result_t js_eval_error(const char *message)
{
    js_eval_result_t res;
    res.ok = false;
    res.control = JS_CTRL_NONE;
    res.value = js_value_make_undefined_internal();
    res.error_message = message ? js_strdup(message) : NULL;
    return res;
}

static js_eval_result_t js_eval_ok(js_value_t value)
{
    js_eval_result_t res;
    res.ok = true;
    res.control = JS_CTRL_NONE;
    res.value = value;
    res.error_message = NULL;
    return res;
}

static js_eval_result_t js_eval_control(js_control_t control, js_value_t value)
{
    js_eval_result_t res;
    res.ok = true;
    res.control = control;
    res.value = value;
    res.error_message = NULL;
    return res;
}

static js_eval_result_t js_eval_expr(js_runtime_t *rt, js_env_t *env, const js_expr_t *expr);
static js_eval_result_t js_eval_statement(js_runtime_t *rt, js_env_t *env, const js_stmt_t *stmt);

static bool js_hoist_vars_in_stmt(js_env_t *var_env, const js_stmt_t *stmt);

static bool js_hoist_binding(js_env_t *var_env, const js_binding_t *binding)
{
    if (!var_env || !binding)
    {
        return true;
    }
    switch (binding->type)
    {
        case JS_BINDING_IDENTIFIER:
        {
            js_value_t undef = js_value_make_undefined_internal();
            return js_env_define_if_absent(var_env, binding->as.ident.name, &undef, false);
        }
        case JS_BINDING_ARRAY:
            for (size_t i = 0; i < binding->as.array.count; ++i)
            {
                if (!js_hoist_binding(var_env, binding->as.array.elements[i].binding))
                {
                    return false;
                }
            }
            return js_hoist_binding(var_env, binding->as.array.rest);
        case JS_BINDING_OBJECT:
            for (size_t i = 0; i < binding->as.object.count; ++i)
            {
                if (!js_hoist_binding(var_env, binding->as.object.props[i].binding))
                {
                    return false;
                }
            }
            if (binding->as.object.rest_name)
            {
                js_value_t undef = js_value_make_undefined_internal();
                if (!js_env_define_if_absent(var_env, binding->as.object.rest_name, &undef, false))
                {
                    return false;
                }
            }
            return true;
    }
    return true;
}

static bool js_hoist_vars(js_env_t *var_env, js_stmt_t **stmts, size_t count)
{
    if (!var_env)
    {
        return false;
    }
    for (size_t i = 0; i < count; ++i)
    {
        if (!js_hoist_vars_in_stmt(var_env, stmts[i]))
        {
            return false;
        }
    }
    return true;
}

static bool js_hoist_vars_in_stmt(js_env_t *var_env, const js_stmt_t *stmt)
{
    if (!stmt || !var_env)
    {
        return true;
    }
    switch (stmt->type)
    {
        case JS_STMT_VAR:
            if (stmt->as.var.kind == JS_VAR_VAR)
            {
                for (size_t i = 0; i < stmt->as.var.count; ++i)
                {
                    if (!js_hoist_binding(var_env, stmt->as.var.bindings[i].binding))
                    {
                        return false;
                    }
                }
            }
            return true;
        case JS_STMT_BLOCK:
            return js_hoist_vars(var_env, stmt->as.block.stmts, stmt->as.block.count);
        case JS_STMT_IF:
            if (!js_hoist_vars_in_stmt(var_env, stmt->as.if_stmt.then_branch))
            {
                return false;
            }
            return js_hoist_vars_in_stmt(var_env, stmt->as.if_stmt.else_branch);
        case JS_STMT_WHILE:
            return js_hoist_vars_in_stmt(var_env, stmt->as.while_stmt.body);
        case JS_STMT_DO_WHILE:
            return js_hoist_vars_in_stmt(var_env, stmt->as.do_while_stmt.body);
        case JS_STMT_FOR:
            if (!js_hoist_vars_in_stmt(var_env, stmt->as.for_stmt.init))
            {
                return false;
            }
            return js_hoist_vars_in_stmt(var_env, stmt->as.for_stmt.body);
        case JS_STMT_FOR_IN:
        case JS_STMT_FOR_OF:
            if (stmt->as.for_inof.is_decl && stmt->as.for_inof.kind == JS_VAR_VAR)
            {
                if (!js_hoist_binding(var_env, stmt->as.for_inof.binding))
                {
                    return false;
                }
            }
            return js_hoist_vars_in_stmt(var_env, stmt->as.for_inof.body);
        case JS_STMT_SWITCH:
            for (size_t c = 0; c < stmt->as.switch_stmt.case_count; ++c)
            {
                if (!js_hoist_vars(var_env,
                                   stmt->as.switch_stmt.cases[c].stmts,
                                   stmt->as.switch_stmt.cases[c].count))
                {
                    return false;
                }
            }
            return true;
        case JS_STMT_TRY:
            if (!js_hoist_vars(var_env,
                               stmt->as.try_stmt.try_block.stmts,
                               stmt->as.try_stmt.try_block.count))
            {
                return false;
            }
            if (stmt->as.try_stmt.has_catch)
            {
                return js_hoist_vars(var_env,
                                     stmt->as.try_stmt.catch_block.stmts,
                                     stmt->as.try_stmt.catch_block.count);
            }
            return true;
        case JS_STMT_FUNCTION_DECL:
        case JS_STMT_RETURN:
        case JS_STMT_THROW:
        case JS_STMT_EXPR:
        case JS_STMT_BREAK:
        case JS_STMT_CONTINUE:
        case JS_STMT_EMPTY:
            return true;
    }
    return true;
}

static js_eval_result_t js_eval_statements(js_runtime_t *rt, js_env_t *env, js_stmt_t **stmts, size_t count)
{
    js_eval_result_t result = js_eval_ok(js_value_make_undefined_internal());
    for (size_t i = 0; i < count; ++i)
    {
        js_eval_result_t step = js_eval_statement(rt, env, stmts[i]);
        if (!step.ok)
        {
            js_value_destroy(&result.value);
            return step;
        }
        if (step.control != JS_CTRL_NONE)
        {
            js_value_destroy(&result.value);
            return step;
        }
        js_value_destroy(&result.value);
        result.value = step.value;
    }
    return result;
}

typedef struct
{
    js_value_t object;
    bool is_length;
    bool has_index;
    size_t index;
    char *property;
    bool property_owned;
} js_member_access_t;

static void js_member_access_release(js_member_access_t *access)
{
    if (!access)
    {
        return;
    }
    if (access->property_owned)
    {
        free(access->property);
    }
    access->property = NULL;
    access->property_owned = false;
    js_value_destroy(&access->object);
    access->object = js_value_make_undefined_internal();
    access->is_length = false;
    access->has_index = false;
    access->index = 0;
}

static bool js_value_to_property_name(js_runtime_t *rt,
                                      const js_value_t *value,
                                      char **out,
                                      char **error_message)
{
    if (!out)
    {
        return false;
    }
    *out = NULL;
    js_temp_string_t temp = {0};
    if (!js_temp_string_from_value(rt, value, &temp, error_message))
    {
        return false;
    }
    char *copy = js_strdup_len(temp.data ? temp.data : "", temp.len);
    js_temp_string_release(&temp);
    if (!copy)
    {
        return false;
    }
    *out = copy;
    return true;
}

static js_property_t *js_object_ensure_property(js_object_t *object,
                                                const char *name,
                                                char **error_message)
{
    if (!object || !name)
    {
        return NULL;
    }
    js_property_t *prop = js_object_find_property(object, name);
    if (prop)
    {
        return prop;
    }
    js_property_t *new_prop = (js_property_t *)calloc(1, sizeof(*new_prop));
    if (!new_prop)
    {
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return NULL;
    }
    new_prop->name = js_strdup(name);
    if (!new_prop->name)
    {
        free(new_prop);
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return NULL;
    }
    new_prop->value = js_value_make_undefined_internal();
    new_prop->getter = js_value_make_undefined_internal();
    new_prop->setter = js_value_make_undefined_internal();
    new_prop->writable = true;
    new_prop->enumerable = true;
    new_prop->configurable = true;
    new_prop->is_accessor = false;
    new_prop->next = object->properties;
    object->properties = new_prop;
    return new_prop;
}

bool js_object_get_property(js_runtime_t *rt,
                            js_object_t *object,
                            const char *name,
                            js_value_t *out,
                            char **error_message)
{
    if (!out)
    {
        return false;
    }
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!name)
    {
        *out = js_value_make_undefined_internal();
        return true;
    }
    js_object_t *receiver = object;
    js_object_t *current = object;
    for (size_t depth = 0; current && depth < 32; ++depth)
    {
        if (current->get_fn)
        {
            js_value_t value = js_value_make_undefined_internal();
            if (!current->get_fn(rt, current->user_data, name, &value, error_message))
            {
                return false;
            }
            if (value.type != JS_VALUE_UNDEFINED)
            {
                *out = value;
                return true;
            }
            js_value_destroy(&value);
        }
        js_property_t *prop = js_object_find_property(current, name);
        if (prop)
        {
            if (prop->is_accessor)
            {
                if (prop->getter.type == JS_VALUE_NATIVE_FN)
                {
                    js_value_t result = js_value_make_undefined_internal();
                    js_value_t receiver_val = js_value_make_undefined_internal();
                    receiver_val.type = JS_VALUE_OBJECT;
                    receiver_val.as.object = receiver;
                    js_object_retain(receiver);
                    char *err = NULL;
                    bool ok = js_call_value(rt, &prop->getter, 1, &receiver_val, &result, &err);
                    js_value_destroy(&receiver_val);
                    if (!ok)
                    {
                        if (error_message)
                        {
                            *error_message = err;
                        }
                        else
                        {
                            free(err);
                        }
                        js_value_destroy(&result);
                        return false;
                    }
                    free(err);
                    *out = result;
                    return true;
                }
                if (prop->getter.type == JS_VALUE_FUNCTION)
                {
                    js_value_t result = js_value_make_undefined_internal();
                    char *err = NULL;
                    bool ok = js_call_value(rt, &prop->getter, 0, NULL, &result, &err);
                    if (!ok)
                    {
                        if (error_message)
                        {
                            *error_message = err;
                        }
                        else
                        {
                            free(err);
                        }
                        js_value_destroy(&result);
                        return false;
                    }
                    free(err);
                    *out = result;
                    return true;
                }
                *out = js_value_make_undefined_internal();
                return true;
            }
            return js_value_copy(out, &prop->value);
        }

        js_value_t proto = js_value_make_undefined_internal();
        if (!js_object_get_slot(current, "__proto__", &proto))
        {
            if (error_message)
            {
                *error_message = js_strdup("allocation failed");
            }
            return false;
        }
        if (proto.type != JS_VALUE_OBJECT || !proto.as.object)
        {
            js_value_destroy(&proto);
            break;
        }
        js_object_t *next = proto.as.object;
        js_value_destroy(&proto);
        if (next == current)
        {
            break;
        }
        current = next;
    }

    *out = js_value_make_undefined_internal();
    return true;
}

bool js_object_has_property(js_runtime_t *rt, js_object_t *object, const char *name)
{
    if (!rt || !object || !name)
    {
        return false;
    }
    js_object_t *current = object;
    for (size_t depth = 0; current && depth < 32; ++depth)
    {
        if (current->get_fn)
        {
            js_value_t value = js_value_make_undefined_internal();
            if (!current->get_fn(rt, current->user_data, name, &value, NULL))
            {
                js_value_destroy(&value);
                return false;
            }
            if (value.type != JS_VALUE_UNDEFINED)
            {
                js_value_destroy(&value);
                return true;
            }
            js_value_destroy(&value);
        }
        if (js_object_find_property(current, name))
        {
            return true;
        }
        js_value_t proto = js_value_make_undefined_internal();
        if (!js_object_get_slot(current, "__proto__", &proto))
        {
            return false;
        }
        if (proto.type != JS_VALUE_OBJECT || !proto.as.object)
        {
            js_value_destroy(&proto);
            break;
        }
        js_object_t *next = proto.as.object;
        js_value_destroy(&proto);
        if (next == current)
        {
            break;
        }
        current = next;
    }
    return false;
}

static bool js_object_set_property(js_runtime_t *rt,
                                   js_object_t *object,
                                   const char *name,
                                   const js_value_t *value,
                                   char **error_message)
{
    if (!object)
    {
        return false;
    }
    if (error_message)
    {
        *error_message = NULL;
    }
    if (object->set_fn)
    {
        return object->set_fn(rt, object->user_data, name, value, error_message);
    }
    js_property_t *prop = js_object_find_property(object, name);
    if (prop)
    {
        if (prop->is_accessor)
        {
            if (prop->setter.type == JS_VALUE_FUNCTION || prop->setter.type == JS_VALUE_NATIVE_FN)
            {
                js_value_t result = js_value_make_undefined_internal();
                char *err = NULL;
                bool ok = js_call_value(rt, &prop->setter, 1, value, &result, &err);
                js_value_destroy(&result);
                if (!ok)
                {
                    if (error_message)
                    {
                        *error_message = err;
                    }
                    else
                    {
                        free(err);
                    }
                    return false;
                }
                free(err);
            }
            return true;
        }
        if (!prop->writable)
        {
            return true;
        }
        js_value_destroy(&prop->value);
        if (!js_value_copy(&prop->value, value))
        {
            if (error_message)
            {
                *error_message = js_strdup("allocation failed");
            }
            return false;
        }
        return true;
    }
    return js_object_set_slot(object, name, value);
}

static bool js_array_index_name(size_t index, char *buf, size_t buf_len)
{
    int len = snprintf(buf, buf_len, "%zu", index);
    return len >= 0 && (size_t)len < buf_len;
}

static bool js_array_get_index_value(js_runtime_t *rt,
                                     js_array_t *array,
                                     size_t index,
                                     js_value_t *out,
                                     char **error_message)
{
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    if (!array)
    {
        *out = js_value_make_undefined_internal();
        return true;
    }
    char key[32];
    if (js_array_index_name(index, key, sizeof(key)))
    {
        js_property_t *prop = js_array_find_property(array, key);
        if (prop)
        {
            if (prop->is_accessor)
            {
                if (prop->getter.type == JS_VALUE_FUNCTION || prop->getter.type == JS_VALUE_NATIVE_FN)
                {
                    js_value_t result = js_value_make_undefined_internal();
                    char *err = NULL;
                    bool ok = js_call_value(rt, &prop->getter, 0, NULL, &result, &err);
                    if (!ok)
                    {
                        if (error_message)
                        {
                            *error_message = err ? err : js_strdup("getter failed");
                        }
                        else
                        {
                            free(err);
                        }
                        js_value_destroy(&result);
                        return false;
                    }
                    free(err);
                    *out = result;
                    return true;
                }
                *out = js_value_make_undefined_internal();
                return true;
            }
            return js_value_copy(out, &prop->value);
        }
    }
    return js_array_get(array, index, out);
}

static bool js_array_set_index_value(js_runtime_t *rt,
                                     js_array_t *array,
                                     size_t index,
                                     const js_value_t *value,
                                     char **error_message)
{
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!array || !value)
    {
        return false;
    }
    char key[32];
    if (js_array_index_name(index, key, sizeof(key)))
    {
        js_property_t *prop = js_array_find_property(array, key);
        if (prop)
        {
            if (prop->is_accessor)
            {
                if (prop->setter.type == JS_VALUE_FUNCTION || prop->setter.type == JS_VALUE_NATIVE_FN)
                {
                    js_value_t result = js_value_make_undefined_internal();
                    char *err = NULL;
                    bool ok = js_call_value(rt, &prop->setter, 1, value, &result, &err);
                    js_value_destroy(&result);
                    if (!ok)
                    {
                        if (error_message)
                        {
                            *error_message = err;
                        }
                        else
                        {
                            free(err);
                        }
                        return false;
                    }
                    free(err);
                }
                return true;
            }
            if (!prop->writable)
            {
                return true;
            }
            js_value_destroy(&prop->value);
            if (!js_value_copy(&prop->value, value))
            {
                if (error_message)
                {
                    *error_message = js_strdup("allocation failed");
                }
                return false;
            }
            if (!js_array_set(array, index, value))
            {
                if (error_message)
                {
                    *error_message = js_strdup("allocation failed");
                }
                return false;
            }
            return true;
        }
    }
    return js_array_set(array, index, value);
}

static bool js_array_set_named_property(js_runtime_t *rt,
                                        js_array_t *array,
                                        const char *name,
                                        const js_value_t *value,
                                        char **error_message)
{
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!array || !name || !value)
    {
        return false;
    }
    js_property_t *prop = js_array_find_property(array, name);
    if (prop)
    {
        if (prop->is_accessor)
        {
            if (prop->setter.type == JS_VALUE_FUNCTION || prop->setter.type == JS_VALUE_NATIVE_FN)
            {
                js_value_t result = js_value_make_undefined_internal();
                char *err = NULL;
                bool ok = js_call_value(rt, &prop->setter, 1, value, &result, &err);
                js_value_destroy(&result);
                if (!ok)
                {
                    if (error_message)
                    {
                        *error_message = err;
                    }
                    else
                    {
                        free(err);
                    }
                    return false;
                }
                free(err);
            }
            return true;
        }
        if (!prop->writable)
        {
            return true;
        }
        js_value_destroy(&prop->value);
        if (!js_value_copy(&prop->value, value))
        {
            if (error_message)
            {
                *error_message = js_strdup("allocation failed");
            }
            return false;
        }
        return true;
    }
    return js_array_set_property(array, name, value);
}

static js_eval_result_t js_eval_member_access(js_runtime_t *rt,
                                              js_env_t *env,
                                              const js_member_expr_t *member,
                                              js_member_access_t *out)
{
    if (!member || !out)
    {
        return js_eval_error("invalid member");
    }
    out->object = js_value_make_undefined_internal();
    out->is_length = false;
    out->has_index = false;
    out->index = 0;
    out->property = NULL;
    out->property_owned = false;

    js_eval_result_t object_res = js_eval_expr(rt, env, member->object);
    if (!object_res.ok)
    {
        return object_res;
    }
    out->object = object_res.value;

    if (member->computed)
    {
        js_eval_result_t prop_res = js_eval_expr(rt, env, member->property_expr);
        if (!prop_res.ok)
        {
            js_value_destroy(&out->object);
            return prop_res;
        }
        bool handled = false;
        if (out->object.type == JS_VALUE_ARRAY)
        {
            if (js_value_is_length_key(&prop_res.value))
            {
                out->is_length = true;
                handled = true;
            }
            else if (js_value_to_index(&prop_res.value, &out->index))
            {
                out->has_index = true;
                handled = true;
            }
            else
            {
                char *prop_err = NULL;
                if (js_value_to_property_name(rt, &prop_res.value, &out->property, &prop_err))
                {
                    out->property_owned = true;
                    handled = true;
                }
                else if (prop_err)
                {
                    js_value_destroy(&prop_res.value);
                    js_member_access_release(out);
                    js_eval_result_t res = js_eval_error(prop_err);
                    free(prop_err);
                    return res;
                }
            }
        }
        else if (out->object.type == JS_VALUE_STRING)
        {
            if (js_value_is_length_key(&prop_res.value))
            {
                out->is_length = true;
                handled = true;
            }
            else
            {
                char *prop_err = NULL;
                if (js_value_to_property_name(rt, &prop_res.value, &out->property, &prop_err))
                {
                    out->property_owned = true;
                    handled = true;
                }
                else if (prop_err)
                {
                    js_value_destroy(&prop_res.value);
                    js_member_access_release(out);
                    js_eval_result_t res = js_eval_error(prop_err);
                    free(prop_err);
                    return res;
                }
            }
        }
        else if (out->object.type == JS_VALUE_NUMBER)
        {
            char *prop_err = NULL;
            if (js_value_to_property_name(rt, &prop_res.value, &out->property, &prop_err))
            {
                out->property_owned = true;
                handled = true;
            }
            else if (prop_err)
            {
                js_value_destroy(&prop_res.value);
                js_member_access_release(out);
                js_eval_result_t res = js_eval_error(prop_err);
                free(prop_err);
                return res;
            }
        }
        else if (out->object.type == JS_VALUE_BIGINT)
        {
            char *prop_err = NULL;
            if (js_value_to_property_name(rt, &prop_res.value, &out->property, &prop_err))
            {
                out->property_owned = true;
                handled = true;
            }
            else if (prop_err)
            {
                js_value_destroy(&prop_res.value);
                js_member_access_release(out);
                js_eval_result_t res = js_eval_error(prop_err);
                free(prop_err);
                return res;
            }
        }
        else if (out->object.type == JS_VALUE_BOOL)
        {
            char *prop_err = NULL;
            if (js_value_to_property_name(rt, &prop_res.value, &out->property, &prop_err))
            {
                out->property_owned = true;
                handled = true;
            }
            else if (prop_err)
            {
                js_value_destroy(&prop_res.value);
                js_member_access_release(out);
                js_eval_result_t res = js_eval_error(prop_err);
                free(prop_err);
                return res;
            }
        }
        else if (out->object.type == JS_VALUE_FUNCTION || out->object.type == JS_VALUE_NATIVE_FN)
        {
            if (js_value_is_length_key(&prop_res.value))
            {
                out->is_length = true;
                handled = true;
            }
            else if (out->object.type == JS_VALUE_FUNCTION)
            {
                char *prop_err = NULL;
                if (js_value_to_property_name(rt, &prop_res.value, &out->property, &prop_err))
                {
                    out->property_owned = true;
                    handled = true;
                }
                else if (prop_err)
                {
                    js_value_destroy(&prop_res.value);
                    js_member_access_release(out);
                    js_eval_result_t res = js_eval_error(prop_err);
                    free(prop_err);
                    return res;
                }
            }
            else if (out->object.type == JS_VALUE_NATIVE_FN)
            {
                char *prop_err = NULL;
                if (js_value_to_property_name(rt, &prop_res.value, &out->property, &prop_err))
                {
                    out->property_owned = true;
                    handled = true;
                }
                else if (prop_err)
                {
                    js_value_destroy(&prop_res.value);
                    js_member_access_release(out);
                    js_eval_result_t res = js_eval_error(prop_err);
                    free(prop_err);
                    return res;
                }
            }
        }
        else if (out->object.type == JS_VALUE_OBJECT)
        {
            char *prop_err = NULL;
            if (js_value_to_property_name(rt, &prop_res.value, &out->property, &prop_err))
            {
                out->property_owned = true;
                handled = true;
            }
            else if (prop_err)
            {
                js_value_destroy(&prop_res.value);
                js_member_access_release(out);
                js_eval_result_t res = js_eval_error(prop_err);
                free(prop_err);
                return res;
            }
        }

        js_value_destroy(&prop_res.value);
        if (!handled)
        {
            js_member_access_release(out);
            return js_eval_error("invalid property");
        }
    }
    else
    {
        if (out->object.type == JS_VALUE_OBJECT)
        {
            out->property = member->property;
        }
        else if (out->object.type == JS_VALUE_ARRAY)
        {
            if (member->property && strcmp(member->property, "length") == 0)
            {
                out->is_length = true;
            }
            else
            {
                out->property = member->property;
            }
        }
        else if (out->object.type == JS_VALUE_STRING && member->property &&
                 strcmp(member->property, "length") == 0)
        {
            out->is_length = true;
        }
        else if (out->object.type == JS_VALUE_STRING && member->property &&
                 strcmp(member->property, "match") == 0)
        {
            out->property = member->property;
        }
        else if (out->object.type == JS_VALUE_STRING)
        {
            out->property = member->property;
        }
        else if (out->object.type == JS_VALUE_NUMBER)
        {
            if (member->property && strcmp(member->property, "toString") == 0)
            {
                out->property = member->property;
            }
            else
            {
                out->property = member->property;
            }
        }
        else if (out->object.type == JS_VALUE_BIGINT)
        {
            out->property = member->property;
        }
        else if (out->object.type == JS_VALUE_BOOL)
        {
            out->property = member->property;
        }
        else if (out->object.type == JS_VALUE_FUNCTION)
        {
            if (member->property && strcmp(member->property, "length") == 0)
            {
                out->is_length = true;
            }
            else if (member->property && strcmp(member->property, "name") == 0)
            {
                out->property = member->property;
            }
            else if (member->property && strcmp(member->property, "call") == 0)
            {
                out->property = member->property;
            }
            else if (member->property && strcmp(member->property, "bind") == 0)
            {
                out->property = member->property;
            }
            else
            {
                out->property = member->property;
            }
        }
        else if (out->object.type == JS_VALUE_NATIVE_FN && member->property && strcmp(member->property, "length") == 0)
        {
            out->is_length = true;
        }
        else if (out->object.type == JS_VALUE_NATIVE_FN)
        {
            out->property = member->property;
        }
        else
        {
            js_member_access_release(out);
            return js_eval_error("unknown property");
        }
    }

    return js_eval_ok(js_value_make_undefined_internal());
}

static js_eval_result_t js_member_access_value(js_runtime_t *rt, js_member_access_t *access)
{
    if (!access)
    {
        return js_eval_error("invalid member");
    }
    if (access->is_length)
    {
        if (access->object.type == JS_VALUE_ARRAY)
        {
            return js_eval_ok(js_value_make_number((double)access->object.as.array->length));
        }
        if (access->object.type == JS_VALUE_STRING)
        {
            return js_eval_ok(js_value_make_number((double)access->object.as.string.len));
        }
        if (access->object.type == JS_VALUE_FUNCTION)
        {
            return js_eval_ok(js_value_make_number((double)js_function_length(access->object.as.function)));
        }
        if (access->object.type == JS_VALUE_NATIVE_FN)
        {
            size_t length = 0;
            if (!js_value_native_length(rt, &access->object, &length))
            {
                return js_eval_error("unknown property");
            }
            return js_eval_ok(js_value_make_number((double)length));
        }
        return js_eval_error(access->property ? access->property : "unknown property");
    }
    if (access->object.type == JS_VALUE_ARRAY)
    {
        if (access->has_index)
        {
            js_value_t value;
            char *err = NULL;
            if (!js_array_get_index_value(rt, access->object.as.array, access->index, &value, &err))
            {
                if (err)
                {
                    js_eval_result_t res = js_eval_error(err);
                    free(err);
                    return res;
                }
                return js_eval_error("allocation failed");
            }
            return js_eval_ok(value);
        }
        if (access->property)
        {
            js_value_t value;
            char *prop_err = NULL;
            if (!js_array_get_property(rt, access->object.as.array, access->property, &value, &prop_err))
            {
                if (prop_err)
                {
                    js_eval_result_t res = js_eval_error(prop_err);
                    free(prop_err);
                    return res;
                }
                return js_eval_error("allocation failed");
            }
            return js_eval_ok(value);
        }
        return js_eval_ok(js_value_make_undefined_internal());
    }
    if (access->object.type == JS_VALUE_STRING)
    {
        if (access->property && strcmp(access->property, "match") == 0)
        {
            js_value_t value;
            memset(&value, 0, sizeof(value));
            value.type = JS_VALUE_NATIVE_FN;
            value.as.native.fn = js_builtin_string_match;
            value.as.native.user_data = &access->object;
            return js_eval_ok(value);
        }
        if (access->property)
        {
            size_t index = 0;
            if (js_parse_index_key(access->property, &index) &&
                index < access->object.as.string.len && access->object.as.string.data)
            {
                js_value_t value;
                if (!js_make_single_char_string(&value, access->object.as.string.data[index]))
                {
                    return js_eval_error("allocation failed");
                }
                return js_eval_ok(value);
            }
        }
        return js_eval_ok(js_value_make_undefined_internal());
    }
    if (access->object.type == JS_VALUE_NUMBER)
    {
        if (access->property && strcmp(access->property, "toString") == 0)
        {
            js_value_t value;
            memset(&value, 0, sizeof(value));
            value.type = JS_VALUE_NATIVE_FN;
            value.as.native.fn = js_builtin_number_to_string;
            value.as.native.user_data = &access->object;
            return js_eval_ok(value);
        }
        return js_eval_ok(js_value_make_undefined_internal());
    }
    if (access->object.type == JS_VALUE_BIGINT)
    {
        if (access->property && strcmp(access->property, "toString") == 0)
        {
            js_value_t value;
            memset(&value, 0, sizeof(value));
            value.type = JS_VALUE_NATIVE_FN;
            value.as.native.fn = js_builtin_bigint_to_string;
            value.as.native.user_data = &access->object;
            return js_eval_ok(value);
        }
        if (access->property && strcmp(access->property, "valueOf") == 0)
        {
            js_value_t value;
            memset(&value, 0, sizeof(value));
            value.type = JS_VALUE_NATIVE_FN;
            value.as.native.fn = js_builtin_bigint_value_of;
            value.as.native.user_data = &access->object;
            return js_eval_ok(value);
        }
        return js_eval_ok(js_value_make_undefined_internal());
    }
    if (access->object.type == JS_VALUE_BOOL)
    {
        return js_eval_ok(js_value_make_undefined_internal());
    }
    if (access->object.type == JS_VALUE_FUNCTION)
    {
        if (access->property && strcmp(access->property, "call") == 0)
        {
            js_value_t value;
            memset(&value, 0, sizeof(value));
            value.type = JS_VALUE_NATIVE_FN;
            value.as.native.fn = js_builtin_function_call;
            value.as.native.user_data = &access->object;
            return js_eval_ok(value);
        }
        if (access->property && strcmp(access->property, "bind") == 0)
        {
            js_value_t value;
            memset(&value, 0, sizeof(value));
            value.type = JS_VALUE_NATIVE_FN;
            value.as.native.fn = js_builtin_function_bind;
            value.as.native.user_data = &access->object;
            return js_eval_ok(value);
        }
        if (access->property && strcmp(access->property, "name") == 0)
        {
            const char *fn_name = js_function_name(access->object.as.function);
            js_value_t value;
            if (!js_value_make_cstring(&value, fn_name))
            {
                return js_eval_error("allocation failed");
            }
            return js_eval_ok(value);
        }
        if (access->property)
        {
            js_object_t *proto = js_get_function_proto(rt);
            if (proto)
            {
                js_value_t value = js_value_make_undefined_internal();
                char *err = NULL;
                if (!js_object_get_property(rt, proto, access->property, &value, &err))
                {
                    if (err)
                    {
                        js_eval_result_t res = js_eval_error(err);
                        free(err);
                        return res;
                    }
                    return js_eval_error("property lookup failed");
                }
                free(err);
                return js_eval_ok(value);
            }
        }
        return js_eval_ok(js_value_make_undefined_internal());
    }
    if (access->object.type == JS_VALUE_NATIVE_FN)
    {
        const char *native_name = js_value_native_name(rt, &access->object);
        if (access->property && strcmp(access->property, "prototype") == 0)
        {
            js_object_t *proto = NULL;
            if (access->object.as.native.fn == js_builtin_iterator)
            {
                proto = js_get_iterator_proto(rt);
            }
            else if (native_name && strcmp(native_name, "Object") == 0)
            {
                proto = js_get_object_proto(rt);
            }
            else if (native_name && strcmp(native_name, "Array") == 0)
            {
                proto = js_get_array_proto(rt);
            }
            else if (native_name && strcmp(native_name, "Function") == 0)
            {
                proto = js_get_function_proto(rt);
            }
            else if (native_name && strcmp(native_name, "Date") == 0)
            {
                proto = js_get_date_proto(rt);
            }
            else if (native_name && strcmp(native_name, "Number") == 0)
            {
                proto = js_get_number_proto(rt);
            }
            else if (native_name && strcmp(native_name, "Symbol") == 0)
            {
                proto = js_get_symbol_proto(rt);
            }
            else if (native_name && strcmp(native_name, "Duration") == 0)
            {
                proto = js_get_temporal_duration_proto(rt);
            }
            else if (native_name && strcmp(native_name, "Instant") == 0)
            {
                proto = js_get_temporal_instant_proto(rt);
            }
            else if (native_name && strcmp(native_name, "PlainDate") == 0)
            {
                proto = js_get_temporal_plain_date_proto(rt);
            }
            else if (native_name && strcmp(native_name, "PlainTime") == 0)
            {
                proto = js_get_temporal_plain_time_proto(rt);
            }
            else if (native_name && strcmp(native_name, "PlainDateTime") == 0)
            {
                proto = js_get_temporal_plain_date_time_proto(rt);
            }
            else if (native_name && strcmp(native_name, "ZonedDateTime") == 0)
            {
                proto = js_get_temporal_zoned_date_time_proto(rt);
            }
            else if (native_name && strcmp(native_name, "PlainYearMonth") == 0)
            {
                proto = js_get_temporal_plain_year_month_proto(rt);
            }
            else if (native_name && strcmp(native_name, "PlainMonthDay") == 0)
            {
                proto = js_get_temporal_plain_month_day_proto(rt);
            }
            if (proto)
            {
                js_value_t value;
                memset(&value, 0, sizeof(value));
                value.type = JS_VALUE_OBJECT;
                value.as.object = proto;
                js_object_retain(proto);
                return js_eval_ok(value);
            }
        }
        if (access->property && strcmp(access->property, "name") == 0 && native_name)
        {
            js_value_t value;
            if (!js_value_make_cstring(&value, native_name))
            {
                return js_eval_error("allocation failed");
            }
            return js_eval_ok(value);
        }
        if (access->property && strcmp(access->property, "call") == 0)
        {
            js_value_t value;
            memset(&value, 0, sizeof(value));
            value.type = JS_VALUE_NATIVE_FN;
            value.as.native.fn = js_builtin_function_call;
            value.as.native.user_data = &access->object;
            return js_eval_ok(value);
        }
        if (access->property && strcmp(access->property, "bind") == 0)
        {
            js_value_t value;
            memset(&value, 0, sizeof(value));
            value.type = JS_VALUE_NATIVE_FN;
            value.as.native.fn = js_builtin_function_bind;
            value.as.native.user_data = &access->object;
            return js_eval_ok(value);
        }
        if (native_name && access->property && strcmp(native_name, "Object") == 0 &&
            strcmp(access->property, "defineProperty") == 0)
        {
            js_value_t value;
            memset(&value, 0, sizeof(value));
            value.type = JS_VALUE_NATIVE_FN;
            value.as.native.fn = js_builtin_define_property;
            value.as.native.user_data = NULL;
            return js_eval_ok(value);
        }
        if (native_name && access->property && strcmp(native_name, "String") == 0 &&
            strcmp(access->property, "fromCharCode") == 0)
        {
            js_value_t value;
            memset(&value, 0, sizeof(value));
            value.type = JS_VALUE_NATIVE_FN;
            value.as.native.fn = js_builtin_string_from_char_code;
            value.as.native.user_data = NULL;
            return js_eval_ok(value);
        }
        if (native_name && access->property && strcmp(native_name, "Date") == 0)
        {
            js_native_fn_t fn = NULL;
            if (strcmp(access->property, "now") == 0)
            {
                fn = js_builtin_date_now;
            }
            else if (strcmp(access->property, "parse") == 0)
            {
                fn = js_builtin_date_parse;
            }
            else if (strcmp(access->property, "UTC") == 0)
            {
                fn = js_builtin_date_utc;
            }
            if (fn)
            {
                js_value_t value;
                memset(&value, 0, sizeof(value));
                value.type = JS_VALUE_NATIVE_FN;
                value.as.native.fn = fn;
                value.as.native.user_data = NULL;
                return js_eval_ok(value);
            }
        }
        if (native_name && access->property && strcmp(native_name, "Object") == 0 &&
            strcmp(access->property, "defineProperties") == 0)
        {
            js_value_t value;
            memset(&value, 0, sizeof(value));
            value.type = JS_VALUE_NATIVE_FN;
            value.as.native.fn = js_builtin_define_properties;
            value.as.native.user_data = NULL;
            return js_eval_ok(value);
        }
        if (native_name && access->property && strcmp(native_name, "Object") == 0 &&
            strcmp(access->property, "getPrototypeOf") == 0)
        {
            js_value_t value;
            memset(&value, 0, sizeof(value));
            value.type = JS_VALUE_NATIVE_FN;
            value.as.native.fn = js_builtin_object_get_prototype_of;
            value.as.native.user_data = NULL;
            return js_eval_ok(value);
        }
        if (native_name && access->property && strcmp(native_name, "Object") == 0 &&
            strcmp(access->property, "getOwnPropertyDescriptor") == 0)
        {
            js_value_t value;
            memset(&value, 0, sizeof(value));
            value.type = JS_VALUE_NATIVE_FN;
            value.as.native.fn = js_builtin_object_get_own_property_descriptor;
            value.as.native.user_data = NULL;
            return js_eval_ok(value);
        }
        if (native_name && access->property && strcmp(native_name, "Object") == 0 &&
            strcmp(access->property, "getOwnPropertyNames") == 0)
        {
            js_value_t value;
            memset(&value, 0, sizeof(value));
            value.type = JS_VALUE_NATIVE_FN;
            value.as.native.fn = js_builtin_object_get_own_property_names;
            value.as.native.user_data = NULL;
            return js_eval_ok(value);
        }
        if (native_name && access->property && strcmp(native_name, "Object") == 0 &&
            strcmp(access->property, "getOwnPropertyDescriptors") == 0)
        {
            js_value_t value;
            memset(&value, 0, sizeof(value));
            value.type = JS_VALUE_NATIVE_FN;
            value.as.native.fn = js_builtin_object_get_own_property_descriptors;
            value.as.native.user_data = NULL;
            return js_eval_ok(value);
        }
        if (native_name && access->property && strcmp(native_name, "Array") == 0 &&
            strcmp(access->property, "isArray") == 0)
        {
            js_value_t value;
            memset(&value, 0, sizeof(value));
            value.type = JS_VALUE_NATIVE_FN;
            value.as.native.fn = js_builtin_array_is_array;
            value.as.native.user_data = NULL;
            return js_eval_ok(value);
        }
        if (native_name && access->property && strcmp(native_name, "Symbol") == 0)
        {
            if (strcmp(access->property, "toPrimitive") == 0)
            {
                js_value_t value;
                if (!js_value_make_cstring(&value, "Symbol.toPrimitive"))
                {
                    return js_eval_error("allocation failed");
                }
                return js_eval_ok(value);
            }
            if (strcmp(access->property, "iterator") == 0)
            {
                js_value_t value;
                if (!js_value_make_cstring(&value, "Symbol.iterator"))
                {
                    return js_eval_error("allocation failed");
                }
                return js_eval_ok(value);
            }
            if (strcmp(access->property, "match") == 0)
            {
                js_value_t value;
                if (!js_value_make_cstring(&value, "Symbol.match"))
                {
                    return js_eval_error("allocation failed");
                }
                return js_eval_ok(value);
            }
            if (strcmp(access->property, "split") == 0)
            {
                js_value_t value;
                if (!js_value_make_cstring(&value, "Symbol.split"))
                {
                    return js_eval_error("allocation failed");
                }
                return js_eval_ok(value);
            }
            if (strcmp(access->property, "toStringTag") == 0)
            {
                js_value_t value;
                if (!js_value_make_cstring(&value, "Symbol.toStringTag"))
                {
                    return js_eval_error("allocation failed");
                }
                return js_eval_ok(value);
            }
            return js_eval_ok(js_value_make_undefined_internal());
        }
        if (access->property)
        {
            js_object_t *proto = js_get_function_proto(rt);
            if (proto)
            {
                js_value_t value = js_value_make_undefined_internal();
                char *err = NULL;
                if (!js_object_get_property(rt, proto, access->property, &value, &err))
                {
                    if (err)
                    {
                        js_eval_result_t res = js_eval_error(err);
                        free(err);
                        return res;
                    }
                    return js_eval_error("property lookup failed");
                }
                free(err);
                return js_eval_ok(value);
            }
        }
        return js_eval_ok(js_value_make_undefined_internal());
    }
    if (access->object.type == JS_VALUE_OBJECT)
    {
        js_value_t value = js_value_make_undefined_internal();
        char *err = NULL;
        if (!js_object_get_property(rt, access->object.as.object, access->property, &value, &err))
        {
            if (err)
            {
                js_eval_result_t res = js_eval_error(err);
                free(err);
                return res;
            }
            return js_eval_error("property lookup failed");
        }
        return js_eval_ok(value);
    }
    return js_eval_error("value is not indexable");
}

typedef struct
{
    char *name;
    bool owned;
} js_name_ref_t;

static bool js_name_list_push(js_name_ref_t **items,
                              size_t *count,
                              size_t *cap,
                              const char *name,
                              bool owned)
{
    if (!items || !count || !cap || !name)
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
        js_name_ref_t *next = (js_name_ref_t *)realloc(*items, new_cap * sizeof(*next));
        if (!next)
        {
            return false;
        }
        *items = next;
        *cap = new_cap;
    }
    (*items)[*count].name = (char *)name;
    (*items)[*count].owned = owned;
    (*count)++;
    return true;
}

static bool js_name_list_contains(const js_name_ref_t *items, size_t count, const char *name)
{
    if (!name)
    {
        return false;
    }
    for (size_t i = 0; i < count; ++i)
    {
        if (items[i].name && strcmp(items[i].name, name) == 0)
        {
            return true;
        }
    }
    return false;
}

static void js_name_list_destroy(js_name_ref_t *items, size_t count)
{
    if (!items)
    {
        return;
    }
    for (size_t i = 0; i < count; ++i)
    {
        if (items[i].owned)
        {
            free(items[i].name);
        }
    }
    free(items);
}

static bool js_parse_index_key(const char *text, size_t *out_index)
{
    if (!text || !*text || !out_index)
    {
        return false;
    }
    size_t value = 0;
    for (const char *p = text; *p; ++p)
    {
        if (!isdigit((unsigned char)*p))
        {
            return false;
        }
        size_t digit = (size_t)(*p - '0');
        if (value > (SIZE_MAX - digit) / 10u)
        {
            return false;
        }
        value = value * 10u + digit;
    }
    *out_index = value;
    return true;
}

static bool js_make_single_char_string(js_value_t *out, char c)
{
    if (!out)
    {
        return false;
    }
    char buf[2] = {c, '\0'};
    return js_value_make_string(out, buf, 1);
}

static bool js_binding_get_index_value(js_runtime_t *rt,
                                       const js_value_t *value,
                                       size_t index,
                                       js_value_t *out,
                                       char **error_message)
{
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    if (!value)
    {
        *out = js_value_make_undefined_internal();
        return true;
    }
    if (value->type == JS_VALUE_ARRAY)
    {
        char *err = NULL;
        if (!js_array_get_index_value(rt, value->as.array, index, out, &err))
        {
            if (err)
            {
                if (error_message)
                {
                    *error_message = err;
                }
                else
                {
                    free(err);
                }
                return false;
            }
            return false;
        }
        return true;
    }
    if (value->type == JS_VALUE_STRING)
    {
        if (index < value->as.string.len && value->as.string.data)
        {
            return js_make_single_char_string(out, value->as.string.data[index]);
        }
        *out = js_value_make_undefined_internal();
        return true;
    }
    if (value->type == JS_VALUE_OBJECT)
    {
        char key[32];
        int len = snprintf(key, sizeof(key), "%zu", index);
        if (len < 0 || (size_t)len >= sizeof(key))
        {
            *out = js_value_make_undefined_internal();
            return true;
        }
        return js_object_get_property(rt, value->as.object, key, out, error_message);
    }
    *out = js_value_make_undefined_internal();
    return true;
}

static bool js_binding_get_property_value(js_runtime_t *rt,
                                          const js_value_t *value,
                                          const char *name,
                                          js_value_t *out,
                                          char **error_message)
{
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    if (!value || !name)
    {
        *out = js_value_make_undefined_internal();
        return true;
    }
    if (value->type == JS_VALUE_OBJECT)
    {
        return js_object_get_property(rt, value->as.object, name, out, error_message);
    }
    if (value->type == JS_VALUE_ARRAY)
    {
        return js_array_get_property(rt, value->as.array, name, out, error_message);
    }
    if (value->type == JS_VALUE_STRING)
    {
        if (strcmp(name, "length") == 0)
        {
            *out = js_value_make_number((double)value->as.string.len);
            return true;
        }
        size_t index = 0;
        if (js_parse_index_key(name, &index) && index < value->as.string.len && value->as.string.data)
        {
            return js_make_single_char_string(out, value->as.string.data[index]);
        }
        *out = js_value_make_undefined_internal();
        return true;
    }
    *out = js_value_make_undefined_internal();
    return true;
}

static size_t js_binding_length(js_runtime_t *rt, const js_value_t *value)
{
    if (!value)
    {
        return 0;
    }
    if (value->type == JS_VALUE_ARRAY)
    {
        return value->as.array ? value->as.array->length : 0;
    }
    if (value->type == JS_VALUE_STRING)
    {
        return value->as.string.len;
    }
    if (value->type == JS_VALUE_OBJECT)
    {
        js_value_t len_value = js_value_make_undefined_internal();
        char *err = NULL;
        if (js_object_get_property(rt, value->as.object, "length", &len_value, &err))
        {
            size_t length = 0;
            if (js_value_to_array_length(&len_value, &length))
            {
                js_value_destroy(&len_value);
                free(err);
                return length;
            }
            js_value_destroy(&len_value);
        }
        free(err);
    }
    return 0;
}

static js_eval_result_t js_binding_apply(js_runtime_t *rt,
                                         js_env_t *env,
                                         const js_binding_t *binding,
                                         const js_value_t *value,
                                         bool is_decl,
                                         js_var_kind_t kind,
                                         bool allow_redeclare);

static js_eval_result_t js_binding_apply_identifier(js_env_t *env,
                                                    const char *name,
                                                    const js_value_t *value,
                                                    bool is_decl,
                                                    js_var_kind_t kind,
                                                    bool allow_redeclare)
{
    if (!env || !name)
    {
        return js_eval_error("invalid binding");
    }
    const js_value_t *use_value = value;
    js_value_t undef = js_value_make_undefined_internal();
    if (!use_value)
    {
        use_value = &undef;
    }
    if (is_decl)
    {
        if (kind == JS_VAR_VAR)
        {
            js_env_t *var_env = js_env_find_var_scope(env);
            if (!js_env_define_if_absent(var_env, name, &undef, false))
            {
                return js_eval_error("failed to define variable");
            }
            if (!js_env_assign(var_env, name, use_value))
            {
                return js_eval_error("assignment failed");
            }
            return js_eval_ok(js_value_make_undefined_internal());
        }
        bool is_const = (kind == JS_VAR_CONST);
        if (!js_env_define_local(env, name, use_value, is_const, allow_redeclare))
        {
            return js_eval_error("failed to define variable");
        }
        return js_eval_ok(js_value_make_undefined_internal());
    }
    if (!js_env_assign(env, name, use_value))
    {
        return js_eval_error("assignment failed");
    }
    return js_eval_ok(js_value_make_undefined_internal());
}

static js_eval_result_t js_binding_apply_array(js_runtime_t *rt,
                                               js_env_t *env,
                                               const js_binding_t *binding,
                                               const js_value_t *value,
                                               bool is_decl,
                                               js_var_kind_t kind,
                                               bool allow_redeclare)
{
    if (!binding || !env)
    {
        return js_eval_error("invalid binding");
    }
    if (!value || value->type == JS_VALUE_UNDEFINED || value->type == JS_VALUE_NULL)
    {
        return js_eval_error("TypeError: cannot destructure");
    }
    for (size_t i = 0; i < binding->as.array.count; ++i)
    {
        if (!binding->as.array.elements[i].binding)
        {
            continue;
        }
        js_value_t elem_value = js_value_make_undefined_internal();
        char *err = NULL;
        if (!js_binding_get_index_value(rt, value, i, &elem_value, &err))
        {
            js_eval_result_t res = js_eval_error(err ? err : "allocation failed");
            free(err);
            return res;
        }
        if (elem_value.type == JS_VALUE_UNDEFINED && binding->as.array.elements[i].init)
        {
            js_eval_result_t init_res = js_eval_expr(rt, env, binding->as.array.elements[i].init);
            js_value_destroy(&elem_value);
            if (!init_res.ok)
            {
                return init_res;
            }
            elem_value = init_res.value;
        }
        js_eval_result_t bind_res =
            js_binding_apply(rt,
                             env,
                             binding->as.array.elements[i].binding,
                             &elem_value,
                             is_decl,
                             kind,
                             allow_redeclare);
        js_value_destroy(&elem_value);
        if (!bind_res.ok)
        {
            return bind_res;
        }
        js_value_destroy(&bind_res.value);
    }

    if (binding->as.array.rest)
    {
        size_t length = js_binding_length(rt, value);
        size_t start = binding->as.array.count;
        js_value_t rest_value = js_value_make_undefined_internal();
        if (!js_value_make_array(&rest_value))
        {
            return js_eval_error("allocation failed");
        }
        for (size_t i = start; i < length; ++i)
        {
            js_value_t item = js_value_make_undefined_internal();
            char *err = NULL;
            if (!js_binding_get_index_value(rt, value, i, &item, &err))
            {
                js_value_destroy(&rest_value);
                js_eval_result_t res = js_eval_error(err ? err : "allocation failed");
                free(err);
                return res;
            }
            if (!js_value_array_push(&rest_value, &item))
            {
                js_value_destroy(&item);
                js_value_destroy(&rest_value);
                return js_eval_error("allocation failed");
            }
            js_value_destroy(&item);
        }
        js_eval_result_t bind_res =
            js_binding_apply(rt, env, binding->as.array.rest, &rest_value, is_decl, kind, allow_redeclare);
        js_value_destroy(&rest_value);
        if (!bind_res.ok)
        {
            return bind_res;
        }
        js_value_destroy(&bind_res.value);
    }
    return js_eval_ok(js_value_make_undefined_internal());
}

static bool js_binding_add_object_prop(js_runtime_t *rt,
                                       js_value_t *obj,
                                       const char *name,
                                       const js_value_t *value,
                                       char **error_message)
{
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!obj || obj->type != JS_VALUE_OBJECT || !name || !value)
    {
        return false;
    }
    return js_object_set_property(rt, obj->as.object, name, value, error_message);
}

static js_eval_result_t js_binding_apply_object(js_runtime_t *rt,
                                                js_env_t *env,
                                                const js_binding_t *binding,
                                                const js_value_t *value,
                                                bool is_decl,
                                                js_var_kind_t kind,
                                                bool allow_redeclare)
{
    if (!binding || !env)
    {
        return js_eval_error("invalid binding");
    }
    if (!value || value->type == JS_VALUE_UNDEFINED || value->type == JS_VALUE_NULL)
    {
        return js_eval_error("TypeError: cannot destructure");
    }
    js_name_ref_t *exclude = NULL;
    size_t exclude_count = 0;
    size_t exclude_cap = 0;

    for (size_t i = 0; i < binding->as.object.count; ++i)
    {
        const js_binding_property_t *prop = &binding->as.object.props[i];
        char *prop_name = NULL;
        bool owned = false;
        if (prop->computed)
        {
            js_eval_result_t key_res = js_eval_expr(rt, env, prop->name_expr);
            if (!key_res.ok)
            {
                js_name_list_destroy(exclude, exclude_count);
                return key_res;
            }
            char *key_err = NULL;
            if (!js_value_to_property_name(rt, &key_res.value, &prop_name, &key_err))
            {
                js_value_destroy(&key_res.value);
                js_name_list_destroy(exclude, exclude_count);
                js_eval_result_t res = js_eval_error(key_err ? key_err : "allocation failed");
                free(key_err);
                return res;
            }
            js_value_destroy(&key_res.value);
            owned = true;
        }
        else
        {
            prop_name = prop->name;
        }

        if (!js_name_list_push(&exclude, &exclude_count, &exclude_cap, prop_name, owned))
        {
            if (owned)
            {
                free(prop_name);
            }
            js_name_list_destroy(exclude, exclude_count);
            return js_eval_error("allocation failed");
        }

        js_value_t prop_value = js_value_make_undefined_internal();
        char *err = NULL;
        if (!js_binding_get_property_value(rt, value, prop_name, &prop_value, &err))
        {
            js_name_list_destroy(exclude, exclude_count);
            js_eval_result_t res = js_eval_error(err ? err : "allocation failed");
            free(err);
            return res;
        }
        if (prop_value.type == JS_VALUE_UNDEFINED && prop->init)
        {
            js_eval_result_t init_res = js_eval_expr(rt, env, prop->init);
            js_value_destroy(&prop_value);
            if (!init_res.ok)
            {
                js_name_list_destroy(exclude, exclude_count);
                return init_res;
            }
            prop_value = init_res.value;
        }

        js_eval_result_t bind_res =
            js_binding_apply(rt, env, prop->binding, &prop_value, is_decl, kind, allow_redeclare);
        js_value_destroy(&prop_value);
        if (!bind_res.ok)
        {
            js_name_list_destroy(exclude, exclude_count);
            return bind_res;
        }
        js_value_destroy(&bind_res.value);
    }

    if (binding->as.object.rest_name)
    {
        js_value_t rest_obj = js_value_make_undefined_internal();
        if (!js_value_make_host_object(&rest_obj, NULL, NULL, NULL, NULL))
        {
            js_name_list_destroy(exclude, exclude_count);
            return js_eval_error("allocation failed");
        }
        if (value->type == JS_VALUE_OBJECT && value->as.object)
        {
            for (js_property_t *prop = value->as.object->properties; prop; prop = prop->next)
            {
                if (!prop->name || js_name_list_contains(exclude, exclude_count, prop->name))
                {
                    continue;
                }
                char *err = NULL;
                if (!js_binding_add_object_prop(rt, &rest_obj, prop->name, &prop->value, &err))
                {
                    js_name_list_destroy(exclude, exclude_count);
                    js_value_destroy(&rest_obj);
                    js_eval_result_t res = js_eval_error(err ? err : "property set failed");
                    free(err);
                    return res;
                }
            }
        }
        else if (value->type == JS_VALUE_ARRAY && value->as.array)
        {
            for (size_t i = 0; i < value->as.array->length; ++i)
            {
                char key[32];
                int len = snprintf(key, sizeof(key), "%zu", i);
                if (len < 0 || (size_t)len >= sizeof(key))
                {
                    continue;
                }
                if (js_name_list_contains(exclude, exclude_count, key))
                {
                    continue;
                }
                js_value_t item = js_value_make_undefined_internal();
                char *item_err = NULL;
                if (!js_array_get_index_value(rt, value->as.array, i, &item, &item_err))
                {
                    js_name_list_destroy(exclude, exclude_count);
                    js_value_destroy(&rest_obj);
                    free(item_err);
                    return js_eval_error("allocation failed");
                }
                free(item_err);
                char *err = NULL;
                if (!js_binding_add_object_prop(rt, &rest_obj, key, &item, &err))
                {
                    js_value_destroy(&item);
                    js_name_list_destroy(exclude, exclude_count);
                    js_value_destroy(&rest_obj);
                    js_eval_result_t res = js_eval_error(err ? err : "property set failed");
                    free(err);
                    return res;
                }
                js_value_destroy(&item);
            }
            for (js_property_t *prop = value->as.array->properties; prop; prop = prop->next)
            {
                if (!prop->name || js_name_list_contains(exclude, exclude_count, prop->name))
                {
                    continue;
                }
                char *err = NULL;
                if (!js_binding_add_object_prop(rt, &rest_obj, prop->name, &prop->value, &err))
                {
                    js_name_list_destroy(exclude, exclude_count);
                    js_value_destroy(&rest_obj);
                    js_eval_result_t res = js_eval_error(err ? err : "property set failed");
                    free(err);
                    return res;
                }
            }
        }
        else if (value->type == JS_VALUE_STRING)
        {
            for (size_t i = 0; i < value->as.string.len; ++i)
            {
                char key[32];
                int len = snprintf(key, sizeof(key), "%zu", i);
                if (len < 0 || (size_t)len >= sizeof(key))
                {
                    continue;
                }
                if (js_name_list_contains(exclude, exclude_count, key))
                {
                    continue;
                }
                js_value_t item = js_value_make_undefined_internal();
                if (!js_make_single_char_string(&item, value->as.string.data[i]))
                {
                    js_name_list_destroy(exclude, exclude_count);
                    js_value_destroy(&rest_obj);
                    return js_eval_error("allocation failed");
                }
                char *err = NULL;
                if (!js_binding_add_object_prop(rt, &rest_obj, key, &item, &err))
                {
                    js_value_destroy(&item);
                    js_name_list_destroy(exclude, exclude_count);
                    js_value_destroy(&rest_obj);
                    js_eval_result_t res = js_eval_error(err ? err : "property set failed");
                    free(err);
                    return res;
                }
                js_value_destroy(&item);
            }
        }

        js_binding_t rest_binding;
        memset(&rest_binding, 0, sizeof(rest_binding));
        rest_binding.type = JS_BINDING_IDENTIFIER;
        rest_binding.as.ident.name = binding->as.object.rest_name;
        js_eval_result_t bind_res =
            js_binding_apply(rt, env, &rest_binding, &rest_obj, is_decl, kind, allow_redeclare);
        js_value_destroy(&rest_obj);
        if (!bind_res.ok)
        {
            js_name_list_destroy(exclude, exclude_count);
            return bind_res;
        }
        js_value_destroy(&bind_res.value);
    }

    js_name_list_destroy(exclude, exclude_count);
    return js_eval_ok(js_value_make_undefined_internal());
}

static js_eval_result_t js_binding_apply(js_runtime_t *rt,
                                         js_env_t *env,
                                         const js_binding_t *binding,
                                         const js_value_t *value,
                                         bool is_decl,
                                         js_var_kind_t kind,
                                         bool allow_redeclare)
{
    if (!binding)
    {
        return js_eval_ok(js_value_make_undefined_internal());
    }
    switch (binding->type)
    {
        case JS_BINDING_IDENTIFIER:
            return js_binding_apply_identifier(env,
                                               binding->as.ident.name,
                                               value,
                                               is_decl,
                                               kind,
                                               allow_redeclare);
        case JS_BINDING_ARRAY:
            return js_binding_apply_array(rt, env, binding, value, is_decl, kind, allow_redeclare);
        case JS_BINDING_OBJECT:
            return js_binding_apply_object(rt, env, binding, value, is_decl, kind, allow_redeclare);
    }
    return js_eval_ok(js_value_make_undefined_internal());
}

static js_eval_result_t js_assign_to_target(js_runtime_t *rt,
                                            js_env_t *env,
                                            const js_expr_t *target,
                                            const js_value_t *value)
{
    if (!target || !env || !value)
    {
        return js_eval_error("invalid assignment");
    }
    if (target->type == JS_EXPR_IDENTIFIER)
    {
        if (!js_env_assign(env, target->as.ident.name, value))
        {
            return js_eval_error("assignment failed");
        }
        return js_eval_ok(js_value_make_undefined_internal());
    }
    if (target->type != JS_EXPR_MEMBER)
    {
        return js_eval_error("invalid assignment target");
    }

    js_member_access_t access;
    js_eval_result_t access_res = js_eval_member_access(rt, env, &target->as.member, &access);
    if (!access_res.ok)
    {
        return access_res;
    }
    js_value_destroy(&access_res.value);

    if (access.is_length)
    {
        if (access.object.type != JS_VALUE_ARRAY)
        {
            js_member_access_release(&access);
            return js_eval_error("invalid assignment");
        }
        size_t new_length = 0;
        if (!js_value_to_array_length(value, &new_length))
        {
            js_member_access_release(&access);
            return js_eval_error("RangeError: invalid array length");
        }
        if (!js_array_set_length(access.object.as.array, new_length))
        {
            js_member_access_release(&access);
            return js_eval_error("allocation failed");
        }
        js_member_access_release(&access);
        return js_eval_ok(js_value_make_undefined_internal());
    }

    if (access.object.type == JS_VALUE_ARRAY)
    {
        if (access.has_index)
        {
            char *err = NULL;
            if (!js_array_set_index_value(rt, access.object.as.array, access.index, value, &err))
            {
                js_member_access_release(&access);
                if (err)
                {
                    js_eval_result_t res = js_eval_error(err);
                    free(err);
                    return res;
                }
                return js_eval_error("assignment failed");
            }
        }
        else if (access.property)
        {
            char *err = NULL;
            if (!js_array_set_named_property(rt, access.object.as.array, access.property, value, &err))
            {
                js_member_access_release(&access);
                if (err)
                {
                    js_eval_result_t res = js_eval_error(err);
                    free(err);
                    return res;
                }
                return js_eval_error("assignment failed");
            }
        }
        else
        {
            js_member_access_release(&access);
            return js_eval_error("invalid assignment");
        }
    }
    else if (access.object.type == JS_VALUE_OBJECT)
    {
        char *err = NULL;
        bool ok = js_object_set_property(rt, access.object.as.object, access.property, value, &err);
        if (!ok)
        {
            js_member_access_release(&access);
            if (err)
            {
                js_eval_result_t res = js_eval_error(err);
                free(err);
                return res;
            }
            return js_eval_error("assignment failed");
        }
    }
    else
    {
        js_member_access_release(&access);
        return js_eval_error("invalid assignment");
    }

    js_member_access_release(&access);
    return js_eval_ok(js_value_make_undefined_internal());
}

static js_eval_result_t js_for_in_fail(js_value_t *keys,
                                       size_t key_count,
                                       js_value_t *iterable,
                                       const char *message)
{
    if (keys)
    {
        for (size_t i = 0; i < key_count; ++i)
        {
            js_value_destroy(&keys[i]);
        }
        free(keys);
    }
    if (iterable)
    {
        js_value_destroy(iterable);
    }
    return js_eval_error(message);
}

static const js_function_decl_t *js_function_def(const js_function_t *fn)
{
    if (!fn)
    {
        return NULL;
    }
    return fn->is_expr ? (const js_function_decl_t *)fn->expr : fn->decl;
}

static js_eval_result_t js_eval_call_function(js_runtime_t *rt, js_function_t *fn, size_t argc, js_value_t *args)
{
    const js_function_decl_t *def = js_function_def(fn);
    if (!def)
    {
        return js_eval_error("invalid function");
    }
    js_env_t *call_env = js_env_create(fn->closure, true);
    if (!call_env)
    {
        return js_eval_error("allocation failed");
    }
    js_array_t *yield_array = NULL;
    js_array_t *prev_yield = NULL;
    size_t prev_yield_limit = 0;
    size_t prev_yield_count = 0;
    if (def->is_generator)
    {
        yield_array = js_array_create();
        if (!yield_array)
        {
            js_env_release(call_env);
            return js_eval_error("allocation failed");
        }
        if (rt)
        {
            prev_yield = rt->yield_array;
            prev_yield_limit = rt->yield_limit;
            prev_yield_count = rt->yield_count;
            rt->yield_array = yield_array;
            rt->yield_limit = 1u;
            rt->yield_count = 0u;
        }
    }
    if (fn->is_expr && def->name)
    {
        js_value_t self_value;
        memset(&self_value, 0, sizeof(self_value));
        self_value.type = JS_VALUE_FUNCTION;
        self_value.as.function = fn;
        if (!js_env_define_local(call_env, def->name, &self_value, true, false))
        {
            if (def->is_generator && rt)
            {
                rt->yield_array = prev_yield;
                rt->yield_limit = prev_yield_limit;
                rt->yield_count = prev_yield_count;
            }
            if (def->is_generator)
            {
                js_array_release(yield_array);
            }
            js_env_release(call_env);
            return js_eval_error("failed to bind function name");
        }
    }
    for (size_t i = 0; i < def->param_count; ++i)
    {
        const js_param_t *param = &def->params[i];
        js_value_t value = js_value_make_undefined_internal();
        bool value_owned = false;
        if (param->is_rest)
        {
            if (!js_value_make_array(&value))
            {
                if (def->is_generator && rt)
                {
                    rt->yield_array = prev_yield;
                rt->yield_limit = prev_yield_limit;
                rt->yield_count = prev_yield_count;
                }
                if (def->is_generator)
                {
                    js_array_release(yield_array);
                }
                js_env_release(call_env);
                return js_eval_error("allocation failed");
            }
            value_owned = true;
            for (size_t j = i; j < argc; ++j)
            {
                if (!js_value_array_push(&value, &args[j]))
                {
                    js_value_destroy(&value);
                    if (def->is_generator && rt)
                    {
                        rt->yield_array = prev_yield;
                rt->yield_limit = prev_yield_limit;
                rt->yield_count = prev_yield_count;
                    }
                    if (def->is_generator)
                    {
                        js_array_release(yield_array);
                    }
                    js_env_release(call_env);
                    return js_eval_error("allocation failed");
                }
            }
        }
        else if (i < argc)
        {
            if (!js_value_copy(&value, &args[i]))
            {
                if (def->is_generator && rt)
                {
                    rt->yield_array = prev_yield;
                rt->yield_limit = prev_yield_limit;
                rt->yield_count = prev_yield_count;
                }
                if (def->is_generator)
                {
                    js_array_release(yield_array);
                }
                js_env_release(call_env);
                return js_eval_error("allocation failed");
            }
            value_owned = true;
        }

        if (param->init && value.type == JS_VALUE_UNDEFINED)
        {
            if (value_owned)
            {
                js_value_destroy(&value);
            }
            js_eval_result_t init_res = js_eval_expr(rt, call_env, param->init);
            if (!init_res.ok)
            {
                if (def->is_generator && rt)
                {
                    rt->yield_array = prev_yield;
                rt->yield_limit = prev_yield_limit;
                rt->yield_count = prev_yield_count;
                }
                if (def->is_generator)
                {
                    js_array_release(yield_array);
                }
                js_env_release(call_env);
                return init_res;
            }
            value = init_res.value;
            value_owned = true;
        }

        js_eval_result_t bind_res =
            js_binding_apply(rt, call_env, param->binding, &value, true, JS_VAR_LET, true);
        if (value_owned)
        {
            js_value_destroy(&value);
        }
        if (!bind_res.ok)
        {
            if (def->is_generator && rt)
            {
                rt->yield_array = prev_yield;
                rt->yield_limit = prev_yield_limit;
                rt->yield_count = prev_yield_count;
            }
            if (def->is_generator)
            {
                js_array_release(yield_array);
            }
            js_env_release(call_env);
            return bind_res;
        }
        js_value_destroy(&bind_res.value);
        if (param->is_rest)
        {
            break;
        }
    }
    js_value_t args_array;
    if (!js_value_make_array(&args_array))
    {
        if (def->is_generator && rt)
        {
            rt->yield_array = prev_yield;
        }
        if (def->is_generator)
        {
            js_array_release(yield_array);
        }
        js_env_release(call_env);
        return js_eval_error("allocation failed");
    }
    for (size_t i = 0; i < argc; ++i)
    {
        if (!js_value_array_set(&args_array, i, &args[i]))
        {
            js_value_destroy(&args_array);
            if (def->is_generator && rt)
            {
                rt->yield_array = prev_yield;
                rt->yield_limit = prev_yield_limit;
                rt->yield_count = prev_yield_count;
            }
            if (def->is_generator)
            {
                js_array_release(yield_array);
            }
            js_env_release(call_env);
            return js_eval_error("allocation failed");
        }
    }
    if (!js_env_define_local(call_env, "arguments", &args_array, false, true))
    {
        js_value_destroy(&args_array);
        if (def->is_generator && rt)
        {
            rt->yield_array = prev_yield;
        }
        if (def->is_generator)
        {
            js_array_release(yield_array);
        }
        js_env_release(call_env);
        return js_eval_error("failed to bind arguments");
    }
    js_value_destroy(&args_array);
    if (!js_hoist_vars(call_env, def->body.stmts, def->body.count))
    {
        if (def->is_generator && rt)
        {
            rt->yield_array = prev_yield;
        }
        if (def->is_generator)
        {
            js_array_release(yield_array);
        }
        js_env_release(call_env);
        return js_eval_error("failed to hoist vars");
    }
    js_eval_result_t res = js_eval_statements(rt, call_env, def->body.stmts, def->body.count);
    if (def->is_generator && rt)
    {
        rt->yield_array = prev_yield;
    }
    js_env_release(call_env);
    if (def->is_generator)
    {
        if (!res.ok)
        {
            js_array_release(yield_array);
            return res;
        }
        js_value_destroy(&res.value);
        res.control = JS_CTRL_NONE;
        js_value_t map_val;
        memset(&map_val, 0, sizeof(map_val));
        map_val.type = JS_VALUE_NATIVE_FN;
        map_val.as.native.fn = js_builtin_iterator_map;
        map_val.as.native.user_data = NULL;
        if (!js_array_set_property(yield_array, "map", &map_val))
        {
            js_array_release(yield_array);
            return js_eval_error("allocation failed");
        }
        js_value_t out;
        memset(&out, 0, sizeof(out));
        out.type = JS_VALUE_ARRAY;
        out.as.array = yield_array;
        return js_eval_ok(out);
    }
    if (res.control == JS_CTRL_RETURN)
    {
        res.control = JS_CTRL_NONE;
        return res;
    }
    if (res.control != JS_CTRL_NONE)
    {
        js_value_destroy(&res.value);
        res.value = js_value_make_undefined_internal();
        return res;
    }
    js_value_destroy(&res.value);
    res.value = js_value_make_undefined_internal();
    return res;
}

static size_t js_function_length(const js_function_t *fn)
{
    const js_function_decl_t *def = js_function_def(fn);
    if (!def)
    {
        return 0;
    }
    size_t count = 0;
    for (size_t i = 0; i < def->param_count; ++i)
    {
        if (def->params[i].is_rest || def->params[i].init)
        {
            break;
        }
        count++;
    }
    return count;
}

static const char *js_function_name(const js_function_t *fn)
{
    const js_function_decl_t *def = js_function_def(fn);
    return (def && def->name) ? def->name : "";
}

bool js_native_needs_this(js_native_fn_t fn)
{
    return fn == js_builtin_iterator_map ||
           fn == js_builtin_array_join ||
           fn == js_builtin_array_push ||
           fn == js_builtin_array_map ||
           fn == js_builtin_object_has_own_property ||
           fn == js_builtin_object_property_is_enumerable ||
           fn == js_builtin_object_to_string ||
           fn == js_date_proto_to_string ||
           fn == js_date_proto_to_date_string ||
           fn == js_date_proto_to_time_string ||
           fn == js_date_proto_to_utc_string ||
           fn == js_date_proto_to_gmt_string ||
           fn == js_date_proto_to_iso_string ||
           fn == js_date_proto_to_json ||
           fn == js_date_proto_value_of ||
           fn == js_date_proto_get_time ||
           fn == js_date_proto_get_full_year ||
           fn == js_date_proto_get_utc_full_year ||
           fn == js_date_proto_get_month ||
           fn == js_date_proto_get_utc_month ||
           fn == js_date_proto_get_date ||
           fn == js_date_proto_get_utc_date ||
           fn == js_date_proto_get_day ||
           fn == js_date_proto_get_utc_day ||
           fn == js_date_proto_get_hours ||
           fn == js_date_proto_get_utc_hours ||
           fn == js_date_proto_get_minutes ||
           fn == js_date_proto_get_utc_minutes ||
           fn == js_date_proto_get_seconds ||
           fn == js_date_proto_get_utc_seconds ||
           fn == js_date_proto_get_milliseconds ||
           fn == js_date_proto_get_utc_milliseconds ||
           fn == js_date_proto_get_timezone_offset ||
           fn == js_date_proto_set_time ||
           fn == js_date_proto_set_full_year ||
           fn == js_date_proto_set_utc_full_year ||
           fn == js_date_proto_set_month ||
           fn == js_date_proto_set_utc_month ||
           fn == js_date_proto_set_date ||
           fn == js_date_proto_set_utc_date ||
           fn == js_date_proto_set_hours ||
           fn == js_date_proto_set_utc_hours ||
           fn == js_date_proto_set_minutes ||
           fn == js_date_proto_set_utc_minutes ||
           fn == js_date_proto_set_seconds ||
           fn == js_date_proto_set_utc_seconds ||
           fn == js_date_proto_set_milliseconds ||
           fn == js_date_proto_set_utc_milliseconds ||
           fn == js_date_proto_get_year ||
           fn == js_date_proto_set_year ||
           fn == js_temporal_duration_getter ||
           fn == js_temporal_duration_negated ||
           fn == js_temporal_duration_abs ||
           fn == js_temporal_duration_to_string ||
           fn == js_temporal_duration_to_json ||
           fn == js_temporal_duration_to_locale_string ||
           fn == js_temporal_duration_value_of ||
           fn == js_temporal_duration_with ||
           fn == js_temporal_duration_add ||
           fn == js_temporal_duration_subtract ||
           fn == js_temporal_duration_round ||
           fn == js_temporal_duration_total ||
           fn == js_temporal_instant_getter ||
           fn == js_temporal_instant_to_string ||
           fn == js_temporal_instant_to_json ||
           fn == js_temporal_instant_to_locale_string ||
           fn == js_temporal_instant_value_of ||
           fn == js_temporal_instant_add ||
           fn == js_temporal_instant_subtract ||
           fn == js_temporal_instant_since ||
           fn == js_temporal_instant_until ||
           fn == js_temporal_instant_round ||
           fn == js_temporal_instant_equals ||
           fn == js_temporal_instant_to_zoned_date_time_iso;
}

bool js_call_value(js_runtime_t *rt,
                   const js_value_t *callee,
                   size_t argc,
                   const js_value_t *argv,
                   js_value_t *out,
                   char **error_message)
{
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!rt || !callee || !out)
    {
        if (error_message)
        {
            *error_message = js_strdup("invalid call");
        }
        return false;
    }
    if (callee->type == JS_VALUE_NATIVE_FN)
    {
        return callee->as.native.fn(rt, argc, argv, callee->as.native.user_data, out, error_message);
    }
    if (callee->type == JS_VALUE_FUNCTION)
    {
        js_eval_result_t res = js_eval_call_function(rt, callee->as.function, argc, (js_value_t *)argv);
        if (res.ok)
        {
            *out = res.value;
            return true;
        }
        if (error_message)
        {
            *error_message = res.error_message ? res.error_message : js_strdup("call failed");
        }
        else
        {
            free(res.error_message);
        }
        js_value_destroy(&res.value);
        return false;
    }
    if (callee->type == JS_VALUE_OBJECT && callee->as.object)
    {
        js_value_t method = js_value_make_undefined_internal();
        char *err = NULL;
        if (js_object_get_property(rt, callee->as.object, "isTrue", &method, &err))
        {
            if (method.type == JS_VALUE_FUNCTION || method.type == JS_VALUE_NATIVE_FN)
            {
                bool ok = js_call_value(rt, &method, argc, argv, out, error_message);
                js_value_destroy(&method);
                return ok;
            }
        }
        js_value_destroy(&method);
        free(err);
    }
    if (error_message)
    {
        *error_message = js_strdup("value is not callable");
    }
    return false;
}

static js_eval_result_t js_eval_expr(js_runtime_t *rt, js_env_t *env, const js_expr_t *expr)
{
    if (!expr)
    {
        return js_eval_error("null expression");
    }
    switch (expr->type)
    {
        case JS_EXPR_LITERAL:
        {
            js_value_t copy;
            if (!js_value_copy(&copy, &expr->as.literal.value))
            {
                return js_eval_error("allocation failed");
            }
            return js_eval_ok(copy);
        }
        case JS_EXPR_TEMPLATE:
        {
            const js_template_expr_t *templ = &expr->as.template;
            char *joined = NULL;
            size_t joined_len = 0;
            size_t joined_cap = 0;
            if (templ->segment_count == 0)
            {
                js_value_t out;
                if (!js_value_make_cstring(&out, ""))
                {
                    return js_eval_error("allocation failed");
                }
                return js_eval_ok(out);
            }
            for (size_t i = 0; i < templ->segment_count; ++i)
            {
                const js_template_segment_t *seg = &templ->segments[i];
                if (!js_string_builder_append(&joined,
                                              &joined_len,
                                              &joined_cap,
                                              seg->data ? seg->data : "",
                                              seg->len))
                {
                    free(joined);
                    return js_eval_error("allocation failed");
                }
                if (i < templ->expr_count)
                {
                    js_eval_result_t expr_res = js_eval_expr(rt, env, templ->exprs[i]);
                    if (!expr_res.ok)
                    {
                        free(joined);
                        return expr_res;
                    }
                    js_temp_string_t temp = {0};
                    char *err = NULL;
                    if (!js_temp_string_from_value(rt, &expr_res.value, &temp, &err))
                    {
                        js_value_destroy(&expr_res.value);
                        free(joined);
                        if (err)
                        {
                            js_eval_result_t res = js_eval_error(err);
                            free(err);
                            return res;
                        }
                        return js_eval_error("allocation failed");
                    }
                    js_value_destroy(&expr_res.value);
                    if (!js_string_builder_append(&joined,
                                                  &joined_len,
                                                  &joined_cap,
                                                  temp.data ? temp.data : "",
                                                  temp.len))
                    {
                        js_temp_string_release(&temp);
                        free(joined);
                        return js_eval_error("allocation failed");
                    }
                    js_temp_string_release(&temp);
                }
            }
            if (!joined)
            {
                joined = js_strdup_len("", 0);
                if (!joined)
                {
                    return js_eval_error("allocation failed");
                }
            }
            js_value_t out;
            out.type = JS_VALUE_STRING;
            out.as.string.data = joined;
            out.as.string.len = joined_len;
            return js_eval_ok(out);
        }
        case JS_EXPR_IDENTIFIER:
        {
            js_value_t value;
            if (!js_env_get(env, expr->as.ident.name, &value))
            {
                return js_eval_error("unknown identifier");
            }
            return js_eval_ok(value);
        }
        case JS_EXPR_THIS:
        {
            if (!rt || !rt->global_object)
            {
                return js_eval_error("invalid this");
            }
            js_value_t value;
            memset(&value, 0, sizeof(value));
            value.type = JS_VALUE_OBJECT;
            value.as.object = rt->global_object;
            js_object_retain(value.as.object);
            return js_eval_ok(value);
        }
        case JS_EXPR_UNARY:
        {
            if (expr->as.unary.op == JS_UNARY_TYPEOF)
            {
                const js_expr_t *operand = expr->as.unary.expr;
                if (operand && operand->type == JS_EXPR_IDENTIFIER)
                {
                    js_value_t value;
                    if (!js_env_get(env, operand->as.ident.name, &value))
                    {
                        js_value_t out;
                        if (!js_value_make_cstring(&out, "undefined"))
                        {
                            return js_eval_error("allocation failed");
                        }
                        return js_eval_ok(out);
                    }
                    const char *type_name = js_typeof_name(&value);
                    js_value_destroy(&value);
                    js_value_t out;
                    if (!js_value_make_cstring(&out, type_name))
                    {
                        return js_eval_error("allocation failed");
                    }
                    return js_eval_ok(out);
                }
                js_eval_result_t right = js_eval_expr(rt, env, operand);
                if (!right.ok)
                {
                    return right;
                }
                const char *type_name = js_typeof_name(&right.value);
                js_value_destroy(&right.value);
                js_value_t out;
                if (!js_value_make_cstring(&out, type_name))
                {
                    return js_eval_error("allocation failed");
                }
                return js_eval_ok(out);
            }
            js_eval_result_t right = js_eval_expr(rt, env, expr->as.unary.expr);
            if (!right.ok)
            {
                return right;
            }
            js_value_t result = js_value_make_undefined_internal();
            if (expr->as.unary.op == JS_UNARY_NOT)
            {
                result = js_value_make_bool(!js_value_is_truthy(&right.value));
            }
            else
            {
                if (right.value.type == JS_VALUE_BIGINT)
                {
                    if (expr->as.unary.op == JS_UNARY_POSITIVE)
                    {
                        js_value_destroy(&right.value);
                        return js_eval_error("TypeError: cannot convert BigInt to number");
                    }
                    js_value_t zero_val;
                    if (!js_value_make_bigint_from_int64(&zero_val, 0))
                    {
                        js_value_destroy(&right.value);
                        return js_eval_error("allocation failed");
                    }
                    js_bigint_t *negated = js_bigint_sub(zero_val.as.bigint, right.value.as.bigint);
                    js_value_destroy(&zero_val);
                    if (!negated)
                    {
                        js_value_destroy(&right.value);
                        return js_eval_error("allocation failed");
                    }
                    result.type = JS_VALUE_BIGINT;
                    result.as.bigint = negated;
                }
                else
                {
                    bool ok = true;
                    double num = js_value_to_number(&right.value, &ok);
                    if (!ok || js_is_nan(num))
                    {
                        js_value_destroy(&right.value);
                        return js_eval_error("expected number");
                    }
                    if (expr->as.unary.op == JS_UNARY_NEGATE)
                    {
                        result = js_value_make_number(-num);
                    }
                    else
                    {
                        result = js_value_make_number(num);
                    }
                }
            }
            js_value_destroy(&right.value);
            return js_eval_ok(result);
        }
        case JS_EXPR_UPDATE:
        {
            js_expr_t *target = expr->as.update.target;
            js_value_t current = js_value_make_undefined_internal();
            js_member_access_t access;
            bool has_access = false;
            bool length_update = false;
            if (target->type == JS_EXPR_IDENTIFIER)
            {
                if (!js_env_get(env, target->as.ident.name, &current))
                {
                    return js_eval_error("unknown identifier");
                }
            }
            else if (target->type == JS_EXPR_MEMBER)
            {
                js_eval_result_t access_res = js_eval_member_access(rt, env, &target->as.member, &access);
                if (!access_res.ok)
                {
                    return access_res;
                }
                js_value_destroy(&access_res.value);
                if (access.is_length)
                {
                    if (access.object.type != JS_VALUE_ARRAY)
                    {
                        js_member_access_release(&access);
                        return js_eval_error("invalid assignment");
                    }
                    length_update = true;
                }
                js_eval_result_t cur_res = js_member_access_value(rt, &access);
                if (!cur_res.ok)
                {
                    js_member_access_release(&access);
                    return cur_res;
                }
                current = cur_res.value;
                has_access = true;
            }
            else
            {
                return js_eval_error("invalid assignment target");
            }

            js_value_t new_value = js_value_make_undefined_internal();
            if (current.type == JS_VALUE_BIGINT)
            {
                js_value_t one_value = js_value_make_undefined_internal();
                if (!js_value_make_bigint_from_int64(&one_value, 1))
                {
                    if (has_access)
                    {
                        js_member_access_release(&access);
                    }
                    js_value_destroy(&current);
                    return js_eval_error("allocation failed");
                }
                js_bigint_t *updated = expr->as.update.is_increment
                    ? js_bigint_add(current.as.bigint, one_value.as.bigint)
                    : js_bigint_sub(current.as.bigint, one_value.as.bigint);
                js_value_destroy(&one_value);
                if (!updated)
                {
                    if (has_access)
                    {
                        js_member_access_release(&access);
                    }
                    js_value_destroy(&current);
                    return js_eval_error("allocation failed");
                }
                new_value.type = JS_VALUE_BIGINT;
                new_value.as.bigint = updated;
            }
            else
            {
                bool ok_num = true;
                double num = js_value_to_number(&current, &ok_num);
                if (!ok_num || js_is_nan(num))
                {
                    if (has_access)
                    {
                        js_member_access_release(&access);
                    }
                    js_value_destroy(&current);
                    return js_eval_error("expected number");
                }
                double new_num = expr->as.update.is_increment ? (num + 1.0) : (num - 1.0);
                new_value = js_value_make_number(new_num);
            }

            bool assigned_ok = false;
            if (target->type == JS_EXPR_IDENTIFIER)
            {
                assigned_ok = js_env_assign(env, target->as.ident.name, &new_value);
            }
            else if (has_access)
            {
                if (length_update)
                {
                    size_t new_length = 0;
                    if (!js_value_to_array_length(&new_value, &new_length))
                    {
                        js_member_access_release(&access);
                        js_value_destroy(&new_value);
                        js_value_destroy(&current);
                        return js_eval_error("RangeError: invalid array length");
                    }
                    if (!js_array_set_length(access.object.as.array, new_length))
                    {
                        js_member_access_release(&access);
                        js_value_destroy(&new_value);
                        js_value_destroy(&current);
                        return js_eval_error("allocation failed");
                    }
                    assigned_ok = true;
                }
                else if (access.object.type == JS_VALUE_ARRAY)
                {
                    char *err = NULL;
                    if (access.has_index)
                    {
                        assigned_ok = js_array_set_index_value(rt, access.object.as.array, access.index, &new_value, &err);
                    }
                    else if (access.property)
                    {
                        assigned_ok = js_array_set_named_property(rt, access.object.as.array, access.property, &new_value, &err);
                    }
                    if (!assigned_ok && err)
                    {
                        js_member_access_release(&access);
                        js_value_destroy(&current);
                        js_value_destroy(&new_value);
                        js_eval_result_t res = js_eval_error(err);
                        free(err);
                        return res;
                    }
                    free(err);
                }
                else if (access.object.type == JS_VALUE_OBJECT)
                {
                    char *err = NULL;
                    assigned_ok = js_object_set_property(rt, access.object.as.object, access.property, &new_value, &err);
                    free(err);
                }
            }

            if (!assigned_ok)
            {
                if (has_access)
                {
                    js_member_access_release(&access);
                }
                js_value_destroy(&current);
                return js_eval_error("assignment failed");
            }

            js_value_t result = js_value_make_undefined_internal();
            if (expr->as.update.is_prefix)
            {
                result = new_value;
            }
            else
            {
                if (!js_value_copy(&result, &current))
                {
                    js_value_destroy(&new_value);
                    if (has_access)
                    {
                        js_member_access_release(&access);
                    }
                    js_value_destroy(&current);
                    return js_eval_error("allocation failed");
                }
                js_value_destroy(&new_value);
            }
            if (has_access)
            {
                js_member_access_release(&access);
            }
            js_value_destroy(&current);
            return js_eval_ok(result);
        }
        case JS_EXPR_BINARY:
        {
            js_binary_op_t op = expr->as.binary.op;
            if (op == JS_BINARY_AND || op == JS_BINARY_OR)
            {
                js_eval_result_t left = js_eval_expr(rt, env, expr->as.binary.left);
                if (!left.ok)
                {
                    return left;
                }
                bool truthy = js_value_is_truthy(&left.value);
                if ((op == JS_BINARY_AND && !truthy) || (op == JS_BINARY_OR && truthy))
                {
                    js_value_t out;
                    if (!js_value_copy(&out, &left.value))
                    {
                        js_value_destroy(&left.value);
                        return js_eval_error("allocation failed");
                    }
                    js_value_destroy(&left.value);
                    return js_eval_ok(out);
                }
                js_value_destroy(&left.value);
                return js_eval_expr(rt, env, expr->as.binary.right);
            }

            js_eval_result_t left = js_eval_expr(rt, env, expr->as.binary.left);
            if (!left.ok)
            {
                return left;
            }
            js_eval_result_t right = js_eval_expr(rt, env, expr->as.binary.right);
            if (!right.ok)
            {
                js_value_destroy(&left.value);
                return right;
            }
            js_value_t result = js_value_make_undefined_internal();

            if (op == JS_BINARY_ADD)
            {
                js_eval_result_t add_res = js_eval_add_values(rt, &left.value, &right.value);
                js_value_destroy(&left.value);
                js_value_destroy(&right.value);
                return add_res;
            }
            else if (op == JS_BINARY_SUB || op == JS_BINARY_MUL || op == JS_BINARY_DIV || op == JS_BINARY_MOD)
            {
                if (left.value.type == JS_VALUE_BIGINT || right.value.type == JS_VALUE_BIGINT)
                {
                    if (left.value.type != JS_VALUE_BIGINT || right.value.type != JS_VALUE_BIGINT)
                    {
                        js_value_destroy(&left.value);
                        js_value_destroy(&right.value);
                        return js_eval_error("TypeError: cannot mix BigInt and other types");
                    }
                    js_bigint_t *big_result = NULL;
                    if (op == JS_BINARY_SUB)
                    {
                        big_result = js_bigint_sub(left.value.as.bigint, right.value.as.bigint);
                    }
                    else if (op == JS_BINARY_MUL)
                    {
                        big_result = js_bigint_mul(left.value.as.bigint, right.value.as.bigint);
                    }
                    else
                    {
                        js_bigint_t *quot = NULL;
                        js_bigint_t *rem = NULL;
                        char *err = NULL;
                        bool ok = js_bigint_divmod(left.value.as.bigint, right.value.as.bigint, &quot, &rem, &err);
                        if (!ok)
                        {
                            js_value_destroy(&left.value);
                            js_value_destroy(&right.value);
                            if (err)
                            {
                                js_eval_result_t res = js_eval_error(err);
                                free(err);
                                return res;
                            }
                            return js_eval_error("division failed");
                        }
                        if (op == JS_BINARY_DIV)
                        {
                            big_result = quot;
                            js_bigint_destroy(rem);
                        }
                        else
                        {
                            big_result = rem;
                            js_bigint_destroy(quot);
                        }
                    }
                    if (!big_result)
                    {
                        js_value_destroy(&left.value);
                        js_value_destroy(&right.value);
                        return js_eval_error("allocation failed");
                    }
                    result.type = JS_VALUE_BIGINT;
                    result.as.bigint = big_result;
                }
                else
                {
                    bool ok_left = true;
                    bool ok_right = true;
                    double ln = js_value_to_number(&left.value, &ok_left);
                    double rn = js_value_to_number(&right.value, &ok_right);
                    if (!ok_left || !ok_right || js_is_nan(ln) || js_is_nan(rn))
                    {
                        js_value_destroy(&left.value);
                        js_value_destroy(&right.value);
                        return js_eval_error("expected number");
                    }
                    if (op == JS_BINARY_SUB)
                    {
                        result = js_value_make_number(ln - rn);
                    }
                    else if (op == JS_BINARY_MUL)
                    {
                        result = js_value_make_number(ln * rn);
                    }
                    else if (op == JS_BINARY_DIV)
                    {
                        result = js_value_make_number(ln / rn);
                    }
                    else
                    {
                        double quotient = ln / rn;
                        result = js_value_make_number(ln - js_trunc(quotient) * rn);
                    }
                }
            }
            else if (op == JS_BINARY_EXP)
            {
                if (left.value.type == JS_VALUE_BIGINT || right.value.type == JS_VALUE_BIGINT)
                {
                    if (left.value.type != JS_VALUE_BIGINT || right.value.type != JS_VALUE_BIGINT)
                    {
                        js_value_destroy(&left.value);
                        js_value_destroy(&right.value);
                        return js_eval_error("TypeError: cannot mix BigInt and other types");
                    }
                    char *err = NULL;
                    js_bigint_t *pow_val = js_bigint_pow(left.value.as.bigint, right.value.as.bigint, &err);
                    if (!pow_val)
                    {
                        js_value_destroy(&left.value);
                        js_value_destroy(&right.value);
                        if (err)
                        {
                            js_eval_result_t res = js_eval_error(err);
                            free(err);
                            return res;
                        }
                        return js_eval_error("pow failed");
                    }
                    result.type = JS_VALUE_BIGINT;
                    result.as.bigint = pow_val;
                }
                else
                {
                    bool ok_left = true;
                    bool ok_right = true;
                    double ln = js_value_to_number(&left.value, &ok_left);
                    double rn = js_value_to_number(&right.value, &ok_right);
                    if (!ok_left || !ok_right || js_is_nan(ln) || js_is_nan(rn))
                    {
                        js_value_destroy(&left.value);
                        js_value_destroy(&right.value);
                        return js_eval_error("expected number");
                    }
                    result = js_value_make_number(pow(ln, rn));
                }
            }
            else if (op == JS_BINARY_INSTANCEOF)
            {
                if (right.value.type != JS_VALUE_NATIVE_FN)
                {
                    js_value_destroy(&left.value);
                    js_value_destroy(&right.value);
                    return js_eval_error("TypeError: right-hand side of instanceof is not callable");
                }
                if (left.value.type != JS_VALUE_OBJECT || !left.value.as.object)
                {
                    result = js_value_make_bool(false);
                }
                else
                {
                    js_object_t *proto = NULL;
                    const char *native_name = js_value_native_name(rt, &right.value);
                    if (right.value.as.native.fn == js_builtin_iterator)
                    {
                        proto = js_get_iterator_proto(rt);
                    }
                    else if (native_name && strcmp(native_name, "Object") == 0)
                    {
                        proto = js_get_object_proto(rt);
                    }
                    else if (native_name && strcmp(native_name, "Array") == 0)
                    {
                        proto = js_get_array_proto(rt);
                    }
                    else if (native_name && strcmp(native_name, "Function") == 0)
                    {
                        proto = js_get_function_proto(rt);
                    }
                    else if (native_name && strcmp(native_name, "Date") == 0)
                    {
                        proto = js_get_date_proto(rt);
                    }
                    else if (native_name && strcmp(native_name, "Number") == 0)
                    {
                        proto = js_get_number_proto(rt);
                    }
                    else if (native_name && strcmp(native_name, "Symbol") == 0)
                    {
                        proto = js_get_symbol_proto(rt);
                    }
                    else if (native_name && strcmp(native_name, "Duration") == 0)
                    {
                        proto = js_get_temporal_duration_proto(rt);
                    }
                    else if (native_name && strcmp(native_name, "Instant") == 0)
                    {
                        proto = js_get_temporal_instant_proto(rt);
                    }
                    else if (native_name && strcmp(native_name, "PlainDate") == 0)
                    {
                        proto = js_get_temporal_plain_date_proto(rt);
                    }
                    else if (native_name && strcmp(native_name, "PlainTime") == 0)
                    {
                        proto = js_get_temporal_plain_time_proto(rt);
                    }
                    else if (native_name && strcmp(native_name, "PlainDateTime") == 0)
                    {
                        proto = js_get_temporal_plain_date_time_proto(rt);
                    }
                    else if (native_name && strcmp(native_name, "ZonedDateTime") == 0)
                    {
                        proto = js_get_temporal_zoned_date_time_proto(rt);
                    }
                    else if (native_name && strcmp(native_name, "PlainYearMonth") == 0)
                    {
                        proto = js_get_temporal_plain_year_month_proto(rt);
                    }
                    else if (native_name && strcmp(native_name, "PlainMonthDay") == 0)
                    {
                        proto = js_get_temporal_plain_month_day_proto(rt);
                    }
                    if (!proto)
                    {
                        js_value_destroy(&left.value);
                        js_value_destroy(&right.value);
                        return js_eval_error("TypeError: invalid prototype");
                    }
                    js_object_t *cursor = left.value.as.object;
                    bool found = false;
                    while (cursor)
                    {
                        js_value_t proto_val = js_value_make_undefined_internal();
                        if (!js_object_get_slot(cursor, "__proto__", &proto_val))
                        {
                            break;
                        }
                        if (proto_val.type == JS_VALUE_OBJECT && proto_val.as.object == proto)
                        {
                            found = true;
                            js_value_destroy(&proto_val);
                            break;
                        }
                        if (proto_val.type != JS_VALUE_OBJECT || !proto_val.as.object)
                        {
                            js_value_destroy(&proto_val);
                            break;
                        }
                        cursor = proto_val.as.object;
                        js_value_destroy(&proto_val);
                    }
                    result = js_value_make_bool(found);
                }
            }
            else if (op == JS_BINARY_EQ || op == JS_BINARY_NEQ || op == JS_BINARY_STRICT_EQ || op == JS_BINARY_STRICT_NEQ)
            {
                bool equal = false;
                if (op == JS_BINARY_EQ || op == JS_BINARY_NEQ)
                {
                    equal = js_value_loose_equal(&left.value, &right.value);
                }
                else
                {
                    equal = js_value_strict_equal(&left.value, &right.value);
                }
                if (op == JS_BINARY_NEQ || op == JS_BINARY_STRICT_NEQ)
                {
                    equal = !equal;
                }
                result = js_value_make_bool(equal);
            }
            else
            {
                bool cmp = false;
                if (left.value.type == JS_VALUE_BIGINT || right.value.type == JS_VALUE_BIGINT)
                {
                    if (left.value.type == JS_VALUE_BIGINT && right.value.type == JS_VALUE_BIGINT)
                    {
                        int ord = js_bigint_compare(left.value.as.bigint, right.value.as.bigint);
                        switch (op)
                        {
                            case JS_BINARY_LT: cmp = ord < 0; break;
                            case JS_BINARY_LTE: cmp = ord <= 0; break;
                            case JS_BINARY_GT: cmp = ord > 0; break;
                            case JS_BINARY_GTE: cmp = ord >= 0; break;
                            default: cmp = false; break;
                        }
                    }
                    else
                    {
                        bool ok_left = true;
                        bool ok_right = true;
                        double ln = js_value_to_number(&left.value, &ok_left);
                        double rn = js_value_to_number(&right.value, &ok_right);
                        if (!ok_left || !ok_right || js_is_nan(ln) || js_is_nan(rn))
                        {
                            js_value_destroy(&left.value);
                            js_value_destroy(&right.value);
                            return js_eval_error("expected number");
                        }
                        switch (op)
                        {
                            case JS_BINARY_LT: cmp = ln < rn; break;
                            case JS_BINARY_LTE: cmp = ln <= rn; break;
                            case JS_BINARY_GT: cmp = ln > rn; break;
                            case JS_BINARY_GTE: cmp = ln >= rn; break;
                            default: cmp = false; break;
                        }
                    }
                }
                else if (left.value.type == JS_VALUE_STRING && right.value.type == JS_VALUE_STRING)
                {
                    int ord = strcmp(left.value.as.string.data ? left.value.as.string.data : "",
                                     right.value.as.string.data ? right.value.as.string.data : "");
                    switch (op)
                    {
                        case JS_BINARY_LT: cmp = ord < 0; break;
                        case JS_BINARY_LTE: cmp = ord <= 0; break;
                        case JS_BINARY_GT: cmp = ord > 0; break;
                        case JS_BINARY_GTE: cmp = ord >= 0; break;
                        default: cmp = false; break;
                    }
                }
                else
                {
                    bool ok_left = true;
                    bool ok_right = true;
                    double ln = js_value_to_number(&left.value, &ok_left);
                    double rn = js_value_to_number(&right.value, &ok_right);
                    if (!ok_left || !ok_right || js_is_nan(ln) || js_is_nan(rn))
                    {
                        js_value_destroy(&left.value);
                        js_value_destroy(&right.value);
                        return js_eval_error("expected number");
                    }
                    switch (op)
                    {
                        case JS_BINARY_LT: cmp = ln < rn; break;
                        case JS_BINARY_LTE: cmp = ln <= rn; break;
                        case JS_BINARY_GT: cmp = ln > rn; break;
                        case JS_BINARY_GTE: cmp = ln >= rn; break;
                        default: cmp = false; break;
                    }
                }
                result = js_value_make_bool(cmp);
            }
            js_value_destroy(&left.value);
            js_value_destroy(&right.value);
            return js_eval_ok(result);
        }
        case JS_EXPR_ASSIGN:
        {
            js_expr_t *target = expr->as.assign.target;
            js_eval_result_t rhs = js_eval_expr(rt, env, expr->as.assign.value);
            if (!rhs.ok)
            {
                return rhs;
            }

            if (expr->as.assign.op == JS_ASSIGN_ADD && target->type == JS_EXPR_MEMBER)
            {
                js_member_access_t access;
                js_eval_result_t access_res = js_eval_member_access(rt, env, &target->as.member, &access);
                if (!access_res.ok)
                {
                    js_value_destroy(&rhs.value);
                    return access_res;
                }
                js_value_destroy(&access_res.value);
                if (access.is_length)
                {
                    if (access.object.type != JS_VALUE_ARRAY)
                    {
                        js_member_access_release(&access);
                        js_value_destroy(&rhs.value);
                        return js_eval_error("invalid assignment");
                    }
                }
                js_eval_result_t current = js_member_access_value(rt, &access);
                if (!current.ok)
                {
                    js_member_access_release(&access);
                    js_value_destroy(&rhs.value);
                    return current;
                }
                js_eval_result_t add_res = js_eval_add_values(rt, &current.value, &rhs.value);
                js_value_destroy(&current.value);
                js_value_destroy(&rhs.value);
                if (!add_res.ok)
                {
                    js_member_access_release(&access);
                    return add_res;
                }
                if (access.is_length)
                {
                    size_t new_length = 0;
                    if (!js_value_to_array_length(&add_res.value, &new_length))
                    {
                        js_member_access_release(&access);
                        js_value_destroy(&add_res.value);
                        return js_eval_error("RangeError: invalid array length");
                    }
                    if (!js_array_set_length(access.object.as.array, new_length))
                    {
                        js_member_access_release(&access);
                        js_value_destroy(&add_res.value);
                        return js_eval_error("allocation failed");
                    }
                    js_member_access_release(&access);
                    return add_res;
                }
                if (access.object.type == JS_VALUE_ARRAY)
                {
                    char *err = NULL;
                    if (access.has_index)
                    {
                        if (!js_array_set_index_value(rt, access.object.as.array, access.index, &add_res.value, &err))
                        {
                            js_member_access_release(&access);
                            js_value_destroy(&add_res.value);
                            if (err)
                            {
                                js_eval_result_t res = js_eval_error(err);
                                free(err);
                                return res;
                            }
                            return js_eval_error("assignment failed");
                        }
                    }
                    else if (access.property)
                    {
                        if (!js_array_set_named_property(rt, access.object.as.array, access.property, &add_res.value, &err))
                        {
                            js_member_access_release(&access);
                            js_value_destroy(&add_res.value);
                            if (err)
                            {
                                js_eval_result_t res = js_eval_error(err);
                                free(err);
                                return res;
                            }
                            return js_eval_error("assignment failed");
                        }
                    }
                    else
                    {
                        js_member_access_release(&access);
                        js_value_destroy(&add_res.value);
                        free(err);
                        return js_eval_error("invalid assignment");
                    }
                    free(err);
                }
                else if (access.object.type == JS_VALUE_OBJECT)
                {
                    char *err = NULL;
                    bool ok = js_object_set_property(rt, access.object.as.object, access.property, &add_res.value, &err);
                    if (!ok)
                    {
                        js_member_access_release(&access);
                        js_value_destroy(&add_res.value);
                        if (err)
                        {
                            js_eval_result_t res = js_eval_error(err);
                            free(err);
                            return res;
                        }
                        return js_eval_error("assignment failed");
                    }
                }
                else
                {
                    js_member_access_release(&access);
                    js_value_destroy(&add_res.value);
                    return js_eval_error("invalid assignment");
                }
                js_member_access_release(&access);
                return add_res;
            }

            js_eval_result_t assigned = rhs;
            if (expr->as.assign.op == JS_ASSIGN_ADD)
            {
                if (target->type != JS_EXPR_IDENTIFIER)
                {
                    js_value_destroy(&rhs.value);
                    return js_eval_error("invalid assignment target");
                }
                js_value_t current;
                if (!js_env_get(env, target->as.ident.name, &current))
                {
                    js_value_destroy(&rhs.value);
                    return js_eval_error("unknown identifier");
                }
                js_eval_result_t add_res = js_eval_add_values(rt, &current, &rhs.value);
                js_value_destroy(&current);
                js_value_destroy(&rhs.value);
                if (!add_res.ok)
                {
                    return add_res;
                }
                assigned = add_res;
            }

            if (target->type == JS_EXPR_IDENTIFIER)
            {
                if (!js_env_assign(env, target->as.ident.name, &assigned.value))
                {
                    js_value_destroy(&assigned.value);
                    return js_eval_error("assignment failed");
                }
                return assigned;
            }
            if (target->type == JS_EXPR_MEMBER)
            {
                js_member_access_t access;
                js_eval_result_t access_res = js_eval_member_access(rt, env, &target->as.member, &access);
                if (!access_res.ok)
                {
                    js_value_destroy(&assigned.value);
                    return access_res;
                }
                js_value_destroy(&access_res.value);
                if (access.is_length)
                {
                    if (access.object.type != JS_VALUE_ARRAY)
                    {
                        js_member_access_release(&access);
                        js_value_destroy(&assigned.value);
                        return js_eval_error("invalid assignment");
                    }
                }
                if (access.is_length)
                {
                    size_t new_length = 0;
                    if (!js_value_to_array_length(&assigned.value, &new_length))
                    {
                        js_member_access_release(&access);
                        js_value_destroy(&assigned.value);
                        return js_eval_error("RangeError: invalid array length");
                    }
                    if (!js_array_set_length(access.object.as.array, new_length))
                    {
                        js_member_access_release(&access);
                        js_value_destroy(&assigned.value);
                        return js_eval_error("allocation failed");
                    }
                }
                else if (access.object.type == JS_VALUE_ARRAY)
                {
                    char *err = NULL;
                    if (access.has_index)
                    {
                        if (!js_array_set_index_value(rt, access.object.as.array, access.index, &assigned.value, &err))
                        {
                            js_member_access_release(&access);
                            js_value_destroy(&assigned.value);
                            if (err)
                            {
                                js_eval_result_t res = js_eval_error(err);
                                free(err);
                                return res;
                            }
                            return js_eval_error("assignment failed");
                        }
                    }
                    else if (access.property)
                    {
                        if (!js_array_set_named_property(rt, access.object.as.array, access.property, &assigned.value, &err))
                        {
                            js_member_access_release(&access);
                            js_value_destroy(&assigned.value);
                            if (err)
                            {
                                js_eval_result_t res = js_eval_error(err);
                                free(err);
                                return res;
                            }
                            return js_eval_error("assignment failed");
                        }
                    }
                    else
                    {
                        js_member_access_release(&access);
                        js_value_destroy(&assigned.value);
                        free(err);
                        return js_eval_error("invalid assignment");
                    }
                    free(err);
                }
                else if (access.object.type == JS_VALUE_OBJECT)
                {
                    char *err = NULL;
                    bool ok = js_object_set_property(rt, access.object.as.object, access.property, &assigned.value, &err);
                    if (!ok)
                    {
                        js_member_access_release(&access);
                        js_value_destroy(&assigned.value);
                        if (err)
                        {
                            js_eval_result_t res = js_eval_error(err);
                            free(err);
                            return res;
                        }
                        return js_eval_error("assignment failed");
                    }
                }
                else
                {
                    js_member_access_release(&access);
                    js_value_destroy(&assigned.value);
                    return js_eval_error("invalid assignment");
                }
                js_member_access_release(&access);
                return assigned;
            }
            js_value_destroy(&assigned.value);
            return js_eval_error("invalid assignment target");
        }
        case JS_EXPR_NEW:
        {
            js_eval_result_t callee_res = js_eval_expr(rt, env, expr->as.new_expr.callee);
            if (!callee_res.ok)
            {
                return callee_res;
            }
            js_value_t callee = callee_res.value;
            size_t argc = expr->as.new_expr.arg_count;
            js_value_t *args = NULL;
            if (argc)
            {
                args = (js_value_t *)calloc(argc, sizeof(*args));
                if (!args)
                {
                    js_value_destroy(&callee);
                    return js_eval_error("allocation failed");
                }
            }
            for (size_t i = 0; i < argc; ++i)
            {
                js_eval_result_t arg = js_eval_expr(rt, env, expr->as.new_expr.args[i]);
                if (!arg.ok)
                {
                    for (size_t j = 0; j < i; ++j)
                    {
                        js_value_destroy(&args[j]);
                    }
                    free(args);
                    js_value_destroy(&callee);
                    return arg;
                }
                args[i] = arg.value;
            }

            if (!js_value_is_constructor(rt, &callee))
            {
                for (size_t i = 0; i < argc; ++i)
                {
                    js_value_destroy(&args[i]);
                }
                free(args);
                js_value_destroy(&callee);
                return js_eval_error("TypeError: not a constructor");
            }

            js_value_t out = js_value_make_undefined_internal();
            char *err = NULL;
            bool prev_constructing = rt->constructing;
            js_native_fn_t prev_constructing_fn = rt->constructing_fn;
            rt->constructing = true;
            rt->constructing_fn =
                (callee.type == JS_VALUE_NATIVE_FN) ? callee.as.native.fn : NULL;
            bool ok = js_call_value(rt, &callee, argc, args, &out, &err);
            rt->constructing = prev_constructing;
            rt->constructing_fn = prev_constructing_fn;
            for (size_t i = 0; i < argc; ++i)
            {
                js_value_destroy(&args[i]);
            }
            free(args);
            js_value_destroy(&callee);
            if (!ok)
            {
                if (err)
                {
                    js_eval_result_t res = js_eval_error(err);
                    free(err);
                    return res;
                }
                return js_eval_error("constructor failed");
            }

            if (out.type == JS_VALUE_OBJECT ||
                out.type == JS_VALUE_ARRAY ||
                out.type == JS_VALUE_FUNCTION)
            {
                return js_eval_ok(out);
            }

            js_value_destroy(&out);
            js_value_t constructed;
            if (!js_value_make_host_object(&constructed, NULL, NULL, NULL, NULL))
            {
                return js_eval_error("allocation failed");
            }
            return js_eval_ok(constructed);
        }
        case JS_EXPR_CALL:
        {
            js_value_t callee = js_value_make_undefined_internal();
            js_member_access_t access;
            bool has_access = false;
            if (expr->as.call.callee && expr->as.call.callee->type == JS_EXPR_MEMBER)
            {
                js_eval_result_t access_res =
                    js_eval_member_access(rt, env, &expr->as.call.callee->as.member, &access);
                if (!access_res.ok)
                {
                    return access_res;
                }
                js_value_destroy(&access_res.value);
                js_eval_result_t callee_res = js_member_access_value(rt, &access);
                if (!callee_res.ok)
                {
                    js_member_access_release(&access);
                    return callee_res;
                }
                callee = callee_res.value;
                has_access = true;
            }
            else
            {
                js_eval_result_t callee_res = js_eval_expr(rt, env, expr->as.call.callee);
                if (!callee_res.ok)
                {
                    return callee_res;
                }
                callee = callee_res.value;
            }
            size_t argc = expr->as.call.arg_count;
            bool inject_this = has_access &&
                               callee.type == JS_VALUE_NATIVE_FN &&
                               js_native_needs_this(callee.as.native.fn);
            size_t call_argc = argc + (inject_this ? 1u : 0u);
            js_value_t *args = NULL;
            if (call_argc)
            {
                args = (js_value_t *)calloc(call_argc, sizeof(*args));
                if (!args)
                {
                    js_value_destroy(&callee);
                    if (has_access)
                    {
                        js_member_access_release(&access);
                    }
                    return js_eval_error("allocation failed");
                }
            }
            if (inject_this)
            {
                if (!js_value_copy(&args[0], &access.object))
                {
                    free(args);
                    js_value_destroy(&callee);
                    if (has_access)
                    {
                        js_member_access_release(&access);
                    }
                    return js_eval_error("allocation failed");
                }
            }
            for (size_t i = 0; i < argc; ++i)
            {
                js_eval_result_t arg = js_eval_expr(rt, env, expr->as.call.args[i]);
                if (!arg.ok)
                {
                    for (size_t j = 0; j < i + (inject_this ? 1u : 0u); ++j)
                    {
                        js_value_destroy(&args[j]);
                    }
                    free(args);
                    js_value_destroy(&callee);
                    if (has_access)
                    {
                        js_member_access_release(&access);
                    }
                    return arg;
                }
                args[i + (inject_this ? 1u : 0u)] = arg.value;
            }

            js_eval_result_t res;
            js_value_t out = js_value_make_undefined_internal();
            char *err = NULL;
            bool ok = js_call_value(rt, &callee, call_argc, args, &out, &err);
            if (ok)
            {
                res = js_eval_ok(out);
            }
            else
            {
                if (err)
                {
                    res = js_eval_error(err);
                    free(err);
                }
                else
                {
                    res = js_eval_error("call failed");
                }
            }

            for (size_t i = 0; i < call_argc; ++i)
            {
                js_value_destroy(&args[i]);
            }
            free(args);
            js_value_destroy(&callee);
            if (has_access)
            {
                js_member_access_release(&access);
            }
            return res;
        }
        case JS_EXPR_ARRAY:
        {
            js_array_t *array = js_array_create();
            if (!array)
            {
                return js_eval_error("allocation failed");
            }
            for (size_t i = 0; i < expr->as.array.count; ++i)
            {
                js_eval_result_t item = js_eval_expr(rt, env, expr->as.array.items[i]);
                if (!item.ok)
                {
                    js_array_release(array);
                    return item;
                }
                if (!js_array_set(array, i, &item.value))
                {
                    js_value_destroy(&item.value);
                    js_array_release(array);
                    return js_eval_error("allocation failed");
                }
                js_value_destroy(&item.value);
            }
            js_value_t out;
            memset(&out, 0, sizeof(out));
            out.type = JS_VALUE_ARRAY;
            out.as.array = array;
            return js_eval_ok(out);
        }
        case JS_EXPR_OBJECT:
        {
            js_value_t obj_value;
            if (!js_value_make_host_object(&obj_value, NULL, NULL, NULL, NULL))
            {
                return js_eval_error("allocation failed");
            }
            for (size_t i = 0; i < expr->as.object.count; ++i)
            {
                const char *prop_name = expr->as.object.props[i].name;
                char *owned_name = NULL;
                if (expr->as.object.props[i].computed)
                {
                    js_eval_result_t key_res = js_eval_expr(rt, env, expr->as.object.props[i].name_expr);
                    if (!key_res.ok)
                    {
                        js_value_destroy(&obj_value);
                        return key_res;
                    }
                    js_temp_string_t temp = {0};
                    char *key_err = NULL;
                    if (!js_temp_string_from_value(rt, &key_res.value, &temp, &key_err))
                    {
                        js_value_destroy(&key_res.value);
                        js_value_destroy(&obj_value);
                        if (key_err)
                        {
                            js_eval_result_t res = js_eval_error(key_err);
                            free(key_err);
                            return res;
                        }
                        return js_eval_error("allocation failed");
                    }
                    owned_name = js_strdup_len(temp.data ? temp.data : "", temp.len);
                    js_temp_string_release(&temp);
                    js_value_destroy(&key_res.value);
                    if (!owned_name)
                    {
                        js_value_destroy(&obj_value);
                        return js_eval_error("allocation failed");
                    }
                    prop_name = owned_name;
                }
                js_eval_result_t item = js_eval_expr(rt, env, expr->as.object.props[i].value);
                if (!item.ok)
                {
                    free(owned_name);
                    js_value_destroy(&obj_value);
                    return item;
                }
                bool ok = false;
                if (expr->as.object.props[i].is_getter || expr->as.object.props[i].is_setter)
                {
                    char *prop_err = NULL;
                    js_property_t *prop = js_object_ensure_property(obj_value.as.object, prop_name, &prop_err);
                    if (!prop)
                    {
                        js_value_destroy(&item.value);
                        free(owned_name);
                        js_value_destroy(&obj_value);
                        if (prop_err)
                        {
                            js_eval_result_t res = js_eval_error(prop_err);
                            free(prop_err);
                            return res;
                        }
                        return js_eval_error("allocation failed");
                    }
                    if (!prop->is_accessor)
                    {
                        js_value_destroy(&prop->value);
                        prop->value = js_value_make_undefined_internal();
                        prop->is_accessor = true;
                        prop->writable = false;
                        js_value_destroy(&prop->getter);
                        js_value_destroy(&prop->setter);
                        prop->getter = js_value_make_undefined_internal();
                        prop->setter = js_value_make_undefined_internal();
                    }
                    prop->enumerable = true;
                    prop->configurable = true;
                    if (expr->as.object.props[i].is_getter)
                    {
                        js_value_destroy(&prop->getter);
                        ok = js_value_copy(&prop->getter, &item.value);
                    }
                    else
                    {
                        js_value_destroy(&prop->setter);
                        ok = js_value_copy(&prop->setter, &item.value);
                    }
                }
                else
                {
                    ok = js_object_set_slot(obj_value.as.object, prop_name, &item.value);
                }
                js_value_destroy(&item.value);
                free(owned_name);
                if (!ok)
                {
                    js_value_destroy(&obj_value);
                    return js_eval_error("allocation failed");
                }
            }
            if (!js_object_has_slot(obj_value.as.object, "__proto__"))
            {
                js_object_t *proto = js_get_object_proto(rt);
                if (proto)
                {
                    js_value_t proto_val;
                    memset(&proto_val, 0, sizeof(proto_val));
                    proto_val.type = JS_VALUE_OBJECT;
                    proto_val.as.object = proto;
                    (void)js_object_set_slot(obj_value.as.object, "__proto__", &proto_val);
                }
            }
            return js_eval_ok(obj_value);
        }
        case JS_EXPR_MEMBER:
        {
            js_member_access_t access;
            js_eval_result_t access_res = js_eval_member_access(rt, env, &expr->as.member, &access);
            if (!access_res.ok)
            {
                return access_res;
            }
            js_value_destroy(&access_res.value);
            js_eval_result_t result;
            if (access.is_length)
            {
                if (access.object.type == JS_VALUE_ARRAY)
                {
                    result = js_eval_ok(js_value_make_number((double)access.object.as.array->length));
                }
                else if (access.object.type == JS_VALUE_STRING)
                {
                    result = js_eval_ok(js_value_make_number((double)access.object.as.string.len));
                }
                else if (access.object.type == JS_VALUE_FUNCTION)
                {
                    result = js_eval_ok(js_value_make_number((double)js_function_length(access.object.as.function)));
                }
                else if (access.object.type == JS_VALUE_NATIVE_FN)
                {
                    size_t len = 0;
                    if (!js_value_native_length(rt, &access.object, &len))
                    {
                        js_member_access_release(&access);
                        return js_eval_error("unknown property");
                    }
                    result = js_eval_ok(js_value_make_number((double)len));
                }
                else
                {
                    js_member_access_release(&access);
                    return js_eval_error("unknown property");
                }
            }
            else if (access.object.type == JS_VALUE_ARRAY)
            {
                if (access.has_index)
                {
                    js_value_t value;
                    char *err = NULL;
                    if (!js_array_get_index_value(rt, access.object.as.array, access.index, &value, &err))
                    {
                        if (err)
                        {
                            js_member_access_release(&access);
                            js_eval_result_t res = js_eval_error(err);
                            free(err);
                            return res;
                        }
                        js_member_access_release(&access);
                        return js_eval_error("allocation failed");
                    }
                    result = js_eval_ok(value);
                }
                else if (access.property)
                {
                    js_value_t value;
                    char *prop_err = NULL;
                    if (!js_array_get_property(rt, access.object.as.array, access.property, &value, &prop_err))
                    {
                        js_member_access_release(&access);
                        if (prop_err)
                        {
                            js_eval_result_t res = js_eval_error(prop_err);
                            free(prop_err);
                            return res;
                        }
                        return js_eval_error("allocation failed");
                    }
                    result = js_eval_ok(value);
                }
                else
                {
                    js_member_access_release(&access);
                    return js_eval_error("unknown property");
                }
            }
            else if (access.object.type == JS_VALUE_OBJECT)
            {
                js_value_t value = js_value_make_undefined_internal();
                char *err = NULL;
                if (!js_object_get_property(rt, access.object.as.object, access.property, &value, &err))
                {
                    js_member_access_release(&access);
                    if (err)
                    {
                        js_eval_result_t res = js_eval_error(err);
                        free(err);
                        return res;
                    }
                    return js_eval_error("property lookup failed");
                }
                result = js_eval_ok(value);
            }
            else if (access.object.type == JS_VALUE_FUNCTION)
            {
                if (access.property && strcmp(access.property, "name") == 0)
                {
                    js_value_t value;
                    if (!js_value_make_cstring(&value, js_function_name(access.object.as.function)))
                    {
                        js_member_access_release(&access);
                        return js_eval_error("allocation failed");
                    }
                    result = js_eval_ok(value);
                }
                else if (access.property && strcmp(access.property, "call") == 0)
                {
                    js_value_t value;
                    memset(&value, 0, sizeof(value));
                    value.type = JS_VALUE_NATIVE_FN;
                    value.as.native.fn = js_builtin_function_call;
                    value.as.native.user_data = &access.object;
                    result = js_eval_ok(value);
                }
                else
                {
                    js_member_access_release(&access);
                    return js_eval_error("unknown property");
                }
            }
            else if (access.object.type == JS_VALUE_NATIVE_FN)
            {
                const char *native_name = js_value_native_name(rt, &access.object);
                if (access.property && strcmp(access.property, "name") == 0)
                {
                    js_value_t value;
                    if (!js_value_make_cstring(&value, native_name ? native_name : ""))
                    {
                        js_member_access_release(&access);
                        return js_eval_error("allocation failed");
                    }
                    result = js_eval_ok(value);
                    js_member_access_release(&access);
                    return result;
                }
                if (access.property && strcmp(access.property, "prototype") == 0 &&
                    (access.object.as.native.fn == js_builtin_iterator ||
                     (native_name && strcmp(native_name, "Iterator") == 0)))
                {
                    js_object_t *proto = js_get_iterator_proto(rt);
                    if (!proto)
                    {
                        js_member_access_release(&access);
                        return js_eval_error("allocation failed");
                    }
                    js_value_t value;
                    memset(&value, 0, sizeof(value));
                    value.type = JS_VALUE_OBJECT;
                    value.as.object = proto;
                    js_object_retain(proto);
                    result = js_eval_ok(value);
                    js_member_access_release(&access);
                    return result;
                }
                if ((native_name && strcmp(native_name, "RegExp") == 0) ||
                    (access.object.as.native.fn == js_builtin_regexp))
                {
                    if (access.property && strcmp(access.property, "prototype") == 0)
                    {
                        js_value_t proto;
                        if (!js_value_make_host_object(&proto, NULL, NULL, NULL, NULL))
                        {
                            js_member_access_release(&access);
                            return js_eval_error("allocation failed");
                        }
                        js_value_t compile;
                        memset(&compile, 0, sizeof(compile));
                        compile.type = JS_VALUE_NATIVE_FN;
                        compile.as.native.fn = js_regexp_compile_proto;
                        compile.as.native.user_data = access.object.as.native.user_data;
                        if (!js_object_set_slot(proto.as.object, "compile", &compile))
                        {
                            js_value_destroy(&proto);
                            js_member_access_release(&access);
                            return js_eval_error("allocation failed");
                        }
                        result = js_eval_ok(proto);
                        js_member_access_release(&access);
                        return result;
                    }
                }
                if (native_name && access.property && strcmp(native_name, "Symbol") == 0 &&
                    strcmp(access.property, "toPrimitive") == 0)
                {
                    js_value_t value;
                    if (!js_value_make_cstring(&value, "Symbol.toPrimitive"))
                    {
                        js_member_access_release(&access);
                        return js_eval_error("allocation failed");
                    }
                    result = js_eval_ok(value);
                    js_member_access_release(&access);
                    return result;
                }
                if (native_name && access.property && strcmp(native_name, "Symbol") == 0 &&
                    strcmp(access.property, "iterator") == 0)
                {
                    js_value_t value;
                    if (!js_value_make_cstring(&value, "Symbol.iterator"))
                    {
                        js_member_access_release(&access);
                        return js_eval_error("allocation failed");
                    }
                    result = js_eval_ok(value);
                    js_member_access_release(&access);
                    return result;
                }
                if (native_name && access.property && strcmp(native_name, "Symbol") == 0 &&
                    strcmp(access.property, "match") == 0)
                {
                    js_value_t value;
                    if (!js_value_make_cstring(&value, "Symbol.match"))
                    {
                        js_member_access_release(&access);
                        return js_eval_error("allocation failed");
                    }
                    result = js_eval_ok(value);
                    js_member_access_release(&access);
                    return result;
                }
                if (native_name && access.property && strcmp(native_name, "Symbol") == 0 &&
                    strcmp(access.property, "split") == 0)
                {
                    js_value_t value;
                    if (!js_value_make_cstring(&value, "Symbol.split"))
                    {
                        js_member_access_release(&access);
                        return js_eval_error("allocation failed");
                    }
                    result = js_eval_ok(value);
                    js_member_access_release(&access);
                    return result;
                }
                if (native_name && access.property && strcmp(native_name, "Symbol") == 0 &&
                    strcmp(access.property, "toStringTag") == 0)
                {
                    js_value_t value;
                    if (!js_value_make_cstring(&value, "Symbol.toStringTag"))
                    {
                        js_member_access_release(&access);
                        return js_eval_error("allocation failed");
                    }
                    result = js_eval_ok(value);
                    js_member_access_release(&access);
                    return result;
                }
                if (native_name && access.property && strcmp(native_name, "Object") == 0 &&
                    strcmp(access.property, "defineProperty") == 0)
                {
                    js_value_t value;
                    memset(&value, 0, sizeof(value));
                    value.type = JS_VALUE_NATIVE_FN;
                    value.as.native.fn = js_builtin_define_property;
                    value.as.native.user_data = NULL;
                    result = js_eval_ok(value);
                    js_member_access_release(&access);
                    return result;
                }
                if (native_name && access.property && strcmp(native_name, "Object") == 0 &&
                    strcmp(access.property, "getPrototypeOf") == 0)
                {
                    js_value_t value;
                    memset(&value, 0, sizeof(value));
                    value.type = JS_VALUE_NATIVE_FN;
                    value.as.native.fn = js_builtin_object_get_prototype_of;
                    value.as.native.user_data = NULL;
                    result = js_eval_ok(value);
                    js_member_access_release(&access);
                    return result;
                }
                if (native_name && access.property && strcmp(native_name, "String") == 0 &&
                    strcmp(access.property, "fromCharCode") == 0)
                {
                    js_value_t value;
                    memset(&value, 0, sizeof(value));
                    value.type = JS_VALUE_NATIVE_FN;
                    value.as.native.fn = js_builtin_string_from_char_code;
                    value.as.native.user_data = NULL;
                    result = js_eval_ok(value);
                    js_member_access_release(&access);
                    return result;
                }
                if (native_name && access.property && strcmp(native_name, "Object") == 0 &&
                    strcmp(access.property, "defineProperties") == 0)
                {
                    js_value_t value;
                    memset(&value, 0, sizeof(value));
                    value.type = JS_VALUE_NATIVE_FN;
                    value.as.native.fn = js_builtin_define_properties;
                    value.as.native.user_data = NULL;
                    result = js_eval_ok(value);
                    js_member_access_release(&access);
                    return result;
                }
                if (native_name && access.property && strcmp(native_name, "Number") == 0)
                {
                    if (strcmp(access.property, "POSITIVE_INFINITY") == 0)
                    {
                        double inf_value = 1.0 / 0.0;
                        result = js_eval_ok(js_value_make_number(inf_value));
                        js_member_access_release(&access);
                        return result;
                    }
                    if (strcmp(access.property, "NEGATIVE_INFINITY") == 0)
                    {
                        double inf_value = 1.0 / 0.0;
                        result = js_eval_ok(js_value_make_number(-inf_value));
                        js_member_access_release(&access);
                        return result;
                    }
                    if (strcmp(access.property, "NaN") == 0)
                    {
                        result = js_eval_ok(js_value_make_number(js_nan()));
                        js_member_access_release(&access);
                        return result;
                    }
                }
                js_member_access_release(&access);
                return js_eval_error("unknown property");
            }
            else
            {
                js_member_access_release(&access);
                return js_eval_error("value is not indexable");
            }
            js_member_access_release(&access);
            return result;
        }
        case JS_EXPR_REGEXP_SUBCLASS:
        {
            js_value_t value;
            memset(&value, 0, sizeof(value));
            value.type = JS_VALUE_NATIVE_FN;
            value.as.native.fn = js_builtin_regexp_subclass;
            value.as.native.user_data = NULL;
            return js_eval_ok(value);
        }
        case JS_EXPR_FUNCTION:
        {
            bool constructible = (!expr->as.func.is_arrow && !expr->as.func.is_generator);
            js_function_t *fn = js_function_create(NULL, &expr->as.func, env, constructible);
            if (!fn)
            {
                return js_eval_error("allocation failed");
            }
            js_value_t out;
            memset(&out, 0, sizeof(out));
            out.type = JS_VALUE_FUNCTION;
            out.as.function = fn;
            return js_eval_ok(out);
        }
        case JS_EXPR_TERNARY:
        {
            js_eval_result_t cond = js_eval_expr(rt, env, expr->as.ternary.condition);
            if (!cond.ok)
            {
                return cond;
            }
            bool truthy = js_value_is_truthy(&cond.value);
            js_value_destroy(&cond.value);
            if (truthy)
            {
                return js_eval_expr(rt, env, expr->as.ternary.then_expr);
            }
            return js_eval_expr(rt, env, expr->as.ternary.else_expr);
        }
        case JS_EXPR_YIELD:
        {
            if (!rt || !rt->yield_array)
            {
                return js_eval_error("invalid yield");
            }
            js_value_t value = js_value_make_undefined_internal();
            if (expr->as.yield.value)
            {
                js_eval_result_t yielded = js_eval_expr(rt, env, expr->as.yield.value);
                if (!yielded.ok)
                {
                    return yielded;
                }
                value = yielded.value;
            }
            if (!js_array_set(rt->yield_array, rt->yield_array->length, &value))
            {
                js_value_destroy(&value);
                return js_eval_error("allocation failed");
            }
            if (rt->yield_limit > 0)
            {
                rt->yield_count++;
                if (rt->yield_count >= rt->yield_limit)
                {
                    return js_eval_control(JS_CTRL_RETURN, value);
                }
            }
            return js_eval_ok(value);
        }
    }
    return js_eval_error("unknown expression");
}

static js_eval_result_t js_eval_statement(js_runtime_t *rt, js_env_t *env, const js_stmt_t *stmt)
{
    if (!stmt)
    {
        return js_eval_ok(js_value_make_undefined_internal());
    }
    switch (stmt->type)
    {
        case JS_STMT_VAR:
        {
            for (size_t i = 0; i < stmt->as.var.count; ++i)
            {
                bool has_init = (stmt->as.var.bindings[i].init != NULL);
                js_value_t value = js_value_make_undefined_internal();
                bool value_owned = false;
                if (has_init)
                {
                    js_eval_result_t init_res = js_eval_expr(rt, env, stmt->as.var.bindings[i].init);
                    if (!init_res.ok)
                    {
                        return init_res;
                    }
                    value = init_res.value;
                    value_owned = true;
                }

                if (stmt->as.var.kind == JS_VAR_VAR)
                {
                    if (!has_init && stmt->as.var.bindings[i].binding &&
                        stmt->as.var.bindings[i].binding->type == JS_BINDING_IDENTIFIER)
                    {
                        if (value_owned)
                        {
                            js_value_destroy(&value);
                        }
                        continue;
                    }
                    js_eval_result_t bind_res =
                        js_binding_apply(rt,
                                         env,
                                         stmt->as.var.bindings[i].binding,
                                         &value,
                                         true,
                                         JS_VAR_VAR,
                                         false);
                    if (value_owned)
                    {
                        js_value_destroy(&value);
                    }
                    if (!bind_res.ok)
                    {
                        return bind_res;
                    }
                    js_value_destroy(&bind_res.value);
                }
                else
                {
                    js_eval_result_t bind_res =
                        js_binding_apply(rt,
                                         env,
                                         stmt->as.var.bindings[i].binding,
                                         &value,
                                         true,
                                         stmt->as.var.kind,
                                         false);
                    if (value_owned)
                    {
                        js_value_destroy(&value);
                    }
                    if (!bind_res.ok)
                    {
                        return bind_res;
                    }
                    js_value_destroy(&bind_res.value);
                }
            }
            return js_eval_ok(js_value_make_undefined_internal());
        }
        case JS_STMT_EXPR:
            return js_eval_expr(rt, env, stmt->as.expr.expr);
        case JS_STMT_BLOCK:
        {
            js_env_t *child = js_env_create(env, false);
            if (!child)
            {
                return js_eval_error("allocation failed");
            }
            js_eval_result_t res = js_eval_statements(rt, child, stmt->as.block.stmts, stmt->as.block.count);
            js_env_release(child);
            return res;
        }
        case JS_STMT_RETURN:
        {
            js_value_t value = js_value_make_undefined_internal();
            if (stmt->as.ret.value)
            {
                js_eval_result_t r = js_eval_expr(rt, env, stmt->as.ret.value);
                if (!r.ok)
                {
                    return r;
                }
                value = r.value;
            }
            return js_eval_control(JS_CTRL_RETURN, value);
        }
        case JS_STMT_THROW:
        {
            js_eval_result_t thrown = js_eval_expr(rt, env, stmt->as.throw_stmt.expr);
            if (!thrown.ok)
            {
                return thrown;
            }
            js_temp_string_t temp = {0};
            char *err = NULL;
            if (!js_temp_string_from_value(rt, &thrown.value, &temp, &err))
            {
                js_value_destroy(&thrown.value);
                if (err)
                {
                    js_eval_result_t res = js_eval_error(err);
                    free(err);
                    return res;
                }
                return js_eval_error("throw");
            }
            char *msg = js_strdup_len(temp.data ? temp.data : "", temp.len);
            js_temp_string_release(&temp);
            js_value_destroy(&thrown.value);
            if (!msg)
            {
                return js_eval_error("allocation failed");
            }
            js_eval_result_t res = js_eval_error(msg);
            free(msg);
            return res;
        }
        case JS_STMT_FUNCTION_DECL:
        {
            bool constructible = !stmt->as.func.is_generator;
            js_function_t *fn = js_function_create(&stmt->as.func, NULL, env, constructible);
            if (!fn)
            {
                return js_eval_error("allocation failed");
            }
            js_value_t val;
            memset(&val, 0, sizeof(val));
            val.type = JS_VALUE_FUNCTION;
            val.as.function = fn;
            if (!js_env_define_local(env, stmt->as.func.name, &val, false, true))
            {
                js_function_release(fn);
                return js_eval_error("failed to define function");
            }
            js_function_release(fn);
            return js_eval_ok(js_value_make_undefined_internal());
        }
        case JS_STMT_IF:
        {
            js_eval_result_t cond = js_eval_expr(rt, env, stmt->as.if_stmt.condition);
            if (!cond.ok)
            {
                return cond;
            }
            bool truthy = js_value_is_truthy(&cond.value);
            js_value_destroy(&cond.value);
            if (truthy)
            {
                return js_eval_statement(rt, env, stmt->as.if_stmt.then_branch);
            }
            if (stmt->as.if_stmt.else_branch)
            {
                return js_eval_statement(rt, env, stmt->as.if_stmt.else_branch);
            }
            return js_eval_ok(js_value_make_undefined_internal());
        }
        case JS_STMT_WHILE:
        {
            for (;;)
            {
                js_eval_result_t cond = js_eval_expr(rt, env, stmt->as.while_stmt.condition);
                if (!cond.ok)
                {
                    return cond;
                }
                bool truthy = js_value_is_truthy(&cond.value);
                js_value_destroy(&cond.value);
                if (!truthy)
                {
                    break;
                }
                js_eval_result_t body = js_eval_statement(rt, env, stmt->as.while_stmt.body);
                if (!body.ok)
                {
                    return body;
                }
                if (body.control == JS_CTRL_RETURN)
                {
                    return body;
                }
                if (body.control == JS_CTRL_BREAK)
                {
                    js_value_destroy(&body.value);
                    break;
                }
                if (body.control == JS_CTRL_CONTINUE)
                {
                    js_value_destroy(&body.value);
                    continue;
                }
                js_value_destroy(&body.value);
            }
            return js_eval_ok(js_value_make_undefined_internal());
        }
        case JS_STMT_DO_WHILE:
        {
            for (;;)
            {
                js_eval_result_t body = js_eval_statement(rt, env, stmt->as.do_while_stmt.body);
                if (!body.ok)
                {
                    return body;
                }
                if (body.control == JS_CTRL_RETURN)
                {
                    return body;
                }
                if (body.control == JS_CTRL_BREAK)
                {
                    js_value_destroy(&body.value);
                    break;
                }
                js_value_destroy(&body.value);

                js_eval_result_t cond = js_eval_expr(rt, env, stmt->as.do_while_stmt.condition);
                if (!cond.ok)
                {
                    return cond;
                }
                bool truthy = js_value_is_truthy(&cond.value);
                js_value_destroy(&cond.value);
                if (!truthy)
                {
                    break;
                }
            }
            return js_eval_ok(js_value_make_undefined_internal());
        }
        case JS_STMT_FOR:
        {
            js_env_t *loop_env = js_env_create(env, false);
            if (!loop_env)
            {
                return js_eval_error("allocation failed");
            }
            if (stmt->as.for_stmt.init)
            {
                js_eval_result_t init = js_eval_statement(rt, loop_env, stmt->as.for_stmt.init);
                if (!init.ok)
                {
                    js_env_release(loop_env);
                    return init;
                }
                if (init.control != JS_CTRL_NONE)
                {
                    js_env_release(loop_env);
                    return init;
                }
                js_value_destroy(&init.value);
            }

            for (;;)
            {
                if (stmt->as.for_stmt.condition)
                {
                    js_eval_result_t cond = js_eval_expr(rt, loop_env, stmt->as.for_stmt.condition);
                    if (!cond.ok)
                    {
                        js_env_release(loop_env);
                        return cond;
                    }
                    bool truthy = js_value_is_truthy(&cond.value);
                    js_value_destroy(&cond.value);
                    if (!truthy)
                    {
                        break;
                    }
                }

                js_eval_result_t body = js_eval_statement(rt, loop_env, stmt->as.for_stmt.body);
                if (!body.ok)
                {
                    js_env_release(loop_env);
                    return body;
                }
                if (body.control == JS_CTRL_RETURN)
                {
                    js_env_release(loop_env);
                    return body;
                }
                if (body.control == JS_CTRL_BREAK)
                {
                    js_value_destroy(&body.value);
                    break;
                }

                if (stmt->as.for_stmt.post)
                {
                    js_eval_result_t post = js_eval_expr(rt, loop_env, stmt->as.for_stmt.post);
                    if (!post.ok)
                    {
                        js_env_release(loop_env);
                        js_value_destroy(&body.value);
                        return post;
                    }
                    js_value_destroy(&post.value);
                }

                if (body.control == JS_CTRL_CONTINUE)
                {
                    js_value_destroy(&body.value);
                    continue;
                }
                js_value_destroy(&body.value);
            }

            js_env_release(loop_env);
            return js_eval_ok(js_value_make_undefined_internal());
        }
        case JS_STMT_FOR_IN:
        case JS_STMT_FOR_OF:
        {
            bool is_of = (stmt->type == JS_STMT_FOR_OF);
            js_eval_result_t rhs = js_eval_expr(rt, env, stmt->as.for_inof.expr);
            if (!rhs.ok)
            {
                return rhs;
            }
            js_value_t iterable = rhs.value;

            if (is_of)
            {
                if (iterable.type != JS_VALUE_ARRAY && iterable.type != JS_VALUE_STRING)
                {
                    js_value_destroy(&iterable);
                    return js_eval_error("TypeError: not iterable");
                }
                size_t length = (iterable.type == JS_VALUE_ARRAY && iterable.as.array)
                                    ? iterable.as.array->length
                                    : iterable.as.string.len;
                for (size_t i = 0; i < length; ++i)
                {
                    js_value_t item = js_value_make_undefined_internal();
                    if (iterable.type == JS_VALUE_ARRAY)
                    {
                        char *item_err = NULL;
                        if (!js_array_get_index_value(rt, iterable.as.array, i, &item, &item_err))
                        {
                            js_value_destroy(&iterable);
                            free(item_err);
                            return js_eval_error("allocation failed");
                        }
                        free(item_err);
                    }
                    else
                    {
                        if (!js_make_single_char_string(&item, iterable.as.string.data[i]))
                        {
                            js_value_destroy(&iterable);
                            return js_eval_error("allocation failed");
                        }
                    }

                    js_env_t *iter_env = env;
                    if (stmt->as.for_inof.is_decl && stmt->as.for_inof.kind != JS_VAR_VAR)
                    {
                        iter_env = js_env_create(env, false);
                        if (!iter_env)
                        {
                            js_value_destroy(&item);
                            js_value_destroy(&iterable);
                            return js_eval_error("allocation failed");
                        }
                    }

                    js_eval_result_t bind_res;
                    if (stmt->as.for_inof.is_decl)
                    {
                        bind_res = js_binding_apply(rt,
                                                    iter_env,
                                                    stmt->as.for_inof.binding,
                                                    &item,
                                                    true,
                                                    stmt->as.for_inof.kind,
                                                    false);
                    }
                    else if (stmt->as.for_inof.binding)
                    {
                        bind_res = js_binding_apply(rt,
                                                    iter_env,
                                                    stmt->as.for_inof.binding,
                                                    &item,
                                                    false,
                                                    stmt->as.for_inof.kind,
                                                    false);
                    }
                    else
                    {
                        bind_res = js_assign_to_target(rt, iter_env, stmt->as.for_inof.target, &item);
                    }
                    js_value_destroy(&item);
                    if (!bind_res.ok)
                    {
                        if (iter_env != env)
                        {
                            js_env_release(iter_env);
                        }
                        js_value_destroy(&iterable);
                        return bind_res;
                    }
                    js_value_destroy(&bind_res.value);

                    js_eval_result_t body = js_eval_statement(rt, iter_env, stmt->as.for_inof.body);
                    if (iter_env != env)
                    {
                        js_env_release(iter_env);
                    }
                    if (!body.ok)
                    {
                        js_value_destroy(&iterable);
                        return body;
                    }
                    if (body.control == JS_CTRL_RETURN)
                    {
                        js_value_destroy(&iterable);
                        return body;
                    }
                    if (body.control == JS_CTRL_BREAK)
                    {
                        js_value_destroy(&body.value);
                        break;
                    }
                    if (body.control == JS_CTRL_CONTINUE)
                    {
                        js_value_destroy(&body.value);
                        continue;
                    }
                    js_value_destroy(&body.value);
                }
                js_value_destroy(&iterable);
                return js_eval_ok(js_value_make_undefined_internal());
            }

            if (iterable.type == JS_VALUE_UNDEFINED || iterable.type == JS_VALUE_NULL)
            {
                js_value_destroy(&iterable);
                return js_eval_error("TypeError: cannot convert object to primitive");
            }

            js_value_t *keys = NULL;
            size_t key_count = 0;
            size_t key_cap = 0;
            if (iterable.type == JS_VALUE_ARRAY && iterable.as.array)
            {
                for (size_t i = 0; i < iterable.as.array->length; ++i)
                {
                    char key[32];
                    int len = snprintf(key, sizeof(key), "%zu", i);
                    if (len < 0 || (size_t)len >= sizeof(key))
                    {
                        continue;
                    }
                    if (key_count + 1 > key_cap)
                    {
                        size_t new_cap = key_cap ? key_cap * 2u : 8u;
                        js_value_t *next = (js_value_t *)realloc(keys, new_cap * sizeof(*next));
                        if (!next)
                        {
                            return js_for_in_fail(keys, key_count, &iterable, "allocation failed");
                        }
                        keys = next;
                        key_cap = new_cap;
                    }
                    if (!js_value_make_string(&keys[key_count], key, (size_t)len))
                    {
                        return js_for_in_fail(keys, key_count, &iterable, "allocation failed");
                    }
                    key_count++;
                }
                for (js_property_t *prop = iterable.as.array->properties; prop; prop = prop->next)
                {
                    if (!prop->name)
                    {
                        continue;
                    }
                    if (!prop->enumerable)
                    {
                        continue;
                    }
                    size_t len = strlen(prop->name);
                    if (key_count + 1 > key_cap)
                    {
                        size_t new_cap = key_cap ? key_cap * 2u : 8u;
                        js_value_t *next = (js_value_t *)realloc(keys, new_cap * sizeof(*next));
                        if (!next)
                        {
                            return js_for_in_fail(keys, key_count, &iterable, "allocation failed");
                        }
                        keys = next;
                        key_cap = new_cap;
                    }
                    if (!js_value_make_string(&keys[key_count], prop->name, len))
                    {
                        return js_for_in_fail(keys, key_count, &iterable, "allocation failed");
                    }
                    key_count++;
                }
            }
            else if (iterable.type == JS_VALUE_OBJECT && iterable.as.object)
            {
                for (js_property_t *prop = iterable.as.object->properties; prop; prop = prop->next)
                {
                    if (!prop->name)
                    {
                        continue;
                    }
                    if (!prop->enumerable)
                    {
                        continue;
                    }
                    size_t len = strlen(prop->name);
                    if (key_count + 1 > key_cap)
                    {
                        size_t new_cap = key_cap ? key_cap * 2u : 8u;
                        js_value_t *next = (js_value_t *)realloc(keys, new_cap * sizeof(*next));
                        if (!next)
                        {
                            return js_for_in_fail(keys, key_count, &iterable, "allocation failed");
                        }
                        keys = next;
                        key_cap = new_cap;
                    }
                    if (!js_value_make_string(&keys[key_count], prop->name, len))
                    {
                        return js_for_in_fail(keys, key_count, &iterable, "allocation failed");
                    }
                    key_count++;
                }
            }
            else if (iterable.type == JS_VALUE_STRING)
            {
                for (size_t i = 0; i < iterable.as.string.len; ++i)
                {
                    char key[32];
                    int len = snprintf(key, sizeof(key), "%zu", i);
                    if (len < 0 || (size_t)len >= sizeof(key))
                    {
                        continue;
                    }
                    if (key_count + 1 > key_cap)
                    {
                        size_t new_cap = key_cap ? key_cap * 2u : 8u;
                        js_value_t *next = (js_value_t *)realloc(keys, new_cap * sizeof(*next));
                        if (!next)
                        {
                            return js_for_in_fail(keys, key_count, &iterable, "allocation failed");
                        }
                        keys = next;
                        key_cap = new_cap;
                    }
                    if (!js_value_make_string(&keys[key_count], key, (size_t)len))
                    {
                        return js_for_in_fail(keys, key_count, &iterable, "allocation failed");
                    }
                    key_count++;
                }
            }

            for (size_t i = 0; i < key_count; ++i)
            {
                js_env_t *iter_env = env;
                if (stmt->as.for_inof.is_decl && stmt->as.for_inof.kind != JS_VAR_VAR)
                {
                    iter_env = js_env_create(env, false);
                    if (!iter_env)
                    {
                        for (size_t k = 0; k < key_count; ++k)
                        {
                            js_value_destroy(&keys[k]);
                        }
                        free(keys);
                        js_value_destroy(&iterable);
                        return js_eval_error("allocation failed");
                    }
                }

                js_eval_result_t bind_res;
                if (stmt->as.for_inof.is_decl)
                {
                    bind_res = js_binding_apply(rt,
                                                iter_env,
                                                stmt->as.for_inof.binding,
                                                &keys[i],
                                                true,
                                                stmt->as.for_inof.kind,
                                                false);
                }
                else if (stmt->as.for_inof.binding)
                {
                    bind_res = js_binding_apply(rt,
                                                iter_env,
                                                stmt->as.for_inof.binding,
                                                &keys[i],
                                                false,
                                                stmt->as.for_inof.kind,
                                                false);
                }
                else
                {
                    bind_res = js_assign_to_target(rt, iter_env, stmt->as.for_inof.target, &keys[i]);
                }
                if (!bind_res.ok)
                {
                    if (iter_env != env)
                    {
                        js_env_release(iter_env);
                    }
                    for (size_t k = 0; k < key_count; ++k)
                    {
                        js_value_destroy(&keys[k]);
                    }
                    free(keys);
                    js_value_destroy(&iterable);
                    return bind_res;
                }
                js_value_destroy(&bind_res.value);

                js_eval_result_t body = js_eval_statement(rt, iter_env, stmt->as.for_inof.body);
                if (iter_env != env)
                {
                    js_env_release(iter_env);
                }
                if (!body.ok)
                {
                    for (size_t k = 0; k < key_count; ++k)
                    {
                        js_value_destroy(&keys[k]);
                    }
                    free(keys);
                    js_value_destroy(&iterable);
                    return body;
                }
                if (body.control == JS_CTRL_RETURN)
                {
                    for (size_t k = 0; k < key_count; ++k)
                    {
                        js_value_destroy(&keys[k]);
                    }
                    free(keys);
                    js_value_destroy(&iterable);
                    return body;
                }
                if (body.control == JS_CTRL_BREAK)
                {
                    js_value_destroy(&body.value);
                    break;
                }
                if (body.control == JS_CTRL_CONTINUE)
                {
                    js_value_destroy(&body.value);
                    continue;
                }
                js_value_destroy(&body.value);
            }

            for (size_t k = 0; k < key_count; ++k)
            {
                js_value_destroy(&keys[k]);
            }
            free(keys);
            js_value_destroy(&iterable);
            return js_eval_ok(js_value_make_undefined_internal());
        }
        case JS_STMT_SWITCH:
        {
            js_eval_result_t test = js_eval_expr(rt, env, stmt->as.switch_stmt.expr);
            if (!test.ok)
            {
                return test;
            }
            size_t start = SIZE_MAX;
            size_t default_index = SIZE_MAX;
            for (size_t i = 0; i < stmt->as.switch_stmt.case_count; ++i)
            {
                js_switch_case_t *case_stmt = &stmt->as.switch_stmt.cases[i];
                if (!case_stmt->test)
                {
                    if (default_index == SIZE_MAX)
                    {
                        default_index = i;
                    }
                    continue;
                }
                if (start != SIZE_MAX)
                {
                    break;
                }
                js_eval_result_t case_val = js_eval_expr(rt, env, case_stmt->test);
                if (!case_val.ok)
                {
                    js_value_destroy(&test.value);
                    return case_val;
                }
                bool match = js_value_strict_equal(&test.value, &case_val.value);
                js_value_destroy(&case_val.value);
                if (match)
                {
                    start = i;
                    break;
                }
            }
            if (start == SIZE_MAX)
            {
                start = default_index;
            }
            if (start == SIZE_MAX)
            {
                js_value_destroy(&test.value);
                return js_eval_ok(js_value_make_undefined_internal());
            }
            js_env_t *switch_env = js_env_create(env, false);
            if (!switch_env)
            {
                js_value_destroy(&test.value);
                return js_eval_error("allocation failed");
            }
            for (size_t i = start; i < stmt->as.switch_stmt.case_count; ++i)
            {
                js_switch_case_t *case_stmt = &stmt->as.switch_stmt.cases[i];
                js_eval_result_t res = js_eval_statements(rt, switch_env, case_stmt->stmts, case_stmt->count);
                if (!res.ok)
                {
                    js_env_release(switch_env);
                    js_value_destroy(&test.value);
                    return res;
                }
                if (res.control == JS_CTRL_BREAK)
                {
                    js_value_destroy(&res.value);
                    js_env_release(switch_env);
                    js_value_destroy(&test.value);
                    return js_eval_ok(js_value_make_undefined_internal());
                }
                if (res.control != JS_CTRL_NONE)
                {
                    js_env_release(switch_env);
                    js_value_destroy(&test.value);
                    return res;
                }
                js_value_destroy(&res.value);
            }
            js_env_release(switch_env);
            js_value_destroy(&test.value);
            return js_eval_ok(js_value_make_undefined_internal());
        }
        case JS_STMT_TRY:
        {
            js_eval_result_t res = js_eval_statements(rt,
                                                      env,
                                                      stmt->as.try_stmt.try_block.stmts,
                                                      stmt->as.try_stmt.try_block.count);
            if (res.ok)
            {
                return res;
            }
            if (!stmt->as.try_stmt.has_catch)
            {
                return res;
            }
            js_env_t *catch_env = js_env_create(env, false);
            if (!catch_env)
            {
                js_value_destroy(&res.value);
                free(res.error_message);
                return js_eval_error("allocation failed");
            }
            js_value_t err_value;
            const char *msg = res.error_message ? res.error_message : "error";
            if (!js_value_make_cstring(&err_value, msg))
            {
                js_env_release(catch_env);
                js_value_destroy(&res.value);
                free(res.error_message);
                return js_eval_error("allocation failed");
            }
            bool ok = js_env_define_local(catch_env, stmt->as.try_stmt.catch_name, &err_value, false, false);
            js_value_destroy(&err_value);
            js_value_destroy(&res.value);
            free(res.error_message);
            if (!ok)
            {
                js_env_release(catch_env);
                return js_eval_error("failed to bind catch");
            }
            js_eval_result_t catch_res = js_eval_statements(rt,
                                                            catch_env,
                                                            stmt->as.try_stmt.catch_block.stmts,
                                                            stmt->as.try_stmt.catch_block.count);
            js_env_release(catch_env);
            return catch_res;
        }
        case JS_STMT_BREAK:
            return js_eval_control(JS_CTRL_BREAK, js_value_make_undefined_internal());
        case JS_STMT_CONTINUE:
            return js_eval_control(JS_CTRL_CONTINUE, js_value_make_undefined_internal());
        case JS_STMT_EMPTY:
            return js_eval_ok(js_value_make_undefined_internal());
    }
    return js_eval_ok(js_value_make_undefined_internal());
}

js_exec_result_t js_execute(js_runtime_t *rt, const js_program_t *program)
{
    js_exec_result_t out;
    memset(&out, 0, sizeof(out));
    out.ok = false;
    out.value = js_value_make_undefined_internal();
    out.error_offset = 0;
    if (!rt || !rt->global || !program)
    {
        out.error_message = js_strdup("invalid runtime");
        return out;
    }

    if (!js_hoist_vars(rt->global, program->statements, program->count))
    {
        out.ok = false;
        out.error_message = js_strdup("failed to hoist vars");
        out.value = js_value_make_undefined_internal();
        return out;
    }

    js_eval_result_t res = js_eval_statements(rt, rt->global, program->statements, program->count);
    if (!res.ok)
    {
        out.ok = false;
        out.error_message = res.error_message ? res.error_message : js_strdup("execution failed");
        out.value = js_value_make_undefined_internal();
        return out;
    }
    if (res.control == JS_CTRL_RETURN)
    {
        js_value_destroy(&res.value);
        out.ok = false;
        out.error_message = js_strdup("return not allowed at top level");
        out.value = js_value_make_undefined_internal();
        return out;
    }
    if (res.control == JS_CTRL_BREAK)
    {
        js_value_destroy(&res.value);
        out.ok = false;
        out.error_message = js_strdup("break not allowed at top level");
        out.value = js_value_make_undefined_internal();
        return out;
    }
    if (res.control == JS_CTRL_CONTINUE)
    {
        js_value_destroy(&res.value);
        out.ok = false;
        out.error_message = js_strdup("continue not allowed at top level");
        out.value = js_value_make_undefined_internal();
        return out;
    }
    out.ok = true;
    out.value = res.value;
    out.error_message = NULL;
    return out;
}

js_exec_result_t js_eval(js_runtime_t *rt, const char *source)
{
    js_exec_result_t out;
    memset(&out, 0, sizeof(out));
    out.ok = false;
    out.value = js_value_make_undefined_internal();
    out.error_offset = 0;
    js_parse_error_t err = {0};
    js_program_t *program = js_parse(source, &err);
    if (!program)
    {
        out.error_offset = err.offset;
        out.error_message = err.message ? js_strdup(err.message) : js_strdup("parse error");
        return out;
    }
    if (!js_runtime_track_program(rt, program))
    {
        js_program_destroy(program);
        out.error_message = js_strdup("failed to retain program");
        return out;
    }
    out = js_execute(rt, program);
    return out;
}

void js_exec_result_destroy(js_exec_result_t *result)
{
    if (!result)
    {
        return;
    }
    js_value_destroy(&result->value);
    free(result->error_message);
    result->error_message = NULL;
    result->error_offset = 0;
    result->ok = false;
}
