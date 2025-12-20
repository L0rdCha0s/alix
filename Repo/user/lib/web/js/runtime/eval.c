#include "web/js/runtime/runtime_internal.h"

#include "libc.h"
#include "math.h"

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

static double js_trunc(double value)
{
    return (value < 0.0) ? ceil(value) : floor(value);
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
    if (num > (double)SIZE_MAX)
    {
        return false;
    }
    *out_index = (size_t)num;
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
                    js_value_t undef = js_value_make_undefined_internal();
                    if (!js_env_define_if_absent(var_env, stmt->as.var.bindings[i].name, &undef, false))
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

static bool js_object_get_property(js_runtime_t *rt,
                                   js_object_t *object,
                                   const char *name,
                                   js_value_t *out,
                                   char **error_message)
{
    if (!out)
    {
        return false;
    }
    if (!object)
    {
        *out = js_value_make_undefined_internal();
        return true;
    }
    if (object->get_fn)
    {
        return object->get_fn(rt, object->user_data, name, out, error_message);
    }
    return js_object_get_slot(object, name, out);
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
    if (object->set_fn)
    {
        return object->set_fn(rt, object->user_data, name, value, error_message);
    }
    (void)rt;
    if (error_message)
    {
        *error_message = NULL;
    }
    return js_object_set_slot(object, name, value);
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
        else if (out->object.type == JS_VALUE_NUMBER)
        {
            if (member->property && strcmp(member->property, "toString") == 0)
            {
                out->property = member->property;
            }
            else
            {
                js_member_access_release(out);
                return js_eval_error("unknown property");
            }
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
            else
            {
                js_member_access_release(out);
                return js_eval_error("unknown property");
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
        return js_eval_error("unknown property");
    }
    if (access->object.type == JS_VALUE_ARRAY)
    {
        if (access->has_index)
        {
            js_value_t value;
            if (!js_array_get(access->object.as.array, access->index, &value))
            {
                return js_eval_error("allocation failed");
            }
            return js_eval_ok(value);
        }
        if (access->property)
        {
            js_value_t value;
            if (!js_array_get_property(access->object.as.array, access->property, &value))
            {
                return js_eval_error("allocation failed");
            }
            return js_eval_ok(value);
        }
        return js_eval_error("unknown property");
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
        return js_eval_error("unknown property");
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
        return js_eval_error("unknown property");
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
        return js_eval_error("unknown property");
    }
    if (access->object.type == JS_VALUE_NATIVE_FN)
    {
        const char *native_name = js_value_native_name(rt, &access->object);
        if (access->property && strcmp(access->property, "call") == 0)
        {
            js_value_t value;
            memset(&value, 0, sizeof(value));
            value.type = JS_VALUE_NATIVE_FN;
            value.as.native.fn = js_builtin_function_call;
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
                }
                return js_eval_error("unknown property");
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
    if (fn->is_expr && def->name)
    {
        js_value_t self_value;
        memset(&self_value, 0, sizeof(self_value));
        self_value.type = JS_VALUE_FUNCTION;
        self_value.as.function = fn;
        if (!js_env_define_local(call_env, def->name, &self_value, true, false))
        {
            js_env_release(call_env);
            return js_eval_error("failed to bind function name");
        }
    }
    for (size_t i = 0; i < def->param_count; ++i)
    {
        js_value_t value = js_value_make_undefined_internal();
        if (i < argc)
        {
            value = args[i];
        }
        if (!js_env_define_local(call_env, def->params[i], &value, false, true))
        {
            js_env_release(call_env);
            return js_eval_error("failed to bind parameter");
        }
    }
    js_value_t args_array;
    if (!js_value_make_array(&args_array))
    {
        js_env_release(call_env);
        return js_eval_error("allocation failed");
    }
    for (size_t i = 0; i < argc; ++i)
    {
        if (!js_value_array_set(&args_array, i, &args[i]))
        {
            js_value_destroy(&args_array);
            js_env_release(call_env);
            return js_eval_error("allocation failed");
        }
    }
    if (!js_env_define_local(call_env, "arguments", &args_array, false, true))
    {
        js_value_destroy(&args_array);
        js_env_release(call_env);
        return js_eval_error("failed to bind arguments");
    }
    js_value_destroy(&args_array);
    if (!js_hoist_vars(call_env, def->body.stmts, def->body.count))
    {
        js_env_release(call_env);
        return js_eval_error("failed to hoist vars");
    }
    js_eval_result_t res = js_eval_statements(rt, call_env, def->body.stmts, def->body.count);
    js_env_release(call_env);
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
    return def ? def->param_count : 0;
}

static const char *js_function_name(const js_function_t *fn)
{
    const js_function_decl_t *def = js_function_def(fn);
    return (def && def->name) ? def->name : "";
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
            js_value_destroy(&right.value);
            return js_eval_ok(result);
        }
        case JS_EXPR_UPDATE:
        {
            js_expr_t *target = expr->as.update.target;
            js_value_t current = js_value_make_undefined_internal();
            js_member_access_t access;
            bool has_access = false;
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
                    js_member_access_release(&access);
                    return js_eval_error("invalid assignment");
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
            js_value_t new_value = js_value_make_number(new_num);

            bool assigned_ok = false;
            if (target->type == JS_EXPR_IDENTIFIER)
            {
                assigned_ok = js_env_assign(env, target->as.ident.name, &new_value);
            }
            else if (has_access)
            {
                if (access.object.type == JS_VALUE_ARRAY)
                {
                    if (access.has_index)
                    {
                        assigned_ok = js_array_set(access.object.as.array, access.index, &new_value);
                    }
                    else if (access.property)
                    {
                        assigned_ok = js_array_set_property(access.object.as.array, access.property, &new_value);
                    }
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

            js_value_t result = expr->as.update.is_prefix ? new_value : js_value_make_number(num);
            if (!expr->as.update.is_prefix)
            {
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
                if (left.value.type == JS_VALUE_STRING && right.value.type == JS_VALUE_STRING)
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
                    js_member_access_release(&access);
                    js_value_destroy(&rhs.value);
                    return js_eval_error("invalid assignment");
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
                if (access.object.type == JS_VALUE_ARRAY)
                {
                    if (access.has_index)
                    {
                        if (!js_array_set(access.object.as.array, access.index, &add_res.value))
                        {
                            js_member_access_release(&access);
                            js_value_destroy(&add_res.value);
                            return js_eval_error("assignment failed");
                        }
                    }
                    else if (access.property)
                    {
                        if (!js_array_set_property(access.object.as.array, access.property, &add_res.value))
                        {
                            js_member_access_release(&access);
                            js_value_destroy(&add_res.value);
                            return js_eval_error("assignment failed");
                        }
                    }
                    else
                    {
                        js_member_access_release(&access);
                        js_value_destroy(&add_res.value);
                        return js_eval_error("invalid assignment");
                    }
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
                    js_member_access_release(&access);
                    js_value_destroy(&assigned.value);
                    return js_eval_error("invalid assignment");
                }
                if (access.object.type == JS_VALUE_ARRAY)
                {
                    if (access.has_index)
                    {
                        if (!js_array_set(access.object.as.array, access.index, &assigned.value))
                        {
                            js_member_access_release(&access);
                            js_value_destroy(&assigned.value);
                            return js_eval_error("assignment failed");
                        }
                    }
                    else if (access.property)
                    {
                        if (!js_array_set_property(access.object.as.array, access.property, &assigned.value))
                        {
                            js_member_access_release(&access);
                            js_value_destroy(&assigned.value);
                            return js_eval_error("assignment failed");
                        }
                    }
                    else
                    {
                        js_member_access_release(&access);
                        js_value_destroy(&assigned.value);
                        return js_eval_error("invalid assignment");
                    }
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
            bool ok = js_call_value(rt, &callee, argc, args, &out, &err);
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
            js_value_t *args = NULL;
            if (argc)
            {
                args = (js_value_t *)calloc(argc, sizeof(*args));
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
            for (size_t i = 0; i < argc; ++i)
            {
                js_eval_result_t arg = js_eval_expr(rt, env, expr->as.call.args[i]);
                if (!arg.ok)
                {
                    for (size_t j = 0; j < i; ++j)
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
                args[i] = arg.value;
            }

            js_eval_result_t res;
            js_value_t out = js_value_make_undefined_internal();
            char *err = NULL;
            bool ok = js_call_value(rt, &callee, argc, args, &out, &err);
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

            for (size_t i = 0; i < argc; ++i)
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
                char *err = NULL;
                bool ok = js_object_set_property(rt,
                                                 obj_value.as.object,
                                                 prop_name,
                                                 &item.value,
                                                 &err);
                js_value_destroy(&item.value);
                free(owned_name);
                if (!ok)
                {
                    js_value_destroy(&obj_value);
                    if (err)
                    {
                        js_eval_result_t res = js_eval_error(err);
                        free(err);
                        return res;
                    }
                    return js_eval_error("property set failed");
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
                    if (!js_array_get(access.object.as.array, access.index, &value))
                    {
                        js_member_access_release(&access);
                        return js_eval_error("allocation failed");
                    }
                    result = js_eval_ok(value);
                }
                else if (access.property)
                {
                    js_value_t value;
                    if (!js_array_get_property(access.object.as.array, access.property, &value))
                    {
                        js_member_access_release(&access);
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
            js_function_t *fn = js_function_create(NULL, &expr->as.func, env, !expr->as.func.is_arrow);
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
                js_value_t value = js_value_make_undefined_internal();
                if (stmt->as.var.bindings[i].init)
                {
                    js_eval_result_t init_res = js_eval_expr(rt, env, stmt->as.var.bindings[i].init);
                    if (!init_res.ok)
                    {
                        return init_res;
                    }
                    value = init_res.value;
                }
                if (stmt->as.var.kind == JS_VAR_VAR)
                {
                    js_env_t *var_env = js_env_find_var_scope(env);
                    js_value_t undef = js_value_make_undefined_internal();
                    if (!js_env_define_if_absent(var_env, stmt->as.var.bindings[i].name, &undef, false))
                    {
                        js_value_destroy(&value);
                        return js_eval_error("failed to define variable");
                    }
                    if (stmt->as.var.bindings[i].init)
                    {
                        if (!js_env_assign(var_env, stmt->as.var.bindings[i].name, &value))
                        {
                            js_value_destroy(&value);
                            return js_eval_error("assignment failed");
                        }
                    }
                    js_value_destroy(&value);
                }
                else
                {
                    bool is_const = (stmt->as.var.kind == JS_VAR_CONST);
                    bool ok = js_env_define_local(env, stmt->as.var.bindings[i].name, &value, is_const, false);
                    js_value_destroy(&value);
                    if (!ok)
                    {
                        return js_eval_error("failed to define variable");
                    }
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
            js_function_t *fn = js_function_create(&stmt->as.func, NULL, env, true);
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
