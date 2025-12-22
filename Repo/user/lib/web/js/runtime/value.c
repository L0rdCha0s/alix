#include "web/js/runtime/runtime_internal.h"

#include "ctype.h"
#include "float.h"
#include "libc.h"

typedef struct
{
    char *description;
} js_symbol_data_t;

static bool js_symbol_get(js_runtime_t *rt,
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
    js_symbol_data_t *sym = (js_symbol_data_t *)user_data;
    if (strcmp(name, "description") == 0)
    {
        if (!sym || !sym->description)
        {
            *out = js_value_make_undefined_internal();
            return true;
        }
        return js_value_make_cstring(out, sym->description);
    }
    *out = js_value_make_undefined_internal();
    return true;
}

static void js_symbol_finalize(void *user_data)
{
    js_symbol_data_t *sym = (js_symbol_data_t *)user_data;
    if (!sym)
    {
        return;
    }
    free(sym->description);
    free(sym);
}

bool js_object_is_symbol(const js_object_t *object)
{
    return object && object->get_fn == js_symbol_get;
}

js_value_t js_value_make_undefined_internal(void)
{
    js_value_t value;
    memset(&value, 0, sizeof(value));
    value.type = JS_VALUE_UNDEFINED;
    return value;
}

js_value_t js_value_make_undefined(void)
{
    return js_value_make_undefined_internal();
}

js_value_t js_value_make_null(void)
{
    js_value_t value;
    memset(&value, 0, sizeof(value));
    value.type = JS_VALUE_NULL;
    return value;
}

js_value_t js_value_make_bool(bool value)
{
    js_value_t out;
    memset(&out, 0, sizeof(out));
    out.type = JS_VALUE_BOOL;
    out.as.boolean = value;
    return out;
}

js_value_t js_value_make_number(double value)
{
    js_value_t out;
    memset(&out, 0, sizeof(out));
    out.type = JS_VALUE_NUMBER;
    out.as.number = value;
    return out;
}

bool js_value_make_string(js_value_t *out, const char *data, size_t len)
{
    if (!out)
    {
        return false;
    }
    if (!data)
    {
        data = "";
        len = 0;
    }
    char *copy = js_strdup_len(data, len);
    if (!copy)
    {
        return false;
    }
    out->type = JS_VALUE_STRING;
    out->as.string.data = copy;
    out->as.string.len = len;
    return true;
}

bool js_value_make_cstring(js_value_t *out, const char *text)
{
    if (!text)
    {
        text = "";
    }
    return js_value_make_string(out, text, strlen(text));
}

bool js_value_make_array(js_value_t *out)
{
    if (!out)
    {
        return false;
    }
    js_array_t *array = js_array_create();
    if (!array)
    {
        return false;
    }
    out->type = JS_VALUE_ARRAY;
    out->as.array = array;
    return true;
}

bool js_value_make_host_object(js_value_t *out,
                               js_host_get_fn_t get_fn,
                               js_host_set_fn_t set_fn,
                               js_host_finalize_fn_t finalize_fn,
                               void *user_data)
{
    if (!out)
    {
        return false;
    }
    js_object_t *object = (js_object_t *)calloc(1, sizeof(*object));
    if (!object)
    {
        return false;
    }
    object->refcount = 1;
    object->get_fn = get_fn;
    object->set_fn = set_fn;
    object->finalize_fn = finalize_fn;
    object->user_data = user_data;
    out->type = JS_VALUE_OBJECT;
    out->as.object = object;
    return true;
}

bool js_value_make_symbol(js_value_t *out, const char *description)
{
    if (!out)
    {
        return false;
    }
    js_symbol_data_t *sym = (js_symbol_data_t *)calloc(1, sizeof(*sym));
    if (!sym)
    {
        return false;
    }
    if (description)
    {
        sym->description = js_strdup(description);
        if (!sym->description)
        {
            free(sym);
            return false;
        }
    }
    if (!js_value_make_host_object(out, js_symbol_get, NULL, js_symbol_finalize, sym))
    {
        free(sym->description);
        free(sym);
        return false;
    }
    return true;
}

bool js_value_array_set(js_value_t *array_value, size_t index, const js_value_t *value)
{
    if (!array_value || array_value->type != JS_VALUE_ARRAY || !value || !array_value->as.array)
    {
        return false;
    }
    return js_array_set(array_value->as.array, index, value);
}

bool js_value_array_push(js_value_t *array_value, const js_value_t *value)
{
    if (!array_value || array_value->type != JS_VALUE_ARRAY || !value || !array_value->as.array)
    {
        return false;
    }
    return js_array_set(array_value->as.array, array_value->as.array->length, value);
}

void js_value_destroy(js_value_t *value)
{
    if (!value)
    {
        return;
    }
    if (value->type == JS_VALUE_STRING)
    {
        free(value->as.string.data);
        value->as.string.data = NULL;
        value->as.string.len = 0;
    }
    else if (value->type == JS_VALUE_ARRAY)
    {
        js_array_release(value->as.array);
        value->as.array = NULL;
    }
    else if (value->type == JS_VALUE_OBJECT)
    {
        js_object_release(value->as.object);
        value->as.object = NULL;
    }
    else if (value->type == JS_VALUE_FUNCTION)
    {
        js_function_release(value->as.function);
        value->as.function = NULL;
    }
    value->type = JS_VALUE_UNDEFINED;
}

bool js_value_copy(js_value_t *out, const js_value_t *in)
{
    if (!out || !in)
    {
        return false;
    }
    *out = *in;
    if (in->type == JS_VALUE_STRING)
    {
        char *copy = js_strdup_len(in->as.string.data ? in->as.string.data : "", in->as.string.len);
        if (!copy)
        {
            out->type = JS_VALUE_UNDEFINED;
            out->as.string.data = NULL;
            out->as.string.len = 0;
            return false;
        }
        out->as.string.data = copy;
        out->as.string.len = in->as.string.len;
    }
    else if (in->type == JS_VALUE_ARRAY)
    {
        js_array_retain(in->as.array);
    }
    else if (in->type == JS_VALUE_OBJECT)
    {
        js_object_retain(in->as.object);
    }
    else if (in->type == JS_VALUE_FUNCTION)
    {
        js_function_retain(in->as.function);
    }
    return true;
}

double js_nan(void)
{
    volatile double zero = 0.0;
    return zero / zero;
}

bool js_is_nan(double value)
{
    return value != value;
}

bool js_value_is_truthy(const js_value_t *value)
{
    if (!value)
    {
        return false;
    }
    switch (value->type)
    {
        case JS_VALUE_UNDEFINED:
        case JS_VALUE_NULL:
            return false;
        case JS_VALUE_BOOL:
            return value->as.boolean;
        case JS_VALUE_NUMBER:
            return value->as.number != 0.0 && !js_is_nan(value->as.number);
        case JS_VALUE_STRING:
            return value->as.string.len != 0;
        case JS_VALUE_ARRAY:
        case JS_VALUE_OBJECT:
        case JS_VALUE_NATIVE_FN:
        case JS_VALUE_FUNCTION:
            return true;
    }
    return false;
}

static char *js_number_to_string(double value, size_t *out_len)
{
    if (out_len)
    {
        *out_len = 0;
    }

    if (js_is_nan(value))
    {
        if (out_len)
        {
            *out_len = 3;
        }
        return js_strdup_len("NaN", 3);
    }

    if (value > DBL_MAX)
    {
        if (out_len)
        {
            *out_len = 8;
        }
        return js_strdup_len("Infinity", 8);
    }
    if (value < -DBL_MAX)
    {
        if (out_len)
        {
            *out_len = 9;
        }
        return js_strdup_len("-Infinity", 9);
    }

    bool neg = value < 0.0;
    if (neg)
    {
        value = -value;
    }

    uint64_t int_part = (uint64_t)value;
    double frac = value - (double)int_part;

    const int max_frac = 6;
    double rounder = 0.5;
    for (int i = 0; i < max_frac; ++i)
    {
        rounder *= 0.1;
    }
    frac += rounder;
    if (frac >= 1.0)
    {
        uint64_t max_uint64 = ~(uint64_t)0;
        if (int_part < max_uint64)
        {
            int_part += 1;
        }
        frac -= 1.0;
    }

    char *int_digits = (char *)malloc(32);
    if (!int_digits)
    {
        return NULL;
    }
    size_t int_len = 0;
    do
    {
        int digit = (int)(int_part % 10u);
        int_digits[int_len++] = (char)('0' + digit);
        int_part /= 10u;
    } while (int_part > 0u && int_len < 32);

    char *frac_digits = NULL;
    size_t frac_len = 0;
    if (frac > 0.0)
    {
        frac_digits = (char *)malloc((size_t)max_frac);
        if (!frac_digits)
        {
            free(int_digits);
            return NULL;
        }
        double scaled = frac;
        for (int i = 0; i < max_frac; ++i)
        {
            scaled *= 10.0;
            int digit = (int)scaled;
            if (digit < 0) digit = 0;
            if (digit > 9) digit = 9;
            frac_digits[frac_len++] = (char)('0' + digit);
            scaled -= (double)digit;
        }
        while (frac_len > 0 && frac_digits[frac_len - 1] == '0')
        {
            frac_len--;
        }
    }

    size_t total_len = (neg ? 1u : 0u) + int_len + (frac_len ? (1u + frac_len) : 0u);
    char *out = (char *)malloc(total_len + 1);
    if (!out)
    {
        free(int_digits);
        free(frac_digits);
        return NULL;
    }
    size_t pos = 0;
    if (neg)
    {
        out[pos++] = '-';
    }
    for (size_t i = 0; i < int_len; ++i)
    {
        out[pos++] = int_digits[int_len - 1 - i];
    }
    if (frac_len)
    {
        out[pos++] = '.';
        memcpy(out + pos, frac_digits, frac_len);
        pos += frac_len;
    }
    out[pos] = '\0';

    if (out_len)
    {
        *out_len = pos;
    }
    free(int_digits);
    free(frac_digits);
    return out;
}

static bool js_value_is_primitive(const js_value_t *value)
{
    if (!value)
    {
        return false;
    }
    switch (value->type)
    {
        case JS_VALUE_UNDEFINED:
        case JS_VALUE_NULL:
        case JS_VALUE_BOOL:
        case JS_VALUE_NUMBER:
        case JS_VALUE_STRING:
            return true;
        default:
            return false;
    }
}

static bool js_object_get_value(js_runtime_t *rt,
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
    return js_object_get_property(rt, object, name, out, error_message);
}

static bool js_try_object_method(js_runtime_t *rt,
                                 js_object_t *object,
                                 const char *name,
                                 js_value_t *out,
                                 bool *called,
                                 char **error_message)
{
    if (called)
    {
        *called = false;
    }
    if (!out)
    {
        return false;
    }
    js_value_t method = js_value_make_undefined_internal();
    if (!js_object_get_value(rt, object, name, &method, error_message))
    {
        return false;
    }
    if (method.type != JS_VALUE_FUNCTION && method.type != JS_VALUE_NATIVE_FN)
    {
        js_value_destroy(&method);
        *out = js_value_make_undefined_internal();
        return true;
    }
    if (called)
    {
        *called = true;
    }
    js_value_t result = js_value_make_undefined_internal();
    char *err = NULL;
    bool ok = js_call_value(rt, &method, 0, NULL, &result, &err);
    js_value_destroy(&method);
    if (!ok)
    {
        if (error_message)
        {
            *error_message = err ? err : js_strdup("method call failed");
        }
        else
        {
            free(err);
        }
        return false;
    }
    *out = result;
    return true;
}

static bool js_object_to_primitive(js_runtime_t *rt,
                                   js_object_t *object,
                                   js_value_t *out,
                                   char **error_message)
{
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!rt || !object || !out)
    {
        return false;
    }

    bool called = false;
    js_value_t result = js_value_make_undefined_internal();
    if (!js_try_object_method(rt, object, "Symbol.toPrimitive", &result, &called, error_message))
    {
        return false;
    }
    if (called)
    {
        if (js_value_is_primitive(&result))
        {
            *out = result;
            return true;
        }
        js_value_destroy(&result);
        if (error_message)
        {
            *error_message = js_strdup("TypeError: @@toPrimitive must return a primitive");
        }
        return false;
    }

    const char *order[2] = {"toString", "valueOf"};
    for (size_t i = 0; i < 2; ++i)
    {
        called = false;
        result = js_value_make_undefined_internal();
        if (!js_try_object_method(rt, object, order[i], &result, &called, error_message))
        {
            return false;
        }
        if (!called)
        {
            continue;
        }
        if (js_value_is_primitive(&result))
        {
            *out = result;
            return true;
        }
        js_value_destroy(&result);
    }
    if (error_message)
    {
        *error_message = js_strdup("TypeError: cannot convert object to primitive");
    }
    return false;
}

bool js_temp_string_from_value(js_runtime_t *rt,
                               const js_value_t *value,
                               js_temp_string_t *out,
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
    memset(out, 0, sizeof(*out));
    if (!value)
    {
        out->data = js_strdup("undefined");
        if (!out->data)
        {
            return false;
        }
        out->len = strlen(out->data);
        out->owned = true;
        return true;
    }
    if (value->type == JS_VALUE_STRING)
    {
        char *copy = js_strdup_len(value->as.string.data ? value->as.string.data : "", value->as.string.len);
        if (!copy)
        {
            return false;
        }
        out->data = copy;
        out->len = value->as.string.len;
        out->owned = true;
        return true;
    }

    if (value->type == JS_VALUE_BOOL)
    {
        const char *text = value->as.boolean ? "true" : "false";
        out->data = js_strdup(text);
        if (!out->data)
        {
            return false;
        }
        out->len = strlen(out->data);
        out->owned = true;
        return true;
    }

    if (value->type == JS_VALUE_NULL)
    {
        out->data = js_strdup("null");
        if (!out->data)
        {
            return false;
        }
        out->len = strlen(out->data);
        out->owned = true;
        return true;
    }

    if (value->type == JS_VALUE_UNDEFINED)
    {
        out->data = js_strdup("undefined");
        if (!out->data)
        {
            return false;
        }
        out->len = strlen(out->data);
        out->owned = true;
        return true;
    }

    if (value->type == JS_VALUE_NUMBER)
    {
        size_t len = 0;
        out->data = js_number_to_string(value->as.number, &len);
        if (!out->data)
        {
            return false;
        }
        out->len = len;
        out->owned = true;
        return true;
    }

    if (value->type == JS_VALUE_ARRAY)
    {
        out->data = js_strdup("[array]");
        if (!out->data)
        {
            return false;
        }
        out->len = strlen(out->data);
        out->owned = true;
        return true;
    }

    if (value->type == JS_VALUE_OBJECT)
    {
        if (js_object_is_symbol(value->as.object))
        {
            if (error_message)
            {
                *error_message = js_strdup("TypeError: cannot convert Symbol to string");
            }
            return false;
        }
        if (rt)
        {
            js_value_t prim = js_value_make_undefined_internal();
            char *err = NULL;
            if (js_object_to_primitive(rt, value->as.object, &prim, &err))
            {
                bool ok = js_temp_string_from_value(rt, &prim, out, error_message);
                js_value_destroy(&prim);
                return ok;
            }
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
        }
        out->data = js_strdup("[object]");
        if (!out->data)
        {
            return false;
        }
        out->len = strlen(out->data);
        out->owned = true;
        return true;
    }

    out->data = js_strdup("[function]");
    if (!out->data)
    {
        return false;
    }
    out->len = strlen(out->data);
    out->owned = true;
    return true;
}

void js_temp_string_release(js_temp_string_t *temp)
{
    if (!temp)
    {
        return;
    }
    if (temp->owned)
    {
        free(temp->data);
    }
    temp->data = NULL;
    temp->len = 0;
    temp->owned = false;
}

bool js_value_strict_equal(const js_value_t *a, const js_value_t *b)
{
    if (!a || !b)
    {
        return false;
    }
    if (a->type != b->type)
    {
        return false;
    }
    switch (a->type)
    {
        case JS_VALUE_UNDEFINED:
        case JS_VALUE_NULL:
            return true;
        case JS_VALUE_BOOL:
            return a->as.boolean == b->as.boolean;
        case JS_VALUE_NUMBER:
            return a->as.number == b->as.number;
        case JS_VALUE_STRING:
            if (a->as.string.len != b->as.string.len)
            {
                return false;
            }
            if (a->as.string.len == 0)
            {
                return true;
            }
            return memcmp(a->as.string.data, b->as.string.data, a->as.string.len) == 0;
        case JS_VALUE_NATIVE_FN:
            return a->as.native.fn == b->as.native.fn && a->as.native.user_data == b->as.native.user_data;
        case JS_VALUE_ARRAY:
            return a->as.array == b->as.array;
        case JS_VALUE_OBJECT:
            return a->as.object == b->as.object;
        case JS_VALUE_FUNCTION:
            return a->as.function == b->as.function;
    }
    return false;
}

bool js_parse_number_text(const char *text, double *out)
{
    if (!out)
    {
        return false;
    }
    if (!text)
    {
        *out = 0.0;
        return true;
    }
    const char *s = text;
    while (isspace((unsigned char)*s))
    {
        ++s;
    }
    if (*s == '\0')
    {
        *out = 0.0;
        return true;
    }
    int sign = 1;
    if (*s == '+' || *s == '-')
    {
        if (*s == '-')
        {
            sign = -1;
        }
        ++s;
    }
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
    {
        s += 2;
        int digit = js_hex_value(*s);
        if (digit < 0)
        {
            return false;
        }
        double value = 0.0;
        while (digit >= 0)
        {
            value = value * 16.0 + (double)digit;
            ++s;
            digit = js_hex_value(*s);
        }
        while (isspace((unsigned char)*s))
        {
            ++s;
        }
        if (*s != '\0')
        {
            return false;
        }
        *out = value * (double)sign;
        return true;
    }
    bool had_digit = false;
    double value = 0.0;
    while (isdigit((unsigned char)*s))
    {
        had_digit = true;
        value = value * 10.0 + (double)(*s - '0');
        ++s;
    }
    if (*s == '.')
    {
        ++s;
        double place = 0.1;
        while (isdigit((unsigned char)*s))
        {
            had_digit = true;
            value += (double)(*s - '0') * place;
            place *= 0.1;
            ++s;
        }
    }
    if (!had_digit)
    {
        return false;
    }
    if (*s == 'e' || *s == 'E')
    {
        ++s;
        int exp_sign = 1;
        if (*s == '+' || *s == '-')
        {
            if (*s == '-')
            {
                exp_sign = -1;
            }
            ++s;
        }
        if (!isdigit((unsigned char)*s))
        {
            return false;
        }
        int exp = 0;
        while (isdigit((unsigned char)*s))
        {
            exp = exp * 10 + (*s - '0');
            ++s;
        }
        exp *= exp_sign;

        double pow10 = 1.0;
        int e = exp < 0 ? -exp : exp;
        double base = 10.0;
        while (e)
        {
            if (e & 1)
            {
                pow10 *= base;
            }
            base *= base;
            e >>= 1;
        }

        if (exp < 0)
        {
            value /= pow10;
        }
        else
        {
            value *= pow10;
        }
    }
    while (isspace((unsigned char)*s))
    {
        ++s;
    }
    if (*s != '\0')
    {
        return false;
    }
    *out = value * (double)sign;
    return true;
}

double js_value_to_number(const js_value_t *value, bool *ok_out)
{
    if (ok_out)
    {
        *ok_out = true;
    }
    if (!value)
    {
        if (ok_out)
        {
            *ok_out = false;
        }
        return js_nan();
    }
    switch (value->type)
    {
        case JS_VALUE_NUMBER:
            return value->as.number;
        case JS_VALUE_BOOL:
            return value->as.boolean ? 1.0 : 0.0;
        case JS_VALUE_NULL:
            return 0.0;
        case JS_VALUE_UNDEFINED:
            if (ok_out)
            {
                *ok_out = false;
            }
            return js_nan();
        case JS_VALUE_STRING:
        {
            double out = 0.0;
            if (!js_parse_number_text(value->as.string.data ? value->as.string.data : "", &out))
            {
                if (ok_out)
                {
                    *ok_out = false;
                }
                return js_nan();
            }
            return out;
        }
        case JS_VALUE_ARRAY:
        case JS_VALUE_OBJECT:
        case JS_VALUE_NATIVE_FN:
        case JS_VALUE_FUNCTION:
            if (ok_out)
            {
                *ok_out = false;
            }
            return js_nan();
    }
    if (ok_out)
    {
        *ok_out = false;
    }
    return js_nan();
}

bool js_value_loose_equal(const js_value_t *a, const js_value_t *b)
{
    if (!a || !b)
    {
        return false;
    }
    if (a->type == b->type)
    {
        return js_value_strict_equal(a, b);
    }
    if ((a->type == JS_VALUE_NULL && b->type == JS_VALUE_UNDEFINED) ||
        (a->type == JS_VALUE_UNDEFINED && b->type == JS_VALUE_NULL))
    {
        return true;
    }
    if (a->type == JS_VALUE_BOOL)
    {
        bool ok = false;
        double an = js_value_to_number(a, &ok);
        double bn = js_value_to_number(b, NULL);
        if (!ok || js_is_nan(an) || js_is_nan(bn))
        {
            return false;
        }
        return an == bn;
    }
    if (b->type == JS_VALUE_BOOL)
    {
        bool ok = false;
        double an = js_value_to_number(a, NULL);
        double bn = js_value_to_number(b, &ok);
        if (!ok || js_is_nan(an) || js_is_nan(bn))
        {
            return false;
        }
        return an == bn;
    }
    if ((a->type == JS_VALUE_NUMBER && b->type == JS_VALUE_STRING) ||
        (a->type == JS_VALUE_STRING && b->type == JS_VALUE_NUMBER))
    {
        double an = js_value_to_number(a, NULL);
        double bn = js_value_to_number(b, NULL);
        if (js_is_nan(an) || js_is_nan(bn))
        {
            return false;
        }
        return an == bn;
    }
    return false;
}
