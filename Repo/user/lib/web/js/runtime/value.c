#include "web/js/runtime/runtime_internal.h"

#include "ctype.h"
#include "float.h"
#include "math.h"
#include "stdio.h"
#include "libc.h"

typedef struct
{
    char *description;
} js_symbol_data_t;

struct js_bigint
{
    bool negative;
    uint32_t *digits;
    size_t length;
};

#define JS_BIGINT_BASE 1000000000u
#define JS_BIGINT_BASE_DIGITS 9

static double js_trunc_local(double value)
{
    return (value < 0.0) ? ceil(value) : floor(value);
}

static js_bigint_t *js_bigint_new(size_t length)
{
    js_bigint_t *value = (js_bigint_t *)js_calloc(1, sizeof(*value));
    if (!value)
    {
        return NULL;
    }
    if (length)
    {
        value->digits = (uint32_t *)js_calloc(length, sizeof(uint32_t));
        if (!value->digits)
        {
            js_free(value);
            return NULL;
        }
        value->length = length;
    }
    return value;
}

static void js_bigint_free(js_bigint_t *value)
{
    if (!value)
    {
        return;
    }
    js_free(value->digits);
    js_free(value);
}

static void js_bigint_trim(js_bigint_t *value)
{
    if (!value)
    {
        return;
    }
    while (value->length > 0 && value->digits[value->length - 1] == 0)
    {
        value->length--;
    }
    if (value->length == 0)
    {
        value->negative = false;
    }
}

static js_bigint_t *js_bigint_from_u64(uint64_t input)
{
    if (input == 0)
    {
        return js_bigint_new(0);
    }
    uint64_t tmp = input;
    size_t count = 0;
    while (tmp > 0)
    {
        tmp /= JS_BIGINT_BASE;
        count++;
    }
    js_bigint_t *value = js_bigint_new(count);
    if (!value)
    {
        return NULL;
    }
    size_t index = 0;
    while (input > 0)
    {
        value->digits[index++] = (uint32_t)(input % JS_BIGINT_BASE);
        input /= JS_BIGINT_BASE;
    }
    return value;
}

static js_bigint_t *js_bigint_clone_internal(const js_bigint_t *value)
{
    if (!value)
    {
        return NULL;
    }
    js_bigint_t *copy = js_bigint_new(value->length);
    if (!copy)
    {
        return NULL;
    }
    copy->negative = value->negative;
    if (value->length)
    {
        memcpy(copy->digits, value->digits, value->length * sizeof(uint32_t));
    }
    return copy;
}

static int js_bigint_compare_abs(const js_bigint_t *a, const js_bigint_t *b)
{
    if (!a || !b)
    {
        return 0;
    }
    if (a->length < b->length)
    {
        return -1;
    }
    if (a->length > b->length)
    {
        return 1;
    }
    for (size_t i = a->length; i > 0; --i)
    {
        uint32_t da = a->digits[i - 1];
        uint32_t db = b->digits[i - 1];
        if (da < db)
        {
            return -1;
        }
        if (da > db)
        {
            return 1;
        }
    }
    return 0;
}

static js_bigint_t *js_bigint_add_abs(const js_bigint_t *a, const js_bigint_t *b)
{
    size_t len = (a->length > b->length) ? a->length : b->length;
    js_bigint_t *out = js_bigint_new(len + 1);
    if (!out)
    {
        return NULL;
    }
    uint64_t carry = 0;
    for (size_t i = 0; i < len; ++i)
    {
        uint64_t sum = carry;
        if (i < a->length)
        {
            sum += a->digits[i];
        }
        if (i < b->length)
        {
            sum += b->digits[i];
        }
        out->digits[i] = (uint32_t)(sum % JS_BIGINT_BASE);
        carry = sum / JS_BIGINT_BASE;
    }
    if (carry)
    {
        out->digits[len] = (uint32_t)carry;
        out->length = len + 1;
    }
    else
    {
        out->length = len;
    }
    return out;
}

static js_bigint_t *js_bigint_sub_abs(const js_bigint_t *a, const js_bigint_t *b)
{
    js_bigint_t *out = js_bigint_new(a->length);
    if (!out)
    {
        return NULL;
    }
    int64_t carry = 0;
    for (size_t i = 0; i < a->length; ++i)
    {
        int64_t diff = (int64_t)a->digits[i] - carry;
        if (i < b->length)
        {
            diff -= b->digits[i];
        }
        if (diff < 0)
        {
            diff += JS_BIGINT_BASE;
            carry = 1;
        }
        else
        {
            carry = 0;
        }
        out->digits[i] = (uint32_t)diff;
    }
    out->length = a->length;
    js_bigint_trim(out);
    return out;
}

static js_bigint_t *js_bigint_mul_abs(const js_bigint_t *a, const js_bigint_t *b)
{
    if (a->length == 0 || b->length == 0)
    {
        return js_bigint_new(0);
    }
    js_bigint_t *out = js_bigint_new(a->length + b->length);
    if (!out)
    {
        return NULL;
    }
    for (size_t i = 0; i < a->length; ++i)
    {
        uint64_t carry = 0;
        for (size_t j = 0; j < b->length; ++j)
        {
            uint64_t cur = out->digits[i + j] + carry;
            cur += (uint64_t)a->digits[i] * (uint64_t)b->digits[j];
            out->digits[i + j] = (uint32_t)(cur % JS_BIGINT_BASE);
            carry = cur / JS_BIGINT_BASE;
        }
        if (carry)
        {
            out->digits[i + b->length] += (uint32_t)carry;
        }
    }
    out->length = a->length + b->length;
    js_bigint_trim(out);
    return out;
}

static bool js_bigint_mul_small(js_bigint_t *value, uint32_t mul)
{
    if (!value)
    {
        return false;
    }
    if (value->length == 0 || mul == 0)
    {
        value->length = 0;
        value->negative = false;
        return true;
    }
    uint64_t carry = 0;
    for (size_t i = 0; i < value->length; ++i)
    {
        uint64_t cur = (uint64_t)value->digits[i] * (uint64_t)mul + carry;
        value->digits[i] = (uint32_t)(cur % JS_BIGINT_BASE);
        carry = cur / JS_BIGINT_BASE;
    }
    if (carry)
    {
        size_t new_len = value->length + 1;
        uint32_t *digits = (uint32_t *)js_realloc(value->digits, new_len * sizeof(uint32_t));
        if (!digits)
        {
            return false;
        }
        digits[value->length] = (uint32_t)carry;
        value->digits = digits;
        value->length = new_len;
    }
    return true;
}

static bool js_bigint_add_small(js_bigint_t *value, uint32_t add)
{
    if (!value)
    {
        return false;
    }
    if (value->length == 0)
    {
        value->digits = (uint32_t *)js_calloc(1, sizeof(uint32_t));
        if (!value->digits)
        {
            return false;
        }
        value->length = 1;
        value->digits[0] = add;
        return true;
    }
    uint64_t cur = (uint64_t)value->digits[0] + add;
    value->digits[0] = (uint32_t)(cur % JS_BIGINT_BASE);
    uint64_t carry = cur / JS_BIGINT_BASE;
    size_t i = 1;
    while (carry && i < value->length)
    {
        cur = (uint64_t)value->digits[i] + carry;
        value->digits[i] = (uint32_t)(cur % JS_BIGINT_BASE);
        carry = cur / JS_BIGINT_BASE;
        i++;
    }
    if (carry)
    {
        size_t new_len = value->length + 1;
        uint32_t *digits = (uint32_t *)js_realloc(value->digits, new_len * sizeof(uint32_t));
        if (!digits)
        {
            return false;
        }
        digits[value->length] = (uint32_t)carry;
        value->digits = digits;
        value->length = new_len;
    }
    return true;
}

static js_bigint_t *js_bigint_from_string_internal(const char *text, int base, bool *ok_out)
{
    if (ok_out)
    {
        *ok_out = false;
    }
    if (!text || base < 2 || base > 36)
    {
        return NULL;
    }
    js_bigint_t *value = js_bigint_new(0);
    if (!value)
    {
        return NULL;
    }
    bool had_digit = false;
    for (const char *p = text; *p; ++p)
    {
        if (*p == '_')
        {
            continue;
        }
        int digit = -1;
        if (*p >= '0' && *p <= '9')
        {
            digit = *p - '0';
        }
        else if (*p >= 'a' && *p <= 'z')
        {
            digit = *p - 'a' + 10;
        }
        else if (*p >= 'A' && *p <= 'Z')
        {
            digit = *p - 'A' + 10;
        }
        if (digit < 0 || digit >= base)
        {
            js_bigint_free(value);
            return NULL;
        }
        had_digit = true;
        if (!js_bigint_mul_small(value, (uint32_t)base) ||
            !js_bigint_add_small(value, (uint32_t)digit))
        {
            js_bigint_free(value);
            return NULL;
        }
    }
    if (!had_digit)
    {
        js_bigint_free(value);
        return NULL;
    }
    if (ok_out)
    {
        *ok_out = true;
    }
    return value;
}

static bool js_bigint_divmod_small(const js_bigint_t *a,
                                   uint32_t divisor,
                                   js_bigint_t **out_quot,
                                   uint32_t *out_rem)
{
    if (!a || divisor == 0)
    {
        return false;
    }
    js_bigint_t *quot = js_bigint_new(a->length);
    if (!quot)
    {
        return false;
    }
    uint64_t rem = 0;
    for (size_t i = a->length; i > 0; --i)
    {
        uint64_t cur = rem * JS_BIGINT_BASE + a->digits[i - 1];
        uint64_t q = cur / divisor;
        rem = cur % divisor;
        quot->digits[i - 1] = (uint32_t)q;
    }
    quot->length = a->length;
    js_bigint_trim(quot);
    if (out_quot)
    {
        *out_quot = quot;
    }
    else
    {
        js_bigint_free(quot);
    }
    if (out_rem)
    {
        *out_rem = (uint32_t)rem;
    }
    return true;
}

static bool js_bigint_is_small(const js_bigint_t *value, uint32_t *out)
{
    if (!value)
    {
        return false;
    }
    if (value->length == 0)
    {
        if (out)
        {
            *out = 0;
        }
        return true;
    }
    if (value->length > 1)
    {
        return false;
    }
    if (out)
    {
        *out = value->digits[0];
    }
    return true;
}

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
    js_free(sym->description);
    js_free(sym);
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
    js_object_t *object = (js_object_t *)js_calloc(1, sizeof(*object));
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
    js_symbol_data_t *sym = (js_symbol_data_t *)js_calloc(1, sizeof(*sym));
    if (!sym)
    {
        return false;
    }
    if (description)
    {
        sym->description = js_strdup(description);
        if (!sym->description)
        {
            js_free(sym);
            return false;
        }
    }
    if (!js_value_make_host_object(out, js_symbol_get, NULL, js_symbol_finalize, sym))
    {
        js_free(sym->description);
        js_free(sym);
        return false;
    }
    return true;
}

bool js_value_make_bigint(js_value_t *out, const char *text, int base)
{
    if (!out)
    {
        return false;
    }
    bool ok = false;
    js_bigint_t *value = js_bigint_from_string_internal(text, base, &ok);
    if (!value || !ok)
    {
        js_bigint_free(value);
        return false;
    }
    out->type = JS_VALUE_BIGINT;
    out->as.bigint = value;
    return true;
}

bool js_value_make_bigint_from_int64(js_value_t *out, int64_t value)
{
    if (!out)
    {
        return false;
    }
    uint64_t abs_value = (value < 0) ? (uint64_t)(-(value + 1)) + 1u : (uint64_t)value;
    js_bigint_t *bigint = js_bigint_from_u64(abs_value);
    if (!bigint)
    {
        return false;
    }
    bigint->negative = (value < 0 && bigint->length > 0);
    out->type = JS_VALUE_BIGINT;
    out->as.bigint = bigint;
    return true;
}

js_bigint_t *js_bigint_clone(const js_bigint_t *value)
{
    return js_bigint_clone_internal(value);
}

void js_bigint_destroy(js_bigint_t *value)
{
    js_bigint_free(value);
}

bool js_bigint_is_zero(const js_bigint_t *value)
{
    return !value || value->length == 0;
}

int js_bigint_compare(const js_bigint_t *a, const js_bigint_t *b)
{
    if (!a || !b)
    {
        return 0;
    }
    if (a->negative != b->negative)
    {
        return a->negative ? -1 : 1;
    }
    int cmp = js_bigint_compare_abs(a, b);
    return a->negative ? -cmp : cmp;
}

js_bigint_t *js_bigint_add(const js_bigint_t *a, const js_bigint_t *b)
{
    if (!a || !b)
    {
        return NULL;
    }
    if (a->negative == b->negative)
    {
        js_bigint_t *sum = js_bigint_add_abs(a, b);
        if (sum)
        {
            sum->negative = a->negative;
        }
        return sum;
    }
    int cmp = js_bigint_compare_abs(a, b);
    if (cmp == 0)
    {
        return js_bigint_new(0);
    }
    if (cmp > 0)
    {
        js_bigint_t *diff = js_bigint_sub_abs(a, b);
        if (diff)
        {
            diff->negative = a->negative;
        }
        return diff;
    }
    js_bigint_t *diff = js_bigint_sub_abs(b, a);
    if (diff)
    {
        diff->negative = b->negative;
    }
    return diff;
}

js_bigint_t *js_bigint_sub(const js_bigint_t *a, const js_bigint_t *b)
{
    if (!a || !b)
    {
        return NULL;
    }
    js_bigint_t neg_b = *b;
    neg_b.negative = !b->negative;
    return js_bigint_add(a, &neg_b);
}

js_bigint_t *js_bigint_mul(const js_bigint_t *a, const js_bigint_t *b)
{
    if (!a || !b)
    {
        return NULL;
    }
    js_bigint_t *prod = js_bigint_mul_abs(a, b);
    if (!prod)
    {
        return NULL;
    }
    prod->negative = (a->negative != b->negative) && prod->length > 0;
    return prod;
}

bool js_bigint_divmod(const js_bigint_t *a,
                      const js_bigint_t *b,
                      js_bigint_t **out_quot,
                      js_bigint_t **out_rem,
                      char **error_message)
{
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!a || !b || js_bigint_is_zero(b))
    {
        if (error_message)
        {
            *error_message = js_strdup("RangeError: division by zero");
        }
        return false;
    }
    uint32_t divisor = 0;
    if (!js_bigint_is_small(b, &divisor))
    {
        if (error_message)
        {
            *error_message = js_strdup("RangeError: bigint divisor too large");
        }
        return false;
    }
    js_bigint_t *quot = NULL;
    uint32_t rem = 0;
    if (!js_bigint_divmod_small(a, divisor, &quot, &rem))
    {
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }
    quot->negative = (a->negative != b->negative) && quot->length > 0;
    js_bigint_t *rem_val = js_bigint_from_u64(rem);
    if (!rem_val)
    {
        js_bigint_free(quot);
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }
    rem_val->negative = a->negative && rem_val->length > 0;
    if (out_quot)
    {
        *out_quot = quot;
    }
    else
    {
        js_bigint_free(quot);
    }
    if (out_rem)
    {
        *out_rem = rem_val;
    }
    else
    {
        js_bigint_free(rem_val);
    }
    return true;
}

js_bigint_t *js_bigint_pow(const js_bigint_t *base,
                           const js_bigint_t *exp,
                           char **error_message)
{
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!base || !exp)
    {
        return NULL;
    }
    if (exp->negative)
    {
        if (error_message)
        {
            *error_message = js_strdup("RangeError: exponent must be non-negative");
        }
        return NULL;
    }
    uint32_t exp_value = 0;
    if (!js_bigint_is_small(exp, &exp_value))
    {
        if (error_message)
        {
            *error_message = js_strdup("RangeError: exponent too large");
        }
        return NULL;
    }
    js_bigint_t *result = js_bigint_from_u64(1);
    if (!result)
    {
        return NULL;
    }
    js_bigint_t *base_pow = js_bigint_clone_internal(base);
    if (!base_pow)
    {
        js_bigint_free(result);
        return NULL;
    }
    uint32_t exp_work = exp_value;
    while (exp_work > 0)
    {
        if (exp_work & 1u)
        {
            js_bigint_t *tmp = js_bigint_mul(result, base_pow);
            js_bigint_free(result);
            if (!tmp)
            {
                js_bigint_free(base_pow);
                return NULL;
            }
            result = tmp;
        }
        exp_work >>= 1u;
        if (exp_work)
        {
            js_bigint_t *tmp = js_bigint_mul(base_pow, base_pow);
            js_bigint_free(base_pow);
            if (!tmp)
            {
                js_bigint_free(result);
                return NULL;
            }
            base_pow = tmp;
        }
    }
    js_bigint_free(base_pow);
    return result;
}

char *js_bigint_to_string(const js_bigint_t *value)
{
    if (!value || value->length == 0)
    {
        return js_strdup("0");
    }
    size_t buf_len = value->length * JS_BIGINT_BASE_DIGITS + 2;
    char *buf = (char *)js_malloc(buf_len);
    if (!buf)
    {
        return NULL;
    }
    size_t pos = 0;
    if (value->negative)
    {
        buf[pos++] = '-';
    }
    size_t idx = value->length;
    idx--;
    pos += (size_t)snprintf(buf + pos, buf_len - pos, "%u", value->digits[idx]);
    while (idx-- > 0)
    {
        pos += (size_t)snprintf(buf + pos, buf_len - pos, "%09u", value->digits[idx]);
    }
    buf[pos] = '\0';
    return buf;
}

double js_bigint_to_double(const js_bigint_t *value)
{
    if (!value || value->length == 0)
    {
        return 0.0;
    }
    double result = 0.0;
    for (size_t i = value->length; i > 0; --i)
    {
        result = result * (double)JS_BIGINT_BASE + (double)value->digits[i - 1];
    }
    return value->negative ? -result : result;
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
        js_free(value->as.string.data);
        value->as.string.data = NULL;
        value->as.string.len = 0;
    }
    else if (value->type == JS_VALUE_BIGINT)
    {
        js_bigint_free(value->as.bigint);
        value->as.bigint = NULL;
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
    else if (in->type == JS_VALUE_BIGINT)
    {
        js_bigint_t *copy = js_bigint_clone_internal(in->as.bigint);
        if (!copy)
        {
            out->type = JS_VALUE_UNDEFINED;
            out->as.bigint = NULL;
            return false;
        }
        out->as.bigint = copy;
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
        case JS_VALUE_BIGINT:
            return value->as.bigint && !js_bigint_is_zero(value->as.bigint);
        case JS_VALUE_STRING:
            return value->as.string.len != 0;
        case JS_VALUE_ARRAY:
            return true;
        case JS_VALUE_OBJECT:
            return !js_value_is_html_dda(value);
        case JS_VALUE_NATIVE_FN:
        case JS_VALUE_FUNCTION:
            return true;
    }
    return false;
}

bool js_value_is_nullish(const js_value_t *value)
{
    if (!value)
    {
        return true;
    }
    return value->type == JS_VALUE_NULL || value->type == JS_VALUE_UNDEFINED;
}

bool js_value_is_html_dda(const js_value_t *value)
{
    return value && value->type == JS_VALUE_OBJECT && value->as.object &&
           value->as.object->is_html_dda;
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

    char *int_digits = (char *)js_malloc(32);
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
        frac_digits = (char *)js_malloc((size_t)max_frac);
        if (!frac_digits)
        {
            js_free(int_digits);
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
    char *out = (char *)js_malloc(total_len + 1);
    if (!out)
    {
        js_free(int_digits);
        js_free(frac_digits);
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
    js_free(int_digits);
    js_free(frac_digits);
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
        case JS_VALUE_BIGINT:
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
            js_free(err);
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

    if (value->type == JS_VALUE_BIGINT)
    {
        out->data = js_bigint_to_string(value->as.bigint);
        if (!out->data)
        {
            return false;
        }
        out->len = strlen(out->data);
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
                    js_free(err);
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
        js_free(temp->data);
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
        case JS_VALUE_BIGINT:
            return js_bigint_compare(a->as.bigint, b->as.bigint) == 0;
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
        case JS_VALUE_BIGINT:
            return js_bigint_to_double(value->as.bigint);
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

bool js_value_to_bigint(js_runtime_t *rt,
                        const js_value_t *value,
                        js_bigint_t **out,
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
    *out = NULL;
    if (!value)
    {
        if (error_message)
        {
            *error_message = js_strdup("TypeError: cannot convert undefined to BigInt");
        }
        return false;
    }
    if (value->type == JS_VALUE_BIGINT)
    {
        js_bigint_t *copy = js_bigint_clone_internal(value->as.bigint);
        if (!copy)
        {
            if (error_message)
            {
                *error_message = js_strdup("allocation failed");
            }
            return false;
        }
        *out = copy;
        return true;
    }
    if (value->type == JS_VALUE_BOOL)
    {
        js_bigint_t *big = js_bigint_from_u64(value->as.boolean ? 1u : 0u);
        if (!big)
        {
            if (error_message)
            {
                *error_message = js_strdup("allocation failed");
            }
            return false;
        }
        *out = big;
        return true;
    }
    if (value->type == JS_VALUE_NUMBER)
    {
        if (js_is_nan(value->as.number) || value->as.number == INFINITY || value->as.number == -INFINITY)
        {
            if (error_message)
            {
                *error_message = js_strdup("RangeError: invalid number");
            }
            return false;
        }
        double trunc = js_trunc_local(value->as.number);
        if (trunc != value->as.number)
        {
            if (error_message)
            {
                *error_message = js_strdup("RangeError: invalid number");
            }
            return false;
        }
        if (trunc > (double)INT64_MAX || trunc < (double)INT64_MIN)
        {
            if (error_message)
            {
                *error_message = js_strdup("RangeError: bigint out of range");
            }
            return false;
        }
        int64_t ival = (int64_t)trunc;
        uint64_t abs_val = (ival < 0) ? (uint64_t)(-(ival + 1)) + 1u : (uint64_t)ival;
        js_bigint_t *big = js_bigint_from_u64(abs_val);
        if (!big)
        {
            if (error_message)
            {
                *error_message = js_strdup("allocation failed");
            }
            return false;
        }
        big->negative = (ival < 0 && big->length > 0);
        *out = big;
        return true;
    }
    if (value->type == JS_VALUE_STRING)
    {
        const char *text = value->as.string.data ? value->as.string.data : "";
        size_t len = value->as.string.len;
        while (len && isspace((unsigned char)text[0]))
        {
            text++;
            len--;
        }
        while (len && isspace((unsigned char)text[len - 1]))
        {
            len--;
        }
        if (len == 0)
        {
            if (error_message)
            {
                *error_message = js_strdup("SyntaxError: invalid BigInt literal");
            }
            return false;
        }
        bool negative = false;
        if (text[0] == '+' || text[0] == '-')
        {
            negative = (text[0] == '-');
            text++;
            len--;
        }
        int base = 10;
        if (len > 1 && text[0] == '0' && (text[1] == 'x' || text[1] == 'X'))
        {
            base = 16;
            text += 2;
            len -= 2;
        }
        else if (len > 1 && text[0] == '0' && (text[1] == 'b' || text[1] == 'B'))
        {
            base = 2;
            text += 2;
            len -= 2;
        }
        else if (len > 1 && text[0] == '0' && (text[1] == 'o' || text[1] == 'O'))
        {
            base = 8;
            text += 2;
            len -= 2;
        }
        char *buf = js_strdup_len(text, len);
        if (!buf)
        {
            if (error_message)
            {
                *error_message = js_strdup("allocation failed");
            }
            return false;
        }
        bool ok = false;
        js_bigint_t *big = js_bigint_from_string_internal(buf, base, &ok);
        js_free(buf);
        if (!big || !ok)
        {
            js_bigint_free(big);
            if (error_message)
            {
                *error_message = js_strdup("SyntaxError: invalid BigInt literal");
            }
            return false;
        }
        big->negative = negative && big->length > 0;
        *out = big;
        return true;
    }
    if (value->type == JS_VALUE_NULL || value->type == JS_VALUE_UNDEFINED)
    {
        if (error_message)
        {
            *error_message = js_strdup("TypeError: cannot convert undefined or null to BigInt");
        }
        return false;
    }
    if (value->type == JS_VALUE_OBJECT && rt)
    {
        js_value_t prim = js_value_make_undefined_internal();
        char *err = NULL;
        if (!js_object_to_primitive(rt, value->as.object, &prim, &err))
        {
            if (err)
            {
                if (error_message)
                {
                    *error_message = err;
                }
                else
                {
                    js_free(err);
                }
            }
            return false;
        }
        bool ok = js_value_to_bigint(rt, &prim, out, error_message);
        js_value_destroy(&prim);
        return ok;
    }
    if (error_message)
    {
        *error_message = js_strdup("TypeError: cannot convert to BigInt");
    }
    return false;
}

bool js_value_loose_equal(const js_value_t *a, const js_value_t *b)
{
    if (!a || !b)
    {
        return false;
    }
    if (js_value_is_html_dda(a) && (b->type == JS_VALUE_NULL || b->type == JS_VALUE_UNDEFINED))
    {
        return true;
    }
    if (js_value_is_html_dda(b) && (a->type == JS_VALUE_NULL || a->type == JS_VALUE_UNDEFINED))
    {
        return true;
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
    if ((a->type == JS_VALUE_BIGINT && (b->type == JS_VALUE_NUMBER || b->type == JS_VALUE_STRING)) ||
        (b->type == JS_VALUE_BIGINT && (a->type == JS_VALUE_NUMBER || a->type == JS_VALUE_STRING)))
    {
        const js_value_t *big = (a->type == JS_VALUE_BIGINT) ? a : b;
        const js_value_t *other = (a->type == JS_VALUE_BIGINT) ? b : a;
        bool ok = true;
        double num = js_value_to_number(other, &ok);
        if (!ok || js_is_nan(num))
        {
            return false;
        }
        double intpart = js_trunc_local(num);
        if (intpart != num)
        {
            return false;
        }
        double bignum = js_bigint_to_double(big->as.bigint);
        return bignum == intpart;
    }
    return false;
}
