#include "web/js/runtime/runtime_internal.h"
#include "libc.h"

typedef struct
{
    bool exists;
    js_value_t value;
    bool writable;
    bool enumerable;
    bool configurable;
} js_prop_desc_t;

static bool js_append_utf8(char *buf, size_t cap, size_t *len, unsigned int code)
{
    if (!buf || !len)
    {
        return false;
    }
    if (code <= 0x7F)
    {
        if (*len + 1 > cap)
        {
            return false;
        }
        buf[(*len)++] = (char)code;
        return true;
    }
    if (code <= 0x7FF)
    {
        if (*len + 2 > cap)
        {
            return false;
        }
        buf[(*len)++] = (char)(0xC0 | (code >> 6));
        buf[(*len)++] = (char)(0x80 | (code & 0x3F));
        return true;
    }
    if (*len + 3 > cap)
    {
        return false;
    }
    buf[(*len)++] = (char)(0xE0 | (code >> 12));
    buf[(*len)++] = (char)(0x80 | ((code >> 6) & 0x3F));
    buf[(*len)++] = (char)(0x80 | (code & 0x3F));
    return true;
}

static bool js_utf8_next(const char *data, size_t len, size_t *index, unsigned int *out)
{
    if (!data || !index || !out || *index >= len)
    {
        return false;
    }
    unsigned char c = (unsigned char)data[*index];
    if (c < 0x80)
    {
        *out = c;
        (*index)++;
        return true;
    }
    if ((c & 0xE0) == 0xC0 && *index + 1 < len)
    {
        unsigned char c1 = (unsigned char)data[*index + 1];
        if ((c1 & 0xC0) == 0x80)
        {
            *out = ((unsigned int)(c & 0x1F) << 6) | (unsigned int)(c1 & 0x3F);
            *index += 2;
            return true;
        }
    }
    if ((c & 0xF0) == 0xE0 && *index + 2 < len)
    {
        unsigned char c1 = (unsigned char)data[*index + 1];
        unsigned char c2 = (unsigned char)data[*index + 2];
        if ((c1 & 0xC0) == 0x80 && (c2 & 0xC0) == 0x80)
        {
            *out = ((unsigned int)(c & 0x0F) << 12) |
                   ((unsigned int)(c1 & 0x3F) << 6) |
                   (unsigned int)(c2 & 0x3F);
            *index += 3;
            return true;
        }
    }
    if ((c & 0xF8) == 0xF0 && *index + 3 < len)
    {
        unsigned char c1 = (unsigned char)data[*index + 1];
        unsigned char c2 = (unsigned char)data[*index + 2];
        unsigned char c3 = (unsigned char)data[*index + 3];
        if ((c1 & 0xC0) == 0x80 && (c2 & 0xC0) == 0x80 && (c3 & 0xC0) == 0x80)
        {
            *out = ((unsigned int)(c & 0x07) << 18) |
                   ((unsigned int)(c1 & 0x3F) << 12) |
                   ((unsigned int)(c2 & 0x3F) << 6) |
                   (unsigned int)(c3 & 0x3F);
            *index += 4;
            return true;
        }
    }
    *out = c;
    (*index)++;
    return true;
}

static bool js_is_unescaped_char(unsigned int code)
{
    if ((code >= 'A' && code <= 'Z') ||
        (code >= 'a' && code <= 'z') ||
        (code >= '0' && code <= '9'))
    {
        return true;
    }
    switch (code)
    {
        case '@':
        case '*':
        case '_':
        case '+':
        case '-':
        case '.':
        case '/':
            return true;
        default:
            return false;
    }
}

static bool js_append_escape_hex(char *buf, size_t cap, size_t *len, unsigned int code, bool wide)
{
    static const char hex[] = "0123456789ABCDEF";
    if (!buf || !len)
    {
        return false;
    }
    if (wide)
    {
        if (*len + 6 > cap)
        {
            return false;
        }
        buf[(*len)++] = '%';
        buf[(*len)++] = 'u';
        buf[(*len)++] = hex[(code >> 12) & 0xF];
        buf[(*len)++] = hex[(code >> 8) & 0xF];
        buf[(*len)++] = hex[(code >> 4) & 0xF];
        buf[(*len)++] = hex[code & 0xF];
        return true;
    }
    if (*len + 3 > cap)
    {
        return false;
    }
    buf[(*len)++] = '%';
    buf[(*len)++] = hex[(code >> 4) & 0xF];
    buf[(*len)++] = hex[code & 0xF];
    return true;
}

static const js_function_decl_t *js_builtin_function_def(const js_function_t *fn)
{
    if (!fn)
    {
        return NULL;
    }
    return fn->is_expr ? (const js_function_decl_t *)fn->expr : fn->decl;
}

static size_t js_builtin_function_length(const js_function_t *fn)
{
    const js_function_decl_t *def = js_builtin_function_def(fn);
    return def ? def->param_count : 0;
}

static bool js_builtin_get_prop_desc(js_runtime_t *rt,
                                     const js_value_t *obj,
                                     const char *name,
                                     js_prop_desc_t *out,
                                     char **error_message)
{
    if (!out)
    {
        return false;
    }
    out->exists = false;
    out->value = js_value_make_undefined_internal();
    out->writable = true;
    out->enumerable = true;
    out->configurable = true;

    if (!obj || !name)
    {
        if (error_message)
        {
            *error_message = js_strdup("invalid object");
        }
        return false;
    }

    if (strcmp(name, "length") == 0)
    {
        if (obj->type == JS_VALUE_FUNCTION)
        {
            out->exists = true;
            out->value = js_value_make_number((double)js_builtin_function_length(obj->as.function));
            out->writable = false;
            out->enumerable = false;
            out->configurable = true;
            return true;
        }
        if (obj->type == JS_VALUE_NATIVE_FN)
        {
            size_t length = 0;
            if (!js_value_native_length(rt, obj, &length))
            {
                if (error_message)
                {
                    *error_message = js_strdup("unknown native");
                }
                return false;
            }
            out->exists = true;
            out->value = js_value_make_number((double)length);
            out->writable = false;
            out->enumerable = false;
            out->configurable = true;
            return true;
        }
        if (obj->type == JS_VALUE_ARRAY)
        {
            out->exists = true;
            out->value = js_value_make_number((double)obj->as.array->length);
            out->writable = true;
            out->enumerable = false;
            out->configurable = false;
            return true;
        }
        if (obj->type == JS_VALUE_STRING)
        {
            out->exists = true;
            out->value = js_value_make_number((double)obj->as.string.len);
            out->writable = false;
            out->enumerable = false;
            out->configurable = false;
            return true;
        }
    }

    if (obj->type == JS_VALUE_OBJECT)
    {
        out->exists = js_object_has_slot(obj->as.object, name);
        if (!out->exists)
        {
            return true;
        }
        if (!js_object_get_slot(obj->as.object, name, &out->value))
        {
            if (error_message)
            {
                *error_message = js_strdup("allocation failed");
            }
            return false;
        }
        return true;
    }

    if (error_message)
    {
        *error_message = js_strdup("invalid object");
    }
    return false;
}

static bool js_builtin_get_desc_value(js_object_t *desc,
                                      const char *name,
                                      bool *has_out,
                                      js_value_t *value_out,
                                      char **error_message)
{
    if (!has_out || !value_out)
    {
        return false;
    }
    *has_out = false;
    *value_out = js_value_make_undefined_internal();
    if (!desc || !name)
    {
        return true;
    }
    if (!js_object_has_slot(desc, name))
    {
        return true;
    }
    *has_out = true;
    if (!js_object_get_slot(desc, name, value_out))
    {
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }
    return true;
}

bool js_builtin_number(js_runtime_t *rt,
                       size_t argc,
                       const js_value_t *argv,
                       void *user_data,
                       js_value_t *out,
                       char **error_message)
{
    (void)rt;
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    if (argc == 0 || !argv)
    {
        *out = js_value_make_number(0.0);
        return true;
    }
    bool ok = true;
    double value = js_value_to_number(&argv[0], &ok);
    if (!ok)
    {
        value = js_nan();
    }
    *out = js_value_make_number(value);
    return true;
}

bool js_builtin_escape(js_runtime_t *rt,
                       size_t argc,
                       const js_value_t *argv,
                       void *user_data,
                       js_value_t *out,
                       char **error_message)
{
    (void)rt;
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    js_temp_string_t temp = {0};
    const js_value_t *value = (argc > 0 && argv) ? &argv[0] : NULL;
    if (!js_temp_string_from_value(rt, value, &temp, error_message))
    {
        return false;
    }

    size_t cap = temp.len * 6 + 1;
    char *buf = (char *)malloc(cap);
    if (!buf)
    {
        js_temp_string_release(&temp);
        return false;
    }
    size_t out_len = 0;
    size_t index = 0;
    while (index < temp.len)
    {
        unsigned int code = 0;
        if (!js_utf8_next(temp.data, temp.len, &index, &code))
        {
            free(buf);
            js_temp_string_release(&temp);
            return false;
        }
        if (code < 256 && js_is_unescaped_char(code))
        {
            if (out_len + 1 > cap)
            {
                free(buf);
                js_temp_string_release(&temp);
                return false;
            }
            buf[out_len++] = (char)code;
            continue;
        }
        if (code < 256)
        {
            if (!js_append_escape_hex(buf, cap, &out_len, code, false))
            {
                free(buf);
                js_temp_string_release(&temp);
                return false;
            }
            continue;
        }
        if (code <= 0xFFFF)
        {
            if (!js_append_escape_hex(buf, cap, &out_len, code, true))
            {
                free(buf);
                js_temp_string_release(&temp);
                return false;
            }
            continue;
        }
        unsigned int cp = code - 0x10000;
        unsigned int high = 0xD800 + (cp >> 10);
        unsigned int low = 0xDC00 + (cp & 0x3FF);
        if (!js_append_escape_hex(buf, cap, &out_len, high, true) ||
            !js_append_escape_hex(buf, cap, &out_len, low, true))
        {
            free(buf);
            js_temp_string_release(&temp);
            return false;
        }
    }
    buf[out_len] = '\0';

    bool ok = js_value_make_string(out, buf, out_len);
    free(buf);
    js_temp_string_release(&temp);
    return ok;
}

bool js_builtin_unescape(js_runtime_t *rt,
                         size_t argc,
                         const js_value_t *argv,
                         void *user_data,
                         js_value_t *out,
                         char **error_message)
{
    (void)rt;
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    js_temp_string_t temp = {0};
    const js_value_t *value = (argc > 0 && argv) ? &argv[0] : NULL;
    if (!js_temp_string_from_value(rt, value, &temp, error_message))
    {
        return false;
    }

    size_t cap = temp.len * 3 + 1;
    char *buf = (char *)malloc(cap);
    if (!buf)
    {
        js_temp_string_release(&temp);
        return false;
    }
    size_t out_len = 0;
    size_t i = 0;
    while (i < temp.len)
    {
        char c = temp.data ? temp.data[i] : '\0';
        if (c == '%' && i + 1 < temp.len)
        {
            if (temp.data[i + 1] == 'u')
            {
                if (i + 5 < temp.len)
                {
                    int h0 = js_hex_value(temp.data[i + 2]);
                    int h1 = js_hex_value(temp.data[i + 3]);
                    int h2 = js_hex_value(temp.data[i + 4]);
                    int h3 = js_hex_value(temp.data[i + 5]);
                    if (h0 >= 0 && h1 >= 0 && h2 >= 0 && h3 >= 0)
                    {
                        unsigned int code = (unsigned int)((h0 << 12) | (h1 << 8) | (h2 << 4) | h3);
                        if (!js_append_utf8(buf, cap, &out_len, code))
                        {
                            free(buf);
                            js_temp_string_release(&temp);
                            return false;
                        }
                        i += 6;
                        continue;
                    }
                }
            }
            else if (i + 2 < temp.len)
            {
                int h0 = js_hex_value(temp.data[i + 1]);
                int h1 = js_hex_value(temp.data[i + 2]);
                if (h0 >= 0 && h1 >= 0)
                {
                    unsigned int code = (unsigned int)((h0 << 4) | h1);
                    if (!js_append_utf8(buf, cap, &out_len, code))
                    {
                        free(buf);
                        js_temp_string_release(&temp);
                        return false;
                    }
                    i += 3;
                    continue;
                }
            }
        }
        if (out_len + 1 > cap)
        {
            free(buf);
            js_temp_string_release(&temp);
            return false;
        }
        buf[out_len++] = c;
        i++;
    }
    buf[out_len] = '\0';

    bool ok = js_value_make_string(out, buf, out_len);
    free(buf);
    js_temp_string_release(&temp);
    return ok;
}

bool js_builtin_type_error(js_runtime_t *rt,
                           size_t argc,
                           const js_value_t *argv,
                           void *user_data,
                           js_value_t *out,
                           char **error_message)
{
    (void)rt;
    (void)argc;
    (void)argv;
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    *out = js_value_make_undefined();
    return true;
}

static bool js_builtin_test262_error_to_string(js_runtime_t *rt,
                                               size_t argc,
                                               const js_value_t *argv,
                                               void *user_data,
                                               js_value_t *out,
                                               char **error_message)
{
    (void)rt;
    (void)argc;
    (void)argv;
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    return js_value_make_cstring(out, "Test262Error");
}

bool js_builtin_test262_error(js_runtime_t *rt,
                              size_t argc,
                              const js_value_t *argv,
                              void *user_data,
                              js_value_t *out,
                              char **error_message)
{
    (void)rt;
    (void)argc;
    (void)argv;
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    js_value_t obj;
    if (!js_value_make_host_object(&obj, NULL, NULL, NULL, NULL))
    {
        return false;
    }
    js_value_t fn;
    memset(&fn, 0, sizeof(fn));
    fn.type = JS_VALUE_NATIVE_FN;
    fn.as.native.fn = js_builtin_test262_error_to_string;
    fn.as.native.user_data = NULL;
    if (!js_object_set_slot(obj.as.object, "toString", &fn))
    {
        js_value_destroy(&obj);
        return false;
    }
    *out = obj;
    return true;
}

bool js_builtin_verify_property(js_runtime_t *rt,
                                size_t argc,
                                const js_value_t *argv,
                                void *user_data,
                                js_value_t *out,
                                char **error_message)
{
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!rt || !out || argc < 3 || !argv)
    {
        if (error_message)
        {
            *error_message = js_strdup("verifyProperty missing arguments");
        }
        return false;
    }
    const js_value_t *obj = &argv[0];
    const js_value_t *name_val = &argv[1];
    const js_value_t *desc_val = &argv[2];

    js_temp_string_t name_temp = {0};
    char *name_err = NULL;
    if (!js_temp_string_from_value(rt, name_val, &name_temp, &name_err))
    {
        if (name_err)
        {
            if (error_message)
            {
                *error_message = name_err;
            }
            else
            {
                free(name_err);
            }
        }
        else if (error_message)
        {
            *error_message = js_strdup("invalid property name");
        }
        return false;
    }
    char *name = js_strdup_len(name_temp.data ? name_temp.data : "", name_temp.len);
    js_temp_string_release(&name_temp);
    if (!name)
    {
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }

    js_prop_desc_t actual;
    char *err = NULL;
    if (!js_builtin_get_prop_desc(rt, obj, name, &actual, &err))
    {
        free(name);
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
        }
        return false;
    }

    if (desc_val->type == JS_VALUE_UNDEFINED)
    {
        if (actual.exists)
        {
            js_value_destroy(&actual.value);
            free(name);
            if (error_message)
            {
                *error_message = js_strdup("property should be undefined");
            }
            return false;
        }
        *out = js_value_make_bool(true);
        free(name);
        return true;
    }

    if (desc_val->type != JS_VALUE_OBJECT)
    {
        js_value_destroy(&actual.value);
        free(name);
        if (error_message)
        {
            *error_message = js_strdup("descriptor must be an object");
        }
        return false;
    }

    bool has_value = false;
    js_value_t expected_value = js_value_make_undefined_internal();
    if (!js_builtin_get_desc_value(desc_val->as.object, "value", &has_value, &expected_value, error_message))
    {
        js_value_destroy(&actual.value);
        free(name);
        return false;
    }

    if (has_value && !js_value_strict_equal(&actual.value, &expected_value))
    {
        js_value_destroy(&expected_value);
        js_value_destroy(&actual.value);
        free(name);
        if (error_message)
        {
            *error_message = js_strdup("property value mismatch");
        }
        return false;
    }
    js_value_destroy(&expected_value);

    bool has_writable = false;
    js_value_t expected_writable = js_value_make_undefined_internal();
    if (!js_builtin_get_desc_value(desc_val->as.object, "writable", &has_writable, &expected_writable, error_message))
    {
        js_value_destroy(&actual.value);
        free(name);
        return false;
    }
    if (has_writable && expected_writable.type != JS_VALUE_UNDEFINED)
    {
        bool expected = js_value_is_truthy(&expected_writable);
        if (expected != actual.writable)
        {
            js_value_destroy(&expected_writable);
            js_value_destroy(&actual.value);
            free(name);
            if (error_message)
            {
                *error_message = js_strdup("writable mismatch");
            }
            return false;
        }
    }
    js_value_destroy(&expected_writable);

    bool has_enumerable = false;
    js_value_t expected_enumerable = js_value_make_undefined_internal();
    if (!js_builtin_get_desc_value(desc_val->as.object, "enumerable", &has_enumerable, &expected_enumerable, error_message))
    {
        js_value_destroy(&actual.value);
        free(name);
        return false;
    }
    if (has_enumerable && expected_enumerable.type != JS_VALUE_UNDEFINED)
    {
        bool expected = js_value_is_truthy(&expected_enumerable);
        if (expected != actual.enumerable)
        {
            js_value_destroy(&expected_enumerable);
            js_value_destroy(&actual.value);
            free(name);
            if (error_message)
            {
                *error_message = js_strdup("enumerable mismatch");
            }
            return false;
        }
    }
    js_value_destroy(&expected_enumerable);

    bool has_configurable = false;
    js_value_t expected_configurable = js_value_make_undefined_internal();
    if (!js_builtin_get_desc_value(desc_val->as.object, "configurable", &has_configurable, &expected_configurable, error_message))
    {
        js_value_destroy(&actual.value);
        free(name);
        return false;
    }
    if (has_configurable && expected_configurable.type != JS_VALUE_UNDEFINED)
    {
        bool expected = js_value_is_truthy(&expected_configurable);
        if (expected != actual.configurable)
        {
            js_value_destroy(&expected_configurable);
            js_value_destroy(&actual.value);
            free(name);
            if (error_message)
            {
                *error_message = js_strdup("configurable mismatch");
            }
            return false;
        }
    }
    js_value_destroy(&expected_configurable);

    js_value_destroy(&actual.value);
    *out = js_value_make_bool(true);
    free(name);
    return true;
}
