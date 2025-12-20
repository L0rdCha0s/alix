#include "web/js/runtime/runtime_internal.h"
#include "libc.h"

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
    if (!js_temp_string_from_value(value, &temp))
    {
        return false;
    }
    bool ok = js_value_make_string(out, temp.data ? temp.data : "", temp.len);
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
