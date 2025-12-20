#include <dirent.h>
#include <errno.h>
#include <math.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "web/js.h"
#include "web/js/runtime/runtime_internal.h"

typedef struct
{
    bool negative;
    bool flag_async;
    bool flag_module;
    bool flag_only_strict;
    bool flag_no_strict;
    bool flag_raw;
} test262_meta_t;

typedef struct
{
    size_t total;
    size_t pass;
    size_t fail;
    size_t skip;
} test262_stats_t;

typedef struct
{
    const char *filter;
    size_t limit;
    size_t run_count;
    bool verbose;
    bool fail_fast;
    bool stop;
    test262_stats_t stats;
} test262_ctx_t;

static char *dup_cstring(const char *text)
{
    if (!text)
    {
        text = "";
    }
    size_t len = strlen(text);
    char *out = (char *)malloc(len + 1);
    if (!out)
    {
        return NULL;
    }
    if (len)
    {
        memcpy(out, text, len);
    }
    out[len] = '\0';
    return out;
}

static char *read_file(const char *path, size_t *out_len)
{
    if (out_len)
    {
        *out_len = 0;
    }
    FILE *fp = fopen(path, "rb");
    if (!fp)
    {
        return NULL;
    }
    if (fseek(fp, 0, SEEK_END) != 0)
    {
        fclose(fp);
        return NULL;
    }
    long len = ftell(fp);
    if (len < 0)
    {
        fclose(fp);
        return NULL;
    }
    if (fseek(fp, 0, SEEK_SET) != 0)
    {
        fclose(fp);
        return NULL;
    }
    char *buf = (char *)malloc((size_t)len + 1);
    if (!buf)
    {
        fclose(fp);
        return NULL;
    }
    size_t read_len = fread(buf, 1, (size_t)len, fp);
    fclose(fp);
    if (read_len != (size_t)len)
    {
        free(buf);
        return NULL;
    }
    buf[len] = '\0';
    if (out_len)
    {
        *out_len = (size_t)len;
    }
    return buf;
}

static char *trim_left(char *s)
{
    if (!s)
    {
        return s;
    }
    while (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n')
    {
        ++s;
    }
    return s;
}

static void trim_right(char *s)
{
    if (!s)
    {
        return;
    }
    size_t len = strlen(s);
    while (len > 0)
    {
        char c = s[len - 1];
        if (c != ' ' && c != '\t' && c != '\r' && c != '\n')
        {
            break;
        }
        s[len - 1] = '\0';
        --len;
    }
}

static bool starts_with(const char *text, const char *prefix)
{
    if (!text || !prefix)
    {
        return false;
    }
    size_t plen = strlen(prefix);
    return strncmp(text, prefix, plen) == 0;
}

static void parse_flags_line(char *line, test262_meta_t *meta)
{
    char *open = strchr(line, '[');
    char *close = strchr(line, ']');
    if (!open || !close || close <= open)
    {
        return;
    }
    *close = '\0';
    char *token = open + 1;
    while (token && *token)
    {
        char *comma = strchr(token, ',');
        if (comma)
        {
            *comma = '\0';
        }
        char *item = trim_left(token);
        trim_right(item);
        if (strcmp(item, "async") == 0)
        {
            meta->flag_async = true;
        }
        else if (strcmp(item, "module") == 0)
        {
            meta->flag_module = true;
        }
        else if (strcmp(item, "onlyStrict") == 0)
        {
            meta->flag_only_strict = true;
        }
        else if (strcmp(item, "noStrict") == 0)
        {
            meta->flag_no_strict = true;
        }
        else if (strcmp(item, "raw") == 0)
        {
            meta->flag_raw = true;
        }
        token = comma ? comma + 1 : NULL;
    }
}

static void parse_test262_meta(const char *source, test262_meta_t *meta)
{
    if (!meta)
    {
        return;
    }
    memset(meta, 0, sizeof(*meta));
    if (!source)
    {
        return;
    }
    const char *start = strstr(source, "/*---");
    if (!start)
    {
        return;
    }
    start += 5;
    const char *end = strstr(start, "---*/");
    if (!end)
    {
        return;
    }
    size_t len = (size_t)(end - start);
    char *header = (char *)malloc(len + 1);
    if (!header)
    {
        return;
    }
    memcpy(header, start, len);
    header[len] = '\0';

    char *save = NULL;
    char *line = strtok_r(header, "\n", &save);
    while (line)
    {
        char *trimmed = trim_left(line);
        trim_right(trimmed);
        if (starts_with(trimmed, "flags:"))
        {
            parse_flags_line(trimmed, meta);
        }
        else if (starts_with(trimmed, "negative:"))
        {
            meta->negative = true;
        }
        line = strtok_r(NULL, "\n", &save);
    }

    free(header);
}

static bool should_skip_test(const test262_meta_t *meta, const char *source)
{
    if (!meta)
    {
        return false;
    }
    if (meta->flag_async || meta->flag_module || meta->flag_raw)
    {
        return true;
    }
    if (meta->flag_only_strict || meta->flag_no_strict)
    {
        return true;
    }
    if (source && strstr(source, "$DONE"))
    {
        return true;
    }
    return false;
}

static bool js_same_value(const js_value_t *a, const js_value_t *b)
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
        {
            double an = a->as.number;
            double bn = b->as.number;
            bool an_nan = (an != an);
            bool bn_nan = (bn != bn);
            if (an_nan || bn_nan)
            {
                return an_nan && bn_nan;
            }
            if (an == 0.0 && bn == 0.0)
            {
                return signbit(an) == signbit(bn);
            }
            return an == bn;
        }
        case JS_VALUE_STRING:
            if (a->as.string.len != b->as.string.len)
            {
                return false;
            }
            if (a->as.string.len == 0)
            {
                return true;
            }
            if (!a->as.string.data || !b->as.string.data)
            {
                return false;
            }
            return memcmp(a->as.string.data, b->as.string.data, a->as.string.len) == 0;
        case JS_VALUE_ARRAY:
            return a->as.array == b->as.array;
        case JS_VALUE_OBJECT:
            return a->as.object == b->as.object;
        case JS_VALUE_NATIVE_FN:
            return a->as.native.fn == b->as.native.fn && a->as.native.user_data == b->as.native.user_data;
        case JS_VALUE_FUNCTION:
            return a->as.function == b->as.function;
    }
    return false;
}

static bool js_compare_array(const js_value_t *a, const js_value_t *b)
{
    if (!a || !b)
    {
        return false;
    }
    if (a->type != JS_VALUE_ARRAY || b->type != JS_VALUE_ARRAY)
    {
        return false;
    }
    const js_array_t *arr_a = a->as.array;
    const js_array_t *arr_b = b->as.array;
    if (!arr_a || !arr_b)
    {
        return arr_a == arr_b;
    }
    if (arr_a->length != arr_b->length)
    {
        return false;
    }
    for (size_t i = 0; i < arr_a->length; ++i)
    {
        if (!js_same_value(&arr_a->items[i], &arr_b->items[i]))
        {
            return false;
        }
    }
    return true;
}

typedef enum
{
    ASSERT_SAME_VALUE = 0,
    ASSERT_NOT_SAME_VALUE,
    ASSERT_TRUE,
    ASSERT_FALSE,
    ASSERT_COMPARE_ARRAY,
    ASSERT_FAIL,
    ASSERT_THROWS
} assert_kind_t;

typedef struct
{
    assert_kind_t kind;
    const char *name;
} assert_fn_t;

static assert_fn_t g_assert_same = { ASSERT_SAME_VALUE, "sameValue" };
static assert_fn_t g_assert_not_same = { ASSERT_NOT_SAME_VALUE, "notSameValue" };
static assert_fn_t g_assert_true = { ASSERT_TRUE, "isTrue" };
static assert_fn_t g_assert_false = { ASSERT_FALSE, "isFalse" };
static assert_fn_t g_assert_compare_array = { ASSERT_COMPARE_ARRAY, "compareArray" };
static assert_fn_t g_assert_fail = { ASSERT_FAIL, "fail" };
static assert_fn_t g_assert_throws = { ASSERT_THROWS, "throws" };

static bool error_matches_type(const char *message, const char *expected_name)
{
    if (!expected_name)
    {
        return true;
    }
    if (!message)
    {
        return false;
    }
    size_t len = strlen(expected_name);
    if (strncmp(message, expected_name, len) != 0)
    {
        return false;
    }
    char next = message[len];
    return next == '\0' || next == ':' || next == ' ';
}

static bool assert_fail(char **error_message, const char *message)
{
    if (error_message)
    {
        *error_message = dup_cstring(message ? message : "assertion failed");
    }
    return false;
}

static bool native_assert(js_runtime_t *rt,
                          size_t argc,
                          const js_value_t *argv,
                          void *user_data,
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
    const assert_fn_t *fn = (const assert_fn_t *)user_data;
    if (!fn)
    {
        return assert_fail(error_message, "assertion failed");
    }
    if (fn->kind == ASSERT_FAIL)
    {
        const char *msg = (argc > 0 && argv && argv[0].type == JS_VALUE_STRING) ? argv[0].as.string.data : "assert.fail";
        return assert_fail(error_message, msg);
    }
    if (fn->kind == ASSERT_TRUE)
    {
        if (argc > 0 && argv && argv[0].type == JS_VALUE_BOOL && argv[0].as.boolean)
        {
            *out = js_value_make_undefined();
            return true;
        }
        return assert_fail(error_message, "assert.isTrue failed");
    }
    if (fn->kind == ASSERT_FALSE)
    {
        if (argc > 0 && argv && argv[0].type == JS_VALUE_BOOL && !argv[0].as.boolean)
        {
            *out = js_value_make_undefined();
            return true;
        }
        return assert_fail(error_message, "assert.isFalse failed");
    }
    if (fn->kind == ASSERT_THROWS)
    {
        if (argc < 2 || !argv)
        {
            return assert_fail(error_message, "assert.throws missing arguments");
        }
        const js_value_t *expected = &argv[0];
        const js_value_t *callable = &argv[1];
        js_value_t result = js_value_make_undefined();
        char *call_error = NULL;
        bool ok = js_call_value(rt, callable, 0, NULL, &result, &call_error);
        if (ok)
        {
            js_value_destroy(&result);
            return assert_fail(error_message, "assert.throws expected error");
        }
        js_value_destroy(&result);
        const char *expected_name = js_value_native_name(rt, expected);
        if (!error_matches_type(call_error, expected_name))
        {
            if (error_message)
            {
                *error_message = dup_cstring("assert.throws wrong error type");
            }
            free(call_error);
            return false;
        }
        free(call_error);
        *out = js_value_make_undefined();
        return true;
    }
    if (argc < 2 || !argv)
    {
        return assert_fail(error_message, "assertion missing operands");
    }

    bool ok = false;
    if (fn->kind == ASSERT_SAME_VALUE)
    {
        ok = js_same_value(&argv[0], &argv[1]);
        if (!ok)
        {
            return assert_fail(error_message, "assert.sameValue failed");
        }
    }
    else if (fn->kind == ASSERT_NOT_SAME_VALUE)
    {
        ok = !js_same_value(&argv[0], &argv[1]);
        if (!ok)
        {
            return assert_fail(error_message, "assert.notSameValue failed");
        }
    }
    else if (fn->kind == ASSERT_COMPARE_ARRAY)
    {
        ok = js_compare_array(&argv[0], &argv[1]);
        if (!ok)
        {
            return assert_fail(error_message, "assert.compareArray failed");
        }
    }
    else
    {
        return assert_fail(error_message, "assertion failed");
    }

    *out = js_value_make_undefined();
    return true;
}

static bool assert_get(js_runtime_t *rt,
                       void *user_data,
                       const char *name,
                       js_value_t *out,
                       char **error_message)
{
    (void)rt;
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out || !name)
    {
        return false;
    }
    const assert_fn_t *fn = NULL;
    if (strcmp(name, "sameValue") == 0)
    {
        fn = &g_assert_same;
    }
    else if (strcmp(name, "notSameValue") == 0)
    {
        fn = &g_assert_not_same;
    }
    else if (strcmp(name, "isTrue") == 0)
    {
        fn = &g_assert_true;
    }
    else if (strcmp(name, "isFalse") == 0)
    {
        fn = &g_assert_false;
    }
    else if (strcmp(name, "compareArray") == 0)
    {
        fn = &g_assert_compare_array;
    }
    else if (strcmp(name, "fail") == 0)
    {
        fn = &g_assert_fail;
    }
    else if (strcmp(name, "throws") == 0)
    {
        fn = &g_assert_throws;
    }
    if (fn)
    {
        out->type = JS_VALUE_NATIVE_FN;
        out->as.native.fn = native_assert;
        out->as.native.user_data = (void *)fn;
        return true;
    }
    *out = js_value_make_undefined();
    return true;
}

static bool assert_set(js_runtime_t *rt,
                       void *user_data,
                       const char *name,
                       const js_value_t *value,
                       char **error_message)
{
    (void)rt;
    (void)user_data;
    (void)name;
    (void)value;
    if (error_message)
    {
        *error_message = NULL;
    }
    return true;
}

static void print_value(FILE *fp, const js_value_t *value)
{
    if (!fp)
    {
        return;
    }
    if (!value)
    {
        fputs("undefined", fp);
        return;
    }
    switch (value->type)
    {
        case JS_VALUE_UNDEFINED:
            fputs("undefined", fp);
            return;
        case JS_VALUE_NULL:
            fputs("null", fp);
            return;
        case JS_VALUE_BOOL:
            fputs(value->as.boolean ? "true" : "false", fp);
            return;
        case JS_VALUE_NUMBER:
            fprintf(fp, "%.17g", value->as.number);
            return;
        case JS_VALUE_STRING:
            if (value->as.string.data && value->as.string.len)
            {
                fwrite(value->as.string.data, 1, value->as.string.len, fp);
            }
            return;
        case JS_VALUE_ARRAY:
            fputs("[array]", fp);
            return;
        case JS_VALUE_OBJECT:
            fputs("[object]", fp);
            return;
        case JS_VALUE_NATIVE_FN:
            fputs("[native]", fp);
            return;
        case JS_VALUE_FUNCTION:
            fputs("[function]", fp);
            return;
    }
}

static bool native_print(js_runtime_t *rt,
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
    for (size_t i = 0; i < argc; ++i)
    {
        if (i)
        {
            fputc(' ', stdout);
        }
        print_value(stdout, &argv[i]);
    }
    fputc('\n', stdout);
    *out = js_value_make_undefined();
    return true;
}

static bool native_error(js_runtime_t *rt,
                         size_t argc,
                         const js_value_t *argv,
                         void *user_data,
                         js_value_t *out,
                         char **error_message)
{
    (void)rt;
    (void)user_data;
    (void)out;
    if (error_message)
    {
        const char *msg = NULL;
        if (argc > 0 && argv && argv[0].type == JS_VALUE_STRING)
        {
            msg = argv[0].as.string.data;
        }
        if (!msg || msg[0] == '\0')
        {
            msg = "Test262Error";
        }
        *error_message = dup_cstring(msg);
    }
    return false;
}

static bool native_done(js_runtime_t *rt,
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
    if (argc > 0 && argv && argv[0].type != JS_VALUE_UNDEFINED && argv[0].type != JS_VALUE_NULL)
    {
        return assert_fail(error_message, "$DONE called with error");
    }
    *out = js_value_make_undefined();
    return true;
}

static bool native_is_constructor(js_runtime_t *rt,
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
    if (!out)
    {
        return false;
    }
    bool is_ctor = false;
    if (argc > 0 && argv)
    {
        is_ctor = js_value_is_constructor(rt, &argv[0]);
    }
    *out = js_value_make_bool(is_ctor);
    return true;
}

static bool console_get(js_runtime_t *rt,
                        void *user_data,
                        const char *name,
                        js_value_t *out,
                        char **error_message)
{
    (void)rt;
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out || !name)
    {
        return false;
    }
    if (strcmp(name, "log") == 0 || strcmp(name, "warn") == 0 || strcmp(name, "error") == 0)
    {
        out->type = JS_VALUE_NATIVE_FN;
        out->as.native.fn = native_print;
        out->as.native.user_data = NULL;
        return true;
    }
    *out = js_value_make_undefined();
    return true;
}

static bool console_set(js_runtime_t *rt,
                        void *user_data,
                        const char *name,
                        const js_value_t *value,
                        char **error_message)
{
    (void)rt;
    (void)user_data;
    (void)name;
    (void)value;
    if (error_message)
    {
        *error_message = NULL;
    }
    return true;
}

static bool global_get(js_runtime_t *rt,
                       void *user_data,
                       const char *name,
                       js_value_t *out,
                       char **error_message)
{
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!rt || !out || !name)
    {
        return false;
    }
    if (!js_env_get(rt->global, name, out))
    {
        *out = js_value_make_undefined();
    }
    return true;
}

static bool global_set(js_runtime_t *rt,
                       void *user_data,
                       const char *name,
                       const js_value_t *value,
                       char **error_message)
{
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!rt || !name || !value)
    {
        return false;
    }
    if (!js_env_assign(rt->global, name, value))
    {
        if (!js_env_define_local(rt->global, name, value, false, true))
        {
            return false;
        }
    }
    return true;
}

static bool setup_harness(js_runtime_t *rt)
{
    if (!rt)
    {
        return false;
    }
    if (!js_runtime_set_native(rt, "print", native_print, NULL))
    {
        return false;
    }
    if (!js_runtime_set_native(rt, "$ERROR", native_error, NULL))
    {
        return false;
    }
    if (!js_runtime_set_native(rt, "$DONE", native_done, NULL))
    {
        return false;
    }
    if (!js_runtime_set_native(rt, "isConstructor", native_is_constructor, NULL))
    {
        return false;
    }

    js_value_t assert_obj;
    if (!js_value_make_host_object(&assert_obj, assert_get, assert_set, NULL, NULL))
    {
        return false;
    }
    bool ok = js_runtime_set_global(rt, "assert", &assert_obj);
    js_value_destroy(&assert_obj);
    if (!ok)
    {
        return false;
    }

    js_value_t console_obj;
    if (!js_value_make_host_object(&console_obj, console_get, console_set, NULL, NULL))
    {
        return false;
    }
    ok = js_runtime_set_global(rt, "console", &console_obj);
    js_value_destroy(&console_obj);
    if (!ok)
    {
        return false;
    }

    js_value_t global_obj;
    if (!js_value_make_host_object(&global_obj, global_get, global_set, NULL, NULL))
    {
        return false;
    }
    ok = js_runtime_set_global(rt, "globalThis", &global_obj);
    js_value_destroy(&global_obj);
    if (!ok)
    {
        return false;
    }

    return true;
}

static bool has_js_extension(const char *name)
{
    if (!name)
    {
        return false;
    }
    size_t len = strlen(name);
    return len > 3 && strcmp(name + len - 3, ".js") == 0;
}

static bool path_is_dir(const char *path)
{
    struct stat st;
    if (stat(path, &st) != 0)
    {
        return false;
    }
    return S_ISDIR(st.st_mode) != 0;
}

static char *path_join(const char *a, const char *b)
{
    if (!a || !b)
    {
        return NULL;
    }
    size_t a_len = strlen(a);
    size_t b_len = strlen(b);
    bool needs_sep = (a_len > 0 && a[a_len - 1] != '/');
    size_t total = a_len + (needs_sep ? 1 : 0) + b_len + 1;
    char *out = (char *)malloc(total);
    if (!out)
    {
        return NULL;
    }
    memcpy(out, a, a_len);
    size_t pos = a_len;
    if (needs_sep)
    {
        out[pos++] = '/';
    }
    if (b_len)
    {
        memcpy(out + pos, b, b_len);
        pos += b_len;
    }
    out[pos] = '\0';
    return out;
}

static bool run_test_file(const char *path, test262_ctx_t *ctx)
{
    if (!ctx || !path)
    {
        return false;
    }
    if (ctx->stop)
    {
        return true;
    }
    if (ctx->filter && !strstr(path, ctx->filter))
    {
        ctx->stats.skip++;
        return true;
    }
    if (ctx->limit && ctx->run_count >= ctx->limit)
    {
        ctx->stop = true;
        return true;
    }

    size_t len = 0;
    char *source = read_file(path, &len);
    if (!source)
    {
        ctx->stats.fail++;
        fprintf(stderr, "FAIL %s (read error)\n", path);
        ctx->stop = true;
        return false;
    }

    test262_meta_t meta;
    parse_test262_meta(source, &meta);
    ctx->stats.total++;

    if (should_skip_test(&meta, source))
    {
        ctx->stats.skip++;
        free(source);
        return true;
    }

    ctx->run_count++;
    js_runtime_t *rt = js_runtime_create();
    if (!rt)
    {
        ctx->stats.fail++;
        free(source);
        fprintf(stderr, "FAIL %s (runtime create)\n", path);
        ctx->stop = true;
        return false;
    }
    if (!setup_harness(rt))
    {
        ctx->stats.fail++;
        js_runtime_destroy(rt);
        free(source);
        fprintf(stderr, "FAIL %s (harness setup)\n", path);
        ctx->stop = true;
        return false;
    }

    js_exec_result_t res = js_eval(rt, source);
    bool passed = meta.negative ? !res.ok : res.ok;

    if (passed)
    {
        ctx->stats.pass++;
    }
    else
    {
        ctx->stats.fail++;
        if (ctx->fail_fast)
        {
            ctx->stop = true;
        }
    }

    if (!passed)
    {
        const char *reason = meta.negative ? "expected failure" : "unexpected failure";
        fprintf(stderr, "FAIL %s (%s)", path, reason);
        if (res.error_message)
        {
            fprintf(stderr, ": %s", res.error_message);
        }
        fprintf(stderr, "\n");
    }
    else
    {
        fprintf(stdout, "PASS %s\n", path);
    }

    js_exec_result_destroy(&res);
    js_runtime_destroy(rt);
    free(source);
    return !ctx->stop;
}

static bool walk_dir(const char *path, test262_ctx_t *ctx)
{
    if (!path || !ctx)
    {
        return false;
    }
    DIR *dir = opendir(path);
    if (!dir)
    {
        fprintf(stderr, "Failed to open %s: %s\n", path, strerror(errno));
        return false;
    }
    struct dirent *ent = NULL;
    while ((ent = readdir(dir)) != NULL)
    {
        if (ctx->stop)
        {
            break;
        }
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
        {
            continue;
        }
        char *full = path_join(path, ent->d_name);
        if (!full)
        {
            closedir(dir);
            return false;
        }
        if (path_is_dir(full))
        {
            if (!walk_dir(full, ctx))
            {
                free(full);
                closedir(dir);
                return false;
            }
        }
        else if (has_js_extension(ent->d_name))
        {
            if (!run_test_file(full, ctx))
            {
                free(full);
                closedir(dir);
                return false;
            }
        }
        free(full);
    }
    closedir(dir);
    return true;
}

static char *resolve_test_root(const char *root)
{
    if (!root)
    {
        return NULL;
    }
    if (!path_is_dir(root))
    {
        return NULL;
    }
    char *test_dir = path_join(root, "test");
    if (test_dir && path_is_dir(test_dir))
    {
        return test_dir;
    }
    free(test_dir);
    return dup_cstring(root);
}

int main(int argc, char **argv)
{
    const char *root = NULL;
    if (argc > 1)
    {
        root = argv[1];
    }
    if (!root)
    {
        root = getenv("TEST262_DIR");
    }
    if (!root)
    {
        fprintf(stderr, "Set TEST262_DIR or pass the test262 path as argv[1].\n");
        return 2;
    }

    char *test_root = resolve_test_root(root);
    if (!test_root)
    {
        fprintf(stderr, "Invalid test262 path: %s\n", root);
        return 2;
    }

    test262_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.filter = getenv("TEST262_FILTER");
    ctx.verbose = getenv("TEST262_VERBOSE") != NULL;
    ctx.fail_fast = getenv("TEST262_FAIL_FAST") != NULL;

    const char *limit_text = getenv("TEST262_LIMIT");
    if (limit_text && limit_text[0])
    {
        char *end = NULL;
        unsigned long long val = strtoull(limit_text, &end, 10);
        if (end && *end == '\0')
        {
            ctx.limit = (size_t)val;
        }
    }

    bool ok = walk_dir(test_root, &ctx);
    free(test_root);
    if (!ok)
    {
        return 2;
    }

    fprintf(stdout,
            "test262: total=%zu pass=%zu fail=%zu skip=%zu\n",
            ctx.stats.total,
            ctx.stats.pass,
            ctx.stats.fail,
            ctx.stats.skip);

    return ctx.stats.fail == 0 ? 0 : 1;
}
