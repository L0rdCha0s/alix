#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "web/js.h"

typedef enum
{
    EXPECT_UNDEFINED = 0,
    EXPECT_NUMBER,
    EXPECT_STRING,
    EXPECT_BOOL,
    EXPECT_ERROR
} expect_kind_t;

typedef bool (*js_setup_fn)(js_runtime_t *rt);

typedef struct
{
    const char *name;
    const char *code;
    expect_kind_t kind;
    double number;
    const char *string;
    bool boolean;
    js_setup_fn setup;
} js_case_t;

static bool value_is_number(const js_value_t *value, double expected)
{
    if (!value || value->type != JS_VALUE_NUMBER)
    {
        return false;
    }
    double diff = value->as.number - expected;
    if (diff < 0.0)
    {
        diff = -diff;
    }
    return diff < 1e-9;
}

static bool value_is_string(const js_value_t *value, const char *expected)
{
    if (!value || value->type != JS_VALUE_STRING)
    {
        return false;
    }
    if (!expected)
    {
        expected = "";
    }
    if (value->as.string.data == NULL)
    {
        return expected[0] == '\0';
    }
    return strcmp(value->as.string.data, expected) == 0;
}

static bool value_is_bool(const js_value_t *value, bool expected)
{
    if (!value || value->type != JS_VALUE_BOOL)
    {
        return false;
    }
    return value->as.boolean == expected;
}

static int g_counter = 0;

static bool native_bump(js_runtime_t *rt,
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
    g_counter++;
    *out = js_value_make_number((double)g_counter);
    return true;
}

static bool native_count(js_runtime_t *rt,
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
    *out = js_value_make_number((double)g_counter);
    return true;
}

static bool setup_native_counter(js_runtime_t *rt)
{
    g_counter = 0;
    if (!js_runtime_set_native(rt, "bump", native_bump, NULL))
    {
        return false;
    }
    return js_runtime_set_native(rt, "count", native_count, NULL);
}

typedef struct
{
    double value;
} test_host_object_t;

static bool host_object_inc(js_runtime_t *rt,
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
    if (!out || !user_data)
    {
        return false;
    }
    test_host_object_t *obj = (test_host_object_t *)user_data;
    double delta = 0.0;
    if (argc > 0 && argv)
    {
        if (argv[0].type == JS_VALUE_NUMBER)
        {
            delta = argv[0].as.number;
        }
        else if (argv[0].type == JS_VALUE_BOOL)
        {
            delta = argv[0].as.boolean ? 1.0 : 0.0;
        }
    }
    obj->value += delta;
    *out = js_value_make_number(obj->value);
    return true;
}

static bool host_object_get(js_runtime_t *rt,
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
    if (!out || !name || !user_data)
    {
        return false;
    }
    test_host_object_t *obj = (test_host_object_t *)user_data;
    if (strcmp(name, "value") == 0)
    {
        *out = js_value_make_number(obj->value);
        return true;
    }
    if (strcmp(name, "inc") == 0)
    {
        out->type = JS_VALUE_NATIVE_FN;
        out->as.native.fn = host_object_inc;
        out->as.native.user_data = obj;
        return true;
    }
    *out = js_value_make_undefined();
    return true;
}

static bool host_object_set(js_runtime_t *rt,
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
    if (!name || !user_data || !value)
    {
        return false;
    }
    test_host_object_t *obj = (test_host_object_t *)user_data;
    if (strcmp(name, "value") == 0 && value->type == JS_VALUE_NUMBER)
    {
        obj->value = value->as.number;
        return true;
    }
    return true;
}

static bool setup_host_object(js_runtime_t *rt)
{
    static test_host_object_t host = {0};
    host.value = 5.0;
    js_value_t obj;
    if (!js_value_make_host_object(&obj, host_object_get, host_object_set, NULL, &host))
    {
        return false;
    }
    bool ok = js_runtime_set_global(rt, "obj", &obj);
    js_value_destroy(&obj);
    return ok;
}

#define JS_CASE_NUM(name, code, val) { name, code, EXPECT_NUMBER, val, NULL, false, NULL }
#define JS_CASE_NUM_SETUP(name, code, val, setup_fn) { name, code, EXPECT_NUMBER, val, NULL, false, setup_fn }
#define JS_CASE_BOOL(name, code, val) { name, code, EXPECT_BOOL, 0.0, NULL, val, NULL }
#define JS_CASE_BOOL_SETUP(name, code, val, setup_fn) { name, code, EXPECT_BOOL, 0.0, NULL, val, setup_fn }
#define JS_CASE_STR(name, code, val) { name, code, EXPECT_STRING, 0.0, val, false, NULL }
#define JS_CASE_UNDEF(name, code) { name, code, EXPECT_UNDEFINED, 0.0, NULL, false, NULL }
#define JS_CASE_ERR(name, code) { name, code, EXPECT_ERROR, 0.0, NULL, false, NULL }

static bool run_case(const js_case_t *tc)
{
    js_runtime_t *rt = js_runtime_create();
    if (!rt)
    {
        printf("js_host_test: %s: runtime create failed\n", tc->name);
        return false;
    }
    if (tc->setup && !tc->setup(rt))
    {
        printf("js_host_test: %s: setup failed\n", tc->name);
        js_runtime_destroy(rt);
        return false;
    }

    js_exec_result_t res = js_eval(rt, tc->code);
    bool ok = false;
    if (tc->kind == EXPECT_ERROR)
    {
        ok = !res.ok;
    }
    else if (res.ok)
    {
        switch (tc->kind)
        {
            case EXPECT_UNDEFINED:
                ok = res.value.type == JS_VALUE_UNDEFINED;
                break;
            case EXPECT_NUMBER:
                ok = value_is_number(&res.value, tc->number);
                break;
            case EXPECT_STRING:
                ok = value_is_string(&res.value, tc->string);
                break;
            case EXPECT_BOOL:
                ok = value_is_bool(&res.value, tc->boolean);
                break;
            case EXPECT_ERROR:
                ok = false;
                break;
        }
    }

    if (!ok)
    {
        if (!res.ok)
        {
            printf("js_host_test: %s: error: %s\n", tc->name,
                   res.error_message ? res.error_message : "<no message>");
        }
        else
        {
            printf("js_host_test: %s: unexpected result\n", tc->name);
        }
    }

    js_exec_result_destroy(&res);
    js_runtime_destroy(rt);
    return ok;
}

static bool test_parse_execute(void)
{
    js_runtime_t *rt = js_runtime_create();
    if (!rt)
    {
        return false;
    }
    js_parse_error_t err = {0};
    js_program_t *program = js_parse("let x = 1; x + 2;", &err);
    if (!program)
    {
        js_runtime_destroy(rt);
        return false;
    }
    js_exec_result_t res = js_execute(rt, program);
    bool ok = res.ok && value_is_number(&res.value, 3.0);
    js_exec_result_destroy(&res);
    js_program_destroy(program);
    js_runtime_destroy(rt);
    return ok;
}

static bool test_function_persistence(void)
{
    js_runtime_t *rt = js_runtime_create();
    if (!rt)
    {
        return false;
    }

    js_exec_result_t res = js_eval(rt, "function add(a, b) { return a + b; }");
    bool ok = res.ok;
    js_exec_result_destroy(&res);
    if (!ok)
    {
        js_runtime_destroy(rt);
        return false;
    }

    res = js_eval(rt, "add(2, 3);");
    ok = res.ok && value_is_number(&res.value, 5.0);
    js_exec_result_destroy(&res);
    js_runtime_destroy(rt);
    return ok;
}

int main(void)
{
    js_case_t cases[] = {
        JS_CASE_NUM("num-decimal", "42;", 42.0),
        JS_CASE_NUM("num-float", "3.5;", 3.5),
        JS_CASE_NUM("num-leading-dot", ".25 + .25;", 0.5),
        JS_CASE_NUM("num-trailing-dot", "2.;", 2.0),
        JS_CASE_NUM("num-exp-pos", "1e3;", 1000.0),
        JS_CASE_NUM("num-exp-neg", "5e-2;", 0.05),
        JS_CASE_NUM("num-hex", "0x10;", 16.0),
        JS_CASE_NUM("num-hex-upper", "0XfF;", 255.0),
        JS_CASE_NUM("num-binary", "0b1010;", 10.0),
        JS_CASE_NUM("num-octal", "0o77;", 63.0),
        JS_CASE_NUM("builtin-number-string", "Number(\"3.5\");", 3.5),
        JS_CASE_NUM("builtin-number-bool", "Number(true);", 1.0),

        JS_CASE_STR("str-basic", "\"hello\";", "hello"),
        JS_CASE_STR("str-escape-nl", "\"a\\nb\";", "a\nb"),
        JS_CASE_STR("str-escape-tab", "\"a\\tb\";", "a\tb"),
        JS_CASE_STR("str-escape-quote", "\"a\\\"b\";", "a\"b"),
        JS_CASE_STR("str-escape-backslash", "\"a\\\\b\";", "a\\b"),
        JS_CASE_STR("str-escape-hex", "\"\\x41\";", "A"),
        JS_CASE_STR("str-escape-unicode", "\"\\u0042\";", "B"),
        JS_CASE_STR("str-escape-vtab", "\"\\v\";", "\v"),
        JS_CASE_STR("str-concat-number", "\"Result: \" + 3;", "Result: 3"),
        JS_CASE_STR("str-concat-float", "\"Value: \" + 2.5;", "Value: 2.5"),

        JS_CASE_BOOL("unary-not-bool", "!true;", false),
        JS_CASE_BOOL("unary-not-zero", "!0;", true),
        JS_CASE_NUM("unary-minus-bool", "-true;", -1.0),
        JS_CASE_NUM("unary-plus-string", "+\"3\";", 3.0),
        JS_CASE_NUM("unary-minus-string", "-\"4\";", -4.0),

        JS_CASE_NUM("add", "1 + 2;", 3.0),
        JS_CASE_NUM("sub", "5 - 2;", 3.0),
        JS_CASE_NUM("mul", "3 * 4;", 12.0),
        JS_CASE_NUM("div", "8 / 2;", 4.0),
        JS_CASE_NUM("mod", "7 % 4;", 3.0),
        JS_CASE_NUM("precedence", "(1 + 2) * 3;", 9.0),

        JS_CASE_BOOL("lt-number", "1 < 2;", true),
        JS_CASE_BOOL("lte-number", "2 <= 2;", true),
        JS_CASE_BOOL("gt-number", "3 > 2;", true),
        JS_CASE_BOOL("gte-number", "3 >= 5;", false),
        JS_CASE_BOOL("lt-string", "\"a\" < \"b\";", true),
        JS_CASE_BOOL("gt-string", "\"b\" > \"a\";", true),
        JS_CASE_BOOL("compare-string-number", "\"2\" < 10;", true),
        JS_CASE_BOOL("compare-number-string", "10 > \"2\";", true),

        JS_CASE_BOOL("strict-eq-number", "1 === 1;", true),
        JS_CASE_BOOL("strict-neq-number", "1 !== 2;", true),
        JS_CASE_BOOL("strict-eq-string", "\"a\" === \"a\";", true),
        JS_CASE_BOOL("strict-type-mismatch", "1 === \"1\";", false),
        JS_CASE_BOOL("loose-eq-number-string", "1 == \"1\";", true),
        JS_CASE_BOOL("loose-neq-number-string", "1 != \"1\";", false),
        JS_CASE_BOOL("loose-eq-bool-number", "true == 1;", true),
        JS_CASE_BOOL("loose-eq-null-undefined", "null == undefined;", true),
        JS_CASE_BOOL("loose-neq-null-zero", "null != 0;", true),
        JS_CASE_BOOL("loose-eq-empty-zero", "\"\" == 0;", true),

        JS_CASE_BOOL("logical-and-true", "true && true;", true),
        JS_CASE_BOOL("logical-and-false", "true && false;", false),
        JS_CASE_BOOL("logical-or-true", "false || true;", true),
        JS_CASE_NUM("logical-and-returns-left", "0 && 5;", 0.0),
        JS_CASE_NUM("logical-or-returns-left", "5 || 0;", 5.0),
        JS_CASE_NUM_SETUP("logical-shortcircuit-and", "false && bump(); count();", 0.0, setup_native_counter),
        JS_CASE_NUM_SETUP("logical-shortcircuit-or", "true || bump(); count();", 0.0, setup_native_counter),
        JS_CASE_NUM("ternary-true", "true ? 1 : 2;", 1.0),
        JS_CASE_NUM("ternary-false", "false ? 1 : 2;", 2.0),

        JS_CASE_NUM("if-true", "let x = 0; if (1) { x = 2; } x;", 2.0),
        JS_CASE_NUM("if-false-else", "let x = 1; if (0) { x = 2; } else { x = 3; } x;", 3.0),
        JS_CASE_NUM("if-else-nested", "let x = 0; if (0) { x = 1; } else { if (1) { x = 4; } } x;", 4.0),
        JS_CASE_NUM("if-truthy-string", "let x = 0; if (\"hi\") { x = 5; } x;", 5.0),
        JS_CASE_NUM("if-falsy-zero", "let x = 7; if (0) { x = 2; } x;", 7.0),
        JS_CASE_NUM("if-falsy-empty-string", "let x = 9; if (\"\") { x = 1; } x;", 9.0),

        JS_CASE_NUM("while-count", "let x = 0; while (x < 3) { x = x + 1; } x;", 3.0),
        JS_CASE_NUM("while-break", "let x = 0; while (1) { x = x + 1; if (x == 2) { break; } } x;", 2.0),
        JS_CASE_NUM("while-continue", "let x = 0; let s = 0; while (x < 4) { x = x + 1; if (x == 2) { continue; } s = s + x; } s;", 8.0),
        JS_CASE_NUM("while-sum", "let i = 0; let s = 0; while (i < 5) { s = s + i; i = i + 1; } s;", 10.0),
        JS_CASE_NUM("while-nested-block", "let x = 0; while (x < 2) { { x = x + 1; } } x;", 2.0),
        JS_CASE_NUM("while-condition-false", "let x = 1; while (0) { x = 2; } x;", 1.0),

        JS_CASE_NUM("do-while-basic", "let x = 0; do { x = x + 1; } while (x < 3); x;", 3.0),
        JS_CASE_NUM("do-while-break", "let x = 0; do { x = x + 1; if (x == 2) { break; } } while (1); x;", 2.0),
        JS_CASE_NUM("do-while-continue", "let x = 0; let s = 0; do { x = x + 1; if (x == 2) { continue; } s = s + x; } while (x < 3); s;", 4.0),

        JS_CASE_NUM("for-sum", "let s = 0; for (let i = 0; i < 3; i = i + 1) { s = s + i; } s;", 3.0),
        JS_CASE_NUM("for-empty-init", "let i = 0; for (; i < 2; i = i + 1) { } i;", 2.0),
        JS_CASE_NUM("for-empty-cond", "let i = 0; for (; ; i = i + 1) { if (i == 3) { break; } } i;", 3.0),
        JS_CASE_NUM("for-empty-post", "let i = 0; for (; i < 3; ) { i = i + 1; } i;", 3.0),
        JS_CASE_NUM("for-continue", "let i = 0; let s = 0; for (; i < 4; i = i + 1) { if (i == 2) { continue; } s = s + i; } s;", 4.0),
        JS_CASE_NUM("for-break", "let i = 0; for (; i < 5; i = i + 1) { if (i == 2) { break; } } i;", 2.0),
        JS_CASE_NUM("for-let-scope", "let i = 5; for (let i = 0; i < 2; i = i + 1) { } i;", 5.0),

        JS_CASE_NUM("switch-match", "let x = 2; let y = 0; switch (x) { case 1: y = 1; break; case 2: y = 4; break; default: y = 9; } y;", 4.0),
        JS_CASE_NUM("switch-fallthrough", "let x = 1; let y = 0; switch (x) { case 1: y = y + 1; case 2: y = y + 2; break; default: y = 9; } y;", 3.0),
        JS_CASE_NUM("switch-default", "let x = 3; let y = 0; switch (x) { case 1: y = 1; break; default: y = 7; } y;", 7.0),
        JS_CASE_NUM("switch-string", "let x = \"b\"; let y = 0; switch (x) { case \"a\": y = 1; break; case \"b\": y = 2; break; } y;", 2.0),

        JS_CASE_NUM("function-basic", "function add(a, b) { return a + b; } add(3, 4);", 7.0),
        JS_CASE_NUM("function-args", "function mul(a, b, c) { return a * b * c; } mul(2, 3, 4);", 24.0),
        JS_CASE_NUM("function-closure", "let x = 5; function f() { return x + 1; } f();", 6.0),
        JS_CASE_NUM("function-nested", "function outer() { let x = 2; function inner() { return x + 3; } return inner(); } outer();", 5.0),
        JS_CASE_NUM("function-return-early", "function t(v) { if (v) { return 1; } return 2; } t(0);", 2.0),
        JS_CASE_NUM("function-call-expression", "function id(x) { return x; } id(id(3));", 3.0),
        JS_CASE_NUM("function-expr-basic", "let f = function(x) { return x + 1; }; f(2);", 3.0),
        JS_CASE_NUM("function-expr-iife", "(function(a) { return a * 3; })(2);", 6.0),
        JS_CASE_NUM("function-expr-closure-block", "let f; { let x = 3; f = function() { return x + 2; }; } f();", 5.0),
        JS_CASE_NUM("function-expr-closure-var", "function outer() { var x = 1; return function() { x = x + 1; return x; }; } let inc = outer(); inc();", 2.0),
        JS_CASE_NUM("function-expr-named-rec", "let f = function fact(n) { if (n <= 1) { return 1; } return n * fact(n - 1); }; f(4);", 24.0),

        JS_CASE_NUM("block-shadow", "let x = 1; { let x = 2; } x;", 1.0),
        JS_CASE_NUM("block-const", "let x = 1; { const y = 3; x = x + y; } x;", 4.0),
        JS_CASE_NUM("block-let-outer", "let x = 1; { let y = 2; x = x + y; } x;", 3.0),
        JS_CASE_NUM("block-var-scope", "var x = 1; { var x = 2; } x;", 2.0),
        JS_CASE_UNDEF("var-hoist-if", "if (0) { var x = 2; } x;"),

        JS_CASE_NUM("array-basic", "let a = [1, 2, 3]; a[0] + a[1] + a[2];", 6.0),
        JS_CASE_NUM("array-length", "let a = [1, 2, 3]; a.length;", 3.0),
        JS_CASE_NUM("array-empty-length", "let a = []; a.length;", 0.0),
        JS_CASE_NUM("array-assign-length", "let a = [1]; a[1] = 4; a.length;", 2.0),
        JS_CASE_NUM("array-assign-value", "let a = [1]; a[3] = 9; a[3];", 9.0),
        JS_CASE_NUM("array-index-string", "let a = [5, 6]; a[\"1\"];", 6.0),
        JS_CASE_NUM("array-length-string", "let a = [5, 6]; a[\"length\"];", 2.0),
        JS_CASE_UNDEF("array-out-of-range", "let a = [1]; a[2];"),
        JS_CASE_NUM("array-nested", "let a = [[1, 2], [3]]; a[0][1];", 2.0),
        JS_CASE_NUM("array-shared", "let a = [1, 2]; let b = a; b[0] = 7; a[0];", 7.0),
        JS_CASE_NUM("array-index-expr", "let a = [1, 2, 3]; let i = 2; a[i];", 3.0),
        JS_CASE_NUM("array-assign-expr", "let a = [1, 2]; let i = 0; a[i] = a[i] + 5; a[0];", 6.0),
        JS_CASE_NUM("array-sum-while", "function sum(a) { var i = 0; var s = 0; while (i < a.length) { s = s + a[i]; i = i + 1; } return s; } let a = [1, 2, 3, 4]; sum(a);", 10.0),
        JS_CASE_NUM("string-length-prop", "\"hello\".length;", 5.0),
        JS_CASE_NUM_SETUP("host-object-get", "obj.value;", 5.0, setup_host_object),
        JS_CASE_NUM_SETUP("host-object-set", "obj.value = 12; obj.value;", 12.0, setup_host_object),
        JS_CASE_NUM_SETUP("host-object-computed", "obj[\"value\"];", 5.0, setup_host_object),
        JS_CASE_NUM_SETUP("host-object-method", "obj.inc(3);", 8.0, setup_host_object),

        JS_CASE_NUM("try-catch-no-error", "let x = 1; try { x = x + 1; } catch (e) { x = 9; } x;", 2.0),
        JS_CASE_NUM("try-catch-error", "let x = 0; try { x = missingVar; } catch (e) { x = 7; } x;", 7.0),
        JS_CASE_STR("try-catch-error-value", "try { missingVar; } catch (e) { e; }", "unknown identifier"),

        JS_CASE_NUM("line-comment", "let x = 1; // comment\n x + 1;", 2.0),
        JS_CASE_NUM("block-comment", "let x = 1; /* comment */ x + 2;", 3.0),
        JS_CASE_NUM("comment-mix", "/*a*/ let x = 2; //b\n x;", 2.0),

        JS_CASE_ERR("error-return-top", "return 1;"),
        JS_CASE_ERR("error-break-top", "break;"),
        JS_CASE_ERR("error-continue-top", "continue;"),
        JS_CASE_ERR("error-const-no-init", "const x;"),
        JS_CASE_ERR("error-assign-target", "1 = 2;"),
        JS_CASE_ERR("error-try-no-catch", "try { let x = 1; }"),
        JS_CASE_ERR("error-unterminated-string", "\"abc;"),
        JS_CASE_ERR("error-unexpected-char", "@;"),
    };

    size_t pass = 0;
    size_t fail = 0;
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i)
    {
        if (run_case(&cases[i]))
        {
            pass++;
        }
        else
        {
            fail++;
        }
    }

    if (test_parse_execute())
    {
        pass++;
    }
    else
    {
        printf("js_host_test: parse-execute failed\n");
        fail++;
    }

    if (test_function_persistence())
    {
        pass++;
    }
    else
    {
        printf("js_host_test: function-persistence failed\n");
        fail++;
    }

    printf("js_host_test: total=%zu pass=%zu fail=%zu\n", pass + fail, pass, fail);
    return fail == 0 ? 0 : 1;
}
