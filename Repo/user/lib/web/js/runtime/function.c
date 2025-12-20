#include "web/js/runtime/runtime_internal.h"

#include "libc.h"

void js_function_retain(js_function_t *fn)
{
    if (!fn)
    {
        return;
    }
    fn->refcount++;
}

void js_function_release(js_function_t *fn)
{
    if (!fn)
    {
        return;
    }
    if (fn->refcount <= 0)
    {
        return;
    }
    fn->refcount--;
    if (fn->refcount > 0)
    {
        return;
    }
    js_env_release(fn->closure);
    free(fn);
}

js_function_t *js_function_create(const js_function_decl_t *decl,
                                  const js_function_expr_t *expr,
                                  js_env_t *closure,
                                  bool is_constructible)
{
    js_function_t *fn = (js_function_t *)calloc(1, sizeof(*fn));
    if (!fn)
    {
        return NULL;
    }
    fn->refcount = 1;
    fn->decl = decl;
    fn->expr = expr;
    fn->is_expr = (expr != NULL);
    fn->is_constructible = is_constructible;
    fn->closure = closure;
    if (closure)
    {
        js_env_retain(closure);
    }
    return fn;
}
