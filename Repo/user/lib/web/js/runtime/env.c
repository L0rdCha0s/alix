#include "web/js/runtime/runtime_internal.h"

#include "libc.h"

typedef struct js_var
{
    char *name;
    js_value_t value;
    bool is_const;
    struct js_var *next;
} js_var_t;

struct js_env
{
    struct js_env *parent;
    js_var_t *vars;
    int refcount;
    bool is_function;
};

void js_env_retain(js_env_t *env)
{
    if (!env)
    {
        return;
    }
    env->refcount++;
}

js_env_t *js_env_create(js_env_t *parent, bool is_function)
{
    js_env_t *env = (js_env_t *)calloc(1, sizeof(*env));
    if (!env)
    {
        return NULL;
    }
    env->parent = parent;
    env->vars = NULL;
    env->refcount = 1;
    env->is_function = is_function;
    if (parent)
    {
        js_env_retain(parent);
    }
    return env;
}

void js_env_release(js_env_t *env)
{
    if (!env)
    {
        return;
    }
    if (env->refcount <= 0)
    {
        return;
    }
    env->refcount--;
    if (env->refcount > 0)
    {
        return;
    }
    js_var_t *var = env->vars;
    while (var)
    {
        js_var_t *next = var->next;
        free(var->name);
        js_value_destroy(&var->value);
        free(var);
        var = next;
    }
    js_env_t *parent = env->parent;
    free(env);
    if (parent)
    {
        js_env_release(parent);
    }
}

static js_var_t *js_env_find_local(js_env_t *env, const char *name)
{
    if (!env || !name)
    {
        return NULL;
    }
    for (js_var_t *var = env->vars; var; var = var->next)
    {
        if (var->name && strcmp(var->name, name) == 0)
        {
            return var;
        }
    }
    return NULL;
}

static js_var_t *js_env_find(js_env_t *env, const char *name)
{
    for (js_env_t *cur = env; cur; cur = cur->parent)
    {
        js_var_t *var = js_env_find_local(cur, name);
        if (var)
        {
            return var;
        }
    }
    return NULL;
}

bool js_env_define_local(js_env_t *env,
                         const char *name,
                         const js_value_t *value,
                         bool is_const,
                         bool allow_redeclare)
{
    if (!env || !name || !value)
    {
        return false;
    }
    js_var_t *existing = js_env_find_local(env, name);
    if (existing)
    {
        if (existing->is_const || !allow_redeclare)
        {
            return false;
        }
        js_value_destroy(&existing->value);
        if (!js_value_copy(&existing->value, value))
        {
            return false;
        }
        existing->is_const = existing->is_const || is_const;
        return true;
    }

    js_var_t *var = (js_var_t *)calloc(1, sizeof(*var));
    if (!var)
    {
        return false;
    }
    var->name = js_strdup(name);
    if (!var->name)
    {
        free(var);
        return false;
    }
    if (!js_value_copy(&var->value, value))
    {
        free(var->name);
        free(var);
        return false;
    }
    var->is_const = is_const;
    var->next = env->vars;
    env->vars = var;
    return true;
}

bool js_env_define_if_absent(js_env_t *env, const char *name, const js_value_t *value, bool is_const)
{
    if (!env || !name || !value)
    {
        return false;
    }
    js_var_t *existing = js_env_find_local(env, name);
    if (existing)
    {
        return true;
    }
    return js_env_define_local(env, name, value, is_const, true);
}

js_env_t *js_env_find_var_scope(js_env_t *env)
{
    for (js_env_t *cur = env; cur; cur = cur->parent)
    {
        if (cur->is_function)
        {
            return cur;
        }
    }
    return env;
}

bool js_env_assign(js_env_t *env, const char *name, const js_value_t *value)
{
    js_var_t *var = js_env_find(env, name);
    if (!var)
    {
        return false;
    }
    if (var->is_const)
    {
        return false;
    }
    js_value_destroy(&var->value);
    return js_value_copy(&var->value, value);
}

bool js_env_get(js_env_t *env, const char *name, js_value_t *out)
{
    if (!out)
    {
        return false;
    }
    js_var_t *var = js_env_find(env, name);
    if (!var)
    {
        return false;
    }
    return js_value_copy(out, &var->value);
}
