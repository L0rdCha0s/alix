#include "web/js/runtime/runtime_internal.h"

#include "libc.h"

static js_property_t *js_object_find(js_object_t *object, const char *name)
{
    if (!object || !name)
    {
        return NULL;
    }
    for (js_property_t *prop = object->properties; prop; prop = prop->next)
    {
        if (prop->name && strcmp(prop->name, name) == 0)
        {
            return prop;
        }
    }
    return NULL;
}

void js_object_retain(js_object_t *object)
{
    if (!object)
    {
        return;
    }
    object->refcount++;
}

void js_object_release(js_object_t *object)
{
    if (!object)
    {
        return;
    }
    if (object->refcount <= 0)
    {
        return;
    }
    object->refcount--;
    if (object->refcount > 0)
    {
        return;
    }
    if (object->finalize_fn)
    {
        object->finalize_fn(object->user_data);
    }
    js_property_t *prop = object->properties;
    while (prop)
    {
        js_property_t *next = prop->next;
        free(prop->name);
        js_value_destroy(&prop->value);
        free(prop);
        prop = next;
    }
    free(object);
}

bool js_object_get_slot(js_object_t *object, const char *name, js_value_t *out)
{
    if (!out)
    {
        return false;
    }
    if (!object || !name)
    {
        *out = js_value_make_undefined_internal();
        return true;
    }
    js_property_t *prop = js_object_find(object, name);
    if (!prop)
    {
        *out = js_value_make_undefined_internal();
        return true;
    }
    return js_value_copy(out, &prop->value);
}

bool js_object_set_slot(js_object_t *object, const char *name, const js_value_t *value)
{
    if (!object || !name || !value)
    {
        return false;
    }
    js_property_t *prop = js_object_find(object, name);
    if (prop)
    {
        js_value_destroy(&prop->value);
        return js_value_copy(&prop->value, value);
    }
    js_property_t *new_prop = (js_property_t *)calloc(1, sizeof(*new_prop));
    if (!new_prop)
    {
        return false;
    }
    new_prop->name = js_strdup(name);
    if (!new_prop->name)
    {
        free(new_prop);
        return false;
    }
    if (!js_value_copy(&new_prop->value, value))
    {
        free(new_prop->name);
        free(new_prop);
        return false;
    }
    new_prop->next = object->properties;
    object->properties = new_prop;
    return true;
}

bool js_object_has_slot(js_object_t *object, const char *name)
{
    if (!object || !name)
    {
        return false;
    }
    return js_object_find(object, name) != NULL;
}
