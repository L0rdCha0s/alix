#include "web/js/runtime/runtime_internal.h"

#include "libc.h"
#include "stdio.h"

enum
{
    JS_ARRAY_DENSE_LIMIT = 1u << 20
};

static js_property_t *js_array_find(js_array_t *array, const char *name)
{
    if (!array || !name)
    {
        return NULL;
    }
    for (js_property_t *prop = array->properties; prop; prop = prop->next)
    {
        if (prop->name && strcmp(prop->name, name) == 0)
        {
            return prop;
        }
    }
    return NULL;
}

static bool js_array_index_key(size_t index, char *buf, size_t buf_len)
{
    int len = snprintf(buf, buf_len, "%zu", index);
    return len >= 0 && (size_t)len < buf_len;
}

js_array_t *js_array_create(void)
{
    js_array_t *array = (js_array_t *)calloc(1, sizeof(*array));
    if (!array)
    {
        return NULL;
    }
    array->refcount = 1;
    array->items = NULL;
    array->length = 0;
    array->capacity = 0;
    return array;
}

void js_array_retain(js_array_t *array)
{
    if (!array)
    {
        return;
    }
    array->refcount++;
}

void js_array_release(js_array_t *array)
{
    if (!array)
    {
        return;
    }
    if (array->refcount <= 0)
    {
        return;
    }
    array->refcount--;
    if (array->refcount > 0)
    {
        return;
    }
    size_t limit = array->length < array->capacity ? array->length : array->capacity;
    for (size_t i = 0; i < limit; ++i)
    {
        js_value_destroy(&array->items[i]);
    }
    free(array->items);
    js_property_t *prop = array->properties;
    while (prop)
    {
        js_property_t *next = prop->next;
        free(prop->name);
        js_value_destroy(&prop->value);
        free(prop);
        prop = next;
    }
    free(array);
}

static bool js_array_reserve(js_array_t *array, size_t needed)
{
    if (!array)
    {
        return false;
    }
    if (needed <= array->capacity)
    {
        return true;
    }
    size_t new_cap = array->capacity ? array->capacity : 4u;
    while (new_cap < needed)
    {
        if (new_cap > SIZE_MAX / 2u)
        {
            new_cap = needed;
            break;
        }
        new_cap *= 2u;
    }
    js_value_t *new_items = (js_value_t *)realloc(array->items, new_cap * sizeof(*new_items));
    if (!new_items)
    {
        return false;
    }
    if (new_cap > array->capacity)
    {
        memset(new_items + array->capacity, 0, (new_cap - array->capacity) * sizeof(*new_items));
    }
    array->items = new_items;
    array->capacity = new_cap;
    return true;
}

bool js_array_set(js_array_t *array, size_t index, const js_value_t *value)
{
    if (!array || !value)
    {
        return false;
    }
    if (index >= JS_ARRAY_DENSE_LIMIT)
    {
        char key[32];
        if (!js_array_index_key(index, key, sizeof(key)))
        {
            return false;
        }
        if (!js_array_set_property(array, key, value))
        {
            return false;
        }
        if (index >= array->length)
        {
            array->length = index + 1;
        }
        return true;
    }
    if (!js_array_reserve(array, index + 1))
    {
        return false;
    }
    if (index >= array->length)
    {
        for (size_t i = array->length; i <= index; ++i)
        {
            array->items[i] = js_value_make_undefined_internal();
        }
        array->length = index + 1;
    }
    else
    {
        js_value_destroy(&array->items[index]);
    }
    if (!js_value_copy(&array->items[index], value))
    {
        array->items[index] = js_value_make_undefined_internal();
        return false;
    }
    return true;
}

bool js_array_get(const js_array_t *array, size_t index, js_value_t *out)
{
    if (!out)
    {
        return false;
    }
    if (!array || index >= array->length)
    {
        *out = js_value_make_undefined_internal();
        return true;
    }
    if (index < array->capacity)
    {
        return js_value_copy(out, &array->items[index]);
    }
    char key[32];
    if (!js_array_index_key(index, key, sizeof(key)))
    {
        *out = js_value_make_undefined_internal();
        return true;
    }
    js_property_t *prop = js_array_find((js_array_t *)array, key);
    if (!prop)
    {
        *out = js_value_make_undefined_internal();
        return true;
    }
    return js_value_copy(out, &prop->value);
}

bool js_array_get_property(js_array_t *array, const char *name, js_value_t *out)
{
    if (!out)
    {
        return false;
    }
    if (!array || !name)
    {
        *out = js_value_make_undefined_internal();
        return true;
    }
    js_property_t *prop = js_array_find(array, name);
    if (!prop)
    {
        *out = js_value_make_undefined_internal();
        return true;
    }
    return js_value_copy(out, &prop->value);
}

bool js_array_set_property(js_array_t *array, const char *name, const js_value_t *value)
{
    if (!array || !name || !value)
    {
        return false;
    }
    js_property_t *prop = js_array_find(array, name);
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
    new_prop->next = array->properties;
    array->properties = new_prop;
    return true;
}

bool js_array_set_length(js_array_t *array, size_t new_length)
{
    if (!array)
    {
        return false;
    }
    if (new_length == array->length)
    {
        return true;
    }
    if (new_length < array->length)
    {
        size_t limit = array->length < array->capacity ? array->length : array->capacity;
        if (new_length < limit)
        {
            for (size_t i = new_length; i < limit; ++i)
            {
                js_value_destroy(&array->items[i]);
                array->items[i] = js_value_make_undefined_internal();
            }
        }
        array->length = new_length;
        return true;
    }
    if (new_length <= JS_ARRAY_DENSE_LIMIT)
    {
        if (!js_array_reserve(array, new_length))
        {
            return false;
        }
        for (size_t i = array->length; i < new_length; ++i)
        {
            array->items[i] = js_value_make_undefined_internal();
        }
    }
    array->length = new_length;
    return true;
}
