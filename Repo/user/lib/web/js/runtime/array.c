#include "web/js/runtime/runtime_internal.h"

#include "libc.h"

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
    for (size_t i = 0; i < array->length; ++i)
    {
        js_value_destroy(&array->items[i]);
    }
    free(array->items);
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
    return js_value_copy(out, &array->items[index]);
}
