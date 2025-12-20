#include "web/js/runtime/runtime_internal.h"

#include "libc.h"

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
    free(object);
}
