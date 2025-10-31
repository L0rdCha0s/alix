#ifndef ATK_OBJECT_H
#define ATK_OBJECT_H

#include "types.h"
#include "libc.h"

typedef struct atk_widget atk_widget_t;
typedef struct atk_class atk_class_t;

typedef struct
{
    void (*destroy)(atk_widget_t *widget);
    void (*draw)(atk_widget_t *widget, void *context);
    void (*layout)(atk_widget_t *widget, int avail_width, int avail_height);
    bool (*hit_test)(atk_widget_t *widget, int x, int y);
    bool (*on_mouse)(atk_widget_t *widget, int x, int y, int buttons, int action);
    bool (*on_key)(atk_widget_t *widget, int key, int modifiers, int action);
} atk_widget_vtable_t;

struct atk_class
{
    const char *name;
    const atk_class_t *parent;
    const atk_widget_vtable_t *vtable;
    size_t payload_size;
};

struct atk_widget
{
    const atk_class_t *cls;
    bool used;
    int x;
    int y;
    int width;
    int height;
    uint32_t flags;
    atk_widget_t *parent;
};

size_t atk_class_total_payload(const atk_class_t *cls);
atk_widget_t *atk_widget_init(void *memory, const atk_class_t *cls);
atk_widget_t *atk_widget_create(const atk_class_t *cls);
void atk_widget_destroy(atk_widget_t *widget);
bool atk_widget_is_a(const atk_widget_t *widget, const atk_class_t *cls);
void *atk_widget_priv(const atk_widget_t *widget, const atk_class_t *cls);

#endif
