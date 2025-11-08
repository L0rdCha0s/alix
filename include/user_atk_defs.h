#ifndef USER_ATK_DEFS_H
#define USER_ATK_DEFS_H

#include "types.h"

#define USER_ATK_TITLE_MAX 64
#define USER_ATK_EVENT_QUEUE_MAX 64

typedef enum
{
    USER_ATK_EVENT_NONE = 0,
    USER_ATK_EVENT_MOUSE = 1,
    USER_ATK_EVENT_KEY = 2,
    USER_ATK_EVENT_CLOSE = 3,
} user_atk_event_type_t;

#define USER_ATK_MOUSE_FLAG_PRESS   (1u << 0)
#define USER_ATK_MOUSE_FLAG_RELEASE (1u << 1)
#define USER_ATK_MOUSE_FLAG_LEFT    (1u << 2)

typedef struct
{
    uint32_t type;   /* user_atk_event_type_t */
    uint32_t flags;
    int32_t x;
    int32_t y;
    uint32_t data0;
    uint32_t data1;
} user_atk_event_t;

typedef struct
{
    uint32_t width;
    uint32_t height;
    uint32_t flags;
    char title[USER_ATK_TITLE_MAX];
} user_atk_window_desc_t;

#define USER_ATK_POLL_FLAG_BLOCK (1u << 0)

#endif /* USER_ATK_DEFS_H */
