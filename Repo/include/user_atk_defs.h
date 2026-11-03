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
    USER_ATK_EVENT_RESIZE = 4,
    USER_ATK_EVENT_FOCUS = 5, /* data0: 1 gained, 0 lost */
    USER_ATK_EVENT_MOVE = 6,  /* x/y: client origin in screen pixels */
} user_atk_event_type_t;

#define USER_ATK_MOUSE_FLAG_PRESS   (1u << 0)
#define USER_ATK_MOUSE_FLAG_RELEASE (1u << 1)
#define USER_ATK_MOUSE_FLAG_LEFT    (1u << 2)
#define USER_ATK_MOUSE_FLAG_RELATIVE (1u << 3)
#define USER_ATK_MOUSE_FLAG_RIGHT   (1u << 4)
#define USER_ATK_MOUSE_FLAG_RIGHT_PRESS (1u << 5)
#define USER_ATK_MOUSE_FLAG_RIGHT_RELEASE (1u << 6)
#define USER_ATK_KEY_FLAG_RELEASE   (1u << 0)
#define USER_ATK_KEY_FLAG_EXTENDED  (1u << 1)
#define USER_ATK_KEY_FLAG_REPEAT    (1u << 2)

typedef struct
{
    uint32_t type;   /* user_atk_event_type_t */
    uint32_t flags;
    int32_t x;
    int32_t y;
    uint32_t data0;
    uint32_t data1;  /* resize events: data0=width, data1=height */
} user_atk_event_t;

typedef struct
{
    uint32_t width;
    uint32_t height;
    uint32_t flags;
    char title[USER_ATK_TITLE_MAX];
} user_atk_window_desc_t;

#define USER_ATK_POLL_FLAG_BLOCK (1u << 0)
#define USER_ATK_WINDOW_FLAG_RESIZABLE (1u << 0)
#define USER_ATK_WINDOW_FLAG_HIDDEN (1u << 1)
#define USER_ATK_WINDOW_FLAG_BORDERLESS (1u << 2)
#define USER_ATK_WINDOW_FLAG_RAW_KEYS (1u << 3)
#define USER_ATK_CAPTURE_ENABLE (1u << 0)
#define USER_ATK_CAPTURE_RELATIVE (1u << 1)

#define USER_ATK_CONTROL_VERSION 1u
typedef enum
{
    USER_ATK_CONTROL_QUERY,
    USER_ATK_CONTROL_BOUNDS,
    USER_ATK_CONTROL_VISIBLE,
    USER_ATK_CONTROL_FOCUS,
    USER_ATK_CONTROL_TITLE,
    USER_ATK_CONTROL_CHROME,
    USER_ATK_CONTROL_DISPLAY,
    USER_ATK_CONTROL_WORK_AREA,
    USER_ATK_CONTROL_INPUT_IDLE,
} user_atk_control_opcode_t;
#define USER_ATK_STATE_VISIBLE 1u
#define USER_ATK_STATE_FOCUSED 2u
#define USER_ATK_STATE_CHROME 4u
#define USER_ATK_STATE_RESIZABLE 8u
/* Every successful operation returns actual state in this fixed-size record.
 * Bounds use client-area screen pixels. VISIBLE/CHROME accept flags 0 or 1.
 * DISPLAY requires handle 0 and returns physical screen dimensions.
 * WORK_AREA also requires handle 0; its client rectangle excludes the desktop
 * menu bar, while screen_width/screen_height retain the physical dimensions.
 * Request flag USER_ATK_STATE_CHROME also reserves the native window frame.
 * INPUT_IDLE requires handle/flags 0 and returns elapsed input-idle milliseconds. */
typedef struct
{
    uint32_t version, size;
    int32_t x, y;
    union { uint32_t width; uint32_t idle_milliseconds; };
    uint32_t height, flags, screen_width, screen_height, reserved;
    char title[USER_ATK_TITLE_MAX];
} user_atk_window_control_t;

#endif /* USER_ATK_DEFS_H */
