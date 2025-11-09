#include "keyboard.h"
#include "io.h"
#include "interrupts.h"
#include "serial.h"
#include "libc.h"
#include "timer.h"
#include "procfs.h"

#define KBD_STATUS 0x64
#define KBD_DATA   0x60

static uint8_t left_shift_pressed = 0;
static uint8_t right_shift_pressed = 0;
static uint8_t caps_lock_enabled = 0;
static uint8_t left_ctrl_pressed = 0;
static uint8_t right_ctrl_pressed = 0;
static uint8_t extended_code_pending = 0;

#define KBD_BUFFER_SIZE 64
static volatile uint8_t scancode_buffer[KBD_BUFFER_SIZE];
static volatile size_t buffer_head = 0;
static volatile size_t buffer_tail = 0;
static uint8_t key_down[128];

/* Place key maps in .data, not .rodata, to avoid early-rodata issues */
static char normal_map[128] = {
    0,   27, '1','2','3','4','5','6','7','8','9','0','-','=', '\b','\t',
    'q','w','e','r','t','y','u','i','o','p','[',']','\n', 0, 'a','s',
    'd','f','g','h','j','k','l',';','\'', '`', 0,'\\','z','x','c','v',
    'b','n','m',',','.','/', 0,'*', 0,' ', 0,  0,   0,   0,   0,   0,
    0,   0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    0
};

static char shift_map[128] = {
    0,   27, '!','@','#','$','%','^','&','*','(',')','_','+','\b','\t',
    'Q','W','E','R','T','Y','U','I','O','P','{','}','\n', 0, 'A','S',
    'D','F','G','H','J','K','L',':','"','~', 0,'|','Z','X','C','V',
    'B','N','M','<','>','?', 0,'*', 0,' ', 0,  0,   0,   0,   0,   0,
    0,   0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    0
};
/* Place key maps in .data, not .rodata, to avoid early-rodata issues */
#define KBD_PENDING_CHARS 64
static char pending_chars[KBD_PENDING_CHARS];
static size_t pending_start = 0;
static size_t pending_count = 0;

#define KEYBOARD_REPEAT_INITIAL_PATH "keyboard/repeat/initial"
#define KEYBOARD_REPEAT_INTERVAL_PATH "keyboard/repeat/repeat"
#define KEYBOARD_REPEAT_MULTI_PATH "keyboard/repeat/multi_mode"

static uint32_t repeat_initial_delay_ms = 500;
static uint32_t repeat_interval_ms = 200;
static uint32_t repeat_initial_delay_ticks = 50;
static uint32_t repeat_interval_ticks = 20;

typedef struct
{
    bool active;
    uint8_t scancode;
    bool extended;
    bool keypad_enter;
    uint64_t next_tick;
    bool waiting_initial;
} keyboard_repeat_entry_t;

#define KEYBOARD_MAX_REPEAT_KEYS 8
static keyboard_repeat_entry_t g_repeat_entries[KEYBOARD_MAX_REPEAT_KEYS];
static size_t g_repeat_next_index = 0;
static bool g_repeat_multi_mode = false;

typedef struct
{
    uint32_t *value_ms;
    const char *name;
} keyboard_proc_value_t;

typedef struct
{
    bool *value;
    void (*on_change)(bool enabled);
} keyboard_proc_bool_entry_t;

static keyboard_proc_value_t g_initial_repeat_entry = { &repeat_initial_delay_ms, "initial" };
static keyboard_proc_value_t g_repeat_interval_entry = { &repeat_interval_ms, "repeat" };
static keyboard_proc_bool_entry_t g_multi_repeat_entry = { &g_repeat_multi_mode, NULL };

static void keyboard_repeat_reset(void);
static void keyboard_start_repeat(uint8_t scancode, bool extended, bool keypad_enter);
static void keyboard_stop_repeat(uint8_t scancode, bool extended);
static bool keyboard_repeat_due(char *out_char);
static void keyboard_update_repeat_ticks(void);
static void keyboard_set_multi_mode(bool enabled);
static bool keyboard_emit_char(uint8_t scancode, bool extended, bool keypad_enter, bool synthetic, char *out_char);
static ssize_t keyboard_proc_value_read(vfs_node_t *node, size_t offset, void *buffer, size_t count, void *context);
static ssize_t keyboard_proc_value_write(vfs_node_t *node, size_t offset, const void *buffer, size_t count, void *context);
static bool pending_pop_char(char *ch);
static void pending_push_sequence(const char *seq, size_t len);

static bool keyboard_is_space(char ch)
{
    return (ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r');
}

static void keyboard_repeat_reset(void)
{
    for (size_t i = 0; i < KEYBOARD_MAX_REPEAT_KEYS; ++i)
    {
        g_repeat_entries[i].active = false;
    }
    g_repeat_next_index = 0;
}

static uint32_t keyboard_ms_to_ticks(uint32_t ms)
{
    uint32_t freq = timer_frequency();
    if (freq == 0)
    {
        freq = 100;
    }
    uint64_t ticks = ((uint64_t)ms * (uint64_t)freq + 999ULL) / 1000ULL;
    if (ticks == 0)
    {
        ticks = 1;
    }
    return (uint32_t)ticks;
}

static void keyboard_update_repeat_ticks(void)
{
    repeat_initial_delay_ticks = keyboard_ms_to_ticks(repeat_initial_delay_ms);
    repeat_interval_ticks = keyboard_ms_to_ticks(repeat_interval_ms);

    uint64_t now = timer_ticks();
    for (size_t i = 0; i < KEYBOARD_MAX_REPEAT_KEYS; ++i)
    {
        keyboard_repeat_entry_t *entry = &g_repeat_entries[i];
        if (!entry->active)
        {
            continue;
        }
        uint32_t delay = entry->waiting_initial ? repeat_initial_delay_ticks : repeat_interval_ticks;
        entry->next_tick = now + delay;
    }
}

static keyboard_repeat_entry_t *keyboard_repeat_find(uint8_t scancode, bool extended)
{
    for (size_t i = 0; i < KEYBOARD_MAX_REPEAT_KEYS; ++i)
    {
        keyboard_repeat_entry_t *entry = &g_repeat_entries[i];
        if (entry->active && entry->scancode == scancode && entry->extended == extended)
        {
            return entry;
        }
    }
    return NULL;
}

static keyboard_repeat_entry_t *keyboard_repeat_alloc(void)
{
    for (size_t i = 0; i < KEYBOARD_MAX_REPEAT_KEYS; ++i)
    {
        keyboard_repeat_entry_t *entry = &g_repeat_entries[i];
        if (!entry->active)
        {
            return entry;
        }
    }
    return NULL;
}

static void keyboard_set_multi_mode(bool enabled)
{
    if (g_repeat_multi_mode == enabled)
    {
        return;
    }
    g_repeat_multi_mode = enabled;
    keyboard_repeat_reset();
}

static void keyboard_start_repeat(uint8_t scancode, bool extended, bool keypad_enter)
{
    if (!g_repeat_multi_mode)
    {
        keyboard_repeat_reset();
    }

    keyboard_repeat_entry_t *entry = keyboard_repeat_find(scancode, extended);
    if (!entry)
    {
        entry = keyboard_repeat_alloc();
    }
    if (!entry)
    {
        return;
    }

    entry->active = true;
    entry->scancode = scancode;
    entry->extended = extended;
    entry->keypad_enter = keypad_enter;
    entry->waiting_initial = true;
    entry->next_tick = timer_ticks() + repeat_initial_delay_ticks;
}

static void keyboard_stop_repeat(uint8_t scancode, bool extended)
{
    keyboard_repeat_entry_t *entry = keyboard_repeat_find(scancode, extended);
    if (entry)
    {
        entry->active = false;
    }
}

static bool keyboard_repeat_due(char *out_char)
{
    if (!out_char)
    {
        return false;
    }

    uint64_t now = timer_ticks();
    for (size_t i = 0; i < KEYBOARD_MAX_REPEAT_KEYS; ++i)
    {
        size_t idx = (g_repeat_next_index + i) % KEYBOARD_MAX_REPEAT_KEYS;
        keyboard_repeat_entry_t *entry = &g_repeat_entries[idx];
        if (!entry->active)
        {
            continue;
        }
        if (now < entry->next_tick)
        {
            continue;
        }
        if (!keyboard_emit_char(entry->scancode,
                                entry->extended,
                                entry->keypad_enter,
                                true,
                                out_char))
        {
            entry->active = false;
            continue;
        }
        entry->waiting_initial = false;
        entry->next_tick = now + repeat_interval_ticks;
        g_repeat_next_index = (idx + 1) % KEYBOARD_MAX_REPEAT_KEYS;
        return true;
    }
    return false;
}

static bool keyboard_emit_arrow_sequence(uint8_t scancode, char *out_char)
{
    switch (scancode)
    {
        case 0x48: /* Up */
            pending_push_sequence("\x1B[A", 3);
            return pending_pop_char(out_char);
        case 0x50: /* Down */
            pending_push_sequence("\x1B[B", 3);
            return pending_pop_char(out_char);
        case 0x4B: /* Left */
            pending_push_sequence("\x1B[D", 3);
            return pending_pop_char(out_char);
        case 0x4D: /* Right */
            pending_push_sequence("\x1B[C", 3);
            return pending_pop_char(out_char);
        default:
            break;
    }
    return false;
}

static bool keyboard_emit_char(uint8_t scancode,
                               bool extended,
                               bool keypad_enter,
                               bool synthetic,
                               char *out_char)
{
    if (!out_char)
    {
        return false;
    }

    if (extended && keyboard_emit_arrow_sequence(scancode, out_char))
    {
        return true;
    }

    if (!synthetic && scancode < 128)
    {
        if (key_down[scancode])
        {
            return false;
        }
        key_down[scancode] = 1;
    }

    bool shift_active = (left_shift_pressed | right_shift_pressed) != 0;
    bool ctrl_active = (left_ctrl_pressed | right_ctrl_pressed) != 0;

    if (scancode >= sizeof(normal_map))
    {
        return false;
    }

    char base = normal_map[scancode];
    if (base == 0)
    {
        return false;
    }

    char ch = base;
    if (base >= 'a' && base <= 'z')
    {
        bool make_upper = shift_active ^ (caps_lock_enabled != 0);
        if (make_upper)
        {
            char shifted = shift_map[scancode];
            ch = (shifted != 0) ? shifted : (char)(base - ('a' - 'A'));
        }
    }
    else if (keypad_enter)
    {
        ch = '\n';
    }
    else if (shift_active)
    {
        char shifted = shift_map[scancode];
        if (shifted != 0)
        {
            ch = shifted;
        }
    }

    if (ch == 0)
    {
        return false;
    }

    if (ctrl_active)
    {
        if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z'))
        {
            ch = (char)(ch & 0x1F);
        }
        else
        {
            return false;
        }
    }

    *out_char = ch;
    return true;
}

static size_t keyboard_append_uint(char *buffer, size_t capacity, size_t pos, uint32_t value)
{
    char tmp[16];
    size_t len = 0;
    if (value == 0)
    {
        tmp[len++] = '0';
    }
    else
    {
        while (value > 0 && len < sizeof(tmp))
        {
            tmp[len++] = (char)('0' + (value % 10U));
            value /= 10U;
        }
    }
    while (len > 0 && pos + 1 < capacity)
    {
        buffer[pos++] = tmp[--len];
    }
    return pos;
}

static bool keyboard_parse_single_uint(const char *text, uint32_t *value_out)
{
    if (!text || !value_out)
    {
        return false;
    }
    const char *cursor = text;
    while (keyboard_is_space(*cursor))
    {
        ++cursor;
    }
    if (*cursor == '\0')
    {
        return false;
    }
    uint64_t value = 0;
    bool any = false;
    while (*cursor >= '0' && *cursor <= '9')
    {
        any = true;
        value = value * 10ULL + (uint64_t)(*cursor - '0');
        if (value > 1000000ULL)
        {
            value = 1000000ULL;
        }
        ++cursor;
    }
    while (keyboard_is_space(*cursor))
    {
        ++cursor;
    }
    if (*cursor != '\0')
    {
        return false;
    }
    if (!any)
    {
        return false;
    }
    *value_out = (uint32_t)value;
    return true;
}

static ssize_t keyboard_proc_value_read(vfs_node_t *node, size_t offset, void *buffer, size_t count, void *context)
{
    (void)node;
    if (!buffer || !context)
    {
        return -1;
    }

    keyboard_proc_value_t *entry = (keyboard_proc_value_t *)context;
    if (!entry || !entry->value_ms)
    {
        return -1;
    }

    char temp[32];
    size_t pos = 0;
    pos = keyboard_append_uint(temp, sizeof(temp), pos, *entry->value_ms);
    if (pos >= sizeof(temp))
    {
        pos = sizeof(temp) - 1;
    }
    if (pos < sizeof(temp) - 1)
    {
        temp[pos++] = '\n';
    }
    temp[pos] = '\0';

    if (offset >= pos || count == 0)
    {
        return 0;
    }
    if (count > pos - offset)
    {
        count = pos - offset;
    }
    memcpy(buffer, temp + offset, count);
    return (ssize_t)count;
}

static ssize_t keyboard_proc_value_write(vfs_node_t *node, size_t offset, const void *buffer, size_t count, void *context)
{
    (void)node;
    if (!buffer || !context || offset != 0)
    {
        return -1;
    }

    keyboard_proc_value_t *entry = (keyboard_proc_value_t *)context;
    if (!entry || !entry->value_ms)
    {
        return -1;
    }
    if (count == 0)
    {
        return 0;
    }

    char temp[64];
    size_t len = count;
    if (len >= sizeof(temp))
    {
        len = sizeof(temp) - 1;
    }
    memcpy(temp, buffer, len);
    temp[len] = '\0';

    uint32_t new_value = *entry->value_ms;
    if (!keyboard_parse_single_uint(temp, &new_value))
    {
        return -1;
    }

    *entry->value_ms = new_value;
    keyboard_update_repeat_ticks();
    return (ssize_t)count;
}

static ssize_t keyboard_proc_bool_read(vfs_node_t *node, size_t offset, void *buffer, size_t count, void *context)
{
    (void)node;
    if (!buffer || !context)
    {
        return -1;
    }
    keyboard_proc_bool_entry_t *entry = (keyboard_proc_bool_entry_t *)context;
    if (!entry->value)
    {
        return -1;
    }

    char temp[4];
    size_t len = 0;
    temp[len++] = *entry->value ? '1' : '0';
    temp[len++] = '\n';

    if (offset >= len || count == 0)
    {
        return 0;
    }
    if (count > len - offset)
    {
        count = len - offset;
    }
    memcpy(buffer, temp + offset, count);
    return (ssize_t)count;
}

static ssize_t keyboard_proc_bool_write(vfs_node_t *node, size_t offset, const void *buffer, size_t count, void *context)
{
    (void)node;
    if (!buffer || !context || offset != 0)
    {
        return -1;
    }
    keyboard_proc_bool_entry_t *entry = (keyboard_proc_bool_entry_t *)context;
    if (!entry->value)
    {
        return -1;
    }
    if (count == 0)
    {
        return 0;
    }

    char temp[32];
    size_t len = count;
    if (len >= sizeof(temp))
    {
        len = sizeof(temp) - 1;
    }
    memcpy(temp, buffer, len);
    temp[len] = '\0';

    uint32_t parsed = 0;
    if (!keyboard_parse_single_uint(temp, &parsed))
    {
        return -1;
    }

    bool new_value = (parsed != 0);
    if (*entry->value != new_value)
    {
        *entry->value = new_value;
        if (entry->on_change)
        {
            entry->on_change(new_value);
        }
    }
    return (ssize_t)count;
}

static bool buffer_empty(void)
{
    return buffer_head == buffer_tail;
}

static bool buffer_full(void)
{
    return ((buffer_head + 1) % KBD_BUFFER_SIZE) == buffer_tail;
}

static void buffer_push(uint8_t code)
{
    if (buffer_full())
    {
        return;
    }
    scancode_buffer[buffer_head] = code;
    buffer_head = (buffer_head + 1) % KBD_BUFFER_SIZE;

    //serial_write_string("keyboard.c: buffer_push scancode=0x");
    //static const char hex[] = "0123456789ABCDEF";
    //serial_write_char(hex[(code >> 4) & 0xF]);
    //serial_write_char(hex[code & 0xF]);
    //serial_write_string("\r\n");
}

static bool buffer_pop(uint8_t *code)
{
    if (buffer_empty())
    {
        return false;
    }
    *code = scancode_buffer[buffer_tail];
    buffer_tail = (buffer_tail + 1) % KBD_BUFFER_SIZE;
    return true;
}

static bool read_scancode(uint8_t *code)
{
    if (buffer_pop(code))
    {
        return true;
    }
    uint8_t status = inb(KBD_STATUS);
    if ((status & 0x01) == 0)
    {
        return false;
    }
    if ((status & 0x20) != 0)
    {
        return false;
    }
    *code = inb(KBD_DATA);
    return true;
}

static void keyboard_reset_state(void)
{
    left_shift_pressed = 0;
    right_shift_pressed = 0;
    caps_lock_enabled = 0;
    left_ctrl_pressed = 0;
    right_ctrl_pressed = 0;
    extended_code_pending = 0;
    buffer_head = 0;
    buffer_tail = 0;
    for (size_t i = 0; i < sizeof(key_down); ++i)
    {
        key_down[i] = 0;
    }

    pending_start = 0;
    pending_count = 0;

    /* Drain any outstanding scancodes the firmware may have queued. */
    uint8_t discard;
    while (read_scancode(&discard))
    {
    }

    keyboard_repeat_reset();
}

static bool pending_pop_char(char *ch)
{
    if (pending_count == 0 || !ch)
    {
        return false;
    }
    *ch = pending_chars[pending_start];
    pending_start = (pending_start + 1) % KBD_PENDING_CHARS;
    pending_count--;
    return true;
}

static void pending_push_char(char ch)
{
    if (pending_count >= KBD_PENDING_CHARS)
    {
        return;
    }
    size_t index = (pending_start + pending_count) % KBD_PENDING_CHARS;
    pending_chars[index] = ch;
    pending_count++;
}

static void pending_push_sequence(const char *seq, size_t len)
{
    if (!seq || len == 0)
    {
        return;
    }
    for (size_t i = 0; i < len; ++i)
    {
        pending_push_char(seq[i]);
    }
}

void keyboard_init(void)
{
    keyboard_reset_state();
    keyboard_update_repeat_ticks();

    if (!procfs_mkdir("keyboard"))
    {
        serial_write_string("[keyboard] failed to ensure /proc/keyboard\r\n");
    }
    if (!procfs_mkdir("keyboard/repeat"))
    {
        serial_write_string("[keyboard] failed to ensure /proc/keyboard/repeat\r\n");
    }

    g_multi_repeat_entry.on_change = keyboard_set_multi_mode;

    if (!procfs_create_file_at(KEYBOARD_REPEAT_INITIAL_PATH,
                               keyboard_proc_value_read,
                               keyboard_proc_value_write,
                               &g_initial_repeat_entry))
    {
        serial_write_string("[keyboard] failed to create /proc/keyboard/repeat/initial\r\n");
    }
    if (!procfs_create_file_at(KEYBOARD_REPEAT_INTERVAL_PATH,
                               keyboard_proc_value_read,
                               keyboard_proc_value_write,
                               &g_repeat_interval_entry))
    {
        serial_write_string("[keyboard] failed to create /proc/keyboard/repeat/repeat\r\n");
    }
    if (!procfs_create_file_at(KEYBOARD_REPEAT_MULTI_PATH,
                               keyboard_proc_bool_read,
                               keyboard_proc_bool_write,
                               &g_multi_repeat_entry))
    {
        serial_write_string("[keyboard] failed to create /proc/keyboard/repeat/multi_mode\r\n");
    }
}

bool keyboard_try_read(char *out_char)
{
    if (pending_pop_char(out_char))
    {
        return true;
    }
    if (keyboard_repeat_due(out_char))
    {
        return true;
    }

    //serial_write_string("keybaord.c: keyboard_try_read\n");


    uint8_t scancode;
    if (!read_scancode(&scancode))
    {
        return false;
    }

    bool keypad_enter = false;
    bool extended = false;

    if (scancode == 0xE0)
    {
        extended_code_pending = 1;
        return false;
    }

    bool released = (scancode & 0x80) != 0;
    scancode &= 0x7F;

    if (extended_code_pending)
    {
        extended_code_pending = 0;
        extended = true;
        if (scancode == 0x1C)
        {
            keypad_enter = true;
        }
    }

    if (scancode == 0x2A)
    {
        left_shift_pressed = released ? 0 : 1;
        if (scancode < 128)
        {
            key_down[scancode] = released ? 0 : 1;
        }
        return false;
    }
    if (scancode == 0x36)
    {
        right_shift_pressed = released ? 0 : 1;
        if (scancode < 128)
        {
            key_down[scancode] = released ? 0 : 1;
        }
        return false;
    }

    if (scancode == 0x3A && !released)
    {
        caps_lock_enabled ^= 1;
        return false;
    }

    if (!extended && scancode == 0x1D)
    {
        left_ctrl_pressed = released ? 0 : 1;
        if (scancode < 128)
        {
            key_down[scancode] = released ? 0 : 1;
        }
        return false;
    }
    if (extended && scancode == 0x1D)
    {
        right_ctrl_pressed = released ? 0 : 1;
        return false;
    }

    if (released)
    {
        if (scancode < 128)
        {
            key_down[scancode] = 0;
        }
        keyboard_stop_repeat(scancode, extended);
        return false;
    }

    if (keyboard_emit_char(scancode, extended, keypad_enter, false, out_char))
    {
        keyboard_start_repeat(scancode, extended, keypad_enter);
        return true;
    }
    return false;
}

void keyboard_buffer_push(uint8_t scancode)
{
    //serial_write_string("keyboard.c: keyboard_buffer_push scancode=0x");
    //serial_write_char(hex[(scancode >> 4) & 0xF]);
    //serial_write_char(hex[scancode & 0xF]);
    //serial_write_string("\r\n");

    buffer_push(scancode);
}
