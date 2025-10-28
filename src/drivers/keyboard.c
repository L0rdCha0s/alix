#include "keyboard.h"
#include "io.h"

#define KBD_STATUS 0x64
#define KBD_DATA   0x60

static uint8_t left_shift_pressed = 0;
static uint8_t right_shift_pressed = 0;
static uint8_t caps_lock_enabled = 0;
static uint8_t extended_code_pending = 0;

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

static bool read_scancode(uint8_t *code)
{
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
    extended_code_pending = 0;

    /* Drain any outstanding scancodes the firmware may have queued. */
    uint8_t discard;
    while (read_scancode(&discard))
    {
    }
}

void keyboard_init(void)
{
    keyboard_reset_state();
}

bool keyboard_try_read(char *out_char)
{
    uint8_t scancode;
    if (!read_scancode(&scancode))
    {
        return false;
    }

    bool keypad_enter = false;

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
        if (scancode == 0x1C)
        {
            keypad_enter = true;
        }
        else
        {
            /* Ignore other extended-key prefixes for now. */
        }
    }

    if (scancode == 0x2A)
    {
        left_shift_pressed = released ? 0 : 1;
        return false;
    }
    if (scancode == 0x36)
    {
        right_shift_pressed = released ? 0 : 1;
        return false;
    }

    if (scancode == 0x3A && !released)
    {
        caps_lock_enabled ^= 1;
        return false;
    }

    if (released)
    {
        return false;
    }

    bool shift_active = (left_shift_pressed | right_shift_pressed) != 0;
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

    *out_char = ch;
    return true;
}
