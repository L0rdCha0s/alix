#include "keyboard.h"
#include "io.h"

#define KBD_STATUS 0x64
#define KBD_DATA   0x60

static bool shift_pressed = false;

static const char normal_map[128] = {
    0,   27, '1','2','3','4','5','6','7','8','9','0','-','=', '\b','\t',
    'q','w','e','r','t','y','u','i','o','p','[',']','\n', 0, 'a','s',
    'd','f','g','h','j','k','l',';','\'', '`', 0,'\\','z','x','c','v',
    'b','n','m',',','.','/', 0,'*', 0,' ', 0,  0,   0,   0,   0,   0,
    0,   0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    0
};

static const char shift_map[128] = {
    0,   27, '!','@','#','$','%','^','&','*','(',')','_','+','\b','\t',
    'Q','W','E','R','T','Y','U','I','O','P','{','}','\n', 0, 'A','S',
    'D','F','G','H','J','K','L',':','"','~', 0,'|','Z','X','C','V',
    'B','N','M','<','>','?', 0,'*', 0,' ', 0,  0,   0,   0,   0,   0,
    0,   0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    0
};

static bool read_scancode(uint8_t *code)
{
    if ((inb(KBD_STATUS) & 0x01) == 0)
    {
        return false;
    }
    *code = inb(KBD_DATA);
    return true;
}

void keyboard_init(void)
{
    shift_pressed = false;
}

bool keyboard_try_read(char *out_char)
{
    uint8_t scancode;
    if (!read_scancode(&scancode))
    {
        return false;
    }

    bool released = (scancode & 0x80) != 0;
    scancode &= 0x7F;

    if (scancode == 0x2A || scancode == 0x36)
    {
        shift_pressed = !released;
        return false;
    }

    if (released)
    {
        return false;
    }

    char ch = shift_pressed ? shift_map[scancode] : normal_map[scancode];
    if (ch == 0)
    {
        return false;
    }

    *out_char = ch;
    return true;
}
