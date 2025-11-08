#ifndef FONT_H
#define FONT_H

#include <stdint.h>

#define FONT_BASIC_FIRST_CHAR 32
#define FONT_BASIC_LAST_CHAR  127
#define FONT_BASIC_CHAR_COUNT (FONT_BASIC_LAST_CHAR - FONT_BASIC_FIRST_CHAR + 1)
#define FONT_BASIC_WIDTH      8
#define FONT_BASIC_HEIGHT     8
#define FONT_BASIC_HEIGHT_X2  16

const uint8_t *font_basic_get_glyph8x8(uint8_t ch);
void font_basic_copy_glyph8x16(uint8_t ch, uint8_t dest[FONT_BASIC_HEIGHT_X2]);

#endif /* FONT_H */
