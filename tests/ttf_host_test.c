#define TTF_HOST_BUILD 1
#include "ttf.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static bool read_entire_file(const char *path, uint8_t **out_data, size_t *out_size)
{
    if (!path || !out_data || !out_size)
    {
        return false;
    }
    FILE *fp = fopen(path, "rb");
    if (!fp)
    {
        perror("fopen");
        return false;
    }
    if (fseek(fp, 0, SEEK_END) != 0)
    {
        perror("fseek");
        fclose(fp);
        return false;
    }
    long length = ftell(fp);
    if (length < 0)
    {
        perror("ftell");
        fclose(fp);
        return false;
    }
    if (fseek(fp, 0, SEEK_SET) != 0)
    {
        perror("fseek");
        fclose(fp);
        return false;
    }
    uint8_t *buffer = (uint8_t *)malloc((size_t)length);
    if (!buffer)
    {
        fprintf(stderr, "ttf_host_test: allocation failed for %ld bytes\n", length);
        fclose(fp);
        return false;
    }
    size_t bytes_read = fread(buffer, 1, (size_t)length, fp);
    fclose(fp);
    if (bytes_read != (size_t)length)
    {
        fprintf(stderr, "ttf_host_test: short read (%zu/%ld)\n", bytes_read, length);
        free(buffer);
        return false;
    }
    *out_data = buffer;
    *out_size = (size_t)length;
    return true;
}

static bool render_codepoint(ttf_font_t *font, uint32_t codepoint, int pixel_height)
{
    uint16_t glyph_index = ttf_font_lookup_glyph(font, codepoint);
    if (glyph_index == 0)
    {
        fprintf(stderr, "ttf_host_test: missing glyph for U+%04X\n", codepoint);
        return false;
    }
    ttf_bitmap_t bitmap = {0};
    ttf_glyph_metrics_t metrics = {0};
    if (!ttf_font_render_glyph_bitmap(font, codepoint, pixel_height, &bitmap, &metrics))
    {
        fprintf(stderr, "ttf_host_test: failed to render U+%04X (glyph %u)\n",
                codepoint, glyph_index);
        return false;
    }
    printf("glyph U+%04X idx=%u size=%dx%d offset=(%d,%d) advance=%d\n",
           codepoint,
           glyph_index,
           metrics.width,
           metrics.height,
           bitmap.offset_x,
           bitmap.offset_y,
           metrics.advance);
    ttf_bitmap_destroy(&bitmap);
    return true;
}

int main(int argc, char **argv)
{
    const char *font_path = (argc > 1) ? argv[1] : "SF-Pro.ttf";
    uint8_t *font_data = NULL;
    size_t font_size = 0;
    if (!read_entire_file(font_path, &font_data, &font_size))
    {
        fprintf(stderr, "ttf_host_test: failed to read %s\n", font_path);
        return 1;
    }

    ttf_font_t font = {0};
    if (!ttf_font_load(&font, font_data, font_size))
    {
        fprintf(stderr, "ttf_host_test: ttf_font_load failed\n");
        free(font_data);
        return 1;
    }

    free(font_data);

    ttf_font_metrics_t metrics;
    if (!ttf_font_metrics(&font, 48, &metrics))
    {
        fprintf(stderr, "ttf_host_test: ttf_font_metrics failed\n");
        ttf_font_unload(&font);
        return 1;
    }
    printf("metrics: ascent=%d descent=%d line_gap=%d\n",
           metrics.ascent,
           metrics.descent,
           metrics.line_gap);

    const uint32_t samples[] = { 'A', 'g', '0', 0x00E9, 0x20AC };
    for (size_t i = 0; i < sizeof(samples) / sizeof(samples[0]); ++i)
    {
        if (!render_codepoint(&font, samples[i], 48))
        {
            ttf_font_unload(&font);
            return 1;
        }
    }

    ttf_font_unload(&font);
    puts("ttf_host_test: success");
    return 0;
}
