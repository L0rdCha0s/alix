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

typedef struct
{
    uint32_t codepoint;
    int pixel_height;
    bool expect_fallback;
} advance_case_t;

static bool compare_glyph_advance(ttf_font_t *font, const advance_case_t *test_case)
{
    if (!font || !test_case)
    {
        return false;
    }

    uint16_t glyph_index = ttf_font_lookup_glyph(font, test_case->codepoint);
    if (test_case->expect_fallback && glyph_index != 0)
    {
        fprintf(stderr,
                "ttf_host_test: fallback codepoint U+%04X unexpectedly mapped to glyph %u\n",
                test_case->codepoint,
                glyph_index);
        return false;
    }

    int advance_only = 0;
    if (!ttf_font_glyph_advance(font,
                                test_case->codepoint,
                                test_case->pixel_height,
                                &advance_only))
    {
        fprintf(stderr,
                "ttf_host_test: failed to measure U+%04X at %d px\n",
                test_case->codepoint,
                test_case->pixel_height);
        return false;
    }

    ttf_bitmap_t bitmap = {0};
    ttf_glyph_metrics_t metrics = {0};
    if (!ttf_font_render_glyph_bitmap(font,
                                      test_case->codepoint,
                                      test_case->pixel_height,
                                      &bitmap,
                                      &metrics))
    {
        fprintf(stderr,
                "ttf_host_test: failed to render U+%04X at %d px (glyph %u)\n",
                test_case->codepoint,
                test_case->pixel_height,
                glyph_index);
        return false;
    }

    bool ok = advance_only == metrics.advance;
    if (!ok)
    {
        fprintf(stderr,
                "ttf_host_test: advance mismatch U+%04X at %d px: metrics-only=%d rendered=%d\n",
                test_case->codepoint,
                test_case->pixel_height,
                advance_only,
                metrics.advance);
    }

    if (test_case->expect_fallback)
    {
        int question_advance = 0;
        if (!ttf_font_glyph_advance(font,
                                    '?',
                                    test_case->pixel_height,
                                    &question_advance) ||
            question_advance != advance_only)
        {
            fprintf(stderr,
                    "ttf_host_test: fallback advance U+%04X at %d px did not match '?'\n",
                    test_case->codepoint,
                    test_case->pixel_height);
            ok = false;
        }
    }

    printf("advance U+%04X idx=%u px=%d metrics-only=%d rendered=%d fallback=%u\n",
           test_case->codepoint,
           glyph_index,
           test_case->pixel_height,
           advance_only,
           metrics.advance,
           test_case->expect_fallback ? 1u : 0u);
    ttf_bitmap_destroy(&bitmap);
    return ok;
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

    int unused_advance = 0;
    if (ttf_font_glyph_advance(NULL, 'A', 16, &unused_advance) ||
        ttf_font_glyph_advance(&font, 'A', 0, &unused_advance) ||
        ttf_font_glyph_advance(&font, 'A', 16, NULL))
    {
        fprintf(stderr, "ttf_host_test: glyph advance accepted invalid arguments\n");
        ttf_font_unload(&font);
        return 1;
    }

    const advance_case_t cases[] = {
        { 'A', 9, false },
        { 'A', 16, false },
        { 'A', 48, false },
        { 'A', 96, false },
        { 'g', 13, false },
        { '0', 48, false },
        { 0x00E9, 12, false },
        { 0x00E9, 48, false },
        { 0x20AC, 24, false },
        { 0x20AC, 73, false },
        { 0x0378, 9, true },
        { 0x0378, 48, true },
        { 0x0378, 96, true },
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i)
    {
        if (!compare_glyph_advance(&font, &cases[i]))
        {
            ttf_font_unload(&font);
            return 1;
        }
    }

    ttf_font_unload(&font);
    puts("ttf_host_test: success");
    return 0;
}
