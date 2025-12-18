#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#define TTF_HOST_BUILD 1
#define PNG_HOST_BUILD 1

#include "atk/util/png.h"

static const uint8_t g_png_sample_1x1_rgba[] = {
    0x89,'P','N','G',0x0D,0x0A,0x1A,0x0A,
    0x00,0x00,0x00,0x0D,'I','H','D','R',
    0x00,0x00,0x00,0x01,
    0x00,0x00,0x00,0x01,
    0x08,
    0x06,
    0x00,
    0x00,
    0x00,
    0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x10,'I','D','A','T',
    0x78,0x01,0x01,0x05,0x00,0xFA,0xFF,
    0x00,0xFF,0x00,0x00,0xFF,
    0x05,0x00,0x01,0xFF,
    0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,'I','E','N','D',
    0x00,0x00,0x00,0x00
};

static bool read_entire_file(const char *path, uint8_t **out_data, size_t *out_size)
{
    if (!path || !out_data || !out_size)
    {
        return false;
    }

    FILE *f = fopen(path, "rb");
    if (!f)
    {
        return false;
    }

    if (fseek(f, 0, SEEK_END) != 0)
    {
        fclose(f);
        return false;
    }
    long len = ftell(f);
    if (len < 0)
    {
        fclose(f);
        return false;
    }
    if (fseek(f, 0, SEEK_SET) != 0)
    {
        fclose(f);
        return false;
    }

    uint8_t *buffer = (uint8_t *)malloc((size_t)len);
    if (!buffer)
    {
        fclose(f);
        return false;
    }

    size_t read_bytes = fread(buffer, 1, (size_t)len, f);
    fclose(f);
    if (read_bytes != (size_t)len)
    {
        free(buffer);
        return false;
    }

    *out_data = buffer;
    *out_size = (size_t)len;
    return true;
}

int main(int argc, char **argv)
{
    const char *path = (argc > 1) ? argv[1] : NULL;
    const uint8_t *data = g_png_sample_1x1_rgba;
    size_t size = sizeof(g_png_sample_1x1_rgba);
    uint8_t *owned_data = NULL;
    if (path)
    {
        if (!read_entire_file(path, &owned_data, &size))
        {
            fprintf(stderr, "png_host_test: failed to read %s\n", path);
            return 1;
        }
        data = owned_data;
    }

    video_color_t *pixels = NULL;
    int w = 0, h = 0, stride = 0;
    int rc = png_decode_rgba32(data, size, &pixels, &w, &h, &stride);
    free(owned_data);

    if (rc != 0 || !pixels)
    {
        fprintf(stderr, "png_host_test: decode failed (%s)\n", png_last_error());
        free(pixels);
        return 2;
    }

    if (!path)
    {
        if (w != 1 || h != 1 || stride != (int)(sizeof(video_color_t)))
        {
            fprintf(stderr, "png_host_test: unexpected sample dimensions %dx%d stride=%d\n",
                    w, h, stride);
            free(pixels);
            return 3;
        }
        if (pixels[0] != 0xFFFF0000U)
        {
            fprintf(stderr, "png_host_test: unexpected sample pixel 0x%08X\n", pixels[0]);
            free(pixels);
            return 4;
        }
        printf("png_host_test: decoded embedded sample -> %dx%d stride=%d first=0x%08X\n",
               w, h, stride, pixels[0]);
    }
    else
    {
        printf("png_host_test: decoded %s -> %dx%d stride=%d first=0x%08X\n",
               path, w, h, stride, pixels[0]);
    }
    free(pixels);
    return 0;
}
