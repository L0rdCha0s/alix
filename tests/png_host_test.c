#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#define TTF_HOST_BUILD 1
#define PNG_HOST_BUILD 1

#include "atk/util/png.h"

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
    const char *path = (argc > 1) ? argv[1] : "lenna.png";
    uint8_t *data = NULL;
    size_t size = 0;
    if (!read_entire_file(path, &data, &size))
    {
        fprintf(stderr, "png_host_test: failed to read %s\n", path);
        return 1;
    }

    video_color_t *pixels = NULL;
    int w = 0, h = 0, stride = 0;
    int rc = png_decode_rgba32(data, size, &pixels, &w, &h, &stride);
    free(data);

    if (rc != 0 || !pixels)
    {
        fprintf(stderr, "png_host_test: decode failed (%s)\n", png_last_error());
        free(pixels);
        return 2;
    }

    printf("png_host_test: decoded %s -> %dx%d stride=%d first=0x%08X\n",
           path, w, h, stride, pixels[0]);
    free(pixels);
    return 0;
}
