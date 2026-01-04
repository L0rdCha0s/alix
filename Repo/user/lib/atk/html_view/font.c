#include "atk/html_view/html_view_internal.h"

static void html_view_font_glyph_free(html_view_font_glyph_t *glyph)
{
    if (!glyph)
    {
        return;
    }
    free(glyph->alpha);
    memset(glyph, 0, sizeof(*glyph));
}

static void html_view_font_cache_clear_glyphs(html_view_font_size_cache_t *cache)
{
    if (!cache)
    {
        return;
    }

    for (size_t i = 0; i < HTML_VIEW_FONT_CACHE_COUNT; ++i)
    {
        html_view_font_glyph_free(&cache->glyphs[i]);
    }

    for (size_t i = 0; i < HTML_VIEW_FONT_EXTRA_CACHE_SLOTS; ++i)
    {
        html_view_font_glyph_free(&cache->extra_glyphs[i].glyph);
        cache->extra_glyphs[i].codepoint = 0;
        cache->extra_glyphs[i].last_used = 0;
    }

    cache->glyph_use_counter = 0;
}

void html_view_font_state_reset(html_view_font_state_t *state)
{
    if (!state)
    {
        return;
    }

    for (size_t i = 0; i < HTML_VIEW_FONT_SIZE_CACHE_SLOTS; ++i)
    {
        html_view_font_size_cache_t *cache = &state->size_caches[i];
        if (cache->used)
        {
            html_view_font_cache_clear_glyphs(cache);
        }
    }
    if (state->font.impl)
    {
        ttf_font_unload(&state->font);
    }
    free(state->font_blob);
    memset(state, 0, sizeof(*state));
}

static bool html_view_font_state_load(html_view_font_state_t *state)
{
    if (!state)
    {
        return false;
    }
    if (state->ready)
    {
        return true;
    }

    ssize_t size = sys_font_cache(NULL, 0);
    if (size <= 0)
    {
        return false;
    }

    uint8_t *buffer = (uint8_t *)malloc((size_t)size);
    if (!buffer)
    {
        return false;
    }

    ssize_t got = sys_font_cache(buffer, (size_t)size);
    if (got <= 0)
    {
        free(buffer);
        return false;
    }

    if (!ttf_font_load(&state->font, buffer, (size_t)got))
    {
        free(buffer);
        return false;
    }

    state->font_blob = buffer;
    state->font_blob_size = (size_t)got;
    state->ready = true;
    return true;
}

html_view_font_size_cache_t *html_view_font_state_get_cache(html_view_font_state_t *state, int pixel_height)
{
    if (!state)
    {
        return NULL;
    }
    if (pixel_height < 6)
    {
        pixel_height = 6;
    }
    if (!html_view_font_state_load(state))
    {
        return NULL;
    }

    for (size_t i = 0; i < HTML_VIEW_FONT_SIZE_CACHE_SLOTS; ++i)
    {
        html_view_font_size_cache_t *cache = &state->size_caches[i];
        if (cache->used && cache->pixel_height == pixel_height)
        {
            cache->last_used = ++state->cache_use_counter;
            return cache;
        }
    }

    size_t slot = (size_t)-1;
    for (size_t i = 0; i < HTML_VIEW_FONT_SIZE_CACHE_SLOTS; ++i)
    {
        if (!state->size_caches[i].used)
        {
            slot = i;
            break;
        }
    }

    if (slot == (size_t)-1)
    {
        slot = 0;
        uint32_t best = state->size_caches[0].last_used;
        for (size_t i = 1; i < HTML_VIEW_FONT_SIZE_CACHE_SLOTS; ++i)
        {
            if (state->size_caches[i].last_used < best)
            {
                best = state->size_caches[i].last_used;
                slot = i;
            }
        }
    }

    html_view_font_size_cache_t *cache = &state->size_caches[slot];
    if (cache->used)
    {
        html_view_font_cache_clear_glyphs(cache);
    }

    memset(cache, 0, sizeof(*cache));
    cache->used = true;
    cache->pixel_height = pixel_height;
    cache->last_used = ++state->cache_use_counter;
    if (!ttf_font_metrics(&state->font, pixel_height, &cache->metrics))
    {
        cache->metrics.ascent = pixel_height;
        cache->metrics.descent = pixel_height / 4;
        cache->metrics.line_gap = 0;
    }
    return cache;
}

static bool html_view_font_render_glyph(html_view_font_state_t *state,
                                        const html_view_font_size_cache_t *cache,
                                        uint32_t codepoint,
                                        html_view_font_glyph_t *out)
{
    if (!state || !cache || !out || cache->pixel_height <= 0)
    {
        return false;
    }

    ttf_bitmap_t bitmap = {0};
    ttf_glyph_metrics_t metrics = {0};
    if (!ttf_font_render_glyph_bitmap(&state->font, codepoint, cache->pixel_height, &bitmap, &metrics))
    {
        return false;
    }

    size_t alpha_bytes = (size_t)bitmap.stride * (size_t)bitmap.height;
    uint8_t *alpha = NULL;
    if (alpha_bytes > 0)
    {
        alpha = (uint8_t *)malloc(alpha_bytes);
        if (!alpha)
        {
            ttf_bitmap_destroy(&bitmap);
            return false;
        }
        for (int row = 0; row < bitmap.height; ++row)
        {
            memcpy(alpha + (size_t)row * (size_t)bitmap.stride,
                   bitmap.pixels + (size_t)row * (size_t)bitmap.stride,
                   (size_t)bitmap.stride);
        }
    }

    out->alpha = alpha;
    out->width = bitmap.width;
    out->height = bitmap.height;
    out->stride = bitmap.stride;
    out->advance = metrics.advance;
    out->bearing_x = metrics.bearing_x;
    out->bearing_y = metrics.bearing_y;
    out->ready = true;

    ttf_bitmap_destroy(&bitmap);
    return true;
}

static html_view_font_glyph_t *html_view_font_cache_get_glyph(html_view_font_state_t *state,
                                                              html_view_font_size_cache_t *cache,
                                                              uint32_t codepoint)
{
    if (!state || !cache || !state->ready || cache->pixel_height <= 0)
    {
        return NULL;
    }

    if (codepoint < 0x20u || codepoint == 0x7Fu)
    {
        codepoint = (uint32_t)'?';
    }

    if (codepoint >= HTML_VIEW_FONT_CACHE_FIRST && codepoint <= HTML_VIEW_FONT_CACHE_LAST)
    {
        size_t idx = (size_t)(codepoint - HTML_VIEW_FONT_CACHE_FIRST);
        html_view_font_glyph_t *glyph = &cache->glyphs[idx];
        if (!glyph->ready)
        {
            (void)html_view_font_render_glyph(state, cache, codepoint, glyph);
        }
        return glyph;
    }

    uint32_t tick = ++cache->glyph_use_counter;
    html_view_font_glyph_entry_t *slot = NULL;
    html_view_font_glyph_entry_t *oldest = NULL;

    for (size_t i = 0; i < HTML_VIEW_FONT_EXTRA_CACHE_SLOTS; ++i)
    {
        html_view_font_glyph_entry_t *entry = &cache->extra_glyphs[i];
        if (entry->codepoint == codepoint)
        {
            entry->last_used = tick;
            if (!entry->glyph.ready)
            {
                (void)html_view_font_render_glyph(state, cache, codepoint, &entry->glyph);
            }
            return &entry->glyph;
        }
        if (!entry->glyph.ready)
        {
            slot = entry;
        }
        if (!oldest || entry->last_used < oldest->last_used)
        {
            oldest = entry;
        }
    }

    if (!slot)
    {
        slot = oldest;
    }
    if (!slot)
    {
        return NULL;
    }

    html_view_font_glyph_free(&slot->glyph);
    slot->codepoint = codepoint;
    slot->last_used = tick;
    (void)html_view_font_render_glyph(state, cache, codepoint, &slot->glyph);
    return &slot->glyph;
}

static html_view_font_size_cache_t *html_view_font_cache_for_ctx(const html_view_ctx_t *ctx)
{
    if (!ctx || !ctx->priv)
    {
        return NULL;
    }
    if (ctx->actual_font_px <= 0)
    {
        return NULL;
    }
    return html_view_font_state_get_cache(&ctx->priv->font, ctx->actual_font_px);
}

int html_view_text_width(const html_view_ctx_t *ctx, const char *text)
{
    if (!ctx || !text || *text == '\0')
    {
        return 0;
    }

    html_view_font_size_cache_t *cache = html_view_font_cache_for_ctx(ctx);
    if (!cache)
    {
        return atk_font_text_width(text);
    }

    html_view_font_state_t *font_state = &ctx->priv->font;
    int width = 0;
    size_t guard = 0;
    const char *cursor = text;
    while (*cursor && guard < HTML_VIEW_FONT_TEXT_GUARD)
    {
        utf8_decode_result_t dec = utf8_decode_one(cursor);
        if (dec.consumed == 0)
        {
            break;
        }
        guard += (size_t)dec.consumed;
        cursor += dec.consumed;

        html_view_font_glyph_t *glyph = html_view_font_cache_get_glyph(font_state, cache, dec.codepoint);
        if (!glyph || !glyph->ready)
        {
            width += ctx->actual_font_px / 2;
            continue;
        }
        width += glyph->advance;
    }
    return width;
}

int html_view_text_width_len(const html_view_ctx_t *ctx, const char *text, size_t len)
{
    if (!ctx || !text || len == 0)
    {
        return 0;
    }

    html_view_font_size_cache_t *cache = html_view_font_cache_for_ctx(ctx);
    if (!cache)
    {
        char *copy = (char *)malloc(len + 1);
        if (!copy)
        {
            return 0;
        }
        memcpy(copy, text, len);
        copy[len] = '\0';
        int width = atk_font_text_width(copy);
        free(copy);
        return width;
    }

    html_view_font_state_t *font_state = &ctx->priv->font;
    int width = 0;
    size_t guard = 0;
    size_t offset = 0;
    while (offset < len && guard < HTML_VIEW_FONT_TEXT_GUARD)
    {
        utf8_decode_result_t dec = utf8_decode_one_len(text + offset, len - offset);
        if (dec.consumed == 0)
        {
            break;
        }
        guard += (size_t)dec.consumed;
        offset += dec.consumed;

        html_view_font_glyph_t *glyph = html_view_font_cache_get_glyph(font_state, cache, dec.codepoint);
        if (!glyph || !glyph->ready)
        {
            width += ctx->actual_font_px / 2;
            continue;
        }
        width += glyph->advance;
    }
    return width;
}

int html_view_baseline_for_rect(const html_view_ctx_t *ctx, int top, int height)
{
    if (!ctx)
    {
        return atk_font_baseline_for_rect(top, height);
    }

    html_view_font_size_cache_t *cache = html_view_font_cache_for_ctx(ctx);
    if (!cache)
    {
        return atk_font_baseline_for_rect(top, height);
    }

    int ascent = cache->metrics.ascent;
    int descent = cache->metrics.descent;
    if (descent < 0)
    {
        descent = -descent;
    }
    int total = ascent + descent;
    if (total <= 0)
    {
        total = ctx->base_font_px;
    }
    int offset = (height - total) / 2 + ascent;
    return top + offset;
}

void html_view_draw_string_clipped(const html_view_ctx_t *ctx,
                                   int x,
                                   int baseline_y,
                                   const char *text,
                                   video_color_t fg,
                                   const atk_rect_t *clip)
{
    if (!ctx || !text || *text == '\0')
    {
        return;
    }

    html_view_font_size_cache_t *cache = html_view_font_cache_for_ctx(ctx);
    if (!cache)
    {
        atk_font_draw_string_clipped(x, baseline_y, text, fg, ctx->bg, clip);
        return;
    }

    html_view_font_state_t *font_state = &ctx->priv->font;

    int clip_x0 = clip ? clip->x : 0;
    int clip_y0 = clip ? clip->y : 0;
    int clip_x1 = clip ? (clip->x + clip->width) : video_screen_width();
    int clip_y1 = clip ? (clip->y + clip->height) : video_screen_height();
    if (clip && (clip_x1 <= clip_x0 || clip_y1 <= clip_y0))
    {
        return;
    }

    video_color_t row_pixels[HTML_VIEW_FONT_MAX_ROW_PIXELS];
    int pen_x = x;

    size_t guard = 0;
    const char *cursor = text;
    while (*cursor && guard < HTML_VIEW_FONT_TEXT_GUARD)
    {
        utf8_decode_result_t dec = utf8_decode_one(cursor);
        if (dec.consumed == 0)
        {
            break;
        }
        guard += (size_t)dec.consumed;
        cursor += dec.consumed;

        html_view_font_glyph_t *glyph = html_view_font_cache_get_glyph(font_state, cache, dec.codepoint);
        if (!glyph || !glyph->ready)
        {
            pen_x += ctx->actual_font_px / 2;
            continue;
        }

        const uint8_t *glyph_alpha = glyph->alpha;
        int glyph_width = glyph->width;
        int glyph_height = glyph->height;
        int glyph_stride = glyph->stride;
        int glyph_advance = glyph->advance;
        int glyph_bearing_x = glyph->bearing_x;
        int glyph_bearing_y = glyph->bearing_y;

        if (glyph_width <= 0 || glyph_height <= 0 || !glyph_alpha || glyph_stride <= 0)
        {
            pen_x += glyph_advance;
            continue;
        }

        if (glyph_width > HTML_VIEW_FONT_MAX_ROW_PIXELS)
        {
            pen_x += glyph_advance;
            continue;
        }

        int dst_x = pen_x + glyph_bearing_x;
        int dst_y = baseline_y - glyph_bearing_y;

        int glyph_x0 = dst_x;
        int glyph_y0 = dst_y;
        int glyph_x1 = glyph_x0 + glyph_width;
        int glyph_y1 = glyph_y0 + glyph_height;

        if (glyph_x1 <= clip_x0 || glyph_x0 >= clip_x1 ||
            glyph_y1 <= clip_y0 || glyph_y0 >= clip_y1)
        {
            pen_x += glyph_advance;
            continue;
        }

        int visible_x0 = (glyph_x0 < clip_x0) ? clip_x0 : glyph_x0;
        int visible_x1 = (glyph_x1 > clip_x1) ? clip_x1 : glyph_x1;
        int visible_y0 = (glyph_y0 < clip_y0) ? clip_y0 : glyph_y0;
        int visible_y1 = (glyph_y1 > clip_y1) ? clip_y1 : glyph_y1;

        int start_col = visible_x0 - glyph_x0;
        int width = visible_x1 - visible_x0;
        int start_row = visible_y0 - glyph_y0;
        int rows = visible_y1 - visible_y0;

        if (width <= 0 || rows <= 0)
        {
            pen_x += glyph_advance;
            continue;
        }

        if (start_col >= glyph_stride)
        {
            pen_x += glyph_advance;
            continue;
        }
        if (width > glyph_stride - start_col)
        {
            width = glyph_stride - start_col;
            if (width <= 0)
            {
                pen_x += glyph_advance;
                continue;
            }
        }

        if (start_row >= glyph_height)
        {
            pen_x += glyph_advance;
            continue;
        }
        if (rows > glyph_height - start_row)
        {
            rows = glyph_height - start_row;
        }

        for (int row = 0; row < rows; ++row)
        {
            const uint8_t *src = glyph_alpha + (start_row + row) * glyph_stride + start_col;
            for (int col = 0; col < width; ++col)
            {
                uint8_t alpha = src[col];
                row_pixels[col] = ((video_color_t)alpha << 24) | (fg & 0x00FFFFFFU);
            }
            video_blit_rgba32_untracked(visible_x0,
                                        visible_y0 + row,
                                        width,
                                        1,
                                        row_pixels,
                                        width * (int)sizeof(video_color_t),
                                        true);
        }

        pen_x += glyph_advance;
    }
}

void html_view_draw_string_clipped_len(const html_view_ctx_t *ctx,
                                       int x,
                                       int baseline_y,
                                       const char *text,
                                       size_t len,
                                       video_color_t fg,
                                       const atk_rect_t *clip)
{
    if (!ctx || !text || len == 0)
    {
        return;
    }

    html_view_font_size_cache_t *cache = html_view_font_cache_for_ctx(ctx);
    if (!cache)
    {
        char *copy = (char *)malloc(len + 1);
        if (!copy)
        {
            return;
        }
        memcpy(copy, text, len);
        copy[len] = '\0';
        atk_font_draw_string_clipped(x, baseline_y, copy, fg, ctx->bg, clip);
        free(copy);
        return;
    }

    html_view_font_state_t *font_state = &ctx->priv->font;

    int clip_x0 = clip ? clip->x : 0;
    int clip_y0 = clip ? clip->y : 0;
    int clip_x1 = clip ? (clip->x + clip->width) : video_screen_width();
    int clip_y1 = clip ? (clip->y + clip->height) : video_screen_height();
    if (clip && (clip_x1 <= clip_x0 || clip_y1 <= clip_y0))
    {
        return;
    }

    video_color_t row_pixels[HTML_VIEW_FONT_MAX_ROW_PIXELS];
    int pen_x = x;

    size_t guard = 0;
    size_t offset = 0;
    while (offset < len && guard < HTML_VIEW_FONT_TEXT_GUARD)
    {
        utf8_decode_result_t dec = utf8_decode_one_len(text + offset, len - offset);
        if (dec.consumed == 0)
        {
            break;
        }
        guard += (size_t)dec.consumed;
        offset += dec.consumed;

        html_view_font_glyph_t *glyph = html_view_font_cache_get_glyph(font_state, cache, dec.codepoint);
        if (!glyph || !glyph->ready)
        {
            pen_x += ctx->actual_font_px / 2;
            continue;
        }

        const uint8_t *glyph_alpha = glyph->alpha;
        int glyph_width = glyph->width;
        int glyph_height = glyph->height;
        int glyph_stride = glyph->stride;
        int glyph_advance = glyph->advance;
        int glyph_bearing_x = glyph->bearing_x;
        int glyph_bearing_y = glyph->bearing_y;

        if (glyph_width <= 0 || glyph_height <= 0 || !glyph_alpha || glyph_stride <= 0)
        {
            pen_x += glyph_advance;
            continue;
        }

        if (glyph_width > HTML_VIEW_FONT_MAX_ROW_PIXELS)
        {
            pen_x += glyph_advance;
            continue;
        }

        int dst_x = pen_x + glyph_bearing_x;
        int dst_y = baseline_y - glyph_bearing_y;

        int glyph_x0 = dst_x;
        int glyph_y0 = dst_y;
        int glyph_x1 = glyph_x0 + glyph_width;
        int glyph_y1 = glyph_y0 + glyph_height;

        if (glyph_x1 <= clip_x0 || glyph_x0 >= clip_x1 ||
            glyph_y1 <= clip_y0 || glyph_y0 >= clip_y1)
        {
            pen_x += glyph_advance;
            continue;
        }

        int visible_x0 = (glyph_x0 < clip_x0) ? clip_x0 : glyph_x0;
        int visible_x1 = (glyph_x1 > clip_x1) ? clip_x1 : glyph_x1;
        int visible_y0 = (glyph_y0 < clip_y0) ? clip_y0 : glyph_y0;
        int visible_y1 = (glyph_y1 > clip_y1) ? clip_y1 : glyph_y1;

        int start_col = visible_x0 - glyph_x0;
        int width = visible_x1 - visible_x0;
        int start_row = visible_y0 - glyph_y0;
        int rows = visible_y1 - visible_y0;

        if (width <= 0 || rows <= 0)
        {
            pen_x += glyph_advance;
            continue;
        }

        if (start_col >= glyph_stride)
        {
            pen_x += glyph_advance;
            continue;
        }
        if (width > glyph_stride - start_col)
        {
            width = glyph_stride - start_col;
            if (width <= 0)
            {
                pen_x += glyph_advance;
                continue;
            }
        }

        if (start_row >= glyph_height)
        {
            pen_x += glyph_advance;
            continue;
        }
        if (rows > glyph_height - start_row)
        {
            rows = glyph_height - start_row;
        }

        for (int row = 0; row < rows; ++row)
        {
            const uint8_t *src = glyph_alpha + (start_row + row) * glyph_stride + start_col;
            for (int col = 0; col < width; ++col)
            {
                uint8_t alpha = src[col];
                row_pixels[col] = ((video_color_t)alpha << 24) | (fg & 0x00FFFFFFU);
            }
            video_blit_rgba32_untracked(visible_x0,
                                        visible_y0 + row,
                                        width,
                                        1,
                                        row_pixels,
                                        width * (int)sizeof(video_color_t),
                                        true);
        }

        pen_x += glyph_advance;
    }
}
