/*
 * Native HTML/CSS renderer harness.
 *
 * The regression test owns the host implementations of the Alix video, font,
 * image and render-cache hooks.  Include that implementation here so this
 * executable exercises exactly the same renderer without copying a second set
 * of host shims.  Its main is renamed; the focused harness main is below.
 */
#define main html_view_regression_main
#include "html_view_host_test.c"
#undef main

typedef struct
{
    const char *input_path;
    const char *asset_root;
    const char *output_path;
    const char *label;
    bool draw;
} web_render_options_t;

typedef struct
{
    size_t elements;
    size_t local_candidates;
    size_t loaded;
    size_t reused;
    size_t remote_skipped;
    size_t missing_src;
    size_t failed;
    double elapsed_ms;
} web_render_image_preload_stats_t;

typedef struct
{
    size_t inline_blocks;
    size_t local_stylesheets;
    size_t stylesheet_remote_skipped;
    size_t stylesheet_failed;
    size_t url_references;
    size_t image_candidates;
    size_t loaded;
    size_t reused;
    size_t remote_skipped;
    size_t non_image_skipped;
    size_t failed;
} web_render_css_asset_stats_t;

typedef struct
{
    size_t html_bytes;
    size_t css_bytes;
    size_t node_count;
    size_t rule_count;
    size_t image_count;
    web_render_image_preload_stats_t image_preload;
    web_render_css_asset_stats_t css_assets;
    size_t op_count;
    int document_height;
    uint64_t op_hash;
    uint64_t pixel_hash;
    double read_ms;
    double html_parse_ms;
    double css_collect_ms;
    double css_parse_ms;
    double layout_ms;
    double draw_ms;
    double total_ms;
    bool drew_pixels;
    bool wrote_output;
} web_render_result_t;

static void web_render_usage(const char *exe)
{
    const char *name = exe && exe[0] != '\0' ? exe : "web_render_harness";
    printf("usage: %s [OPTIONS]\n", name);
    printf("  --input PATH       HTML file (default: Stack Overflow fixture)\n");
    printf("  --asset-root PATH  base directory for linked CSS/images (default: input directory)\n");
    printf("  --output PATH      write the rendered 1920x1080 PNG\n");
    printf("  --no-draw          measure parsing/layout only; skip pixels and PNG\n");
    printf("  --label NAME       label used in trace output (default: stackoverflow or host_render)\n");
    printf("  --dump-dom[=FILTER] dump the computed DOM; FILTER accepts .class or #id\n");
    printf("  -h, --help         show this help\n");
}

static bool web_render_take_value(int argc,
                                  char **argv,
                                  int *index,
                                  const char *option,
                                  const char **out)
{
    if (!index || !out || *index + 1 >= argc)
    {
        fprintf(stderr, "web_render_harness: %s requires a value\n", option);
        return false;
    }
    *index += 1;
    *out = argv[*index];
    if (!*out || (*out)[0] == '\0')
    {
        fprintf(stderr, "web_render_harness: %s requires a non-empty value\n", option);
        return false;
    }
    return true;
}

static bool web_render_parse_options(int argc, char **argv, web_render_options_t *options)
{
    if (!options)
    {
        return false;
    }

    *options = (web_render_options_t){
        .input_path = "tests/stackoverflow-test/stackoverflow.html",
        .asset_root = NULL,
        .output_path = NULL,
        .label = NULL,
        .draw = true,
    };

    for (int i = 1; i < argc; ++i)
    {
        const char *arg = argv[i];
        if (!arg || arg[0] == '\0')
        {
            continue;
        }
        if (strcmp(arg, "--input") == 0)
        {
            if (!web_render_take_value(argc, argv, &i, arg, &options->input_path))
            {
                return false;
            }
            continue;
        }
        if (strcmp(arg, "--asset-root") == 0)
        {
            if (!web_render_take_value(argc, argv, &i, arg, &options->asset_root))
            {
                return false;
            }
            continue;
        }
        if (strcmp(arg, "--output") == 0)
        {
            if (!web_render_take_value(argc, argv, &i, arg, &options->output_path))
            {
                return false;
            }
            continue;
        }
        if (strcmp(arg, "--label") == 0)
        {
            if (!web_render_take_value(argc, argv, &i, arg, &options->label))
            {
                return false;
            }
            continue;
        }
        if (strcmp(arg, "--no-draw") == 0)
        {
            options->draw = false;
            continue;
        }
        if (strcmp(arg, "--dump-dom") == 0)
        {
            g_dump_dom = true;
            continue;
        }
        if (strncmp(arg, "--dump-dom=", 11) == 0)
        {
            g_dump_dom = true;
            if (!host_set_dump_dom_filter(arg + 11))
            {
                fprintf(stderr, "web_render_harness: invalid DOM filter: %s\n", arg + 11);
                return false;
            }
            continue;
        }
        if (strcmp(arg, "--help") == 0 || strcmp(arg, "-h") == 0)
        {
            web_render_usage(argv[0]);
            exit(0);
        }

        fprintf(stderr, "web_render_harness: unknown option: %s\n", arg);
        return false;
    }

    if (!options->label)
    {
        options->label = strcmp(options->input_path,
                                "tests/stackoverflow-test/stackoverflow.html") == 0
                             ? "stackoverflow"
                             : "host_render";
    }
    return true;
}

static char *web_render_input_dir(const char *path)
{
    if (!path || path[0] == '\0')
    {
        return NULL;
    }

    const char *slash = strrchr(path, '/');
    if (!slash)
    {
        return html_view_strdup(".");
    }
    if (slash == path)
    {
        return html_view_strdup("/");
    }

    size_t len = (size_t)(slash - path);
    char *dir = (char *)malloc(len + 1);
    if (!dir)
    {
        return NULL;
    }
    memcpy(dir, path, len);
    dir[len] = '\0';
    return dir;
}

static size_t web_render_count_images(const atk_html_view_priv_t *priv)
{
    size_t count = 0;
    for (const html_view_image_t *image = priv ? priv->images : NULL; image; image = image->next)
    {
        count++;
    }
    return count;
}

static char *web_render_css_unescape_range(const char *start, const char *end)
{
    if (!start || !end || end <= start)
    {
        return NULL;
    }
    while (start < end && isspace((unsigned char)*start))
    {
        start++;
    }
    while (end > start && isspace((unsigned char)end[-1]))
    {
        end--;
    }
    if (end <= start)
    {
        return NULL;
    }

    size_t cap = (size_t)(end - start) + 1;
    char *value = (char *)malloc(cap);
    if (!value)
    {
        return NULL;
    }
    size_t len = 0;
    for (const char *p = start; p < end; ++p)
    {
        if (*p == '\\' && p + 1 < end)
        {
            ++p;
        }
        value[len++] = *p;
    }
    value[len] = '\0';
    return value;
}

static void web_render_preload_css_url(atk_html_view_priv_t *priv,
                                       const char *url,
                                       const char *css_base_dir,
                                       web_render_css_asset_stats_t *stats)
{
    if (!priv || !url || url[0] == '\0' || !stats)
    {
        return;
    }
    stats->url_references++;

    bool is_data = strncasecmp(url, "data:", 5) == 0;
    if (!is_data && host_is_remote_url(url))
    {
        stats->remote_skipped++;
        return;
    }
    if (is_data)
    {
        if (strncasecmp(url, "data:image/", 11) != 0)
        {
            stats->non_image_skipped++;
            return;
        }
    }
    else
    {
        char *path = host_resolve_local_url(css_base_dir, url);
        if (!path)
        {
            stats->failed++;
            return;
        }
        size_t file_len = 0;
        char *file = read_file(path, &file_len);
        free(path);
        if (!file || file_len == 0)
        {
            free(file);
            stats->failed++;
            return;
        }
        host_image_type_t type =
            host_detect_image_type((const uint8_t *)file, file_len);
        free(file);
        if (type == HOST_IMAGE_UNKNOWN)
        {
            stats->non_image_skipped++;
            return;
        }
    }

    stats->image_candidates++;
    if (html_view_image_find(priv, url))
    {
        stats->reused++;
        return;
    }
    if (host_try_load_image(priv, url, css_base_dir))
    {
        stats->loaded++;
    }
    else
    {
        stats->failed++;
    }
}

static bool web_render_scan_css_urls(atk_html_view_priv_t *priv,
                                     const char *css,
                                     size_t css_len,
                                     const char *css_base_dir,
                                     web_render_css_asset_stats_t *stats)
{
    if (!priv || !css || !stats)
    {
        return false;
    }

    const char *p = css;
    const char *end = css + css_len;
    while (p < end)
    {
        if (p + 1 < end && p[0] == '/' && p[1] == '*')
        {
            p += 2;
            while (p + 1 < end && !(p[0] == '*' && p[1] == '/'))
            {
                p++;
            }
            p = p + 1 < end ? p + 2 : end;
            continue;
        }
        if (*p == '"' || *p == '\'')
        {
            char quote = *p++;
            while (p < end)
            {
                if (*p == '\\' && p + 1 < end)
                {
                    p += 2;
                    continue;
                }
                if (*p++ == quote)
                {
                    break;
                }
            }
            continue;
        }

        bool boundary = p == css ||
                        !(isalnum((unsigned char)p[-1]) || p[-1] == '_' || p[-1] == '-');
        if (!boundary || end - p < 4 || strncasecmp(p, "url(", 4) != 0)
        {
            p++;
            continue;
        }

        const char *cursor = p + 4;
        while (cursor < end && isspace((unsigned char)*cursor))
        {
            cursor++;
        }
        const char *value_start = cursor;
        const char *value_end = NULL;
        char quote = 0;
        if (cursor < end && (*cursor == '"' || *cursor == '\''))
        {
            quote = *cursor++;
            value_start = cursor;
            while (cursor < end)
            {
                if (*cursor == '\\' && cursor + 1 < end)
                {
                    cursor += 2;
                    continue;
                }
                if (*cursor == quote)
                {
                    value_end = cursor++;
                    break;
                }
                cursor++;
            }
            while (cursor < end && isspace((unsigned char)*cursor))
            {
                cursor++;
            }
            if (!value_end || cursor >= end || *cursor != ')')
            {
                p += 4;
                continue;
            }
        }
        else
        {
            while (cursor < end)
            {
                if (*cursor == '\\' && cursor + 1 < end)
                {
                    cursor += 2;
                    continue;
                }
                if (*cursor == ')')
                {
                    value_end = cursor;
                    break;
                }
                cursor++;
            }
            if (!value_end)
            {
                p += 4;
                continue;
            }
        }

        char *url = web_render_css_unescape_range(value_start, value_end);
        if (url)
        {
            web_render_preload_css_url(priv, url, css_base_dir, stats);
            free(url);
        }
        p = cursor + 1;
    }
    return true;
}

static bool web_render_preload_linked_stylesheet(atk_html_view_priv_t *priv,
                                                 const char *href,
                                                 const char *asset_base_dir,
                                                 web_render_css_asset_stats_t *stats)
{
    if (!priv || !href || href[0] == '\0' || !stats)
    {
        return false;
    }

    char *data_css = decode_data_css(href);
    if (data_css)
    {
        bool ok = web_render_scan_css_urls(priv,
                                           data_css,
                                           strlen(data_css),
                                           asset_base_dir,
                                           stats);
        free(data_css);
        return ok;
    }
    if (host_is_remote_url(href))
    {
        stats->stylesheet_remote_skipped++;
        return true;
    }

    char *path = host_resolve_local_url(asset_base_dir, href);
    if (!path)
    {
        stats->stylesheet_failed++;
        return true;
    }
    size_t css_len = 0;
    char *css = read_file(path, &css_len);
    if (!css)
    {
        free(path);
        stats->stylesheet_failed++;
        return true;
    }
    char *css_base_dir = web_render_input_dir(path);
    free(path);
    if (!css_base_dir)
    {
        free(css);
        return false;
    }

    stats->local_stylesheets++;
    bool ok = web_render_scan_css_urls(priv, css, css_len, css_base_dir, stats);
    free(css_base_dir);
    free(css);
    return ok;
}

static bool web_render_preload_element_images(atk_html_view_priv_t *priv,
                                              const html_document_t *doc,
                                              css_stylesheet_t *sheet,
                                              const char *asset_base_dir,
                                              void *context)
{
    (void)sheet;
    web_render_result_t *result = (web_render_result_t *)context;
    if (!priv || !doc || !doc->root || !result)
    {
        return false;
    }
    web_render_image_preload_stats_t *stats = &result->image_preload;
    web_render_css_asset_stats_t *css_stats = &result->css_assets;

    double started = host_now_ms();
    size_t cap = 256;
    size_t count = 0;
    const html_node_t **stack =
        (const html_node_t **)malloc(cap * sizeof(*stack));
    if (!stack)
    {
        return false;
    }
    stack[count++] = doc->root;

    while (count > 0)
    {
        const html_node_t *node = stack[--count];
        if (node->type == HTML_NODE_ELEMENT && node->name &&
            strcmp(node->name, "img") == 0)
        {
            stats->elements++;
            const char *src = html_attr_get(node, "src");
            if (!src || src[0] == '\0')
            {
                stats->missing_src++;
            }
            else if (strncasecmp(src, "data:", 5) != 0 && host_is_remote_url(src))
            {
                stats->remote_skipped++;
            }
            else
            {
                stats->local_candidates++;
                html_view_image_t *existing = html_view_image_find(priv, src);
                if (existing)
                {
                    stats->reused++;
                }
                else if (host_try_load_image(priv, src, asset_base_dir))
                {
                    html_view_image_t *loaded = html_view_image_find(priv, src);
                    if (loaded && loaded->pixels && loaded->width > 0 && loaded->height > 0 &&
                        loaded->stride_bytes > 0 &&
                        (size_t)loaded->stride_bytes >=
                            (size_t)loaded->width * sizeof(video_color_t))
                    {
                        stats->loaded++;
                    }
                    else
                    {
                        stats->failed++;
                    }
                }
                else
                {
                    stats->failed++;
                }
            }
        }
        else if (node->type == HTML_NODE_ELEMENT && node->name &&
                 strcmp(node->name, "style") == 0)
        {
            char *style_text = NULL;
            size_t style_len = 0;
            size_t style_cap = 0;
            html_view_collect_text(node, &style_text, &style_len, &style_cap);
            if (style_text)
            {
                css_stats->inline_blocks++;
                bool ok = web_render_scan_css_urls(priv,
                                                   style_text,
                                                   style_len,
                                                   asset_base_dir,
                                                   css_stats);
                free(style_text);
                if (!ok)
                {
                    free(stack);
                    return false;
                }
            }
        }
        else if (node->type == HTML_NODE_ELEMENT && node->name &&
                 strcmp(node->name, "link") == 0)
        {
            const char *rel = html_attr_get(node, "rel");
            const char *type = html_attr_get(node, "type");
            const char *href = html_attr_get(node, "href");
            bool css_type = !type || type[0] == '\0' || strcasecmp(type, "text/css") == 0;
            if (attr_has_token(rel, "stylesheet") && css_type && href && href[0] != '\0' &&
                !web_render_preload_linked_stylesheet(priv,
                                                      href,
                                                      asset_base_dir,
                                                      css_stats))
            {
                free(stack);
                return false;
            }
        }

        for (const html_node_t *child = node->first_child; child; child = child->next_sibling)
        {
            if (count == cap)
            {
                if (cap > SIZE_MAX / 2u || cap * 2u > SIZE_MAX / sizeof(*stack))
                {
                    free(stack);
                    return false;
                }
                size_t new_cap = cap * 2u;
                const html_node_t **next =
                    (const html_node_t **)realloc(stack, new_cap * sizeof(*next));
                if (!next)
                {
                    free(stack);
                    return false;
                }
                stack = next;
                cap = new_cap;
            }
            stack[count++] = child;
        }
    }

    free(stack);
    stats->elapsed_ms = host_now_ms() - started;
    return true;
}

static int web_render_document_height(const html_view_render_cache_t *cache)
{
    int bottom = 0;
    if (!cache)
    {
        return 0;
    }
    for (size_t i = 0; i < cache->op_count; ++i)
    {
        const html_view_op_t *op = &cache->ops[i];
        if (op->fixed)
        {
            continue;
        }
        int64_t op_bottom = (int64_t)op->y + (int64_t)op->h;
        if (op_bottom > INT_MAX)
        {
            return INT_MAX;
        }
        if (op_bottom > bottom)
        {
            bottom = (int)op_bottom;
        }
    }
    return bottom;
}

static uint64_t web_render_hash_pixels(const video_color_t *pixels, size_t count)
{
    uint64_t hash = 14695981039346656037ULL;
    if (!pixels)
    {
        return hash;
    }
    for (size_t i = 0; i < count; ++i)
    {
        hash_u32(&hash, pixels[i]);
    }
    return hash;
}

static void web_render_hash_string(uint64_t *hash, const char *value)
{
    size_t len = value ? strlen(value) : 0;
    hash_u64(hash, (uint64_t)len);
    if (len > 0)
    {
        hash_bytes(hash, value, len);
    }
}

static uint64_t web_render_hash_ops(const html_view_render_cache_t *cache)
{
    uint64_t hash = 14695981039346656037ULL;
    if (!cache)
    {
        return hash;
    }

    hash_u64(&hash, (uint64_t)cache->op_count);
    for (size_t i = 0; i < cache->op_count; ++i)
    {
        const html_view_op_t *op = &cache->ops[i];
        hash_u32(&hash, (uint32_t)op->kind);
        hash_u32(&hash, (uint32_t)op->x);
        hash_u32(&hash, (uint32_t)op->y);
        hash_u32(&hash, (uint32_t)op->w);
        hash_u32(&hash, (uint32_t)op->h);
        hash_u32(&hash, (uint32_t)op->color);
        hash_u32(&hash, (uint32_t)op->text_len);
        hash_u32(&hash, (uint32_t)op->baseline_off);
        hash_u32(&hash, (uint32_t)op->font_px);
        hash_u32(&hash, (uint32_t)op->z_index);
        hash_u32(&hash, op->fixed ? 1u : 0u);
        hash_u32(&hash, op->sticky ? 1u : 0u);
        hash_u32(&hash, (uint32_t)op->sticky_flags);
        hash_u32(&hash, (uint32_t)op->sticky_origin_y);
        hash_u32(&hash, (uint32_t)op->sticky_top);
        hash_u32(&hash, (uint32_t)op->sticky_bottom);
        hash_u32(&hash, (uint32_t)op->sticky_container_top);
        hash_u32(&hash, (uint32_t)op->sticky_container_bottom);
        hash_u32(&hash, (uint32_t)op->sticky_box_h);
        hash_u32(&hash, op->has_clip ? 1u : 0u);
        hash_u32(&hash, op->clip_scroll ? 1u : 0u);
        hash_u32(&hash, op->image_placeholder ? 1u : 0u);
        hash_u32(&hash, (uint32_t)op->stride_bytes);
        if (op->has_clip)
        {
            hash_u32(&hash, (uint32_t)op->clip_x);
            hash_u32(&hash, (uint32_t)op->clip_y);
            hash_u32(&hash, (uint32_t)op->clip_w);
            hash_u32(&hash, (uint32_t)op->clip_h);
        }
        if (op->kind == HTML_VIEW_OP_TEXT && op->text && op->text_len > 0)
        {
            hash_bytes(&hash, op->text, op->text_len);
        }
        web_render_hash_string(&hash, op->image_src);
        web_render_hash_string(&hash, op->href);
    }
    return hash;
}

static video_color_t web_render_body_background(const html_document_t *doc,
                                                css_stylesheet_t *sheet,
                                                atk_html_view_priv_t *priv)
{
    video_color_t background = video_make_color(0xFF, 0xFF, 0xFF);
    if (!doc || !doc->root || !sheet || !priv)
    {
        return background;
    }

    css_style_t base_style = {0};
    base_style.has_color = true;
    base_style.color = video_make_color(0x00, 0x00, 0x00);
    base_style.has_font_size = true;
    base_style.font_size = (css_length_t){
        .valid = true,
        .is_auto = false,
        .value_milli = atk_font_line_height() * 1000,
        .unit = CSS_UNIT_PX,
    };
    base_style.has_line_height = true;
    base_style.line_height_milli = 1000;

    css_style_t html_style = {0};
    css_style_t body_style = {0};
    const css_style_t *html_style_ptr = &base_style;
    const css_style_t *body_style_ptr = html_style_ptr;
    bool release_html = false;
    bool release_body = false;

    const html_node_t *html_node = find_first_tag(doc->root, "html");
    if (html_node)
    {
        html_view_style_for_node(&html_style, sheet, &base_style, html_node, priv);
        html_style_ptr = &html_style;
        body_style_ptr = html_style_ptr;
        release_html = true;
    }

    const html_node_t *body_node = find_first_tag(doc->root, "body");
    if (body_node)
    {
        html_view_style_for_node(&body_style, sheet, html_style_ptr, body_node, priv);
        body_style_ptr = &body_style;
        release_body = true;
    }

    if (body_style_ptr->has_background && !body_style_ptr->background_transparent)
    {
        background = body_style_ptr->background;
    }

    if (release_body)
    {
        css_style_release(&body_style);
    }
    if (release_html)
    {
        css_style_release(&html_style);
    }
    return background;
}

static bool web_render_draw_cache(atk_html_view_priv_t *priv,
                                  css_stylesheet_t *sheet,
                                  video_color_t background,
                                  const char *output_path,
                                  uint64_t *out_hash,
                                  double *out_draw_ms,
                                  bool *out_wrote)
{
    if (out_hash)
    {
        *out_hash = 0;
    }
    if (out_draw_ms)
    {
        *out_draw_ms = 0.0;
    }
    if (out_wrote)
    {
        *out_wrote = false;
    }
    if (!priv || !sheet || !out_hash || !out_draw_ms || !out_wrote)
    {
        return false;
    }

    html_view_render_cache_t *cache = &priv->render_cache;
    int width = cache->viewport_w;
    int height = cache->viewport_h;
    if (width <= 0 || height <= 0)
    {
        return false;
    }

    if (!surface_init(width, height, background))
    {
        return false;
    }
    surface_clear(background);

    html_view_ctx_t draw_ctx = {
        .state = NULL,
        .widget = NULL,
        .priv = priv,
        .sheet = sheet,
        .bg = background,
        .clip = { .x = 0, .y = 0, .width = width, .height = height },
        .viewport_x = 0,
        .viewport_y = 0,
        .viewport_w = width,
        .viewport_h = height,
        .scroll_y = 0,
        .actual_font_px = cache->base_font_px,
        .base_font_px = cache->base_font_px,
        .base_line_height = cache->base_line_height,
        .line_height = cache->base_line_height,
        .draw = true,
        .record = false,
        .doc_origin_x = cache->doc_origin_local_x,
        .doc_origin_y = cache->doc_origin_local_y,
    };

    double draw_start = host_now_ms();
    html_view_render_cache_draw_visible(&draw_ctx);
    double draw_end = host_now_ms();
    *out_draw_ms = draw_end - draw_start;

    size_t pixel_count = (size_t)width * (size_t)height;
    *out_hash = web_render_hash_pixels(g_surface, pixel_count);

    bool ok = true;
    if (output_path)
    {
        ok = host_write_png_rgba32(output_path,
                                   g_surface,
                                   width,
                                   height,
                                   width * (int)sizeof(video_color_t));
        *out_wrote = ok;
    }

    surface_destroy();
    return ok;
}

static void web_render_priv_destroy(atk_html_view_priv_t *priv)
{
    if (!priv)
    {
        return;
    }
    html_view_images_clear(priv);
    html_view_inline_style_cache_clear(priv);
    html_view_measure_cache_clear(priv);
    html_view_rule_index_clear(priv);
    html_view_render_cache_clear(&priv->render_cache);
    html_view_style_cache_clear(priv);
    html_view_style_block_pool_clear(priv);
    free(priv->style_cache);
    priv->style_cache = NULL;
    priv->style_cache_cap = 0;
    priv->style_cache_mask = 0;
}

static void web_render_json_string(const char *text)
{
    putchar('"');
    for (const unsigned char *p = (const unsigned char *)(text ? text : ""); *p; ++p)
    {
        switch (*p)
        {
            case '"': fputs("\\\"", stdout); break;
            case '\\': fputs("\\\\", stdout); break;
            case '\b': fputs("\\b", stdout); break;
            case '\f': fputs("\\f", stdout); break;
            case '\n': fputs("\\n", stdout); break;
            case '\r': fputs("\\r", stdout); break;
            case '\t': fputs("\\t", stdout); break;
            default:
                if (*p < 0x20)
                {
                    printf("\\u%04x", (unsigned)*p);
                }
                else
                {
                    putchar((int)*p);
                }
                break;
        }
    }
    putchar('"');
}

static void web_render_print_error(const char *message)
{
    fputs("WEB_RENDER_RESULT {\"version\":1,\"status\":\"error\",\"error\":", stdout);
    web_render_json_string(message ? message : "unknown error");
    fputs("}\n", stdout);
    fflush(stdout);
}

static void web_render_print_result(const web_render_options_t *options,
                                    const char *asset_root,
                                    const web_render_result_t *result)
{
    fputs("WEB_RENDER_RESULT {\"version\":1,\"status\":\"ok\",\"input\":", stdout);
    web_render_json_string(options->input_path);
    fputs(",\"asset_root\":", stdout);
    web_render_json_string(asset_root);
    fputs(",\"output\":", stdout);
    if (options->output_path)
    {
        web_render_json_string(options->output_path);
    }
    else
    {
        fputs("null", stdout);
    }
    printf(",\"viewport\":{\"width\":1920,\"height\":1080}"
           ",\"counts\":{\"html_bytes\":%zu,\"css_bytes\":%zu,\"nodes\":%zu,"
           "\"rules\":%zu,\"images\":%zu,\"img_elements\":%zu,"
           "\"img_local_candidates\":%zu,\"img_loaded\":%zu,\"img_reused\":%zu,"
           "\"img_remote_skipped\":%zu,\"img_missing_src\":%zu,\"img_failed\":%zu,"
           "\"css_inline_blocks\":%zu,\"css_local_stylesheets\":%zu,"
           "\"css_stylesheet_remote_skipped\":%zu,\"css_stylesheet_failed\":%zu,"
           "\"css_url_references\":%zu,\"css_image_candidates\":%zu,"
           "\"css_images_loaded\":%zu,\"css_images_reused\":%zu,"
           "\"css_url_remote_skipped\":%zu,\"css_non_image_skipped\":%zu,"
           "\"css_image_failed\":%zu,\"assets_failed\":%zu,\"assets_remote_skipped\":%zu,"
           "\"ops\":%zu,\"document_height\":%d}"
           ",\"op_hash\":\"0x%016llX\",\"pixel_hash\":",
           result->html_bytes,
           result->css_bytes,
           result->node_count,
           result->rule_count,
           result->image_count,
           result->image_preload.elements,
           result->image_preload.local_candidates,
           result->image_preload.loaded,
           result->image_preload.reused,
           result->image_preload.remote_skipped,
           result->image_preload.missing_src,
           result->image_preload.failed,
           result->css_assets.inline_blocks,
           result->css_assets.local_stylesheets,
           result->css_assets.stylesheet_remote_skipped,
           result->css_assets.stylesheet_failed,
           result->css_assets.url_references,
           result->css_assets.image_candidates,
           result->css_assets.loaded,
           result->css_assets.reused,
           result->css_assets.remote_skipped,
           result->css_assets.non_image_skipped,
           result->css_assets.failed,
           result->image_preload.failed + result->css_assets.failed +
               result->css_assets.stylesheet_failed,
           result->image_preload.remote_skipped + result->css_assets.remote_skipped +
               result->css_assets.stylesheet_remote_skipped,
           result->op_count,
           result->document_height,
           (unsigned long long)result->op_hash);
    if (result->drew_pixels)
    {
        printf("\"0x%016llX\"", (unsigned long long)result->pixel_hash);
    }
    else
    {
        fputs("null", stdout);
    }
    printf(",\"wrote_output\":%s"
           ",\"timings_ms\":{\"read\":%.3f,\"html_parse\":%.3f,\"css_collect\":%.3f,"
           "\"css_parse\":%.3f,\"asset_preload\":%.3f,\"layout\":%.3f,"
           "\"draw\":%.3f,\"total\":%.3f}}\n",
           result->wrote_output ? "true" : "false",
           result->read_ms,
           result->html_parse_ms,
           result->css_collect_ms,
           result->css_parse_ms,
           result->image_preload.elapsed_ms,
           result->layout_ms,
           result->draw_ms,
           result->total_ms);
    fflush(stdout);
}

int main(int argc, char **argv)
{
    web_render_options_t options = {0};
    if (!web_render_parse_options(argc, argv, &options))
    {
        web_render_usage(argv[0]);
        return 2;
    }

#ifdef HTML_VIEW_HOST_TRACE
    html_view_host_trace_init();
#endif
    if (g_dump_dom || g_html_trace_enabled)
    {
        g_serial_log = stdout;
    }
    css_media_env_set(1920, 1080, CSS_MEDIA_COLOR_SCHEME_LIGHT);

    int exit_code = 1;
    char *derived_asset_root = NULL;
    char *html = NULL;
    char *css = NULL;
    html_document_t *doc = NULL;
    css_stylesheet_t *sheet = NULL;
    atk_html_view_priv_t priv = {0};
    web_render_result_t result = {0};
    html_view_render_stats_t render_stats = {0};
    size_t css_cap = 0;
    const char *asset_root = options.asset_root;
    double total_start = host_now_ms();

    if (!asset_root)
    {
        derived_asset_root = web_render_input_dir(options.input_path);
        if (!derived_asset_root)
        {
            web_render_print_error("failed to derive asset root");
            goto cleanup;
        }
        asset_root = derived_asset_root;
    }

    double phase_start = host_now_ms();
    html = read_file(options.input_path, &result.html_bytes);
    result.read_ms = host_now_ms() - phase_start;
    if (!html)
    {
        web_render_print_error("failed to read input HTML");
        goto cleanup;
    }

    html_parse_error_t parse_error = {0};
    phase_start = host_now_ms();
    doc = html_parse(html, &parse_error);
    result.html_parse_ms = host_now_ms() - phase_start;
    if (!doc)
    {
        char message[256];
        snprintf(message,
                 sizeof(message),
                 "HTML parse failed at byte %zu: %s",
                 parse_error.offset,
                 parse_error.message ? parse_error.message : "unknown error");
        web_render_print_error(message);
        goto cleanup;
    }
    result.node_count = html_view_count_nodes(doc->root);

    phase_start = host_now_ms();
    collect_style_text_with_base(doc->root,
                                 &css,
                                 &result.css_bytes,
                                 &css_cap,
                                 asset_root,
                                 true);
    result.css_collect_ms = host_now_ms() - phase_start;

    phase_start = host_now_ms();
    sheet = css_parse(css ? css : "");
    result.css_parse_ms = host_now_ms() - phase_start;
    if (!sheet)
    {
        web_render_print_error("CSS parse failed");
        goto cleanup;
    }
    result.rule_count = html_view_count_rules(sheet);

    g_html_view_host_before_layout = web_render_preload_element_images;
    g_html_view_host_before_layout_context = &result;
    bool render_ok = render_doc_case(options.label,
                                     NULL,
                                     asset_root,
                                     doc,
                                     sheet,
                                     false,
                                     &render_stats,
                                     &result.layout_ms,
                                     NULL,
                                     &priv);
    g_html_view_host_before_layout = NULL;
    g_html_view_host_before_layout_context = NULL;
    if (!render_ok)
    {
        web_render_print_error("layout/render recording failed");
        goto cleanup;
    }

    result.image_count = web_render_count_images(&priv);
    result.op_count = render_stats.op_count;
    result.op_hash = web_render_hash_ops(&priv.render_cache);
    result.document_height = web_render_document_height(&priv.render_cache);

    if (options.draw)
    {
        video_color_t background = web_render_body_background(doc, sheet, &priv);
        if (!web_render_draw_cache(&priv,
                                   sheet,
                                   background,
                                   options.output_path,
                                   &result.pixel_hash,
                                   &result.draw_ms,
                                   &result.wrote_output))
        {
            web_render_print_error(options.output_path
                                       ? "pixel draw or PNG write failed"
                                       : "pixel draw failed");
            goto cleanup;
        }
        result.drew_pixels = true;
    }

    result.total_ms = host_now_ms() - total_start;
    web_render_print_result(&options, asset_root, &result);
    exit_code = 0;

cleanup:
    g_serial_log = NULL;
    web_render_priv_destroy(&priv);
    css_stylesheet_destroy(sheet);
    html_document_destroy(doc);
    free(css);
    free(html);
    free(derived_asset_root);
    surface_destroy();
    return exit_code;
}
