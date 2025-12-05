#include "atk_user.h"

#include "atk.h"
#include "atk_internal.h"
#include "atk_menu_bar.h"
#include "atk_window.h"
#include "atk/layout.h"
#include "atk/atk_label.h"
#include "atk/atk_scrollbar.h"
#include "atk/atk_text_input.h"
#include <stdio.h>
#include <string.h>
#include "userlib.h"
#include "libc.h"
#include "usyscall.h"
#include "user_atk_defs.h"
#include "video.h"
#include "serial.h"

#define MINIMP3_IMPLEMENTATION
#define MINIMP3_NO_STDIO
#include "minimp3.h"

#define MP3_UI_WIDTH  720
#define MP3_UI_HEIGHT 360
#define MP3_MARGIN    14
#define MP3_ROW_SPACING 10
#define MP3_TITLE_HEIGHT (ATK_FONT_HEIGHT * 2)
#define MP3_BUTTON_HEIGHT (ATK_FONT_HEIGHT + 10)
#define MP3_TARGET_RATE 48000
#define MP3_TARGET_CHANNELS 2
#define MP3_READ_CHUNK 8192u
#define MP3_INPUT_BUFFER_SIZE (MP3_READ_CHUNK * 4u)
#define MP3_MAX_RESAMPLED_SAMPLES 65536u

typedef struct
{
    uint64_t phase;
    int16_t prev[2];
    bool have_prev;
    uint32_t src_rate;
    uint64_t step;
    uint64_t src_pos;
} mp3_resample_state_t;

typedef struct
{
    int input_fd;
    int audio_fd;
    mp3dec_t dec;
    mp3_resample_state_t rs;
    uint8_t *in_buffer;
    size_t in_capacity;
    size_t buf_filled;
    size_t buf_pos;
    mp3d_sample_t *decode_buffer;
    int16_t *out_buffer;
    bool active;
} mp3_player_t;

typedef struct
{
    atk_user_window_t remote;
    atk_widget_t *window;
    atk_widget_t *title_label;
    atk_widget_t *status_label;
    atk_widget_t *file_label;
    atk_widget_t *file_input;
    atk_widget_t *open_button;
    atk_widget_t *rew_button;
    atk_widget_t *play_button;
    atk_widget_t *fwd_button;
    atk_widget_t *scrubber;
    bool running;
    bool playing;
    mp3_player_t player;
} mp3_ui_t;

static bool mp3_play_selected(mp3_ui_t *ui);

static void log_mp3(const char *msg)
{
    if (!msg)
    {
        return;
    }
    sys_serial_write(msg, strlen(msg));
}

static void apply_theme(atk_state_t *state)
{
    if (!state)
    {
        return;
    }
    state->theme.background = video_make_color(0x11, 0x16, 0x1E);
    state->theme.window_border = video_make_color(0x2C, 0x35, 0x42);
    state->theme.window_title = video_make_color(0x28, 0x6A, 0xA8);
    state->theme.window_title_text = video_make_color(0xF5, 0xF7, 0xFA);
    state->theme.window_body = video_make_color(0x0C, 0x11, 0x17);
    state->theme.button_face = video_make_color(0x24, 0x34, 0x48);
    state->theme.button_border = video_make_color(0x12, 0x1A, 0x24);
    state->theme.button_text = video_make_color(0xEE, 0xEE, 0xEE);
    state->theme.desktop_icon_face = video_make_color(0x3A, 0x63, 0x95);
    state->theme.desktop_icon_text = state->theme.window_title_text;
    state->theme.menu_bar_face = video_make_color(0x16, 0x1F, 0x29);
    state->theme.menu_bar_text = state->theme.button_text;
    state->theme.menu_bar_highlight = video_make_color(0x2F, 0x53, 0x83);
    state->theme.menu_dropdown_face = video_make_color(0xF7, 0xF7, 0xF7);
    state->theme.menu_dropdown_border = video_make_color(0x3A, 0x3F, 0x48);
    state->theme.menu_dropdown_text = video_make_color(0x1E, 0x21, 0x24);
    state->theme.menu_dropdown_highlight = video_make_color(0x2F, 0x54, 0x83);
    atk_state_theme_commit(state);
}

static void on_scrollbar_change(atk_widget_t *scrollbar, void *context, int value)
{
    (void)scrollbar;
    mp3_ui_t *ui = (mp3_ui_t *)context;
    if (!ui || !ui->status_label)
    {
        return;
    }
    char buf[64];
    snprintf(buf, sizeof(buf), "Scrub: %d", value);
    atk_label_set_text(ui->status_label, buf);
    atk_window_mark_dirty(ui->window);
}

static void on_placeholder_button(atk_widget_t *button, void *context)
{
    (void)button;
    mp3_ui_t *ui = (mp3_ui_t *)context;
    if (!ui || !ui->status_label)
    {
        return;
    }
    atk_label_set_text(ui->status_label, "TODO: implement playback");
    atk_window_mark_dirty(ui->window);
}

static void on_open_click(atk_widget_t *button, void *context)
{
    (void)button;
    mp3_ui_t *ui = (mp3_ui_t *)context;
    mp3_play_selected(ui);
}

static void on_play_click(atk_widget_t *button, void *context)
{
    (void)button;
    mp3_play_selected((mp3_ui_t *)context);
}

static void build_ui(mp3_ui_t *ui)
{
    log_mp3("[atk_mp3] build_ui begin\r\n");
    atk_init();
    atk_state_t *state = atk_state_get();
    if (!state)
    {
        log_mp3("[atk_mp3] build_ui no state\r\n");
        return;
    }
    atk_menu_bar_set_enabled(state, false);
    apply_theme(state);

    ui->window = atk_window_create_at(state, MP3_UI_WIDTH / 2, MP3_UI_HEIGHT / 2);
    if (!ui->window)
    {
        log_mp3("[atk_mp3] build_ui window create failed\r\n");
        return;
    }
    log_mp3("[atk_mp3] window created\r\n");
    /* For remote windows, keep the surface origin at (0,0) so the whole buffer is filled. */
    ui->window->x = 0;
    ui->window->y = 0;
    ui->window->width = MP3_UI_WIDTH;
    ui->window->height = MP3_UI_HEIGHT;
    atk_window_set_chrome_visible(ui->window, false);
    atk_window_set_title_text(ui->window, "ATK MP3 (UI Prototype)");

    int chrome_top = atk_window_is_chrome_visible(ui->window) ? ATK_WINDOW_TITLE_HEIGHT : 0;
    int x = MP3_MARGIN;
    int y = chrome_top + MP3_MARGIN;
    int content_w = ui->window->width - MP3_MARGIN * 2;

    ui->title_label = atk_window_add_label(ui->window, x, y, content_w, MP3_TITLE_HEIGHT);
    if (ui->title_label)
    {
        atk_label_set_text(ui->title_label, "No track loaded");
    }
    log_mp3("[atk_mp3] title label\r\n");
    y += MP3_TITLE_HEIGHT + MP3_ROW_SPACING;

    ui->status_label = atk_window_add_label(ui->window, x, y, content_w, ATK_FONT_HEIGHT * 2);
    if (ui->status_label)
    {
        atk_label_set_text(ui->status_label, "Status: idle");
    }
    log_mp3("[atk_mp3] status label\r\n");
    y += ATK_FONT_HEIGHT * 2 + MP3_ROW_SPACING;

    int input_h = ATK_FONT_HEIGHT + 8;
    ui->file_label = atk_window_add_label(ui->window, x, y, 48, input_h);
    if (ui->file_label)
    {
        atk_label_set_text(ui->file_label, "File:");
    }

    int button_w = 96;
    int input_x = x + 54;
    int input_w = content_w - (input_x - x) - button_w - MP3_ROW_SPACING;
    ui->file_input = atk_window_add_text_input(ui->window, input_x, y, input_w);
    ui->open_button = atk_window_add_button(ui->window,
                                            "Open...",
                                            input_x + input_w + MP3_ROW_SPACING,
                                            y,
                                            button_w,
                                            input_h,
                                            ATK_BUTTON_STYLE_TITLE_INSIDE,
                                            false,
                                            on_open_click,
                                            ui);
    y += input_h + MP3_ROW_SPACING;
    log_mp3("[atk_mp3] file input/button\r\n");

    int control_h = MP3_BUTTON_HEIGHT;
    int btn_spacing = 10;
    ui->rew_button = atk_window_add_button(ui->window,
                                           "<<",
                                           x,
                                           y,
                                           60,
                                           control_h,
                                           ATK_BUTTON_STYLE_TITLE_INSIDE,
                                           false,
                                           on_placeholder_button,
                                           ui);
    log_mp3(ui->rew_button ? "[atk_mp3] rew button ok\r\n" : "[atk_mp3] rew button FAIL\r\n");

    ui->play_button = atk_window_add_button(ui->window,
                                            "Play/Pause",
                                            x + 60 + btn_spacing,
                                            y,
                                            110,
                                            control_h,
                                            ATK_BUTTON_STYLE_TITLE_INSIDE,
                                            false,
                                            on_play_click,
                                            ui);
    log_mp3(ui->play_button ? "[atk_mp3] play button ok\r\n" : "[atk_mp3] play button FAIL\r\n");

    ui->fwd_button = atk_window_add_button(ui->window,
                                           ">>",
                                           x + 60 + btn_spacing + 110 + btn_spacing,
                                           y,
                                           60,
                                           control_h,
                                           ATK_BUTTON_STYLE_TITLE_INSIDE,
                                           false,
                                           on_placeholder_button,
                                           ui);
    log_mp3(ui->fwd_button ? "[atk_mp3] fwd button ok\r\n" : "[atk_mp3] fwd button FAIL\r\n");
    y += control_h + MP3_ROW_SPACING;
    log_mp3("[atk_mp3] transport buttons done\r\n");

    ui->scrubber = atk_window_add_scrollbar(ui->window,
                                            x,
                                            y,
                                            content_w,
                                            28,
                                            ATK_SCROLLBAR_HORIZONTAL);
    if (ui->scrubber)
    {
        atk_scrollbar_set_range(ui->scrubber, 0, 100, 10);
        atk_scrollbar_set_value(ui->scrubber, 0);
        atk_scrollbar_set_change_handler(ui->scrubber, on_scrollbar_change, ui);
    }
    log_mp3(ui->scrubber ? "[atk_mp3] scrubber ok\r\n" : "[atk_mp3] scrubber FAIL\r\n");

    atk_window_mark_dirty(ui->window);
    log_mp3("[atk_mp3] build_ui end\r\n");
}

static void mp3_set_status(mp3_ui_t *ui, const char *text)
{
    if (!ui || !ui->status_label)
    {
        return;
    }
    atk_label_set_text(ui->status_label, text ? text : "");
    if (ui->window)
    {
        atk_window_mark_dirty(ui->window);
    }
}

static int16_t mp3_clamp16(int32_t v)
{
    if (v > 32767) return 32767;
    if (v < -32768) return -32768;
    return (int16_t)v;
}

static bool mp3_write_all(int fd, const void *data, size_t bytes)
{
    const uint8_t *p = (const uint8_t *)data;
    size_t written = 0;
    while (written < bytes)
    {
        ssize_t w = write(fd, p + written, bytes - written);
        if (w <= 0)
        {
            return false;
        }
        written += (size_t)w;
    }
    return true;
}

static int mp3_open_input(const char *path)
{
    if (!path || path[0] == '\0')
    {
        return -1;
    }

    int fd = open(path, SYSCALL_OPEN_READ);
    if (fd >= 0)
    {
        return fd;
    }

    if (path[0] != '/')
    {
        char alt[256];
        const char prefix[] = "/root/";
        size_t prefix_len = sizeof(prefix) - 1;
        size_t path_len = strlen(path);
        if (prefix_len + path_len < sizeof(alt))
        {
            memcpy(alt, prefix, prefix_len);
            memcpy(alt + prefix_len, path, path_len);
            alt[prefix_len + path_len] = '\0';
            fd = open(alt, SYSCALL_OPEN_READ);
            if (fd >= 0)
            {
                return fd;
            }
        }
    }

    return -1;
}

static size_t mp3_resample_to_target(const mp3d_sample_t *in,
                                     size_t samples_per_channel,
                                     int src_channels,
                                     int src_rate,
                                     int16_t *out,
                                     size_t out_capacity,
                                     mp3_resample_state_t *state)
{
    if (!in || !out || !state || src_rate <= 0 || src_channels <= 0)
    {
        return 0;
    }

    if (state->src_rate != (uint32_t)src_rate)
    {
        state->src_rate = (uint32_t)src_rate;
        state->step = ((uint64_t)src_rate << 32) / MP3_TARGET_RATE;
        state->phase = 0;
        state->src_pos = 0;
        state->have_prev = false;
    }

    size_t produced = 0;
    uint64_t block_start = state->src_pos;
    uint64_t block_end = state->src_pos + (uint64_t)samples_per_channel;

    while (produced + MP3_TARGET_CHANNELS <= out_capacity)
    {
        uint64_t idx = state->phase >> 32;
        if (idx + 1u >= block_end)
        {
            break;
        }

        uint32_t frac = (uint32_t)(state->phase & 0xFFFFFFFFu);
        for (int ch = 0; ch < MP3_TARGET_CHANNELS; ++ch)
        {
            int ch_src = (src_channels == 1) ? 0 : ch;
            int32_t s0;
            int32_t s1;

            if (idx < block_start)
            {
                s0 = state->have_prev ? state->prev[ch_src] : 0;
                s1 = in[ch_src];
            }
            else
            {
                uint64_t idx_local = idx - block_start;
                s0 = in[(idx_local * (uint64_t)src_channels) + ch_src];
                s1 = in[((idx_local + 1u) * (uint64_t)src_channels) + ch_src];
            }

            int64_t blended = (int64_t)s0 * (int64_t)(0x100000000ull - frac) + (int64_t)s1 * (int64_t)frac;
            int32_t sample = (int32_t)(blended >> 32);
            out[produced + (size_t)ch] = mp3_clamp16(sample);
        }

        produced += MP3_TARGET_CHANNELS;
        state->phase += state->step;
    }

    if (samples_per_channel > 0)
    {
        uint64_t last = (uint64_t)samples_per_channel - 1u;
        state->prev[0] = in[last * (uint64_t)src_channels + 0];
        state->prev[1] = in[last * (uint64_t)src_channels + (src_channels > 1 ? 1 : 0)];
        state->have_prev = true;
        state->src_pos += (uint64_t)samples_per_channel;
    }

    return produced;
}

static void mp3_player_cleanup(mp3_ui_t *ui, const char *status)
{
    if (!ui)
    {
        return;
    }
    mp3_player_t *p = &ui->player;
    if (p->input_fd >= 0)
    {
        close(p->input_fd);
    }
    if (p->audio_fd >= 0)
    {
        close(p->audio_fd);
    }
    if (p->in_buffer)
    {
        free(p->in_buffer);
    }
    if (p->decode_buffer)
    {
        free(p->decode_buffer);
    }
    if (p->out_buffer)
    {
        free(p->out_buffer);
    }
    memset(p, 0, sizeof(*p));
    p->input_fd = -1;
    p->audio_fd = -1;
    ui->playing = false;
    if (status)
    {
        mp3_set_status(ui, status);
    }
}

static bool mp3_player_start(mp3_ui_t *ui)
{
    if (!ui)
    {
        return false;
    }

    /* Stop any existing playback first. */
    mp3_player_cleanup(ui, NULL);

    const char *path = ui->file_input ? atk_text_input_text(ui->file_input) : NULL;
    if (!path || path[0] == '\0')
    {
        mp3_set_status(ui, "No file selected");
        return false;
    }

    if (ui->title_label)
    {
        char buf[160];
        snprintf(buf, sizeof(buf), "Track: %s", path);
        atk_label_set_text(ui->title_label, buf);
        if (ui->window)
        {
            atk_window_mark_dirty(ui->window);
        }
    }

    mp3_player_t *p = &ui->player;
    p->input_fd = mp3_open_input(path);
    if (p->input_fd < 0)
    {
        mp3_set_status(ui, "Unable to open file");
        return false;
    }

    p->audio_fd = open("/dev/audio", SYSCALL_OPEN_WRITE);
    if (p->audio_fd < 0)
    {
        mp3_player_cleanup(ui, "Audio device unavailable");
        return false;
    }

    p->out_buffer = (int16_t *)malloc(sizeof(int16_t) * MP3_MAX_RESAMPLED_SAMPLES);
    p->decode_buffer = (mp3d_sample_t *)malloc(sizeof(mp3d_sample_t) * MINIMP3_MAX_SAMPLES_PER_FRAME);
    p->in_buffer = (uint8_t *)malloc(MP3_INPUT_BUFFER_SIZE);
    p->in_capacity = MP3_INPUT_BUFFER_SIZE;
    if (!p->out_buffer || !p->decode_buffer || !p->in_buffer)
    {
        mp3_player_cleanup(ui, "Out of memory");
        return false;
    }

    ssize_t initial = read(p->input_fd, p->in_buffer, p->in_capacity);
    if (initial <= 0)
    {
        mp3_player_cleanup(ui, "Empty input");
        return false;
    }
    p->buf_filled = (size_t)initial;
    p->buf_pos = 0;

    mp3dec_init(&p->dec);
    memset(&p->rs, 0, sizeof(p->rs));
    p->active = true;
    ui->playing = true;
    mp3_set_status(ui, "Playing...");
    return true;
}

static bool mp3_player_refill(mp3_player_t *p)
{
    if (!p || !p->in_buffer || p->in_capacity == 0)
    {
        return false;
    }

    if (p->buf_pos > 0 && p->buf_pos < p->buf_filled)
    {
        memmove(p->in_buffer, p->in_buffer + p->buf_pos, p->buf_filled - p->buf_pos);
        p->buf_filled -= p->buf_pos;
        p->buf_pos = 0;
    }
    else if (p->buf_pos >= p->buf_filled)
    {
        p->buf_pos = 0;
        p->buf_filled = 0;
    }

    if (p->buf_filled >= p->in_capacity)
    {
        return true;
    }

    ssize_t got = read(p->input_fd, p->in_buffer + p->buf_filled, p->in_capacity - p->buf_filled);
    if (got <= 0)
    {
        return false;
    }
    p->buf_filled += (size_t)got;
    return true;
}

static bool mp3_player_tick(mp3_ui_t *ui)
{
    if (!ui)
    {
        return false;
    }
    mp3_player_t *p = &ui->player;
    if (!p->active)
    {
        return false;
    }

    const int MAX_FRAMES_PER_TICK = 4;
    int frames = 0;

    while (frames < MAX_FRAMES_PER_TICK && p->active)
    {
        mp3dec_frame_info_t frame_info;
        int samples = mp3dec_decode_frame(&p->dec,
                                          p->in_buffer + p->buf_pos,
                                          (int)(p->buf_filled - p->buf_pos),
                                          p->decode_buffer,
                                          &frame_info);

        if (frame_info.frame_bytes == 0 && samples == 0)
        {
            if (!mp3_player_refill(p))
            {
                mp3_player_cleanup(ui, "Playback finished");
                return false;
            }
            continue;
        }

        p->buf_pos += (size_t)frame_info.frame_bytes;
        if (samples <= 0)
        {
            if (p->buf_pos >= p->buf_filled)
            {
                p->buf_pos = 0;
                p->buf_filled = 0;
            }
            ++frames;
            continue;
        }

        if (frame_info.hz <= 0 || frame_info.channels <= 0)
        {
            ++frames;
            continue;
        }

        size_t samples_per_channel = (size_t)samples;

        if (frame_info.hz == MP3_TARGET_RATE && frame_info.channels == MP3_TARGET_CHANNELS)
        {
            size_t total_samples = samples_per_channel * MP3_TARGET_CHANNELS;
            size_t bytes_to_write = total_samples * sizeof(int16_t);
            if (!mp3_write_all(p->audio_fd, p->decode_buffer, bytes_to_write))
            {
                mp3_player_cleanup(ui, "Audio write failed");
                return false;
            }
            memset(&p->rs, 0, sizeof(p->rs));
        }
        else
        {
            size_t out_samples = mp3_resample_to_target(p->decode_buffer,
                                                        samples_per_channel,
                                                        frame_info.channels,
                                                        frame_info.hz,
                                                        p->out_buffer,
                                                        MP3_MAX_RESAMPLED_SAMPLES,
                                                        &p->rs);
            if (out_samples > 0)
            {
                size_t bytes_to_write = out_samples * sizeof(int16_t);
                if (!mp3_write_all(p->audio_fd, p->out_buffer, bytes_to_write))
                {
                    mp3_player_cleanup(ui, "Audio write failed");
                    return false;
                }
            }
        }

        if (p->buf_pos >= p->buf_filled)
        {
            p->buf_pos = 0;
            p->buf_filled = 0;
        }
        ++frames;
    }

    return p->active;
}

static bool mp3_play_selected(mp3_ui_t *ui)
{
    return mp3_player_start(ui);
}

static void on_file_submit(atk_widget_t *input, void *context)
{
    (void)input;
    mp3_play_selected((mp3_ui_t *)context);
}

static bool dispatch_event(mp3_ui_t *ui, const user_atk_event_t *event)
{
    if (!ui || !event)
    {
        return false;
    }
    switch (event->type)
    {
        case USER_ATK_EVENT_MOUSE:
        {
            bool left = (event->flags & USER_ATK_MOUSE_FLAG_LEFT) != 0;
            bool press = (event->flags & USER_ATK_MOUSE_FLAG_PRESS) != 0;
            bool release = (event->flags & USER_ATK_MOUSE_FLAG_RELEASE) != 0;
            atk_mouse_event_result_t res = atk_handle_mouse_event(event->x, event->y, press, release, left);
            return res.redraw;
        }
        case USER_ATK_EVENT_KEY:
        {
            atk_key_event_result_t res = atk_handle_key_char((char)event->data0);
            return res.redraw;
        }
        case USER_ATK_EVENT_RESIZE:
        {
            if (ui->window)
            {
                ui->window->width = (int)event->data0;
                ui->window->height = (int)event->data1;
                atk_window_request_layout(ui->window);
                atk_window_mark_dirty(ui->window);
            }
            return true;
        }
        case USER_ATK_EVENT_CLOSE:
            ui->running = false;
            return false;
        default:
            break;
    }
    return false;
}

int main(void)
{
    log_mp3("[atk_mp3] main begin\r\n");
    mp3_ui_t ui;
    memset(&ui, 0, sizeof(ui));
    ui.running = true;

    if (!atk_user_window_open_with_flags(&ui.remote,
                                         "ATK MP3",
                                         MP3_UI_WIDTH,
                                         MP3_UI_HEIGHT,
                                         USER_ATK_WINDOW_FLAG_RESIZABLE))
    {
        printf("atk_mp3_ui: failed to open window\n");
        log_mp3("[atk_mp3] window open failed\r\n");
        return 1;
    }
    atk_user_enable_dirty_tracking(&ui.remote, true);
    log_mp3("[atk_mp3] window opened\r\n");

    build_ui(&ui);
    if (ui.file_input)
    {
        atk_text_input_set_submit_handler(ui.file_input, on_file_submit, &ui);
    }
    if (!ui.window)
    {
        printf("atk_mp3_ui: failed to build UI\n");
        atk_user_close(&ui.remote);
        log_mp3("[atk_mp3] build_ui failed\r\n");
        return 1;
    }
    log_mp3("[atk_mp3] build_ui ok\r\n");

    atk_render();
    atk_user_present_force(&ui.remote);
    log_mp3("[atk_mp3] first present\r\n");

    while (ui.running)
    {
        bool redraw = false;
        bool had_event = false;
        bool progressed = false;
        user_atk_event_t ev;
        while (atk_user_poll_event(&ui.remote, &ev))
        {
            had_event = true;
            redraw |= dispatch_event(&ui, &ev);
        }
        if (ui.playing)
        {
            progressed = mp3_player_tick(&ui);
        }
        if (redraw)
        {
            atk_render();
            atk_user_present(&ui.remote);
        }
        else if (!had_event && !progressed)
        {
            sys_yield();
        }
    }

    mp3_player_cleanup(&ui, NULL);
    atk_user_close(&ui.remote);
    log_mp3("[atk_mp3] main exit\r\n");
    return 0;
}
