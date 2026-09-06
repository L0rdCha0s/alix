#include "atk_user.h"

#include "atk.h"
#include "atk_app.h"
#include "atk_internal.h"
#include "atk_menu_bar.h"
#include "atk_window.h"
#include "atk/layout.h"
#include "atk/atk_label.h"
#include "atk/atk_scrollbar.h"
#include "atk/atk_text_input.h"
#include "atk/atk_file_dialog.h"
#include <stdio.h>
#include <string.h>
#include "userlib.h"
#include "libc.h"
#include "usyscall.h"
#include "user_atk_defs.h"
#include "video.h"
#include "serial.h"
#include "sys/stat.h"

#define MINIMP3_IMPLEMENTATION
#define MINIMP3_NO_STDIO
#include "minimp3.h"
#include "mp3_stream.h"

#define MP3_UI_WIDTH  720
#define MP3_UI_HEIGHT 360
#define MP3_MARGIN    14
#define MP3_ROW_SPACING 10
#define MP3_TITLE_HEIGHT (ATK_FONT_HEIGHT * 2)
#define MP3_BUTTON_HEIGHT (ATK_FONT_HEIGHT + 10)
#define MP3_TARGET_RATE 48000
#define MP3_TARGET_CHANNELS 2
#define MP3_INPUT_BUFFER_SIZE MP3_STREAM_BUFFER_SIZE
#define MP3_MAX_RESAMPLED_SAMPLES 65536u
#define MP3_SEEK_PREROLL_BYTES 4096u
#define MP3_TRANSITION_FRAMES 240u /* 5 ms at the 48 kHz output rate. */
#define MP3_SCRUB_MAX 1000
#define MP3_SCRUB_PAGE 40
#define MP3_MIN_FILE_KNOWN 1024

typedef struct
{
    uint64_t phase;
    int16_t prev[2];
    bool have_prev;
    uint32_t src_rate;
    uint32_t src_channels;
    uint64_t step;
    uint64_t src_pos;
} mp3_resample_state_t;

typedef struct
{
    int input_fd;
    int audio_fd;
    mp3dec_t dec;
    mp3_resample_state_t rs;
    mp3_stream_input_t input;
    mp3d_sample_t *decode_buffer;
    int16_t *out_buffer;
    int16_t *pending_buffer;
    size_t pending_samples;
    uint32_t fade_in_frames;
    bool active;
    bool seekable;
    uint64_t file_size;
    uint64_t consumed_bytes;
    uint64_t discard_until_offset;
    int last_progress;
    /* Only the producer touches decoder/input/PCM state while this is nonzero.
     * The UI joins before control changes; these four publications are atomic. */
    alix_thread_t worker_thread;
    bool worker_stop;
    bool worker_done;
    int worker_result;
    uint64_t progress_offset;
} mp3_player_t;

enum
{
    MP3_PLAYER_RUNNING,
    MP3_PLAYER_FINISHED,
    MP3_PLAYER_READ_ERROR,
    MP3_PLAYER_AUDIO_ERROR
};

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
    atk_widget_t *file_dialog;
    atk_modal_session_t dialog_modal;
    bool running;
    bool playing;
    bool user_scrub_active;
    mp3_player_t player;
} mp3_ui_t;

static void mp3_set_status(mp3_ui_t *ui, const char *text);
static bool mp3_start_selected(mp3_ui_t *ui);
static void mp3_toggle_play(mp3_ui_t *ui);
static void mp3_pause(mp3_ui_t *ui);
static void mp3_resume(mp3_ui_t *ui);
static void mp3_update_play_button(mp3_ui_t *ui);
static bool mp3_update_progress(mp3_ui_t *ui, bool force_update);
static bool mp3_player_seek_percent(mp3_ui_t *ui, int value);
static uint64_t mp3_current_offset(const mp3_player_t *p);
static void mp3_open_file_dialog(mp3_ui_t *ui);
static void mp3_on_file_dialog_result(atk_widget_t *requester, const char *path, bool confirmed, void *context);
static const char *mp3_dialog_initial_path(const mp3_ui_t *ui, char *buf, size_t cap);
static void mp3_close_file_dialog(mp3_ui_t *ui);
static bool mp3_on_resize_event(uint32_t width, uint32_t height, void *context);
static void mp3_on_close_event(void *context);
static bool mp3_on_tick(void *context);
static bool mp3_start_worker(mp3_player_t *p);
static void mp3_stop_worker(mp3_player_t *p);

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
    if (!ui)
    {
        return;
    }

    ui->user_scrub_active = true;

    if (!ui->player.active || !ui->player.seekable || ui->player.file_size == 0)
    {
        mp3_set_status(ui, "Seek unavailable");
        return;
    }

    int percent = (value * 100) / MP3_SCRUB_MAX;
    char buf[64];
    snprintf(buf, sizeof(buf), "%s to %d%%", ui->playing ? "Playing" : "Paused", percent);

    if (mp3_player_seek_percent(ui, value))
    {
        mp3_set_status(ui, buf);
        mp3_update_progress(ui, true);
        if (ui->window)
        {
            atk_window_mark_dirty(ui->window);
        }
    }
    else
    {
        mp3_set_status(ui, "Seek failed");
    }
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

static void mp3_close_file_dialog(mp3_ui_t *ui)
{
    if (!ui)
    {
        return;
    }
    if (ui->file_dialog && ui->file_dialog->used)
    {
        atk_state_t *state = atk_state_get();
        if (state)
        {
            atk_window_close(state, ui->file_dialog);
        }
    }
    if (ui->dialog_modal.active)
    {
        atk_modal_end(&ui->dialog_modal);
    }
    ui->file_dialog = NULL;
    if (ui->window)
    {
        atk_window_mark_dirty(ui->window);
    }
    atk_dirty_mark_all();
    atk_render();
    atk_user_present_force(&ui->remote);
}

static void mp3_on_file_dialog_result(atk_widget_t *requester, const char *path, bool confirmed, void *context)
{
    (void)requester;
    mp3_ui_t *ui = (mp3_ui_t *)context;
    if (!ui)
    {
        return;
    }
    ui->file_dialog = NULL;
    if (confirmed && path && ui->file_input)
    {
        atk_text_input_set_text(ui->file_input, path);
        mp3_start_selected(ui);
    }
    mp3_close_file_dialog(ui);
}

static const char *mp3_dialog_initial_path(const mp3_ui_t *ui, char *buf, size_t cap)
{
    if (!buf || cap == 0)
    {
        return "/root";
    }
    buf[0] = '\0';

    const char *src = (ui && ui->file_input) ? atk_text_input_text(ui->file_input) : NULL;
    if (!src || src[0] == '\0')
    {
        memcpy(buf, "/root", 6);
        return buf;
    }

    size_t len = strlen(src);
    if (len >= cap)
    {
        len = cap - 1;
    }
    memcpy(buf, src, len);
    buf[len] = '\0';

    /* Strip trailing slashes (leave root alone). */
    while (len > 1 && buf[len - 1] == '/')
    {
        buf[--len] = '\0';
    }

    /* If there's no slash, treat it as a bare filename and fall back to /root. */
    char *last_slash = NULL;
    for (size_t i = 0; i < len; ++i)
    {
        if (buf[i] == '/')
        {
            last_slash = &buf[i];
        }
    }
    if (!last_slash)
    {
        memcpy(buf, "/root", 6);
    }
    else if (buf[len - 1] != '/')
    {
        /* Trim off the filename, keeping root if that's all that's left. */
        if (last_slash == buf)
        {
            buf[1] = '\0';
        }
        else
        {
            *last_slash = '\0';
        }
    }

    if (buf[0] == '\0')
    {
        memcpy(buf, "/root", 6);
    }
    return buf;
}

static void mp3_open_file_dialog(mp3_ui_t *ui)
{
    if (!ui || !ui->window)
    {
        return;
    }
    char initial_path[256];
    const char *initial = mp3_dialog_initial_path(ui, initial_path, sizeof(initial_path));
    const uint32_t dialog_w = 720;
    const uint32_t dialog_h = 420;

    ui->file_dialog = atk_app_open_file_dialog_modal(&ui->dialog_modal,
                                                     ui->window,
                                                     "Open MP3",
                                                     initial,
                                                     mp3_on_file_dialog_result,
                                                     ui,
                                                     dialog_w,
                                                     dialog_h,
                                                     USER_ATK_WINDOW_FLAG_RESIZABLE);
    if (!ui->file_dialog)
    {
        mp3_set_status(ui, "Open dialog unavailable");
        return;
    }
    mp3_set_status(ui, "Select a file");
}

static void on_open_click(atk_widget_t *button, void *context)
{
    (void)button;
    mp3_ui_t *ui = (mp3_ui_t *)context;
    mp3_open_file_dialog(ui);
}

static void on_play_click(atk_widget_t *button, void *context)
{
    (void)button;
    mp3_toggle_play((mp3_ui_t *)context);
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
    ui->window->y = MP3_MARGIN;
    ui->window->width = MP3_UI_WIDTH;
    ui->window->height = MP3_UI_HEIGHT - MP3_MARGIN;
    atk_window_set_chrome_visible(ui->window, false);
    atk_window_set_title_text(ui->window, "Alixamp");

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
                                            "Play",
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
        atk_scrollbar_set_range(ui->scrubber, 0, MP3_SCRUB_MAX, MP3_SCRUB_PAGE);
        atk_scrollbar_set_value(ui->scrubber, 0);
        atk_scrollbar_set_change_handler(ui->scrubber, on_scrollbar_change, ui);
    }
    log_mp3(ui->scrubber ? "[atk_mp3] scrubber ok\r\n" : "[atk_mp3] scrubber FAIL\r\n");

    atk_window_mark_dirty(ui->window);
    log_mp3("[atk_mp3] build_ui end\r\n");
}

static uint64_t mp3_current_offset(const mp3_player_t *p)
{
    return p ? mp3_stream_offset(&p->input) : 0;
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

static void mp3_update_play_button(mp3_ui_t *ui)
{
    if (!ui || !ui->play_button)
    {
        return;
    }
    const char *title = (ui->playing && ui->player.active) ? "Pause" : "Play";
    atk_button_set_title(ui->play_button, title);
    if (ui->window)
    {
        atk_window_mark_dirty(ui->window);
    }
}

static bool mp3_update_progress(mp3_ui_t *ui, bool force_update)
{
    if (!ui || !ui->scrubber)
    {
        return false;
    }
    if (ui->user_scrub_active && !force_update)
    {
        return false;
    }

    mp3_player_t *p = &ui->player;
    if (!p->active)
    {
        return false;
    }

    uint64_t consumed = __atomic_load_n(&p->progress_offset, __ATOMIC_ACQUIRE);
    uint64_t size_est = p->file_size;
    if (size_est == 0)
    {
        /* A changing denominator is not a useful seek bar for unknown input. */
        return false;
    }
    if (consumed > size_est)
    {
        consumed = size_est;
    }

    int value = (int)((consumed * MP3_SCRUB_MAX) / size_est);
    if (value < 0) value = 0;
    if (value > MP3_SCRUB_MAX) value = MP3_SCRUB_MAX;
    if (force_update || value != p->last_progress)
    {
        atk_scrollbar_set_value(ui->scrubber, value);
        p->last_progress = value;
        if (ui->window)
        {
            atk_window_mark_dirty(ui->window);
        }
        return true;
    }
    return false;
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

    if (state->src_rate != (uint32_t)src_rate ||
        state->src_channels != (uint32_t)src_channels)
    {
        state->src_rate = (uint32_t)src_rate;
        state->src_channels = (uint32_t)src_channels;
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

static void mp3_apply_pending_fade_in(mp3_player_t *p)
{
    if (!p || !p->pending_buffer || p->fade_in_frames == 0)
    {
        return;
    }

    size_t frames = p->pending_samples / MP3_TARGET_CHANNELS;
    for (size_t frame = 0; frame < frames && p->fade_in_frames > 0; ++frame)
    {
        uint32_t numerator = MP3_TRANSITION_FRAMES - p->fade_in_frames + 1u;
        size_t sample = frame * MP3_TARGET_CHANNELS;
        p->pending_buffer[sample] = (int16_t)(
            ((int32_t)p->pending_buffer[sample] * (int32_t)numerator) /
            (int32_t)MP3_TRANSITION_FRAMES);
        p->pending_buffer[sample + 1u] = (int16_t)(
            ((int32_t)p->pending_buffer[sample + 1u] * (int32_t)numerator) /
            (int32_t)MP3_TRANSITION_FRAMES);
        p->fade_in_frames--;
    }
}

static void mp3_apply_pending_fade_out(mp3_player_t *p)
{
    if (!p || !p->pending_buffer || p->pending_samples == 0)
    {
        return;
    }

    size_t frames = p->pending_samples / MP3_TARGET_CHANNELS;
    size_t fade_frames = (frames < MP3_TRANSITION_FRAMES)
        ? frames
        : MP3_TRANSITION_FRAMES;
    size_t first_fade = frames - fade_frames;
    for (size_t i = 0; i < fade_frames; ++i)
    {
        uint32_t numerator = (uint32_t)(fade_frames - i);
        size_t sample = (first_fade + i) * MP3_TARGET_CHANNELS;
        p->pending_buffer[sample] = (int16_t)(
            ((int32_t)p->pending_buffer[sample] * (int32_t)numerator) /
            (int32_t)fade_frames);
        p->pending_buffer[sample + 1u] = (int16_t)(
            ((int32_t)p->pending_buffer[sample + 1u] * (int32_t)numerator) /
            (int32_t)fade_frames);
    }
}

static bool mp3_write_pending(mp3_player_t *p, bool fade_out)
{
    if (!p || p->pending_samples == 0)
    {
        return true;
    }

    mp3_apply_pending_fade_in(p);
    if (fade_out)
    {
        mp3_apply_pending_fade_out(p);
    }

    size_t samples = p->pending_samples;
    p->pending_samples = 0;
    return mp3_write_all(p->audio_fd,
                         p->pending_buffer,
                         samples * sizeof(int16_t));
}

static bool mp3_queue_pcm(mp3_player_t *p, const int16_t *samples, size_t sample_count)
{
    if (!p || !p->pending_buffer || !samples || sample_count == 0 ||
        sample_count > MP3_MAX_RESAMPLED_SAMPLES)
    {
        return false;
    }
    if (!mp3_write_pending(p, false))
    {
        return false;
    }
    memcpy(p->pending_buffer, samples, sample_count * sizeof(int16_t));
    p->pending_samples = sample_count;
    return true;
}

static void mp3_player_cleanup(mp3_ui_t *ui, const char *status)
{
    if (!ui)
    {
        return;
    }
    mp3_player_t *p = &ui->player;
    mp3_stop_worker(p);
    if (p->audio_fd >= 0 && p->pending_samples > 0)
    {
        (void)mp3_write_pending(p, true);
    }
    if (p->input_fd >= 0)
    {
        close(p->input_fd);
    }
    if (p->audio_fd >= 0)
    {
        close(p->audio_fd);
    }
    if (p->input.buffer)
    {
        free(p->input.buffer);
    }
    if (p->decode_buffer)
    {
        free(p->decode_buffer);
    }
    if (p->out_buffer)
    {
        free(p->out_buffer);
    }
    if (p->pending_buffer)
    {
        free(p->pending_buffer);
    }
    memset(p, 0, sizeof(*p));
    p->input_fd = -1;
    p->audio_fd = -1;
    p->last_progress = -1;
    ui->user_scrub_active = false;
    ui->playing = false;
    mp3_update_play_button(ui);
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
    p->pending_buffer = (int16_t *)malloc(sizeof(int16_t) * MP3_MAX_RESAMPLED_SAMPLES);
    p->decode_buffer = (mp3d_sample_t *)malloc(sizeof(mp3d_sample_t) * MINIMP3_MAX_SAMPLES_PER_FRAME);
    p->input.buffer = (uint8_t *)malloc(MP3_INPUT_BUFFER_SIZE);
    p->input.capacity = MP3_INPUT_BUFFER_SIZE;
    p->file_size = 0;
    p->input.file_pos = 0;
    p->consumed_bytes = 0;
    p->last_progress = -1;
    p->seekable = false;
    if (!p->out_buffer || !p->pending_buffer || !p->decode_buffer || !p->input.buffer)
    {
        mp3_player_cleanup(ui, "Out of memory");
        return false;
    }

    struct stat st;
    memset(&st, 0, sizeof(st));
    if (fstat(p->input_fd, &st) == 0 && st.st_size > 0)
    {
        p->file_size = (uint64_t)st.st_size;
    }

    int64_t end = lseek(p->input_fd, 0, SYSCALL_SEEK_END);
    if (end >= 0)
    {
        if ((uint64_t)end > p->file_size)
        {
            p->file_size = (uint64_t)end;
        }
        if (lseek(p->input_fd, 0, SYSCALL_SEEK_SET) >= 0)
        {
            p->seekable = true;
        }
    }
    else
    {
        (void)lseek(p->input_fd, 0, SYSCALL_SEEK_SET);
    }

    if (!mp3_stream_refill(&p->input, p->input_fd))
    {
        mp3_player_cleanup(ui, "Input read failed");
        return false;
    }
    if (p->input.filled == 0)
    {
        mp3_player_cleanup(ui, "Empty input");
        return false;
    }
    __atomic_store_n(&p->progress_offset, 0, __ATOMIC_RELEASE);

    mp3dec_init(&p->dec);
    memset(&p->rs, 0, sizeof(p->rs));
    p->fade_in_frames = MP3_TRANSITION_FRAMES;
    p->active = true;
    ui->playing = true;
    ui->user_scrub_active = false;
    if (ui->scrubber)
    {
        atk_scrollbar_set_range(ui->scrubber, 0, MP3_SCRUB_MAX, MP3_SCRUB_PAGE);
        atk_scrollbar_set_value(ui->scrubber, 0);
    }
    mp3_set_status(ui, "Playing...");
    mp3_update_play_button(ui);
    mp3_update_progress(ui, true);
    if (!mp3_start_worker(p))
    {
        mp3_player_cleanup(ui, "Unable to start audio worker");
        return false;
    }
    return true;
}

static bool mp3_player_seek_bytes(mp3_ui_t *ui, uint64_t offset)
{
    if (!ui)
    {
        return false;
    }

    mp3_player_t *p = &ui->player;
    if (!p->active || !p->seekable || !p->input.buffer)
    {
        return false;
    }

    if (p->file_size > 0 && offset >= p->file_size)
    {
        offset = (p->file_size > 0) ? (p->file_size - 1u) : 0u;
    }

    /*
     * Layer III frames can reference the bit reservoir from earlier frames.
     * Start a little before the requested byte and decode/discard through the
     * target so the first audible frame is not a damaged reservoir frame.
     */
    uint64_t target_offset = offset;
    uint64_t read_offset = (target_offset > MP3_SEEK_PREROLL_BYTES)
        ? (target_offset - MP3_SEEK_PREROLL_BYTES)
        : 0u;

    mp3_stop_worker(p);
    if (lseek(p->input_fd, (int64_t)read_offset, SYSCALL_SEEK_SET) < 0)
    {
        if (ui->playing && !mp3_start_worker(p))
        {
            mp3_player_cleanup(ui, "Unable to restart audio worker");
        }
        return false;
    }

    if (!mp3_write_pending(p, true))
    {
        mp3_player_cleanup(ui, "Audio write failed");
        return false;
    }

    p->input.filled = 0;
    p->input.consumed = 0;
    p->input.file_pos = read_offset;
    p->input.eof = false;
    p->input.failed = false;
    p->consumed_bytes = target_offset;
    __atomic_store_n(&p->progress_offset, target_offset, __ATOMIC_RELEASE);
    p->discard_until_offset = target_offset;
    p->last_progress = -1;
    mp3dec_init(&p->dec);
    memset(&p->rs, 0, sizeof(p->rs));
    p->fade_in_frames = MP3_TRANSITION_FRAMES;

    if (!mp3_stream_refill(&p->input, p->input_fd) || p->input.filled == 0)
    {
        mp3_player_cleanup(ui, "Seek failed");
        return false;
    }
    mp3_update_progress(ui, true);
    if (ui->playing && !mp3_start_worker(p))
    {
        mp3_player_cleanup(ui, "Unable to restart audio worker");
        return false;
    }
    return true;
}

static bool mp3_player_seek_percent(mp3_ui_t *ui, int value)
{
    if (!ui)
    {
        return false;
    }

    mp3_player_t *p = &ui->player;
    if (!p->active || !p->seekable || p->file_size == 0)
    {
        return false;
    }

    if (value < 0) value = 0;
    if (value > MP3_SCRUB_MAX) value = MP3_SCRUB_MAX;

    uint64_t target = (uint64_t)value * p->file_size / MP3_SCRUB_MAX;
    return mp3_player_seek_bytes(ui, target);
}

/* Decode bounded batches so a control request is observed between frames. */
static int mp3_player_tick(mp3_player_t *p)
{
    for (unsigned frame = 0; frame < 4u; ++frame)
    {
        if (__atomic_load_n(&p->worker_stop, __ATOMIC_ACQUIRE))
        {
            return MP3_PLAYER_RUNNING;
        }
        uint64_t decode_offset = mp3_current_offset(p);
        mp3dec_frame_info_t frame_info;
        int samples = mp3_stream_next(&p->input, &p->dec, p->input_fd,
                                       p->decode_buffer, &frame_info);
        if (samples == MP3_STREAM_EOF)
        {
            __atomic_store_n(&p->progress_offset, p->input.file_pos, __ATOMIC_RELEASE);
            return MP3_PLAYER_FINISHED;
        }
        if (samples == MP3_STREAM_ERROR)
        {
            return MP3_PLAYER_READ_ERROR;
        }

        uint64_t progress = mp3_current_offset(p);
        if (progress < p->discard_until_offset)
        {
            progress = p->discard_until_offset;
        }
        __atomic_store_n(&p->progress_offset, progress, __ATOMIC_RELEASE);
        if (samples <= 0 || frame_info.hz <= 0 || frame_info.channels <= 0)
        {
            continue;
        }

        uint64_t frame_start_offset = decode_offset;
        if (frame_info.frame_offset > 0)
        {
            frame_start_offset += (uint64_t)frame_info.frame_offset;
        }
        if (p->discard_until_offset != 0)
        {
            if (frame_start_offset < p->discard_until_offset)
            {
                continue;
            }
            p->discard_until_offset = 0;
        }

        if (frame_info.hz == MP3_TARGET_RATE && frame_info.channels == MP3_TARGET_CHANNELS)
        {
            size_t total_samples = (size_t)samples * MP3_TARGET_CHANNELS;
            if (!mp3_queue_pcm(p, p->decode_buffer, total_samples))
            {
                return MP3_PLAYER_AUDIO_ERROR;
            }
            memset(&p->rs, 0, sizeof(p->rs));
        }
        else
        {
            size_t out_samples = mp3_resample_to_target(p->decode_buffer,
                                                        (size_t)samples,
                                                        frame_info.channels,
                                                        frame_info.hz,
                                                        p->out_buffer,
                                                        MP3_MAX_RESAMPLED_SAMPLES,
                                                        &p->rs);
            if (out_samples > 0 && !mp3_queue_pcm(p, p->out_buffer, out_samples))
            {
                return MP3_PLAYER_AUDIO_ERROR;
            }
        }
    }
    return MP3_PLAYER_RUNNING;
}

static void mp3_audio_worker(void *context)
{
    mp3_player_t *p = (mp3_player_t *)context;
    int result = MP3_PLAYER_RUNNING;
    while (!__atomic_load_n(&p->worker_stop, __ATOMIC_ACQUIRE))
    {
        result = mp3_player_tick(p);
        if (result != MP3_PLAYER_RUNNING)
        {
            break;
        }
    }
    if (result != MP3_PLAYER_RUNNING && !mp3_write_pending(p, true))
    {
        result = MP3_PLAYER_AUDIO_ERROR;
    }
    __atomic_store_n(&p->worker_result, result, __ATOMIC_RELEASE);
    __atomic_store_n(&p->worker_done, true, __ATOMIC_RELEASE);
}

static bool mp3_start_worker(mp3_player_t *p)
{
    if (!p || p->worker_thread)
    {
        return false;
    }
    __atomic_store_n(&p->worker_stop, false, __ATOMIC_RELEASE);
    __atomic_store_n(&p->worker_done, false, __ATOMIC_RELEASE);
    __atomic_store_n(&p->worker_result, MP3_PLAYER_RUNNING, __ATOMIC_RELEASE);
    return alix_thread_create(&p->worker_thread, "mp3_audio", mp3_audio_worker, p) == 0;
}

static void mp3_stop_worker(mp3_player_t *p)
{
    if (p && p->worker_thread)
    {
        __atomic_store_n(&p->worker_stop, true, __ATOMIC_RELEASE);
        if (alix_thread_join(p->worker_thread, NULL) < 0)
        {
            /* A failed join must never let the UI free live producer buffers.
             * worker_done is the producer's final access to the shared state. */
            while (!__atomic_load_n(&p->worker_done, __ATOMIC_ACQUIRE))
            {
                (void)sys_sleep_ms(1);
            }
            (void)alix_thread_join(p->worker_thread, NULL);
        }
        p->worker_thread = 0;
    }
}

static const char *mp3_worker_status(int result)
{
    if (result == MP3_PLAYER_FINISHED)
    {
        return "Playback finished";
    }
    return result == MP3_PLAYER_READ_ERROR ? "Input read failed" : "Audio write failed";
}

static void mp3_pause(mp3_ui_t *ui)
{
    if (!ui || !ui->player.active || !ui->playing)
    {
        return;
    }
    mp3_stop_worker(&ui->player);
    int result = __atomic_load_n(&ui->player.worker_result, __ATOMIC_ACQUIRE);
    if (result != MP3_PLAYER_RUNNING)
    {
        mp3_player_cleanup(ui, mp3_worker_status(result));
        return;
    }
    if (!mp3_write_pending(&ui->player, true))
    {
        mp3_player_cleanup(ui, "Audio write failed");
        return;
    }
    ui->playing = false;
    mp3_update_play_button(ui);
    mp3_set_status(ui, "Paused");
}

static void mp3_resume(mp3_ui_t *ui)
{
    if (!ui || !ui->player.active || ui->playing)
    {
        return;
    }
    ui->player.fade_in_frames = MP3_TRANSITION_FRAMES;
    if (!mp3_start_worker(&ui->player))
    {
        mp3_player_cleanup(ui, "Unable to restart audio worker");
        return;
    }
    ui->playing = true;
    mp3_update_play_button(ui);
    mp3_set_status(ui, "Playing...");
}

static void mp3_toggle_play(mp3_ui_t *ui)
{
    if (!ui)
    {
        return;
    }
    if (!ui->player.active)
    {
        mp3_player_start(ui);
        return;
    }

    if (ui->playing)
    {
        mp3_pause(ui);
    }
    else
    {
        mp3_resume(ui);
    }
}

static bool mp3_start_selected(mp3_ui_t *ui)
{
    return mp3_player_start(ui);
}

static void on_file_submit(atk_widget_t *input, void *context)
{
    (void)input;
    mp3_start_selected((mp3_ui_t *)context);
}

static bool mp3_on_resize_event(uint32_t width, uint32_t height, void *context)
{
    mp3_ui_t *ui = (mp3_ui_t *)context;
    if (!ui || !ui->window || width == 0 || height == 0)
    {
        return false;
    }
    ui->window->width = (int)width;
    ui->window->height = (int)height;
    atk_window_request_layout(ui->window);
    atk_window_mark_dirty(ui->window);
    return true;
}

static void mp3_on_close_event(void *context)
{
    mp3_ui_t *ui = (mp3_ui_t *)context;
    if (!ui)
    {
        return;
    }
    if (ui->dialog_modal.active)
    {
        mp3_close_file_dialog(ui);
        return;
    }
    ui->running = false;
    mp3_close_file_dialog(ui);
    atk_main_request_exit();
}

static bool mp3_on_tick(void *context)
{
    mp3_ui_t *ui = (mp3_ui_t *)context;
    if (!ui)
    {
        return false;
    }
    ui->user_scrub_active = false;
    mp3_player_t *p = &ui->player;
    if (p->worker_thread && __atomic_load_n(&p->worker_done, __ATOMIC_ACQUIRE))
    {
        mp3_stop_worker(p);
        int result = __atomic_load_n(&p->worker_result, __ATOMIC_ACQUIRE);
        mp3_update_progress(ui, true);
        mp3_player_cleanup(ui, mp3_worker_status(result));
        return true;
    }
    return ui->playing && mp3_update_progress(ui, false);
}

int main(void)
{
    log_mp3("[atk_mp3] main begin\r\n");
    /* The producer receives &ui->player, so the context must outlive all stacks. */
    mp3_ui_t *ui = (mp3_ui_t *)calloc(1, sizeof(*ui));
    if (!ui)
    {
        return 1;
    }
    ui->running = true;
    ui->player.input_fd = -1;
    ui->player.audio_fd = -1;
    ui->player.last_progress = -1;

    if (!atk_user_window_open_with_flags(&ui->remote,
                                         "ATK MP3",
                                         MP3_UI_WIDTH,
                                         MP3_UI_HEIGHT,
                                         USER_ATK_WINDOW_FLAG_RESIZABLE))
    {
        printf("atk_mp3_ui: failed to open window\n");
        log_mp3("[atk_mp3] window open failed\r\n");
        free(ui);
        return 1;
    }
    atk_user_enable_dirty_tracking(&ui->remote, true);
    log_mp3("[atk_mp3] window opened\r\n");

    build_ui(ui);
    if (ui->file_input)
    {
        atk_text_input_set_submit_handler(ui->file_input, on_file_submit, ui);
    }
    if (!ui->window)
    {
        printf("atk_mp3_ui: failed to build UI\n");
        atk_user_close(&ui->remote);
        log_mp3("[atk_mp3] build_ui failed\r\n");
        free(ui);
        return 1;
    }
    log_mp3("[atk_mp3] build_ui ok\r\n");

    atk_main_config_t main_cfg = {
        .window = &ui->remote,
        .tick = mp3_on_tick,
        .tick_context = ui,
        .present_on_idle = false,
        .legacy_input = false
    };

    atk_render();
    atk_user_present_force(&ui->remote);
    log_mp3("[atk_mp3] first present\r\n");

    atk_main_register_resize_handler(mp3_on_resize_event, ui);
    atk_main_register_close_handler(mp3_on_close_event, ui);

    atk_main(&main_cfg);
    mp3_close_file_dialog(ui);
    mp3_player_cleanup(ui, NULL);
    atk_user_close(&ui->remote);
    log_mp3("[atk_mp3] main exit\r\n");
    free(ui);
    return 0;
}
