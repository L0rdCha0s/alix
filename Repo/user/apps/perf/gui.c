#include "atk.h"
#include "atk_button.h"
#include "atk_internal.h"
#include "atk_menu_bar.h"
#include "atk_user.h"
#include "atk_window.h"
#include "errno.h"
#include "perf.h"
#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "unistd.h"
#include "usyscall.h"
#include "video.h"

#define HIST_LIMIT 2000
#define FRAME_NS UINT64_C(16000000)
typedef struct
{
    uint64_t bins[HIST_LIMIT + 1], count, sum, max;
} histogram_t;
typedef struct
{
    perf_config_t *config;
    atk_user_window_t remote;
    atk_widget_t *window;
    atk_widget_t *start, *stop, *export, *previous, *next, *group;
    pthread_t worker;
    bool worker_valid, close, dirty, checkpoint;
    unsigned scroll, group_index, result_count;
    uint64_t frames, last_frame, next_frame, done_at, clicks, dropped;
    histogram_t workload_metrics[6];
    char workload[80];
    uint64_t history[160];
    unsigned history_head;
    histogram_t metrics[2][6]; /* idle/load x
                                  interval/lateness/render/present/queue/input-present */
    char notice[160];
} gui_t;
static const char *groups[] = {NULL,         "memory",  "vm",  "syscall",    "threading",
                               "scheduling", "process", "ipc", "filesystem", "network"};
static const char *metric_names[] = {"frame_interval", "timer_lateness", "render",
                                     "present_call",   "input_queue",    "input_to_present_return"};
static void hist_add(histogram_t *h, uint64_t ns)
{
    uint64_t ms = ns / 1000000;
    h->bins[ms < HIST_LIMIT ? ms : HIST_LIMIT]++;
    h->count++;
    h->sum += ns;
    if (ns > h->max)
        h->max = ns;
}
static uint64_t percentile(histogram_t *h, unsigned percent)
{
    if (!h->count)
        return 0;
    uint64_t target = (h->count * percent + 99) / 100, seen = 0;
    for (unsigned i = 0; i <= HIST_LIMIT; i++)
    {
        seen += h->bins[i];
        if (seen >= target)
            return (uint64_t)i * 1000000;
    }
    return 0;
}
static void *run_worker(void *arg)
{
    gui_t *g = arg;
    perf_run(g->config);
    return NULL;
}
static void start_run(atk_widget_t *widget, void *arg)
{
    (void)widget;
    gui_t *g = arg;
    perf_state_t *s = g->config->state;
    if (__atomic_load_n(&s->running, __ATOMIC_ACQUIRE))
        return;
    if (g->worker_valid)
    {
        pthread_join(g->worker, NULL);
        g->worker_valid = false;
    }
    pthread_mutex_lock(&s->lock);
    s->count = s->failed = s->skipped = 0;
    snprintf(s->current, sizeof(s->current), "Starting");
    pthread_mutex_unlock(&s->lock);
    __atomic_store_n(&s->stop, 0, __ATOMIC_RELEASE);
    __atomic_store_n(&s->done, 0, __ATOMIC_RELEASE);
    __atomic_store_n(&s->running, 1, __ATOMIC_RELEASE);
    memset(g->metrics[1], 0, sizeof(g->metrics[1]));
    g->scroll = 0;
    g->done_at = 0;
    int e = pthread_create(&g->worker, NULL, run_worker, g);
    if (e)
    {
        __atomic_store_n(&s->running, 0, __ATOMIC_RELEASE);
        snprintf(g->notice, sizeof(g->notice), "Could not start worker: %d", e);
    }
    else
    {
        g->worker_valid = true;
        snprintf(g->notice, sizeof(g->notice),
                 "Running. Click Probe or press P to measure input response.");
    }
    g->dirty = true;
}
static void stop_run(atk_widget_t *w, void *arg)
{
    (void)w;
    gui_t *g = arg;
    __atomic_store_n(&g->config->state->stop, 1, __ATOMIC_RELEASE);
    snprintf(g->notice, sizeof(g->notice), "Stopping after the current bounded operation.");
    g->dirty = true;
}
static void ui_workload_report(gui_t *g)
{
    if (!g->workload[0])
        return;
    for (unsigned i = 0; i < 6; i++)
    {
        histogram_t *h = &g->workload_metrics[i];
        if (!h->count)
            continue;
        perf_log("PERF_UI_WORKLOAD,%s,%s,%llu,%llu,%llu,%llu,%llu\n", g->workload, metric_names[i],
                 (unsigned long long)h->count, (unsigned long long)(h->sum / h->count),
                 (unsigned long long)percentile(h, 50), (unsigned long long)percentile(h, 95),
                 (unsigned long long)h->max);
    }
}
static void ui_rotate_workload(gui_t *g, unsigned phase)
{
    char name[80] = {0};
    if (phase)
    {
        pthread_mutex_lock(&g->config->state->lock);
        snprintf(name, sizeof(name), "%s", g->config->state->current);
        pthread_mutex_unlock(&g->config->state->lock);
    }
    if (strcmp(name, g->workload))
    {
        ui_workload_report(g);
        memset(g->workload_metrics, 0, sizeof(g->workload_metrics));
        snprintf(g->workload, sizeof(g->workload), "%s", name);
    }
}
static void ui_sample(gui_t *g, unsigned phase, unsigned metric, uint64_t ns)
{
    hist_add(&g->metrics[phase][metric], ns);
    if (phase && g->workload[0])
        hist_add(&g->workload_metrics[metric], ns);
}
static void ui_reports(gui_t *g, FILE *file)
{
    for (unsigned phase = 0; phase < 2; phase++)
        for (unsigned metric = 0; metric < 6; metric++)
        {
            histogram_t *h = &g->metrics[phase][metric];
            if (!h->count)
                continue;
            char output[256];
            snprintf(output, sizeof(output), "PERF_UI,%s,%s,%llu,%llu,%llu,%llu,%llu\n",
                     phase ? "load" : "idle", metric_names[metric], (unsigned long long)h->count,
                     (unsigned long long)(h->sum / h->count), (unsigned long long)percentile(h, 50),
                     (unsigned long long)percentile(h, 95), (unsigned long long)h->max);
            if (file == stdout)
                perf_log("%s", output);
            else
                fputs(output, file);
        }
    char output[160];
    snprintf(output, sizeof(output), "PERF_UI_EVENTS,clicks=%llu,dropped=%llu\n",
             (unsigned long long)g->clicks, (unsigned long long)g->dropped);
    if (file == stdout)
        perf_log("%s", output);
    else
        fputs(output, file);
}
static void export_run(atk_widget_t *w, void *arg)
{
    (void)w;
    gui_t *g = arg;
    char path[160];
    snprintf(path, sizeof(path), "/tmp/perf-results-%d.csv", getpid());
    FILE *file = fopen(path, "w");
    if (!file)
    {
        snprintf(g->notice, sizeof(g->notice), "Export failed: %d", errno);
        return;
    }
    perf_state_t *s = g->config->state;
    perf_result_t *copy = calloc(PERF_MAX_RESULTS, sizeof(*copy));
    if (!copy)
    {
        fclose(file);
        return;
    }
    pthread_mutex_lock(&s->lock);
    unsigned count = s->count;
    memcpy(copy, s->results, count * sizeof(*copy));
    pthread_mutex_unlock(&s->lock);
    fprintf(file, "group,name,status,samples,workers,operations,bytes,elapsed_ns,p50_ns,"
                  "p95_ns,max_ns,user_us,system_us,minor_faults,major_faults,error\n");
    for (unsigned i = 0; i < count; i++)
    {
        perf_result_t *r = &copy[i];
        fprintf(file, "%s,%s,%s,%u,%u,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%d\n",
                r->group, r->name, perf_status(r->error), r->samples, r->workers,
                (unsigned long long)r->operations, (unsigned long long)r->bytes,
                (unsigned long long)r->elapsed_ns, (unsigned long long)r->p50_ns,
                (unsigned long long)r->p95_ns, (unsigned long long)r->max_ns,
                (unsigned long long)r->user_us, (unsigned long long)r->system_us,
                (unsigned long long)r->minor_faults, (unsigned long long)r->major_faults, r->error);
    }
    ui_reports(g, file);
    free(copy);
    int e = fclose(file);
    perf_log("PERF_EXPORT,%s,status=%d\n", path, e ? errno : 0);
    if (e)
        snprintf(g->notice, sizeof(g->notice), "Export failed: %d", errno);
    else
        snprintf(g->notice, sizeof(g->notice), "Saved %s", path);
    g->dirty = true;
}
static void previous(atk_widget_t *w, void *arg)
{
    (void)w;
    gui_t *g = arg;
    g->scroll = g->scroll > 10 ? g->scroll - 10 : 0;
    g->dirty = true;
}
static void next(atk_widget_t *w, void *arg)
{
    (void)w;
    gui_t *g = arg;
    perf_state_t *s = g->config->state;
    pthread_mutex_lock(&s->lock);
    if (g->scroll + 10 < s->count)
        g->scroll += 10;
    pthread_mutex_unlock(&s->lock);
    g->dirty = true;
}
static void change_group(atk_widget_t *w, void *arg)
{
    gui_t *g = arg;
    if (__atomic_load_n(&g->config->state->running, __ATOMIC_ACQUIRE))
        return;
    g->group_index = (g->group_index + 1) % (sizeof(groups) / sizeof(groups[0]));
    g->config->group = groups[g->group_index];
    g->config->case_name = NULL;
    atk_button_set_title(w, g->config->group ? g->config->group : "All paths");
    g->dirty = true;
}
static void probe(atk_widget_t *w, void *arg)
{
    (void)w;
    gui_t *g = arg;
    g->clicks++;
    snprintf(g->notice, sizeof(g->notice), "Input probe %llu received",
             (unsigned long long)g->clicks);
    g->dirty = true;
}
static video_color_t bg, fg, muted, accent, line;
static void text(int x, int y, const char *str, video_color_t color, int width)
{
    video_draw_text_clipped(x, y, width, 24, str, color, bg);
}
static bool build(gui_t *g)
{
    atk_init();
    atk_state_t *s = atk_state_get();
    atk_menu_bar_set_enabled(s, false);
    bg = video_make_color(17, 23, 31);
    fg = video_make_color(231, 237, 243);
    muted = video_make_color(147, 164, 182);
    accent = video_make_color(75, 184, 210);
    line = video_make_color(45, 58, 72);
    s->theme.window_body = bg;
    s->theme.background = bg;
    s->theme.button_face = line;
    s->theme.button_text = fg;
    s->theme.button_border = line;
    atk_state_theme_commit(s);
    g->window = atk_window_create_at(s, 0, 0);
    if (!g->window)
        return false;
    atk_window_set_chrome_visible(g->window, false);
    g->window->x = 0;
    g->window->y = 0;
    g->window->width = g->remote.width;
    g->window->height = g->remote.height;
    g->start = atk_window_add_button(g->window, "Start", 24, 54, 88, 32,
                                     ATK_BUTTON_STYLE_TITLE_INSIDE, false, start_run, g);
    g->stop = atk_window_add_button(g->window, "Stop", 120, 54, 80, 32,
                                    ATK_BUTTON_STYLE_TITLE_INSIDE, false, stop_run, g);
    g->group =
        atk_window_add_button(g->window, g->config->group ? g->config->group : "All paths", 216, 54,
                              140, 32, ATK_BUTTON_STYLE_TITLE_INSIDE, false, change_group, g);
    g->export = atk_window_add_button(g->window, "Export CSV", 372, 54, 136, 32,
                                      ATK_BUTTON_STYLE_TITLE_INSIDE, false, export_run, g);
    atk_widget_t *p = atk_window_add_button(g->window, "Probe", 524, 54, 88, 32,
                                            ATK_BUTTON_STYLE_TITLE_INSIDE, false, probe, g);
    g->previous = atk_window_add_button(g->window, "Previous", 628, 54, 100, 32,
                                        ATK_BUTTON_STYLE_TITLE_INSIDE, false, previous, g);
    g->next = atk_window_add_button(g->window, "Next", 736, 54, 80, 32,
                                    ATK_BUTTON_STYLE_TITLE_INSIDE, false, next, g);
    return g->start && g->stop && g->group && g->export && p && g->previous && g->next;
}
static void draw(gui_t *g, unsigned phase)
{
    unsigned width = g->remote.width, height = g->remote.height;
    char buf[256];
    atk_window_mark_dirty(g->window);
    atk_render();
    text(24, 18,
         g->config->present_mode == 1   ? "ALIX / PERFORMANCE / STATIC UPLOAD"
         : g->config->present_mode == 2 ? "ALIX / PERFORMANCE / BOTTOM PIXEL"
                                        : "ALIX / PERFORMANCE",
         fg, (int)width - 48);
    perf_state_t *s = g->config->state;
    perf_result_t rows[10]; /* Never shared with worker. */
    pthread_mutex_lock(&s->lock);
    unsigned count = s->count, failed = s->failed, skipped = s->skipped;
    g->result_count = count;
    unsigned visible = count > g->scroll ? count - g->scroll : 0;
    if (visible > 10)
        visible = 10;
    for (unsigned i = 0; i < visible; i++)
        rows[i] = s->results[g->scroll + i];
    snprintf(buf, sizeof(buf), "%s   |   %u results   %u failed   %u skipped",
             s->current[0] ? s->current : "Ready", count, failed, skipped);
    pthread_mutex_unlock(&s->lock);
    text(24, 103, buf, accent, width - 48);
    text(24, 134,
         "WORKLOAD                          P50 us/op    P95 us/op      MiB/s    "
         " STATE",
         muted, width - 48);
    video_draw_rect(24, 158, width > 48 ? (int)width - 48 : 1, 1, line);
    for (unsigned i = 0; i < visible; i++)
    {
        perf_result_t *r = &rows[i];
        uint64_t mib =
            r->elapsed_ns ? r->bytes * UINT64_C(1000000000) / r->elapsed_ns / (1024 * 1024) : 0;
        snprintf(buf, sizeof(buf), "%-32s %8llu.%03llu %8llu.%03llu %10llu     %s", r->name,
                 (unsigned long long)(r->p50_ns / 1000), (unsigned long long)(r->p50_ns % 1000),
                 (unsigned long long)(r->p95_ns / 1000), (unsigned long long)(r->p95_ns % 1000),
                 (unsigned long long)mib, perf_status(r->error));
        text(24, 170 + (int)i * 22, buf, r->error ? muted : fg, width - 48);
    }
    int y = 404;
    text(24, y, "UI LATENCY / milliseconds / 0 = below clock resolution", accent, width - 48);
    const char *labels[] = {"Frame interval", "Timer lateness", "Render",
                            "Present call",   "Input queue",    "Input to present"};
    for (unsigned i = 0; i < 6; i++)
    {
        histogram_t *idle = &g->metrics[0][i], *load = &g->metrics[1][i];
        snprintf(buf, sizeof(buf), "%-18s idle p95 %4llu  load p95 %4llu  max %4llu  n=%llu",
                 labels[i], (unsigned long long)(percentile(idle, 95) / 1000000),
                 (unsigned long long)(percentile(load, 95) / 1000000),
                 (unsigned long long)(load->max / 1000000), (unsigned long long)load->count);
        text(24, y + 28 + (int)i * 22, buf, fg, width - 48);
    }
    int graph_x = width > 900 ? 700 : width - 170, graph_y = y + 35, graph_h = 118;
    video_draw_rect_outline(graph_x, graph_y, 144, graph_h, line);
    for (unsigned i = 0; i < 140; i++)
    {
        unsigned index = (g->history_head + 160 - 140 + i) % 160;
        uint64_t ms = g->history[index] / 1000000;
        int h = (int)(ms > 100 ? 100 : ms);
        video_draw_rect(graph_x + 2 + i, graph_y + graph_h - 3 - h, 1, h, accent);
    }
    /* A moving marker makes stalls visible without inventing compositor FPS. */
    video_draw_rect(24 + (int)(g->frames % 160) * 3, y + 174, 12, 6, accent);
    snprintf(buf, sizeof(buf), "%s  |  input probes %llu  queue drops %llu",
             phase ? "Under load" : "Idle", (unsigned long long)g->clicks,
             (unsigned long long)g->dropped);
    text(24, y + 190, buf, muted, width - 48);
    if (height > 650)
        text(24, height - 44, g->notice, accent, width - 48);
    if (height > 675)
        text(24, height - 22,
             "P: probe   Space: start/stop   E: export   J/K: results   Present "
             "return excludes display scanout",
             muted, width - 48);
}
__attribute__((noinline)) void perf_gui_visual_checkpoint(void)
{
    __asm__ volatile("" ::: "memory");
}
int perf_gui(perf_config_t *c)
{
    gui_t *g = calloc(1, sizeof(*g));
    if (!g)
        return 1;
    g->config = c;
    for (unsigned i = 0; i < sizeof(groups) / sizeof(groups[0]); i++)
        if (c->group && groups[i] && !strcmp(c->group, groups[i]))
            g->group_index = i;
    if (!atk_user_window_open(&g->remote, "Alix Performance", 1000, 720) || !build(g))
    {
        atk_user_close(&g->remote);
        free(g);
        return 1;
    }
    snprintf(g->notice, sizeof(g->notice),
             "Start a run. UI timing continues during every workload.");
    g->next_frame = perf_now_ns();
    uint64_t autorun_at = g->next_frame + UINT64_C(1000000000);
    perf_log("PERF_GUI_READY,width=%u,height=%u\n", g->remote.width, g->remote.height);
    if (c->present_mode)
        snprintf(g->notice, sizeof(g->notice),
                 "Present diagnostic: display holds still; live metrics are exported and logged.");
    bool auto_started = false;
    while (!g->close)
    {
        uint64_t input_stamp = 0;
        user_atk_timed_event_t event;
        unsigned phase = __atomic_load_n(&c->state->running, __ATOMIC_ACQUIRE) ? 1 : 0;
        /* Bound event draining so continuous input cannot starve rendering. */
        for (unsigned drained = 0; drained < 64; drained++)
        {
            int rc = atk_user_poll_timed_event(&g->remote, &event);
            if (rc < 0)
            {
                snprintf(g->notice, sizeof(g->notice), "Event poll failed: %d", rc);
                g->close = true;
                break;
            }
            g->dropped = event.dropped_events;
            if (!rc)
                break;
            user_atk_event_t *e = &event.event;
            uint64_t now = perf_now_ns();
            if (e->type == USER_ATK_EVENT_MOUSE || e->type == USER_ATK_EVENT_KEY)
            {
                uint64_t stamp = event.queued_milliseconds * 1000000;
                if (now >= stamp)
                    ui_sample(g, phase, 4, now - stamp);
                if (!input_stamp || stamp < input_stamp)
                    input_stamp = stamp;
            }
            if (e->type == USER_ATK_EVENT_CLOSE)
                g->close = true;
            else if (e->type == USER_ATK_EVENT_RESIZE)
            {
                g->window->width = g->remote.width;
                g->window->height = g->remote.height;
                g->dirty = true;
            }
            else if (e->type == USER_ATK_EVENT_MOUSE)
            {
                atk_handle_mouse_event(
                    (int)e->data0, (int)e->data1, e->x, e->y, e->flags & USER_ATK_MOUSE_FLAG_PRESS,
                    e->flags & USER_ATK_MOUSE_FLAG_RELEASE, e->flags & USER_ATK_MOUSE_FLAG_LEFT,
                    e->flags & USER_ATK_MOUSE_FLAG_RIGHT_PRESS,
                    e->flags & USER_ATK_MOUSE_FLAG_RIGHT_RELEASE,
                    e->flags & USER_ATK_MOUSE_FLAG_RIGHT);
                g->dirty = true;
            }
            else if (e->type == USER_ATK_EVENT_KEY && !(e->flags & USER_ATK_KEY_FLAG_RELEASE))
            {
                if (e->data0 == 'p' || e->data0 == 'P')
                    probe(NULL, g);
                else if (e->data0 == 'e' || e->data0 == 'E')
                    export_run(NULL, g);
                else if (e->data0 == ' ')
                {
                    if (phase)
                        stop_run(NULL, g);
                    else
                        start_run(NULL, g);
                }
                else if (e->data0 == 'j')
                    next(NULL, g);
                else if (e->data0 == 'k')
                    previous(NULL, g);
                else
                    atk_handle_key_char((char)e->data0);
            }
        }
        uint64_t now = perf_now_ns();
        if (c->autorun && !auto_started && now >= autorun_at)
        {
            auto_started = true;
            start_run(NULL, g);
        }
        if (now >= g->next_frame || g->dirty || input_stamp)
        {
            ui_rotate_workload(g, phase);
            if (now >= g->next_frame)
            {
                ui_sample(g, phase, 1, now - g->next_frame);
                do
                    g->next_frame += FRAME_NS;
                while (g->next_frame <= now);
            }
            if (g->last_frame)
            {
                uint64_t interval = now - g->last_frame;
                ui_sample(g, phase, 0, interval);
                g->history[g->history_head++ % 160] = interval;
            }
            g->last_frame = now;
            uint64_t begin = perf_now_ns();
            if (!c->present_mode || g->dirty || !g->frames)
                draw(g, phase);
            if (c->present_mode == 2 && g->remote.buffer && g->remote.width && g->remote.height)
                g->remote.buffer[(size_t)g->remote.width * g->remote.height - 1] ^= 1u;
            uint64_t rendered = perf_now_ns();
            bool presented = atk_user_present_force(&g->remote);
            uint64_t end = perf_now_ns();
            if (!presented)
            {
                snprintf(g->notice, sizeof(g->notice), "Present failed");
                g->close = true;
            }
            ui_sample(g, phase, 2, rendered - begin);
            ui_sample(g, phase, 3, end - rendered);
            if (input_stamp && end >= input_stamp)
                ui_sample(g, phase, 5, end - input_stamp);
            g->frames++;
            g->dirty = false;
            bool capture_ready = phase && g->result_count >= (c->group ? 1u : 12u);
            if (c->case_name && phase && g->frames >= 90)
                capture_ready = true;
            if (__atomic_load_n(&c->state->done, __ATOMIC_ACQUIRE) && g->result_count)
                capture_ready = true;
            if (!g->checkpoint && g->frames >= 60 && capture_ready)
            {
                g->checkpoint = true;
                perf_gui_visual_checkpoint();
            }
        }
        if (__atomic_load_n(&c->state->done, __ATOMIC_ACQUIRE))
        {
            if (!g->done_at)
            {
                g->done_at = now;
                ui_reports(g, stdout);
                export_run(NULL, g);
            }
            if (c->exit_when_done && now - g->done_at > UINT64_C(1000000000))
                g->close = true;
        }
        usleep(1000);
    }
    __atomic_store_n(&c->state->stop, 1, __ATOMIC_RELEASE);
    if (g->worker_valid)
        pthread_join(g->worker, NULL);
    ui_workload_report(g);
    ui_reports(g, stdout);
    unsigned failed = c->state->failed;
    perf_log("PERF_GUI_DONE,frames=%llu,probes=%llu,dropped=%llu\n", (unsigned long long)g->frames,
             (unsigned long long)g->clicks, (unsigned long long)g->dropped);
    atk_user_close(&g->remote);
    free(g);
    return failed ? 1 : 0;
}
