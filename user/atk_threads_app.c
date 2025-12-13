#include "atk_user.h"
#include "libc.h"
#include "usyscall.h"
#include "video.h"

#define ATK_THREADS_WIDTH  800u
#define ATK_THREADS_HEIGHT 600u

typedef struct
{
    atk_user_window_t window;
    volatile uint32_t running;
    alix_mutex_t left_lock;
    alix_mutex_t right_lock;
} atk_threads_app_t;

static atk_threads_app_t g_app;
static alix_thread_t g_left_thread = 0;
static alix_thread_t g_right_thread = 0;

static void fill_rect(video_color_t *buffer,
                      uint32_t width,
                      uint32_t height,
                      uint32_t x0,
                      uint32_t y0,
                      uint32_t x1,
                      uint32_t y1,
                      video_color_t color)
{
    if (!buffer || width == 0 || height == 0)
    {
        return;
    }
    if (x0 >= x1 || y0 >= y1 || x0 >= width || y0 >= height)
    {
        return;
    }
    if (x1 > width)
    {
        x1 = width;
    }
    if (y1 > height)
    {
        y1 = height;
    }

    for (uint32_t y = y0; y < y1; ++y)
    {
        video_color_t *row = buffer + (size_t)y * width + x0;
        for (uint32_t x = x0; x < x1; ++x)
        {
            *row++ = color;
        }
    }
}

static void worker_left(void *arg)
{
    atk_threads_app_t *app = (atk_threads_app_t *)arg;
    if (!app)
    {
        return;
    }

    const uint32_t bar_width = 48;
    while (__atomic_load_n(&app->running, __ATOMIC_ACQUIRE) != 0)
    {
        uint32_t width = app->window.width;
        uint32_t height = app->window.height;
        uint32_t half = width / 2;
        if (!app->window.buffer || half == 0 || height == 0)
        {
            (void)sys_yield();
            continue;
        }

        uint32_t span = (half > bar_width) ? (half - bar_width) : 1u;
        uint32_t pos = (uint32_t)((sys_time_millis() / 8u) % span);

        video_color_t bg = video_make_color(0x10, 0x12, 0x20);
        video_color_t bar = video_make_color(0xF0, 0x50, 0x50);

        alix_mutex_lock(&app->left_lock);
        fill_rect(app->window.buffer, width, height, 0, 0, half, height, bg);
        fill_rect(app->window.buffer, width, height, pos, 0, pos + bar_width, height, bar);
        alix_mutex_unlock(&app->left_lock);

        (void)sys_yield();
    }
}

static void worker_right(void *arg)
{
    atk_threads_app_t *app = (atk_threads_app_t *)arg;
    if (!app)
    {
        return;
    }

    const uint32_t bar_height = 48;
    while (__atomic_load_n(&app->running, __ATOMIC_ACQUIRE) != 0)
    {
        uint32_t width = app->window.width;
        uint32_t height = app->window.height;
        uint32_t half = width / 2;
        if (!app->window.buffer || half == 0 || height == 0)
        {
            (void)sys_yield();
            continue;
        }

        uint32_t span = (height > bar_height) ? (height - bar_height) : 1u;
        uint32_t pos = (uint32_t)((sys_time_millis() / 11u) % span);

        video_color_t bg = video_make_color(0x12, 0x10, 0x18);
        video_color_t bar = video_make_color(0x60, 0xE0, 0x80);

        alix_mutex_lock(&app->right_lock);
        fill_rect(app->window.buffer, width, height, half, 0, width, height, bg);
        fill_rect(app->window.buffer, width, height, half, pos, width, pos + bar_height, bar);
        alix_mutex_unlock(&app->right_lock);

        (void)sys_yield();
    }
}

int main(void)
{
    memset(&g_app, 0, sizeof(g_app));
    alix_mutex_init(&g_app.left_lock);
    alix_mutex_init(&g_app.right_lock);
    g_app.running = 1u;

    if (!atk_user_window_open(&g_app.window, "ATK Threads", ATK_THREADS_WIDTH, ATK_THREADS_HEIGHT))
    {
        printf("atk_threads: failed to open window\n");
        return 1;
    }

    fill_rect(g_app.window.buffer,
              g_app.window.width,
              g_app.window.height,
              0,
              0,
              g_app.window.width,
              g_app.window.height,
              video_make_color(0x00, 0x00, 0x00));
    atk_user_present_force(&g_app.window);

    if (alix_thread_create(&g_left_thread, "gui-left", worker_left, &g_app) != 0 ||
        alix_thread_create(&g_right_thread, "gui-right", worker_right, &g_app) != 0)
    {
        printf("atk_threads: failed to create threads\n");
        __atomic_store_n(&g_app.running, 0u, __ATOMIC_RELEASE);
        if (g_left_thread)
        {
            (void)alix_thread_join(g_left_thread, NULL);
        }
        if (g_right_thread)
        {
            (void)alix_thread_join(g_right_thread, NULL);
        }
        atk_user_close(&g_app.window);
        return 1;
    }

    uint64_t next_present = sys_time_millis();
    while (__atomic_load_n(&g_app.running, __ATOMIC_ACQUIRE) != 0)
    {
        user_atk_event_t event;
        while (atk_user_poll_event(&g_app.window, &event))
        {
            if (event.type == USER_ATK_EVENT_CLOSE)
            {
                __atomic_store_n(&g_app.running, 0u, __ATOMIC_RELEASE);
                break;
            }
        }

        uint64_t now = sys_time_millis();
        if (now >= next_present)
        {
            alix_mutex_lock(&g_app.left_lock);
            alix_mutex_lock(&g_app.right_lock);
            (void)atk_user_present_force(&g_app.window);
            alix_mutex_unlock(&g_app.right_lock);
            alix_mutex_unlock(&g_app.left_lock);
            next_present = now + 16u;
        }
        else
        {
            (void)sys_yield();
        }
    }

    int status = 0;
    (void)alix_thread_join(g_left_thread, &status);
    (void)alix_thread_join(g_right_thread, &status);
    atk_user_close(&g_app.window);
    return 0;
}
