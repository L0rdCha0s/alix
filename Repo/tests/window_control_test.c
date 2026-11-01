#include "usyscall.h"
#include "pthread.h"
#include "stdlib.h"
#include "string.h"
#include "stdio.h"
#include "serial.h"
#include "errno.h"
#include "alix_process.h"
#include "sys/wait.h"
#include "sys/mman.h"

#define CHECK(c,label) do { if (!(c)) { serial_printf("UI_CONTROL_TEST: FAIL %s line=%u\n", label, __LINE__); return 1; } } while (0)
typedef struct
{
    pthread_t thread;
    uint32_t handle, cpu, failed, ready;
    unsigned *go;
    uint32_t *pixels;
    int close_result;
    bool closing;
} job_t;
typedef struct
{
    user_atk_window_desc_t description;
    user_atk_window_control_t control;
    user_atk_event_t event;
    job_t jobs[8], closers[2];
    uint32_t *pixels;
    uint32_t handle, sibling, go;
    int status;
    char number[32];
    char *arguments[4];
} fixture_t;
static int control(uint32_t handle, unsigned operation, user_atk_window_control_t *value)
{
    value->version = USER_ATK_CONTROL_VERSION; value->size = sizeof(*value); value->reserved = 0;
    return sys_ui_control(handle, operation, value);
}
static void *present_worker(void *pointer)
{
    job_t *job = pointer;
    if (sys_thread_set_affinity(job->cpu) || sys_thread_cpu() != job->cpu) job->failed = 1;
    __atomic_store_n(&job->ready, 1, __ATOMIC_RELEASE);
    while (!__atomic_load_n(job->go, __ATOMIC_ACQUIRE)) sys_yield();
    for (unsigned frame = 0; frame < 16; ++frame)
        if (sys_ui_present(job->handle, job->pixels, 400 * 240 * 4)) job->failed = 2;
    return NULL;
}
static void *close_worker(void *pointer)
{
    job_t *job = pointer;
    __atomic_store_n(&job->ready, 1, __ATOMIC_RELEASE);
    while (!__atomic_load_n(job->go, __ATOMIC_ACQUIRE)) sys_yield();
    job->close_result = sys_ui_close(job->handle);
    return NULL;
}
__attribute__((noinline)) void window_control_visual_checkpoint(void)
{
    __asm__ volatile ("" ::: "memory");
}
static int drain_events(fixture_t *test)
{
    int result;
    do { result = sys_ui_poll_event(test->handle, &test->event, 0); } while (result > 0);
    return result;
}
int main(int argc, char **argv)
{
    fixture_t *test = calloc(1, sizeof(*test));
    CHECK(test, "heap fixture");
    if (argc == 3 && !strcmp(argv[1], "foreign-window"))
    {
        CHECK(control((uint32_t)atoi(argv[2]), USER_ATK_CONTROL_QUERY, &test->control) == -EBADF,
              "child cannot use another process window handle");
        free(test);
        serial_printf("UI_CONTROL_TEST: OWNERSHIP PASS\n");
        return 0;
    }
    CHECK(control(0, USER_ATK_CONTROL_DISPLAY, &test->control) == 0 &&
          test->control.width >= 640 && test->control.height >= 480, "actual display dimensions");
    test->description.width = 320; test->description.height = 180;
    test->description.flags = USER_ATK_WINDOW_FLAG_HIDDEN | USER_ATK_WINDOW_FLAG_BORDERLESS |
                              USER_ATK_WINDOW_FLAG_RESIZABLE | USER_ATK_WINDOW_FLAG_RAW_KEYS;
    strcpy(test->description.title, "Alix window controls");
    int handle = sys_ui_create(&test->description);
    CHECK(handle > 0, "create hidden borderless native window"); test->handle = (uint32_t)handle;
    CHECK(control(test->handle, USER_ATK_CONTROL_QUERY, &test->control) == 0 &&
          test->control.width == 320 && test->control.height == 180 &&
          test->control.flags == USER_ATK_STATE_RESIZABLE, "hidden state and exact client dimensions");
    CHECK(control(test->handle, USER_ATK_CONTROL_FOCUS, &test->control) == -EINVAL, "hidden window cannot take focus");
    test->control.x = 64; test->control.y = 96; test->control.width = 320; test->control.height = 180;
    CHECK(!control(test->handle, USER_ATK_CONTROL_BOUNDS, &test->control) &&
          test->control.x == 64 && test->control.y == 96, "programmatic client bounds");
    test->control.flags = 1;
    CHECK(!control(test->handle, USER_ATK_CONTROL_CHROME, &test->control) &&
          test->control.width == 320 && test->control.height == 180 &&
          test->control.x == 64 && test->control.y == 96 && (test->control.flags & USER_ATK_STATE_CHROME),
          "decorations preserve client geometry");
    test->control.flags = 0;
    CHECK(!control(test->handle, USER_ATK_CONTROL_CHROME, &test->control) &&
          test->control.width == 320 && test->control.height == 180 &&
          test->control.x == 64 && test->control.y == 96, "borderless client geometry restored");
    strcpy(test->control.title, "Native Alix surface");
    CHECK(!control(test->handle, USER_ATK_CONTROL_TITLE, &test->control) &&
          !strcmp(test->control.title, "Native Alix surface"), "title update/readback");
    test->control.flags = 1;
    CHECK(!control(test->handle, USER_ATK_CONTROL_VISIBLE, &test->control) &&
          (test->control.flags & USER_ATK_STATE_VISIBLE), "show native window");
    CHECK(!drain_events(test) && !control(test->handle, USER_ATK_CONTROL_FOCUS, &test->control) &&
          (test->control.flags & USER_ATK_STATE_FOCUSED) &&
          sys_ui_poll_event(test->handle, &test->event, 0) == 1 &&
          test->event.type == USER_ATK_EVENT_FOCUS && test->event.data0 == 1, "focus event");
    test->control.flags = 0;
    CHECK(!control(test->handle, USER_ATK_CONTROL_VISIBLE, &test->control) &&
          !(test->control.flags & (USER_ATK_STATE_VISIBLE | USER_ATK_STATE_FOCUSED)) &&
          sys_ui_poll_event(test->handle, &test->event, 0) == 1 &&
          test->event.type == USER_ATK_EVENT_FOCUS && !test->event.data0, "hide removes focus and emits event");
    test->control.width = 0;
    CHECK(control(test->handle, USER_ATK_CONTROL_BOUNDS, &test->control) == -EINVAL &&
          !control(test->handle, USER_ATK_CONTROL_QUERY, &test->control) &&
          test->control.width == 320 && test->control.height == 180, "invalid bounds preserve surface");
    test->control.version = 2;
    CHECK(sys_ui_control(test->handle, USER_ATK_CONTROL_QUERY, &test->control) == -ENOTSUP &&
          sys_ui_control(test->handle, USER_ATK_CONTROL_QUERY, NULL) == -EFAULT, "version and pointer checks");
    CHECK(!control(test->handle, USER_ATK_CONTROL_QUERY, &test->control), "restore current protocol");
    user_atk_window_control_t *readonly = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                                               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(readonly != MAP_FAILED, "read-only control mapping");
    *readonly = test->control; strcpy(readonly->title, "Must not change title");
    CHECK(!mprotect(readonly, 4096, PROT_READ) &&
          sys_ui_control(test->handle, USER_ATK_CONTROL_TITLE, readonly) == -EFAULT &&
          !control(test->handle, USER_ATK_CONTROL_QUERY, &test->control) &&
          !strcmp(test->control.title, "Native Alix surface") && !munmap(readonly, 4096),
          "read-only reply rejected before mutation");
    test->control.flags = 1;
    CHECK(!control(test->handle, USER_ATK_CONTROL_VISIBLE, &test->control), "show for concurrent presentation");
    for (unsigned cpu = 0; cpu < 8; ++cpu)
    {
        job_t *job = &test->jobs[cpu]; job->handle = test->handle; job->cpu = cpu; job->go = &test->go;
        job->pixels = calloc(400 * 240, 4); CHECK(job->pixels, "worker surface");
        for (unsigned pixel = 0; pixel < 400 * 240; ++pixel) job->pixels[pixel] = 0xff203040u + (cpu << 16);
        CHECK(!pthread_create(&job->thread, NULL, present_worker, job), "presentation worker");
    }
    for (unsigned cpu = 0; cpu < 8; ++cpu)
        while (!__atomic_load_n(&test->jobs[cpu].ready, __ATOMIC_ACQUIRE)) sys_yield();
    __atomic_store_n(&test->go, 1, __ATOMIC_RELEASE);
    for (unsigned size = 0; size < 12; ++size)
    {
        test->control.x = 64 + (int)size; test->control.y = 96 + (int)size;
        test->control.width = 240 + size * 10; test->control.height = 160 + size * 4;
        CHECK(!control(test->handle, USER_ATK_CONTROL_BOUNDS, &test->control) &&
              test->control.width == 240 + size * 10, "resize while CPUs present");
    }
    for (unsigned cpu = 0; cpu < 8; ++cpu)
    {
        CHECK(!pthread_join(test->jobs[cpu].thread, NULL) && !test->jobs[cpu].failed, "all CPUs present through resize");
        free(test->jobs[cpu].pixels);
    }
    serial_printf("UI_CONTROL_TEST: SMP PASS cpus=8 presents=128 resize=12\n");
    snprintf(test->number, sizeof(test->number), "%u", test->handle);
    test->arguments[0] = "/tmp/test.elf"; test->arguments[1] = "foreign-window"; test->arguments[2] = test->number;
    pid_t child = alix_spawn_argv(test->arguments[0], test->arguments);
    CHECK(child > 0 && waitpid(child, &test->status, 0) == child && WIFEXITED(test->status) &&
          WEXITSTATUS(test->status) == 0, "cross-process handle isolation");
    test->control.x = 64; test->control.y = 96; test->control.width = 400; test->control.height = 240;
    CHECK(!control(test->handle, USER_ATK_CONTROL_BOUNDS, &test->control), "final visual bounds");
    test->pixels = calloc(400 * 240, 4); CHECK(test->pixels, "final surface");
    for (unsigned row = 0; row < 240; ++row)
        for (unsigned col = 0; col < 400; ++col) test->pixels[row * 400 + col] = col < 200 ? 0xffd03020u : 0xff2040c0u;
    CHECK(!sys_ui_present(test->handle, test->pixels, 400 * 240 * 4), "final visual present");
    test->description.width = 120; test->description.height = 100;
    handle = sys_ui_create(&test->description); CHECK(handle > 0, "second native window"); test->sibling = (uint32_t)handle;
    test->control.x = 600; test->control.y = 120; test->control.width = 120; test->control.height = 100;
    CHECK(!control(test->sibling, USER_ATK_CONTROL_BOUNDS, &test->control), "second window bounds");
    for (unsigned index = 0; index < 120 * 100; ++index) test->pixels[index] = 0xff20b040u;
    CHECK(!sys_ui_present(test->sibling, test->pixels, 120 * 100 * 4), "second visual present");
    test->control.flags = 1;
    CHECK(!control(test->sibling, USER_ATK_CONTROL_VISIBLE, &test->control) &&
          !control(test->handle, USER_ATK_CONTROL_FOCUS, &test->control), "show second window and focus first");
    CHECK(!drain_events(test), "drain before native key injection");
    sys_sleep_ms(250);
    window_control_visual_checkpoint();
    unsigned key_down = 0, key_up = 0;
    uint64_t key_deadline = sys_monotonic_millis() + 3000;
    while (sys_monotonic_millis() < key_deadline && !key_up)
    {
        int result = sys_ui_poll_event(test->handle, &test->event, 0);
        CHECK(result >= 0, "native key event read");
        if (!result) { sys_sleep_ms(1); continue; }
        if (test->event.type != USER_ATK_EVENT_KEY) continue;
        CHECK(test->event.data1 == 0x4b && !test->event.data0 &&
              (test->event.flags & USER_ATK_KEY_FLAG_EXTENDED), "raw arrow has no terminal escape text");
        if (test->event.flags & USER_ATK_KEY_FLAG_RELEASE) ++key_up;
        else ++key_down;
    }
    if (key_down != 1 || key_up != 1)
        serial_printf("UI_CONTROL_TEST: key counts down=%u up=%u\n", key_down, key_up);
    CHECK(key_down == 1 && key_up == 1, "one physical arrow press/release");
    sys_sleep_ms(50);
    CHECK(!sys_ui_poll_event(test->handle, &test->event, 0), "no escaped arrow suffix remains");
    serial_printf("UI_CONTROL_TEST: RAW_KEYS PASS arrow_down=1 arrow_up=1 ansi=0\n");
    test->description.width = 32; test->description.height = 32;
    handle = sys_ui_create(&test->description); CHECK(handle > 0, "concurrent close window");
    __atomic_store_n(&test->go, 0, __ATOMIC_RELEASE);
    for (unsigned index = 0; index < 2; ++index)
    {
        job_t *job = &test->closers[index]; job->handle = (uint32_t)handle; job->go = &test->go;
        CHECK(!pthread_create(&job->thread, NULL, close_worker, job), "close worker");
    }
    for (unsigned index = 0; index < 2; ++index)
        while (!__atomic_load_n(&test->closers[index].ready, __ATOMIC_ACQUIRE)) sys_yield();
    __atomic_store_n(&test->go, 1, __ATOMIC_RELEASE);
    for (unsigned index = 0; index < 2; ++index) CHECK(!pthread_join(test->closers[index].thread, NULL), "close join");
    CHECK((!test->closers[0].close_result || !test->closers[1].close_result) &&
          !control(test->sibling, USER_ATK_CONTROL_QUERY, &test->control) && test->control.width == 120,
          "concurrent close leaves sibling list intact");
    CHECK(!sys_ui_close(test->handle) && !sys_ui_close(test->sibling) &&
          control(test->handle, USER_ATK_CONTROL_QUERY, &test->control) == -EBADF, "closed handle invalidation");
    free(test->pixels); free(test);
    serial_printf("UI_CONTROL_TEST: PASS bounds=1 visibility=1 focus=1 title=1 chrome=1 cpus=8 ownership=1 close_race=1\n");
    return 0;
}
