/* A freestanding runtime prerequisite test, not a browser or a C++ stdlib. */
#include "userlib.h"
#include "atk_user.h"
#include "video_surface.h"
#include "stdlib.h"
#include "string.h"
#include "stdio.h"
#include "unistd.h"
#include "errno.h"
#include "setjmp.h"
#include "serial.h"

extern "C" size_t cpp_runtime_c_abi_value(unsigned index);

static unsigned sequence;
static bool failed;
static char *allocation;

static void expect_sequence(unsigned expected)
{
    if (sequence != expected)
    {
        failed = true;
    }
    ++sequence;
}

static void preinitialize()
{
    expect_sequence(0);
}

using runtime_hook = void (*)();
__attribute__((section(".preinit_array"), used))
static runtime_hook preinit_hook = preinitialize;

struct EarlyLifetime
{
    EarlyLifetime()
    {
        expect_sequence(1);
        allocation = static_cast<char *>(malloc(32));
        if (allocation)
        {
            memcpy(allocation, "constructed", sizeof("constructed"));
        }
        else
        {
            failed = true;
        }
    }

    ~EarlyLifetime()
    {
        expect_sequence(5);
        free(allocation);
        serial_printf("CPP_RUNTIME_TEST: fini %s\n", failed ? "FAIL" : "PASS");
        if (failed)
        {
            sys_exit(1);
        }
    }
};

struct LateLifetime
{
    LateLifetime() { expect_sequence(2); }
    ~LateLifetime() { expect_sequence(4); }
};

__attribute__((init_priority(200))) static EarlyLifetime early;
__attribute__((init_priority(300))) static LateLifetime late;

int main(int, char **)
{
    static_assert(sizeof(bool) == 1, "C and C++ must use one-byte booleans");
    expect_sequence(3);
    if (!allocation || strcmp(allocation, "constructed") != 0)
    {
        failed = true;
    }

    static const size_t cpp_abi[] = {
        sizeof(bool),
        sizeof(timekeeping_timezone_spec_t),
        __builtin_offsetof(timekeeping_timezone_spec_t, dst_enabled),
        __builtin_offsetof(timekeeping_timezone_spec_t, dst_offset_minutes),
        __builtin_offsetof(timekeeping_timezone_spec_t, use_zone),
        __builtin_offsetof(timekeeping_timezone_spec_t, zone_name),
        sizeof(atk_user_window_t),
        __builtin_offsetof(atk_user_window_t, track_dirty),
        sizeof(user_atk_event_t),
        sizeof(user_atk_window_desc_t),
    };
    for (unsigned i = 0; i < sizeof(cpp_abi) / sizeof(cpp_abi[0]); ++i)
    {
        if (cpp_runtime_c_abi_value(i) != cpp_abi[i])
        {
            failed = true;
        }
    }

    /* These calls prove unmangled linkage to the native C surface and syscall
     * layers without creating UI state. NULL must also be valid in C++. */
    atk_user_window_t *window = NULL;
    atk_user_close(window);
    (void)video_surface_tracking_enabled();
    (void)sys_time_millis();
    serial_printf("CPP_RUNTIME_TEST: main %s\n", failed ? "FAIL" : "PASS");
    return failed ? 1 : 0;
}
