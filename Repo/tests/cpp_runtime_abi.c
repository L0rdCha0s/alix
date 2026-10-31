#include "types.h"
#include "timekeeping.h"
#include "user_atk_defs.h"
#include "atk_user.h"

/* Compile this translation unit as C: C++ must observe identical layouts. */
size_t cpp_runtime_c_abi_value(unsigned index)
{
    switch (index)
    {
        case 0: return sizeof(bool);
        case 1: return sizeof(timekeeping_timezone_spec_t);
        case 2: return __builtin_offsetof(timekeeping_timezone_spec_t, dst_enabled);
        case 3: return __builtin_offsetof(timekeeping_timezone_spec_t, dst_offset_minutes);
        case 4: return __builtin_offsetof(timekeeping_timezone_spec_t, use_zone);
        case 5: return __builtin_offsetof(timekeeping_timezone_spec_t, zone_name);
        case 6: return sizeof(atk_user_window_t);
        case 7: return __builtin_offsetof(atk_user_window_t, track_dirty);
        case 8: return sizeof(user_atk_event_t);
        case 9: return sizeof(user_atk_window_desc_t);
        default: return (size_t)-1;
    }
}
