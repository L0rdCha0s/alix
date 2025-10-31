#include "atk_internal.h"

atk_state_t *atk_state_get(void)
{
    static atk_state_t state;
    return &state;
}
