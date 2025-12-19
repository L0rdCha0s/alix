#include "browser_internal.h"

#include "string.h"

bool browser_script_event_init(browser_ui_event_t *ev,
                               uint64_t load_id,
                               const char *src,
                               char *script,
                               size_t len)
{
    if (!ev || !script || len == 0)
    {
        return false;
    }

    memset(ev, 0, sizeof(*ev));
    ev->type = BROWSER_UI_EVENT_SCRIPT_APPEND;
    ev->load_id = load_id;
    ev->u.script_append.script = script;
    ev->u.script_append.len = len;

    if (src && src[0] != '\0')
    {
        ev->u.script_append.src = browser_strdup(src);
    }

    return true;
}
