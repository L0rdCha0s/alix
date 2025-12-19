#include "browser_internal.h"

#include "stdio.h"
#include "stdlib.h"
#include "string.h"

static bool test_script_event_copies_src(void)
{
    const char *src = "https://example.com/app.js";
    const char *script_text = "console.log('ok');";
    size_t script_len = strlen(script_text);
    char *script = (char *)malloc(script_len + 1);
    if (!script)
    {
        return false;
    }
    memcpy(script, script_text, script_len + 1);

    browser_ui_event_t ev = {0};
    if (!browser_script_event_init(&ev, 1, src, script, script_len))
    {
        free(script);
        return false;
    }

    if (!ev.u.script_append.src)
    {
        free(ev.u.script_append.script);
        return false;
    }
    if (ev.u.script_append.src == src)
    {
        free(ev.u.script_append.src);
        free(ev.u.script_append.script);
        return false;
    }
    if (strcmp(ev.u.script_append.src, src) != 0)
    {
        free(ev.u.script_append.src);
        free(ev.u.script_append.script);
        return false;
    }
    if (ev.u.script_append.script != script)
    {
        free(ev.u.script_append.src);
        free(ev.u.script_append.script);
        return false;
    }

    free(ev.u.script_append.src);
    free(ev.u.script_append.script);
    return true;
}

int main(void)
{
    struct
    {
        const char *name;
        bool (*fn)(void);
    } tests[] = {
        { "script-event-copies-src", test_script_event_copies_src },
    };

    int failed = 0;
    for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); ++i)
    {
        if (!tests[i].fn())
        {
            fprintf(stderr, "FAIL: %s\n", tests[i].name);
            failed++;
        }
        else
        {
            fprintf(stdout, "ok: %s\n", tests[i].name);
        }
    }

    return failed == 0 ? 0 : 1;
}
