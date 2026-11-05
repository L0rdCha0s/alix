#include "shell_commands.h"

#include "video.h"
#include "mouse.h"
#include "console.h"
#include "serial.h"
#include "process.h"

bool shell_cmd_start_video(shell_state_t *shell, shell_output_t *out, const char *args)
{
    (void)shell;
    (void)args;

    thread_disable_context_guard(thread_current());
    serial_printf("%s", "Starting video mode...\r\n");
    video_init();
    mouse_register_listener(video_on_mouse_event);
    mouse_init();
    if (video_enter_mode())
    {
        serial_printf("%s", "Video mode active. Double-click to exit.\r\n");
        /* Run the input/composition loop on the reserved UI CPU instead of
         * competing with browser and storage work on its initial normal CPU.
         * Both priority changes occur outside the video and ATK locks. */
        process_t *compositor = process_current();
        process_set_main_thread_priority_override(compositor, true, THREAD_PRIORITY_UI);
        video_run_loop();
        process_set_main_thread_priority_override(compositor, false, THREAD_PRIORITY_NORMAL);
        video_exit_mode();
        console_clear();
        return true;
    }

    return shell_output_error(out, "video init failed");
}
