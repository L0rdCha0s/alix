#include "shell_commands.h"

#include "video.h"
#include "mouse.h"
#include "console.h"
#include "serial.h"


bool shell_cmd_start_video(shell_state_t *shell, shell_output_t *out, const char *args)
{
    (void)shell;
    (void)args;

    serial_write_string("Starting video mode...\r\n");
    video_init();
    mouse_register_listener(video_on_mouse_event);
    mouse_init();
    if (video_enter_mode())
    {
        serial_write_string("Video mode active. Double-click to exit.\r\n");
        video_run_loop();
        video_exit_mode();
        console_clear();
        return true;
    }

    return shell_output_error(out, "video init failed");
}
