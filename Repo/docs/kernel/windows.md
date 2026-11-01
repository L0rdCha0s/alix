# Native user window controls

The kernel window manager accepts software surfaces from any native renderer.
Gecko does not need Alix's HTML/CSS/JavaScript implementation or user ATK widgets
to use these interfaces. Pixels are 32-bit `0xFFRRGGBB` (BGRA in x86 memory).
Each window has its own kernel-owned front/back surfaces and event queue.

`sys_ui_control(handle, operation, control)` uses appended syscall 73 and a
versioned, 104-byte `user_atk_window_control_t`. Every successful operation
returns actual state, including the client origin in screen pixels, client
dimensions, title, physical screen dimensions and visible/focused/frame flags.
Operations query a window, set client bounds, show/hide, take focus, set its
title and select decorations. `USER_ATK_CONTROL_DISPLAY` requires handle zero
and returns the physical display dimensions. Unsupported versions return
`-ENOTSUP`; malformed requests, inaccessible buffers and foreign/closed handles
return negative errno values. The low-level syscall wrappers return those
values directly.

Bounds allow off-screen positions within +/-1,048,576 pixels and client
dimensions from 1 to 16,384 pixels. Actual allocation can fail with `-ENOMEM`.
Allocation/image-binding failure preserves the previous surface and geometry.
Changing decorations preserves client position and dimensions. Titles use the
existing bounded kernel title storage and readback reports any truncation.

Creation adds `USER_ATK_WINDOW_FLAG_HIDDEN` and
`USER_ATK_WINDOW_FLAG_BORDERLESS`; existing creation flags and wire layouts are
preserved. `USER_ATK_WINDOW_FLAG_RAW_KEYS` requests physical navigation events
instead of the terminal ANSI sequences used by legacy remote-window clients. Hidden windows retain their handle, list membership and surfaces.
They do not paint, mask the background or receive hit tests, and hiding releases
focus, capture and active window drag/resize state. A focus request on a hidden
window fails. Focus changes enqueue `USER_ATK_EVENT_FOCUS` with `data0` equal to
one or zero; programmatic client moves enqueue `USER_ATK_EVENT_MOVE` with screen
coordinates. Existing resize events report committed client dimensions.

Create, control, present, close, capture and nonblocking event polling protect
temporary ownership from caller abandonment. Presentation and resize use the
same ATK-state-then-pixel lock order: a front surface cannot be released between
the pointer swap and image binding. Concurrent closes unlink and release list
ownership once, preserving sibling windows. Handles are owned by the creating
process; inheriting the integer through argv does not grant another process
access. Existing legacy blocking UI waits retain their previous implementation.

Run `make`, then `make zen-window-control-qemu-test`. The disposable graphical
guest receives the current kernel, loader, terminal and fixture. It exercises
window state, read-only control buffers, eight CPU-pinned presenters racing
twelve resizes, process ownership and concurrent close. A hardware breakpoint
captures the actual compositor after presentation; three exact pixel probes
verify two independent surfaces. Evidence is saved as
`build/test-out/window-control-native-qemu.log`,
`window-control-native.ppm`, `window-control-native.png` and the adjacent JSON
analysis. The production host contracts additionally pass ASan/UBSan and TSan
for rollback, state, surface concurrency and idempotent close.
The existing MP3 GUI also passes a fresh 20-second continuous-tone capture plus
restart, pause/resume, seek and clean close after the surface-locking change;
see `build/test-out/audio-widget-controls-paced-long/result.json`.

These checks establish the Alix window boundary. The Gecko widget/event-loop
adapter is now selected and full configuration succeeds; compilation and runtime
validation of that adapter and the complete browser remain unfinished.
