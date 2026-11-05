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

`USER_ATK_CONTROL_WORK_AREA` also uses handle zero and reports the desktop
rectangle below the menu bar. Supplying `USER_ATK_STATE_CHROME` reserves native
window borders and the title bar as well, returning the client rectangle that
fits a maximized decorated window. Gecko uses the outer work area for its screen
service and the frame-adjusted client area when maximizing.

Focus and mouse capture boost the application's main thread, rather than all
of its workers. Background rendering/IPC threads keep their normal priority so
they cannot collectively starve the kernel I/O workers on which the UI waits.

Bounds accept positions within +/-1,048,576 pixels and requested client
dimensions from 1 to 16,384 pixels. The kernel clamps client sizes to the
desktop work area and top positions below the system bar, including native
frame borders. Actual accepted geometry is returned to the caller. Dragging
and resizing use the same top boundary. Actual allocation can fail with `-ENOMEM`.
Allocation/image-binding failure preserves the previous surface and geometry.
Changing decorations preserves client position and dimensions. Window titles
retain up to 4095 UTF-8 bytes; painting clips to the available title-bar space
before the close button. The original fixed-size control record remains
unchanged, including its 63-byte UTF-8-safe title preview on readback.

`sys_ui_set_title(handle, text, length)` uses the appended
`USER_ATK_CONTROL_TITLE_TEXT` opcode on syscall 73. Its input is raw UTF-8 bytes
excluding NUL, with a maximum length of 4095. An empty title is allowed;
embedded NULs, inaccessible input and foreign or closed handles are rejected.
The kernel copies input into owned heap storage before publication under the
ATK state lock. The Gecko adapter uses this path, with its earlier short-title
operation retained as a fallback for older kernels.

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
temporary ownership from caller abandonment. Presenters serialize per window and copy into the back surface under its pixel
lock, outside the global ATK state lock. Publication and resize retain the
ATK-state-then-pixel lock order: a front surface cannot be released between the
pointer swap and image binding. A surface generation prevents an old-sized
frame from being published after a concurrent resize. Concurrent closes unlink and release list
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

These earlier checks establish the Alix window boundary. The actual Gecko
adapter now compiles, links and displays the upstream browser chrome in Alix.
Native Zen now renders local content and executes interactive JavaScript;
remaining painting defects are recorded in docs/zen_port.md.

### Input idle time

`USER_ATK_CONTROL_INPUT_IDLE` is a handle-0 query using the existing 104-byte
control record. Flags and reserved fields must be zero. The `idle_milliseconds`
alias shares the width field's offset and returns time since keyboard activity
or a meaningful mouse packet, clamped to UINT32_MAX. Repeated zero-motion mouse
reports do not reset the timer. Recording uses an atomic maximum of monotonic
time, so input arriving on different CPUs cannot move the timestamp backward.
The query does not retain a user buffer or depend on a particular window.

Alix's Gecko idle-service provider uses this query for the standard
`@mozilla.org/widget/useridleservice;1` contract needed by session saving.
Fresh-profile execution of the new provider is the next runtime checkpoint.

### Optional event timing

`USER_ATK_POLL_FLAG_TIMED` on the existing nonblocking poll syscall selects the
40-byte `user_atk_timed_event_t` reply. Its first 24 bytes are the unchanged
legacy event; appended fields contain the monotonic enqueue time in milliseconds
and cumulative window-queue overflow count. TIMED cannot be combined with BLOCK.
`sys_ui_poll_timed_event` returns 1/event, 0/empty or negative errno.
`atk_user_poll_timed_event` additionally applies the normal surface resize path.
Empty replies still return the overflow count and otherwise contain zeroes.

Timestamps and overflow snapshots are read under the existing event lock.
Coalesced mouse motion and resize updates retain the oldest pending timestamp;
no per-event allocation or logging is added. The optional syscall reply is
heap-owned under the existing nonblocking preemption guard and checked user
copy. As with legacy poll, failed output copying may consume the dequeued event.
This measures queue residence after input routing, not hardware arrival or
display scanout. The native [performance app](../performance.md) exercises it.
