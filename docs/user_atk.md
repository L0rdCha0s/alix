# Userland ATK Applications

This prototype introduces a path for running ATK-based applications in userland while keeping the kernel’s video/ATK pipeline in control of global state (window chrome, focus, mouse routing) and hardware access.

## Architecture

* The kernel hosts **remote ATK windows** (`user_atk_window_t`). Each remote window is a normal ATK window that owns an `atk_image` child. The image points at a pixel buffer that the user process updates via a syscall.
* New syscalls expose the functionality:
  * `SYSCALL_UI_CREATE` – create a remote window (`user_atk_window_desc_t`).
  * `SYSCALL_UI_PRESENT` – copy a RGB565 buffer from userland into the window image and request a refresh.
  * `SYSCALL_UI_POLL_EVENT` – fetch mouse/key/close events; supports blocking.
  * `SYSCALL_UI_CLOSE` – tear a remote window down.
* `user_atk.c` in the kernel bridges ATK’s event handling:
  * `atk_handle_mouse_event`/`atk_handle_key_char` now consult `user_atk_host` helpers. When a remote window sits under the cursor, global focus is updated, window dragging/title-bar operations remain kernel-managed, and a per-window event queue receives content-space events.
  * Mouse capture is honoured so drags continue even if the cursor leaves the window.
  * Closing a window via the title bar emits a `USER_ATK_EVENT_CLOSE` for the owning process.
* When a process exits, all of its remote windows are closed automatically.

## Userland Toolkit

* We compile the ATK sources for userland with `ATK_NO_DESKTOP_APPS` so shared code (window manager, widgets) is available without shell/task-manager dependencies. Rendering helpers (`video_*`) are provided by `user/video_surface.c`, which draws into a software buffer.
* `atk_user.c` wraps the UI syscalls. It owns the software surface, exposes `atk_user_window_open`, `atk_user_present`, `atk_user_wait_event`, and `atk_user_close`, and wires the surface into the ATK renderer.
* Because `video.h` was hard-coded, it now honours `VIDEO_WIDTH`/`VIDEO_HEIGHT` overrides. Userland builds set these constants (currently 640×360) so every ATK call uses the same logical surface size that the kernel remote window allocates.
* User apps render exactly like the kernel: they call `atk_render()` after ATK reports a redraw, then push the buffer via `atk_user_present`. Local widgets (text input, label, etc.) behave exactly as they do in kernel space because we instantiate a regular ATK window and slide it upward (negative Y) so the chrome is clipped before blitting into the remote frame.
* `atk_user_present()` now consults the software surface’s dirty bit and becomes a no-op when no pixels changed, eliminating redundant copies to the kernel. `atk_user_present_force()` is available when a client needs to push the buffer even if nothing was marked dirty (for example after resyncing window contents).

## Event Model

Global vs. local responsibilities are split:

* **Global**: window chrome, z-order, focus changes and capture continue to live in the kernel ATK state. Mouse presses on titles still drag windows, the desktop still receives clicks, etc.
* **Local**: content-space events (mouse within the client area, key presses when the remote window has focus, close notifications) are delivered to the user process via the new syscalls. The user process feeds them into its ATK state (`atk_handle_mouse_event`/`atk_handle_key_char`) and decides when to redraw.
* The kernel coalesces plain mouse-move events per window, so a client only sees the latest coordinates when the pointer is moving without new presses/releases. This keeps queues short and avoids starving UI threads when the pointer is jittery.

## Demo

`user/atk_demo.c` is a minimal userland GUI app:

1. Calls `atk_user_window_open` (title “ATK Demo”) to create a 640×360 remote window.
2. Initialises its own ATK state/theme, creates a single ATK window (Y shifted by `-ATK_WINDOW_TITLE_HEIGHT` so only the body is visible), adds a label + text input, and hooks the submit handler.
3. Runs an event loop that waits on `USER_ATK_EVENT_*`, passes mouse/key events into ATK, and redraws/presents whenever ATK sets the `redraw` flag.

The command `useratk` (wired into the shell) launches `/bin/atk_demo`, letting us exercise the full path end-to-end.

Two additional userland binaries are now available:

* `atkshell` launches a graphical shell window backed by the kernel’s shell session service.
* `taskmgr` opens the ATK Task Manager, showing process and network snapshots gathered via the new syscalls.
