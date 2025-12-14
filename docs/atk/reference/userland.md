# Userland ATK (Remote Windows)

Headers:

- `user/atk_user.h` – syscall wrapper + backbuffer ownership
- `user/atk_app.h` – standard event loop and modal helpers

## Remote window wrapper (`atk_user_*`)

- `atk_user_window_open*()` – creates a remote window, allocates a backbuffer, and attaches it as the active userland video surface.
- `atk_user_enable_dirty_tracking()` – enables the software surface dirty bit so `atk_user_present()` can skip uploads when nothing changed.
- `atk_user_present()` / `atk_user_present_force()` – push the buffer to the kernel window (forced present ignores the dirty bit).
- `atk_user_wait_event()` / `atk_user_poll_event()` – receive `USER_ATK_EVENT_*` events (resize events resize the buffer automatically).
- `atk_user_close()` – closes the kernel window and frees the buffer.

## Standard loop (`atk_main`)

`atk_main()` drives a typical UI loop:

- drains events from the active remote window,
- dispatches mouse/key into ATK (default path),
- runs optional registered handlers (`atk_main_register_*_handler()`),
- calls an optional tick function,
- renders/presents when ATK marks the state dirty.

## Modals

- `atk_modal_begin()` / `atk_modal_end()` create a new remote window, push it on an internal stack, and optionally “suspend” an underlying ATK window widget while a modal is open.
- `atk_app_open_file_dialog_modal()` / `atk_app_save_file_dialog_modal()` are convenience wrappers around modals + `atk_file_dialog_*()`.
