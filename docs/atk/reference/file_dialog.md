# File Dialog (`atk_file_dialog_*`)

Header: `include/atk/atk_file_dialog.h`

ATK provides simple modal dialogs for choosing a file path. The dialog is a window owned by ATK and returns its result via a callback.

## Key functions

- `atk_file_dialog_open(requester, title, initial_path, on_result, ctx)`
- `atk_file_dialog_save(requester, title, initial_path, on_result, ctx)`

## Result callback

`atk_file_dialog_result_t` receives:

- `requester` – the widget that opened the dialog
- `path` – chosen path (may be NULL/empty depending on cancel)
- `confirmed` – true on confirm, false on cancel
- `context` – user context pointer passed at open time

## Userland helper

For userland remote windows, `atk_app_open_file_dialog_modal()` and `atk_app_save_file_dialog_modal()` wrap dialog creation in a modal remote window and ensure an initial present.
