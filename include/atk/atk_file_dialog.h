#ifndef ATK_FILE_DIALOG_H
#define ATK_FILE_DIALOG_H

#include "atk/object.h"

typedef void (*atk_file_dialog_result_t)(atk_widget_t *requester,
                                         const char *path,
                                         bool confirmed,
                                         void *context);

typedef enum
{
    ATK_FILE_DIALOG_MODE_OPEN = 0,
    ATK_FILE_DIALOG_MODE_SAVE = 1,
} atk_file_dialog_mode_t;

/*
 * Open a modal file-open dialog owned by `requester`.
 *
 * - `title` is shown in the dialog chrome.
 * - `initial_path` selects the starting directory (may be NULL/empty).
 * - `on_result` is invoked when the user confirms/cancels.
 *
 * Returns the dialog window widget (owned by ATK) or NULL on failure.
 */
atk_widget_t *atk_file_dialog_open(atk_widget_t *requester,
                                   const char *title,
                                   const char *initial_path,
                                   atk_file_dialog_result_t on_result,
                                   void *context);

/*
 * Open a modal file-save dialog owned by `requester`.
 *
 * The result callback receives the chosen path when confirmed.
 */
atk_widget_t *atk_file_dialog_save(atk_widget_t *requester,
                                   const char *title,
                                   const char *initial_path,
                                   atk_file_dialog_result_t on_result,
                                   void *context);

#endif
