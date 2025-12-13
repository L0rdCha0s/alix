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

atk_widget_t *atk_file_dialog_open(atk_widget_t *requester,
                                   const char *title,
                                   const char *initial_path,
                                   atk_file_dialog_result_t on_result,
                                   void *context);

atk_widget_t *atk_file_dialog_save(atk_widget_t *requester,
                                   const char *title,
                                   const char *initial_path,
                                   atk_file_dialog_result_t on_result,
                                   void *context);

#endif
