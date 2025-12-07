#ifndef ATK_FILE_DIALOG_H
#define ATK_FILE_DIALOG_H

#include "atk/object.h"

typedef void (*atk_file_dialog_result_t)(atk_widget_t *requester,
                                         const char *path,
                                         bool confirmed,
                                         void *context);

atk_widget_t *atk_file_dialog_open(atk_widget_t *requester,
                                   const char *title,
                                   const char *initial_path,
                                   atk_file_dialog_result_t on_result,
                                   void *context);

#endif
