#ifndef SHELL_H
#define SHELL_H

#include "types.h"
#include "vfs.h"
#include "process.h"

typedef struct shell_output shell_output_t;
typedef struct shell_state shell_state_t;

struct shell_output
{
    bool to_file;
    vfs_node_t *file;
    bool to_buffer;
    char *buffer;
    size_t length;
    size_t capacity;
};

struct shell_state
{
    vfs_node_t *cwd;
    void (*stream_fn)(void *context, const char *data, size_t len);
    void *stream_context;
    int stdout_fd;
    process_t *foreground_process;
    process_wait_hook_t wait_hook;
    void *wait_context;
};

void shell_main(void);

void shell_output_init_console(shell_output_t *out);
void shell_output_init_buffer(shell_output_t *out);
bool shell_output_prepare_file(shell_output_t *out, vfs_node_t *file);
bool shell_output_write(shell_output_t *out, const char *text);
bool shell_output_write_len(shell_output_t *out, const char *text, size_t len);
void shell_print_error(const char *msg);
char *shell_output_take_buffer(shell_output_t *out);
void shell_output_reset(shell_output_t *out);

char *shell_execute_line(shell_state_t *shell, const char *line, bool *success);
bool shell_output_error(shell_output_t *out, const char *msg);
bool shell_request_interrupt(shell_state_t *shell);

#endif
