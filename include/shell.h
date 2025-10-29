#ifndef SHELL_H
#define SHELL_H

#include "types.h"
#include "vfs.h"

typedef struct shell_output shell_output_t;
typedef struct shell_state shell_state_t;

struct shell_output
{
    bool to_file;
    vfs_node_t *file;
};

struct shell_state
{
    vfs_node_t *cwd;
};

void shell_main(void);

void shell_output_init_console(shell_output_t *out);
bool shell_output_write(shell_output_t *out, const char *text);
bool shell_output_write_len(shell_output_t *out, const char *text, size_t len);
void shell_print_error(const char *msg);

#endif
