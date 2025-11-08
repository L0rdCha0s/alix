#include "shell.h"

#include "vfs.h"
#include "libc.h"
#include "process.h"

static void free_tokens(char **tokens, size_t count)
{
    if (!tokens)
    {
        return;
    }
    for (size_t i = 0; i < count; ++i)
    {
        free(tokens[i]);
    }
    free(tokens);
}

static bool tokenize_arguments(const char *args, char ***tokens_out, size_t *count_out)
{
    if (!tokens_out || !count_out)
    {
        return false;
    }
    *tokens_out = NULL;
    *count_out = 0;

    const char *cursor = args ? args : "";
    size_t capacity = 0;
    char **tokens = NULL;
    size_t count = 0;

    while (*cursor)
    {
        while (*cursor == ' ' || *cursor == '\t')
        {
            ++cursor;
        }
        if (*cursor == '\0')
        {
            break;
        }

        const char *start = cursor;
        while (*cursor && *cursor != ' ' && *cursor != '\t')
        {
            ++cursor;
        }
        size_t len = (size_t)(cursor - start);
        char *token = (char *)malloc(len + 1);
        if (!token)
        {
            free_tokens(tokens, count);
            return false;
        }
        memcpy(token, start, len);
        token[len] = '\0';

        if (count >= capacity)
        {
            size_t new_capacity = (capacity == 0) ? 4 : capacity * 2;
            char **new_tokens = (char **)realloc(tokens, new_capacity * sizeof(char *));
            if (!new_tokens)
            {
                free(token);
                free_tokens(tokens, count);
                return false;
            }
            tokens = new_tokens;
            capacity = new_capacity;
        }
        tokens[count++] = token;
    }

    *tokens_out = tokens;
    *count_out = count;
    return true;
}

bool shell_cmd_runelf(shell_state_t *shell, shell_output_t *out, const char *args)
{
    char **tokens = NULL;
    size_t token_count = 0;
    if (!tokenize_arguments(args, &tokens, &token_count))
    {
        free_tokens(tokens, token_count);
        return shell_output_error(out, "runelf: failed to parse args");
    }
    if (token_count == 0)
    {
        free_tokens(tokens, token_count);
        return shell_output_error(out, "runelf: path required");
    }

    char *path = tokens[0];
    vfs_node_t *cwd = (shell && shell->cwd) ? shell->cwd : vfs_root();
    vfs_node_t *node = vfs_resolve(cwd, path);
    if (!node)
    {
        /* allow absolute paths even if cwd is NULL */
        node = vfs_resolve(vfs_root(), path);
    }

    if (!node || !vfs_is_file(node))
    {
        free_tokens(tokens, token_count);
        return shell_output_error(out, "runelf: file not found");
    }

    size_t size = 0;
    const char *data = vfs_data(node, &size);
    if (!data || size == 0)
    {
        free_tokens(tokens, token_count);
        return shell_output_error(out, "runelf: empty file");
    }

    process_t *proc = process_create_user_elf_with_parent(path,
                                                          (const uint8_t *)data,
                                                          size,
                                                          -1,
                                                          process_current(),
                                                          (const char *const *)tokens,
                                                          token_count);
    free_tokens(tokens, token_count);

    if (!proc)
    {
        return shell_output_error(out, "runelf: failed to start process");
    }

    process_join(proc, NULL);
    process_destroy(proc);
    return true;
}
