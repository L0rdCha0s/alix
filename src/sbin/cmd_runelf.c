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

static bool shell_exec_error(shell_output_t *out, const char *label, const char *message)
{
    char buffer[128];
    size_t pos = 0;
    if (label && *label)
    {
        size_t len = strlen(label);
        if (len > sizeof(buffer) - 1)
        {
            len = sizeof(buffer) - 1;
        }
        memcpy(buffer + pos, label, len);
        pos += len;
        if (pos < sizeof(buffer) - 1)
        {
            buffer[pos++] = ':';
        }
        if (pos < sizeof(buffer) - 1)
        {
            buffer[pos++] = ' ';
        }
    }
    size_t msg_len = strlen(message);
    if (msg_len > sizeof(buffer) - 1 - pos)
    {
        msg_len = sizeof(buffer) - 1 - pos;
    }
    memcpy(buffer + pos, message, msg_len);
    pos += msg_len;
    buffer[pos] = '\0';
    return shell_output_error(out, buffer);
}

bool shell_execute_binary(shell_state_t *shell,
                          shell_output_t *out,
                          const char *path,
                          const char *args,
                          const char *label)
{
    if (!path || *path == '\0')
    {
        return shell_exec_error(out, label ? label : "exec", "path required");
    }

    size_t path_len = strlen(path);
    size_t args_len = args ? strlen(args) : 0;
    size_t combined_len = path_len + (args_len ? (1 + args_len) : 0);
    char *combined = (char *)malloc(combined_len + 1);
    if (!combined)
    {
        return shell_exec_error(out, label ? label : "exec", "out of memory");
    }
    memcpy(combined, path, path_len);
    if (args_len)
    {
        combined[path_len] = ' ';
        memcpy(combined + path_len + 1, args, args_len);
        combined[combined_len] = '\0';
    }
    else
    {
        combined[path_len] = '\0';
    }

    char **tokens = NULL;
    size_t token_count = 0;
    bool parsed = tokenize_arguments(combined, &tokens, &token_count);
    free(combined);
    if (!parsed || token_count == 0)
    {
        free_tokens(tokens, token_count);
        return shell_exec_error(out, label ? label : "exec", "failed to parse args");
    }

    char *exec_path = tokens[0];
    vfs_node_t *cwd = (shell && shell->cwd) ? shell->cwd : vfs_root();
    vfs_node_t *node = vfs_resolve(cwd, exec_path);
    if (!node)
    {
        node = vfs_resolve(vfs_root(), exec_path);
    }

    if (!node || !vfs_is_file(node))
    {
        free_tokens(tokens, token_count);
        return shell_exec_error(out, label ? label : exec_path, "file not found");
    }

    size_t size = 0;
    const char *data = vfs_data(node, &size);
    if (!data || size == 0)
    {
        free_tokens(tokens, token_count);
        return shell_exec_error(out, label ? label : exec_path, "empty file");
    }

    process_t *proc = process_create_user_elf_with_parent(exec_path,
                                                          (const uint8_t *)data,
                                                          size,
                                                          -1,
                                                          process_current(),
                                                          (const char *const *)tokens,
                                                          token_count);
    free_tokens(tokens, token_count);

    if (!proc)
    {
        return shell_exec_error(out, label ? label : exec_path, "failed to start process");
    }

    process_join(proc, NULL);
    process_destroy(proc);
    return true;
}

bool shell_cmd_runelf(shell_state_t *shell, shell_output_t *out, const char *args)
{
    const char *cursor = args ? args : "";
    while (*cursor == ' ' || *cursor == '\t')
    {
        ++cursor;
    }
    if (*cursor == '\0')
    {
        return shell_output_error(out, "runelf: path required");
    }

    const char *start = cursor;
    while (*cursor && *cursor != ' ' && *cursor != '\t')
    {
        ++cursor;
    }
    size_t len = (size_t)(cursor - start);
    char *path = (char *)malloc(len + 1);
    if (!path)
    {
        return shell_output_error(out, "runelf: out of memory");
    }
    memcpy(path, start, len);
    path[len] = '\0';

    while (*cursor == ' ' || *cursor == '\t')
    {
        ++cursor;
    }

    bool ok = shell_execute_binary(shell, out, path, cursor, "runelf");
    free(path);
    return ok;
}
