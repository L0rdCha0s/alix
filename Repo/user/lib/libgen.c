#include "libgen.h"
#include "string.h"

char *dirname(char *path)
{
    if (!path || !*path) return ".";
    size_t length = strlen(path);
    size_t root = path[0] == '/' ? 1 : 0;
    /* POSIX permits a distinct root for exactly two leading slashes. */
    if (length >= 2 && path[0] == '/' && path[1] == '/' && path[2] != '/') root = 2;
    size_t end = length;
    while (end > root && path[end - 1] == '/') --end;
    while (end > root && path[end - 1] != '/') --end;
    while (end > root && path[end - 1] == '/') --end;
    if (!end) return ".";
    path[end] = '\0';
    return path;
}

char *basename(char *path)
{
    if (!path || !*path) return ".";
    size_t end = strlen(path);
    while (end > 1 && path[end - 1] == '/') --end;
    path[end] = '\0';
    if (end == 1 && path[0] == '/') return path;
    size_t start = end;
    while (start && path[start - 1] != '/') --start;
    return path + start;
}
