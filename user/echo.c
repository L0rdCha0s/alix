#include "libc.h"

int main(int argc, char **argv)
{
    if (argc <= 1)
    {
        write(1, "\n", 1);
        return 0;
    }

    for (int i = 1; i < argc; ++i)
    {
        const char *text = argv[i] ? argv[i] : "";
        size_t len = strlen(text);
        if (len > 0)
        {
            write(1, text, len);
        }
        if (i + 1 < argc)
        {
            write(1, " ", 1);
        }
    }
    write(1, "\n", 1);
    return 0;
}
