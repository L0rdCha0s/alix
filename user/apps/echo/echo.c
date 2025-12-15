#include "userlib.h"

int main(int argc, char **argv)
{
    if (argc <= 1)
    {
        write(1, "\n", 1);
        return 0;
    }

    for (int i = 1; i < argc; ++i)
    {
        const char *arg = argv[i];
        size_t len = strlen(arg);
        if (len > 0)
        {
            write(1, arg, len);
        }
        if (i + 1 < argc)
        {
            write(1, " ", 1);
        }
    }
    write(1, "\n", 1);
    return 0;
}
