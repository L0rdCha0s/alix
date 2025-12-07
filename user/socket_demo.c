#include "userlib.h"
#include "usyscall.h"
#include "stdio.h"

static void usage(void)
{
    const char msg[] =
        "usage: socket_demo <ipv4> <port> [iface] [path]\n"
        "       example: socket_demo 10.0.2.2 80 rtl0 /\n";
    write(1, msg, sizeof(msg) - 1);
}

static void build_http_request(char *out,
                               size_t out_cap,
                               const char *path,
                               const char *host)
{
    if (!out || out_cap == 0)
    {
        return;
    }
    if (!path || path[0] == '\0')
    {
        path = "/";
    }
    if (!host)
    {
        host = "unknown";
    }
    /* Minimal HTTP/1.0 request. */
    snprintf(out, out_cap, "GET %s HTTP/1.0\r\nHost: %s\r\nConnection: close\r\n\r\n", path, host);
}

int main(int argc, char **argv)
{
    if (argc < 3)
    {
        usage();
        return 1;
    }

    const char *ip_text = argv[1];
    const char *port_text = argv[2];
    const char *iface_name = (argc >= 4) ? argv[3] : NULL;
    const char *path = (argc >= 5) ? argv[4] : "/";

    int port = atoi(port_text);
    if (port <= 0 || port > 65535)
    {
        const char msg[] = "invalid port\n";
        write(1, msg, sizeof(msg) - 1);
        return 1;
    }

    int fd = socket_open(iface_name);
    if (fd < 0)
    {
        const char msg[] = "socket_open failed\n";
        write(1, msg, sizeof(msg) - 1);
        return 1;
    }

    if (socket_connect(fd, ip_text, (uint16_t)port) != 0)
    {
        const char msg[] = "socket_connect failed\n";
        write(1, msg, sizeof(msg) - 1);
        close(fd);
        return 1;
    }

    char request[256];
    build_http_request(request, sizeof(request), path, ip_text);
    ssize_t sent = write(fd, request, strlen(request));
    if (sent <= 0)
    {
        const char msg[] = "write failed\n";
        write(1, msg, sizeof(msg) - 1);
        close(fd);
        return 1;
    }

    char buffer[512];
    while (1)
    {
        ssize_t got = read(fd, buffer, sizeof(buffer));
        if (got < 0)
        {
            const char msg[] = "read error\n";
            write(1, msg, sizeof(msg) - 1);
            break;
        }
        if (got == 0)
        {
            break;
        }
        write(1, buffer, (size_t)got);
    }

    close(fd);
    return 0;
}
