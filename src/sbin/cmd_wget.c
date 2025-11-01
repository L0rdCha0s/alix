#include "shell_commands.h"

#include <stddef.h>
#include <stdint.h>

#include "net/arp.h"
#include "net/interface.h"
#include "net/route.h"
#include "net/dns.h"
#include "net/tcp.h"
#include "net/tls.h"
#include "rtl8139.h"
#include "timer.h"
#include "vfs.h"
#include "libc.h"

#define WGET_HEADER_CAP 2048
#define WGET_CHUNK_SIZE 512

static const char *skip_ws(const char *cursor);
static bool read_token(const char **cursor, char *out, size_t capacity);
static bool parse_host_and_port(const char *text, char *host_out, size_t host_cap, uint16_t *port_out);
static bool parse_decimal_u16(const char *text, uint16_t *out);
static bool parse_decimal_size(const char *text, size_t *out);
static const char *find_substring(const char *haystack, const char *needle);
static bool find_header_value(const char *headers, const char *name_lower,
                              char *value_out, size_t capacity);
static bool parse_http_status(const char *headers, int *status_out);

static bool ensure_arp(net_interface_t *iface, uint32_t next_hop_ip, uint64_t timeout_ticks);
static bool append_body_chunk(vfs_node_t *file, const uint8_t *data, size_t len,
                              size_t *written, bool have_length, size_t expected_length,
                              shell_output_t *out);
static bool format_decimal(char *buf, size_t cap, unsigned value, size_t *out_len);


// --- chunked decoding helpers ---

typedef enum
{
    CHUNK_READ_SIZE = 0,
    CHUNK_READ_DATA,
    CHUNK_READ_DATA_CR,
    CHUNK_READ_DATA_LF,
    CHUNK_READ_TRAILERS,
    CHUNK_DONE
} chunk_parse_state_t;

typedef struct
{
    chunk_parse_state_t state;
    size_t current_size;      // size of the current chunk
    size_t remaining;         // bytes remaining to write for current chunk
    char   linebuf[64];       // accumulates the "<hex>[;ext]*" size line (no CRLF)
    size_t line_len;          // bytes in linebuf
    int    trailer_stage;     // 0,1,2,3 progressing toward CRLFCRLF
} chunked_state_t;

static void chunked_init(chunked_state_t *st)
{
    st->state = CHUNK_READ_SIZE;
    st->current_size = 0;
    st->remaining = 0;
    st->line_len = 0;
    st->trailer_stage = 0;
}

static bool parse_chunk_size_line(const char *line, size_t len, size_t *out)
{
    // Parse hex number up to ';' (ignore chunk extensions)
    size_t val = 0;
    bool saw_digit = false;
    for (size_t i = 0; i < len; ++i)
    {
        char c = line[i];
        if (c == ';' || c == ' ' || c == '\t') break;

        unsigned d;
        if (c >= '0' && c <= '9') d = (unsigned)(c - '0');
        else if (c >= 'a' && c <= 'f') d = 10u + (unsigned)(c - 'a');
        else if (c >= 'A' && c <= 'F') d = 10u + (unsigned)(c - 'A');
        else return false;

        saw_digit = true;
        if (val > (SIZE_MAX - d) / 16) return false; // overflow guard
        val = (val << 4) | d;
    }
    if (!saw_digit) return false;
    *out = val;
    return true;
}

// Feed bytes into the chunked decoder. Writes body to `file`.
// Sets *done=true when the final chunk + trailers complete.
static bool chunked_consume(chunked_state_t *st,
                            vfs_node_t *file,
                            const uint8_t *data, size_t len,
                            size_t *written,
                            shell_output_t *out,
                            bool *done)
{
    size_t pos = 0;
    *done = false;

    while (pos < len && st->state != CHUNK_DONE)
    {
        switch (st->state)
        {
        case CHUNK_READ_SIZE:
        {
            // accumulate until CRLF
            char b = (char)data[pos++];
            if (st->line_len >= sizeof(st->linebuf))
            {
                shell_output_error(out, "chunk-size line too long");
                return false;
            }
            st->linebuf[st->line_len++] = b;

            if (st->line_len >= 2 &&
                st->linebuf[st->line_len - 2] == '\r' &&
                st->linebuf[st->line_len - 1] == '\n')
            {
                // parse without the trailing CRLF
                size_t linelen = st->line_len - 2;
                if (!parse_chunk_size_line(st->linebuf, linelen, &st->current_size))
                {
                    shell_output_error(out, "invalid chunk-size");
                    return false;
                }
                st->line_len = 0;

                st->remaining = st->current_size;
                if (st->current_size == 0)
                {
                    st->state = CHUNK_READ_TRAILERS; // next: trailers then end
                    st->trailer_stage = 0;
                }
                else
                {
                    st->state = CHUNK_READ_DATA;
                }
            }
            break;
        }

        case CHUNK_READ_DATA:
        {
            size_t avail = len - pos;
            size_t take = (st->remaining < avail) ? st->remaining : avail;
            if (take > 0)
            {
                if (!vfs_append(file, (const char *)data + pos, take))
                {
                    shell_output_error(out, "failed to write to file");
                    return false;
                }
                pos += take;
                st->remaining -= take;
                *written += take;
            }
            if (st->remaining == 0)
            {
                st->state = CHUNK_READ_DATA_CR; // expect "\r\n" after data
            }
            break;
        }

        case CHUNK_READ_DATA_CR:
            if (pos >= len) return true; // need more data
            if (data[pos++] != '\r')
            {
                shell_output_error(out, "malformed chunk: missing CR");
                return false;
            }
            st->state = CHUNK_READ_DATA_LF;
            break;

        case CHUNK_READ_DATA_LF:
            if (pos >= len) return true; // need more data
            if (data[pos++] != '\n')
            {
                shell_output_error(out, "malformed chunk: missing LF");
                return false;
            }
            st->state = CHUNK_READ_SIZE; // next chunk
            break;

        case CHUNK_READ_TRAILERS:
        {
            // look for CRLFCRLF
            char c = (char)data[pos++];
            switch (st->trailer_stage)
            {
            case 0: st->trailer_stage = (c == '\r') ? 1 : 0; break;
            case 1: st->trailer_stage = (c == '\n') ? 2 : (c == '\r' ? 1 : 0); break;
            case 2: st->trailer_stage = (c == '\r') ? 3 : 0; break;
            case 3:
                if (c == '\n')
                {
                    st->state = CHUNK_DONE;
                    *done = true;
                }
                else
                {
                    st->trailer_stage = 0;
                }
                break;
            }
            break;
        }

        case CHUNK_DONE:
            *done = true;
            break;
        }
    }

    return true;
}

bool shell_cmd_wget(shell_state_t *shell, shell_output_t *out, const char *args)
{
    const char *cursor = args ? args : "";
    char t1[128];
    char t2[256];
    char t3[256];
    char t4[128];
    bool have_iface = false;

    if (!read_token(&cursor, t1, sizeof(t1)) ||
        !read_token(&cursor, t2, sizeof(t2)) ||
        !read_token(&cursor, t3, sizeof(t3)))
    {
        return shell_output_error(out, "Usage: wget [iface] <host[:port]> <path> <dest>");
    }

    bool have_fourth = read_token(&cursor, t4, sizeof(t4));
    cursor = skip_ws(cursor);
    if (*cursor != '\0')
    {
        return shell_output_error(out, "Usage: wget [iface] <host[:port]> <path> <dest>");
    }

    char iface_name[NET_IF_NAME_MAX];
    char host_token[128];
    char path_token[256];
    char dest_token[128];

    if (have_fourth)
    {
        have_iface = true;
        memcpy(iface_name, t1, strlen(t1) + 1);
        memcpy(host_token, t2, strlen(t2) + 1);
        memcpy(path_token, t3, strlen(t3) + 1);
        memcpy(dest_token, t4, strlen(t4) + 1);
    }
    else
    {
        have_iface = false;
        memcpy(host_token, t1, strlen(t1) + 1);
        memcpy(path_token, t2, strlen(t2) + 1);
        memcpy(dest_token, t3, strlen(t3) + 1);
    }

    if (path_token[0] == '\0' || dest_token[0] == '\0')
    {
        return shell_output_error(out, "path and destination must be non-empty");
    }

    net_interface_t *iface = NULL;
    if (have_iface)
    {
        iface = net_if_by_name(iface_name);
        if (!iface || !iface->present)
        {
            return shell_output_error(out, "interface not found");
        }
    }

    char host_name[128];
    uint16_t remote_port = 80;
    bool use_tls = false;
    if (!parse_host_and_port(host_token, host_name, sizeof(host_name), &remote_port))
    {
        return shell_output_error(out, "invalid host or port");
    }

    uint32_t remote_ip = 0;
    if (!net_parse_ipv4(host_name, &remote_ip))
    {
        shell_output_write(out, "Resolving ");
        shell_output_write(out, host_name);
        shell_output_write(out, "...\n");
        if (!net_dns_resolve_ipv4(host_name, iface, &remote_ip))
        {
            return shell_output_error(out, "DNS resolution failed");
        }
    }

    uint32_t next_hop_ip = remote_ip;
    if (!net_route_next_hop(iface, remote_ip, &iface, &next_hop_ip))
    {
        return shell_output_error(out, "no route to host");
    }
    if (!iface || !iface->present || !iface->link_up || iface->ipv4_addr == 0)
    {
        return shell_output_error(out, "no usable interface");
    }

    uint32_t frequency = timer_frequency();
    if (frequency == 0)
    {
        frequency = 100;
    }
    uint64_t arp_timeout = (uint64_t)frequency * 3;
    uint64_t connect_timeout = (uint64_t)frequency * 5;
    uint64_t data_timeout = (uint64_t)frequency * 10;

    if (!ensure_arp(iface, next_hop_ip, arp_timeout))
    {
        return shell_output_error(out, "ARP resolution failed");
    }

    use_tls = (remote_port == 443);

    net_tcp_socket_t *socket = net_tcp_socket_open(iface);
    if (!socket)
    {
        return shell_output_error(out, "no TCP sockets available");
    }

    bool success = false;
    bool request_sent = false;
    bool tls_active = false;
    tls_session_t tls_session;
    vfs_node_t *file = NULL;
    size_t written = 0;

    char request_path[256];
    if (path_token[0] == '/')
    {
        memcpy(request_path, path_token, strlen(path_token) + 1);
    }
    else
    {
        size_t len = strlen(path_token);
        if (len + 1 >= sizeof(request_path))
        {
            shell_output_error(out, "path too long");
            goto cleanup;
        }
        request_path[0] = '/';
        memcpy(request_path + 1, path_token, len + 1);
    }

    if (!net_tcp_socket_connect(socket, remote_ip, remote_port))
    {
        shell_output_error(out, "failed to initiate TCP connection");
        goto cleanup;
    }

    shell_output_write(out, "Connecting...\n");

    uint64_t start = timer_ticks();
    while (!net_tcp_socket_is_established(socket))
    {
        if (net_tcp_socket_has_error(socket))
        {
            shell_output_error(out, "TCP handshake failed");
            goto cleanup;
        }
        if (timer_ticks() - start >= connect_timeout)
        {
            shell_output_error(out, "TCP connect timeout");
            goto cleanup;
        }
        rtl8139_poll();
    }

    if (use_tls)
    {
        if (!tls_session_init(&tls_session, socket))
        {
            shell_output_error(out, "TLS session init failed");
            goto cleanup;
        }
        shell_output_write(out, "Negotiating TLS...\n");
        if (!tls_session_handshake(&tls_session, host_name))
        {
            shell_output_error(out, "TLS handshake failed");
            goto cleanup;
        }
        tls_active = true;
    }

    file = vfs_open_file(shell->cwd, dest_token, true, true);
    if (!file)
    {
        shell_output_error(out, "could not open destination file");
        goto cleanup;
    }
    vfs_truncate(file);

    char host_header[160];
    size_t host_len = strlen(host_name);
    if (host_len == 0 || host_len >= sizeof(host_header))
    {
        shell_output_error(out, "host name too long");
        goto cleanup;
    }
    memcpy(host_header, host_name, host_len);
    if (remote_port != 80)
    {
        if (host_len + 1 >= sizeof(host_header))
        {
            shell_output_error(out, "host header too long");
            goto cleanup;
        }
        host_header[host_len++] = ':';
        size_t port_len = 0;
        if (!format_decimal(host_header + host_len, sizeof(host_header) - host_len, remote_port, &port_len))
        {
            shell_output_error(out, "port formatting failed");
            goto cleanup;
        }
        host_len += port_len;
    }
    host_header[host_len] = '\0';

    char request[512];
    size_t req_len = 0;
    const char *line;

    line = "GET ";
    memcpy(request + req_len, line, strlen(line));
    req_len += strlen(line);
    size_t path_len = strlen(request_path);
    if (req_len + path_len + 64 >= sizeof(request))
    {
        shell_output_error(out, "request too long");
        goto cleanup;
    }
    memcpy(request + req_len, request_path, path_len);
    req_len += path_len;
    line = " HTTP/1.1\r\nHost: ";
    memcpy(request + req_len, line, strlen(line));
    req_len += strlen(line);
    memcpy(request + req_len, host_header, host_len);
    req_len += host_len;
    line = "\r\nUser-Agent: alix-wget/0.1\r\nConnection: close\r\nAccept: */*\r\n\r\n";
    memcpy(request + req_len, line, strlen(line));
    req_len += strlen(line);

    if (tls_active)
    {
        if (!tls_session_send(&tls_session, (const uint8_t *)request, req_len))
        {
            shell_output_error(out, "failed to send HTTPS request");
            goto cleanup;
        }
    }
    else
    {
        if (!net_tcp_socket_send(socket, (const uint8_t *)request, req_len))
        {
            shell_output_error(out, "failed to send HTTP request");
            goto cleanup;
        }
    }
    request_sent = true;
    shell_output_write(out, "Request sent, awaiting response...\n");

    char header_buf[WGET_HEADER_CAP];
    size_t header_len = 0;
    bool header_done = false;
    bool header_parsed = false;
    bool have_length = false;
    size_t content_length = 0;
    bool is_chunked = false;
    chunked_state_t cstate;
    bool chunked_done = false;
    uint64_t last_progress = timer_ticks();

    uint8_t chunk[WGET_CHUNK_SIZE];

    while (1)
    {
        rtl8139_poll();

        if (net_tcp_socket_has_error(socket))
        {
            shell_output_error(out, "TCP connection error");
            goto cleanup;
        }

        size_t read = 0;
        if (tls_active)
        {
            read = tls_session_recv(&tls_session, chunk, sizeof(chunk));
            if (read == 0)
            {
                if (net_tcp_socket_remote_closed(socket))
                {
                    // If chunked and not finished, it's an error
                    if (is_chunked && !chunked_done)
                    {
                        shell_output_error(out, "connection closed before complete chunked body");
                        goto cleanup;
                    }
                    if (have_length && written < content_length)
                    {
                        shell_output_error(out, "connection closed before full body");
                        goto cleanup;
                    }
                    break;
                }

                if (timer_ticks() - last_progress >= data_timeout)
                {
                    shell_output_error(out, "no data received (timeout)");
                    goto cleanup;
                }
                continue;
            }
        }
        else
        {
            size_t available = net_tcp_socket_available(socket);
            if (available == 0)
            {
                if (net_tcp_socket_remote_closed(socket))
                {
                    if (is_chunked && !chunked_done)
                    {
                        shell_output_error(out, "connection closed before complete chunked body");
                        goto cleanup;
                    }
                    if (have_length && written < content_length)
                    {
                        shell_output_error(out, "connection closed before full body");
                        goto cleanup;
                    }
                    break;
                }

                if (timer_ticks() - last_progress >= data_timeout)
                {
                    shell_output_error(out, "no data received (timeout)");
                    goto cleanup;
                }
                continue;
            }

            size_t to_read = available < sizeof(chunk) ? available : sizeof(chunk);
            read = net_tcp_socket_read(socket, chunk, to_read);
            if (read == 0)
            {
                continue;
            }
        }
        last_progress = timer_ticks();

        size_t offset = 0;
        if (!header_done)
        {
            while (!header_done && offset < read)
            {
                if (header_len >= sizeof(header_buf) - 1)
                {
                    shell_output_error(out, "HTTP headers too large");
                    goto cleanup;
                }
                header_buf[header_len++] = (char)chunk[offset++];
                if (header_len >= 4 &&
                    header_buf[header_len - 4] == '\r' &&
                    header_buf[header_len - 3] == '\n' &&
                    header_buf[header_len - 2] == '\r' &&
                    header_buf[header_len - 1] == '\n')
                {
                    header_done = true;
                    header_len -= 4;
                    header_buf[header_len] = '\0';
                    break;
                }
            }

            if (header_done && !header_parsed)
            {
                int status_code = 0;
                if (!parse_http_status(header_buf, &status_code))
                {
                    shell_output_error(out, "invalid HTTP status line");
                    goto cleanup;
                }
                if (status_code != 200)
                {
                    shell_output_write(out, "HTTP status ");
                    char code_str[4];
                    code_str[0] = (char)('0' + (status_code / 100) % 10);
                    code_str[1] = (char)('0' + (status_code / 10) % 10);
                    code_str[2] = (char)('0' + status_code % 10);
                    code_str[3] = '\0';
                    shell_output_write(out, code_str);
                    shell_output_write(out, " received\n");
                    shell_output_error(out, "wget aborted");
                    goto cleanup;
                }

                char value[64];
                if (find_header_value(header_buf, "transfer-encoding", value, sizeof(value)))
                {
                    for (size_t i = 0; value[i]; ++i)
                    {
                        char c = value[i];
                        if (c >= 'A' && c <= 'Z') value[i] = (char)(c + 32);
                    }
                    if (find_substring(value, "chunked"))
                    {
                        is_chunked = true;
                        have_length = false; // TE: chunked takes precedence over Content-Length
                        chunked_init(&cstate);
                    }
                }

                if (!is_chunked && find_header_value(header_buf, "content-length", value, sizeof(value)))
                {
                    if (!parse_decimal_size(value, &content_length))
                    {
                        shell_output_error(out, "invalid Content-Length");
                        goto cleanup;
                    }
                    have_length = true;
                }

                header_parsed = true;
            }
        }

        if (!header_done)
        {
            continue;
        }

        size_t body_offset = offset;
        if (read > body_offset)
        {
            size_t body_len = read - body_offset;

            if (is_chunked)
            {
                bool done = false;
                if (!chunked_consume(&cstate, file, chunk + body_offset, body_len,
                                     &written, out, &done))
                {
                    goto cleanup;
                }
                if (done)
                {
                    chunked_done = true;
                }
            }
            else
            {
                if (!append_body_chunk(file, chunk + body_offset, body_len,
                                       &written, have_length, content_length, out))
                {
                    goto cleanup;
                }
            }
        }

        if ((is_chunked && chunked_done) ||
            (have_length && written >= content_length))
        {
            break;
        }
    }

    success = true;
    shell_output_write(out, "Saved ");
    char size_buf[16];
    size_t temp = written;
    int idx = 0;
    if (temp == 0)
    {
        size_buf[idx++] = '0';
    }
    else
    {
        char rev[16];
        int ridx = 0;
        while (temp > 0 && ridx < (int)sizeof(rev))
        {
            rev[ridx++] = (char)('0' + (temp % 10));
            temp /= 10;
        }
        while (ridx > 0)
        {
            size_buf[idx++] = rev[--ridx];
        }
    }
    size_buf[idx] = '\0';
    shell_output_write(out, size_buf);
    shell_output_write(out, " bytes to ");
    shell_output_write(out, dest_token);
    shell_output_write(out, "\n");

cleanup:
    if (tls_active)
    {
        tls_session_close(&tls_session);
    }
    if (socket)
    {
        if (request_sent)
        {
            net_tcp_socket_close(socket);
        }
        net_tcp_socket_release(socket);
    }
    if (!success && file)
    {
        vfs_truncate(file);
    }
    return success;
}


static const char *skip_ws(const char *cursor)
{
    while (*cursor == ' ' || *cursor == '\t')
    {
        ++cursor;
    }
    return cursor;
}

static bool read_token(const char **cursor, char *out, size_t capacity)
{
    const char *start = skip_ws(*cursor);
    if (*start == '\0')
    {
        *cursor = start;
        return false;
    }
    size_t total_len = 0;
    while (start[total_len] && start[total_len] != ' ' && start[total_len] != '\t')
    {
        if (total_len + 1 < capacity)
        {
            out[total_len] = start[total_len];
        }
        ++total_len;
    }
    size_t copy_len = total_len;
    if (copy_len >= capacity)
    {
        copy_len = capacity - 1;
    }
    out[copy_len] = '\0';
    *cursor = start + total_len;
    return true;
}

static bool parse_host_and_port(const char *text, char *host_out, size_t host_cap, uint16_t *port_out)
{
    if (!text || !host_out || host_cap == 0 || !port_out)
    {
        return false;
    }

    const char *colon = NULL;
    for (const char *p = text; *p; ++p)
    {
        if (*p == ':')
        {
            colon = p;
            break;
        }
    }

    size_t host_len = colon ? (size_t)(colon - text) : strlen(text);
    if (host_len == 0 || host_len >= host_cap)
    {
        return false;
    }
    memcpy(host_out, text, host_len);
    host_out[host_len] = '\0';

    if (colon)
    {
        return parse_decimal_u16(colon + 1, port_out);
    }
    *port_out = 80;
    return true;
}

static bool parse_decimal_u16(const char *text, uint16_t *out)
{
    uint32_t value = 0;
    if (!text || *text == '\0')
    {
        return false;
    }
    const char *p = text;
    while (*p)
    {
        if (*p < '0' || *p > '9')
        {
            return false;
        }
        value = value * 10U + (uint32_t)(*p - '0');
        if (value > 65535U)
        {
            return false;
        }
        ++p;
    }
    *out = (uint16_t)value;
    return true;
}

static bool format_decimal(char *buf, size_t cap, unsigned value, size_t *out_len)
{
    if (!buf || cap == 0)
    {
        return false;
    }
    char tmp[16];
    size_t count = 0;
    do
    {
        if (count >= sizeof(tmp))
        {
            return false;
        }
        tmp[count++] = (char)('0' + (value % 10));
        value /= 10;
    } while (value != 0);

    if (count + 1 > cap)
    {
        return false;
    }
    for (size_t i = 0; i < count; ++i)
    {
        buf[i] = tmp[count - 1 - i];
    }
    buf[count] = '\0';
    if (out_len)
    {
        *out_len = count;
    }
    return true;
}

static bool parse_decimal_size(const char *text, size_t *out)
{
    size_t value = 0;
    if (!text || *text == '\0')
    {
        return false;
    }
    const char *p = text;
    while (*p)
    {
        if (*p < '0' || *p > '9')
        {
            return false;
        }
        size_t digit = (size_t)(*p - '0');
        if (value > (SIZE_MAX - digit) / 10)
        {
            return false;
        }
        value = value * 10 + digit;
        ++p;
    }
    *out = value;
    return true;
}

static bool find_header_value(const char *headers, const char *name_lower,
                              char *value_out, size_t capacity)
{
    size_t name_len = strlen(name_lower);
    const char *cursor = headers;
    while (*cursor)
    {
        const char *line_end = find_substring(cursor, "\r\n");
        size_t line_len = line_end ? (size_t)(line_end - cursor) : strlen(cursor);
        if (line_len == 0)
        {
            break;
        }
        if (line_len >= name_len + 1)
        {
            bool match = true;
            for (size_t i = 0; i < name_len; ++i)
            {
                char c = cursor[i];
                if (c >= 'A' && c <= 'Z')
                {
                    c = (char)(c + 32);
                }
                if (c != name_lower[i])
                {
                    match = false;
                    break;
                }
            }
            if (match && cursor[name_len] == ':')
            {
                const char *value = cursor + name_len + 1;
                const char *line_limit = cursor + line_len;
                while (value < line_limit && (*value == ' ' || *value == '\t'))
                {
                    ++value;
                }
                size_t value_len = (size_t)(line_limit - value);
                if (value_len >= capacity)
                {
                    value_len = capacity - 1;
                }
                memcpy(value_out, value, value_len);
                value_out[value_len] = '\0';
                return true;
            }
        }
        if (!line_end)
        {
            break;
        }
        cursor = line_end + 2;
    }
    return false;
}

static bool parse_http_status(const char *headers, int *status_out)
{
    const char *line_end = find_substring(headers, "\r\n");
    size_t line_len = line_end ? (size_t)(line_end - headers) : strlen(headers);
    if (line_len < 12)
    {
        return false;
    }

    const char *cursor = headers;
    const char *space = NULL;
    for (size_t i = 0; i < line_len; ++i)
    {
        if (cursor[i] == ' ')
        {
            space = cursor + i;
            break;
        }
    }
    if (!space || (size_t)(space - cursor) < 5)
    {
        return false;
    }
    const char *code = space + 1;
    if (code + 3 > headers + line_len)
    {
        return false;
    }
    if (code[0] < '0' || code[0] > '9' ||
        code[1] < '0' || code[1] > '9' ||
        code[2] < '0' || code[2] > '9')
    {
        return false;
    }
    *status_out = (code[0] - '0') * 100 + (code[1] - '0') * 10 + (code[2] - '0');
    return true;
}

static bool ensure_arp(net_interface_t *iface, uint32_t next_hop_ip, uint64_t timeout_ticks)
{
    uint8_t mac[6];
    if (net_arp_lookup(next_hop_ip, mac))
    {
        return true;
    }
    if (!net_arp_send_request(iface, next_hop_ip))
    {
        return false;
    }
    uint64_t start = timer_ticks();
    while (timer_ticks() - start < timeout_ticks)
    {
        rtl8139_poll();
        if (net_arp_lookup(next_hop_ip, mac))
        {
            return true;
        }
    }
    return false;
}

static bool append_body_chunk(vfs_node_t *file, const uint8_t *data, size_t len,
                              size_t *written, bool have_length, size_t expected_length,
                              shell_output_t *out)
{
    if (len == 0)
    {
        return true;
    }

    if (have_length && *written + len > expected_length)
    {
        size_t allowed = expected_length - *written;
        len = allowed;
    }

    if (!vfs_append(file, (const char *)data, len))
    {
        shell_output_error(out, "failed to write to file");
        return false;
    }

    *written += len;
    return true;
}

static const char *find_substring(const char *haystack, const char *needle)
{
    size_t needle_len = strlen(needle);
    if (needle_len == 0)
    {
        return haystack;
    }
    const char *cursor = haystack;
    while (*cursor)
    {
        if (*cursor == needle[0])
        {
            if (strncmp(cursor, needle, needle_len) == 0)
            {
                return cursor;
            }
        }
        ++cursor;
    }
    return NULL;
}
