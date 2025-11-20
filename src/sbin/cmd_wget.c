#include "shell_commands.h"

#include <stddef.h>
#include <stdint.h>

#include "net/arp.h"
#include "net/interface.h"
#include "net/route.h"
#include "net/dns.h"
#include "net/tcp.h"
#include "net/tls.h"
#include "serial.h"
#include "timer.h"
#include "timekeeping.h"
#include "vfs.h"
#include "libc.h"

#ifndef WGET_TRACE_ENABLE
#define WGET_TRACE_ENABLE 0
#endif

#ifndef WGET_PROGRESS_LOG
#define WGET_PROGRESS_LOG 1
#endif

#ifndef WGET_TLS_TRACE_ENABLE
#define WGET_TLS_TRACE_ENABLE 1
#endif

#define WGET_HEADER_CAP 2048
#define WGET_CHUNK_SIZE 4096

static const char *skip_ws(const char *cursor);
static bool read_token(const char **cursor, char *out, size_t capacity);
static bool parse_url(const char *text,
                      char *host_out,
                      size_t host_cap,
                      uint16_t *port_out,
                      char *path_out,
                      size_t path_cap,
                      bool *use_tls_out);
static bool parse_decimal_u16(const char *text, uint16_t *out);
static bool parse_decimal_size(const char *text, size_t *out);
static const char *find_substring(const char *haystack, const char *needle);
static bool find_header_value(const char *headers, const char *name_lower,
                              char *value_out, size_t capacity);
static bool parse_http_status(const char *headers, int *status_out);
static const char *string_chr(const char *s, char ch);
static const char *string_rchr(const char *s, char ch);

#if WGET_TLS_TRACE_ENABLE
static bool format_decimal_u64(char *buf, size_t cap, uint64_t value, size_t *out_len);
static void wget_tls_trace_line(shell_output_t *out, const char *text);
static void wget_tls_trace_label_value(shell_output_t *out, const char *label, const char *value);
static void wget_tls_trace_label_bool(shell_output_t *out, const char *label, bool value);
static void wget_tls_trace_label_u64(shell_output_t *out, const char *label, uint64_t value);
static void wget_tls_trace_label_int(shell_output_t *out, const char *label, int value);
static void wget_tls_trace_ipv4(shell_output_t *out, const char *label, uint32_t addr);
static void wget_tls_trace_hex(shell_output_t *out, const char *label,
                               const uint8_t *data, size_t len, size_t max_len);
static size_t wget_tls_bignum_bits(const bignum_t *num);
static void wget_tls_trace_state(shell_output_t *out, const char *label, const tls_session_t *session);
static void wget_tls_trace_server_key(shell_output_t *out, const tls_session_t *session);
static void wget_tls_trace_socket_state(shell_output_t *out, const net_tcp_socket_t *socket);
static void wget_tls_trace_request(shell_output_t *out, const uint8_t *data, size_t len);
static void wget_tls_trace_payload_preview(shell_output_t *out, const uint8_t *data, size_t len);
static bool wget_tls_handshake(shell_output_t *out,
                               tls_session_t *session,
                               const char *hostname,
                               const net_interface_t *iface,
                               net_tcp_socket_t *socket,
                               uint32_t remote_ip,
                               uint16_t remote_port);
#endif

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

static uint64_t wget_ticks_to_ms(uint64_t ticks)
{
    uint32_t freq = timer_frequency();
    if (freq == 0)
    {
        freq = 1000;
    }
    return (ticks * 1000ULL) / (uint64_t)freq;
}

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

#if WGET_TLS_TRACE_ENABLE
static bool format_decimal_u64(char *buf, size_t cap, uint64_t value, size_t *out_len)
{
    if (!buf || cap == 0)
    {
        return false;
    }
    char tmp[32];
    size_t count = 0;
    do
    {
        if (count >= sizeof(tmp))
        {
            return false;
        }
        uint8_t digit = (uint8_t)(value % 10ULL);
        tmp[count++] = (char)('0' + digit);
        value /= 10ULL;
    } while (value != 0ULL);

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

static void wget_tls_trace_line(shell_output_t *out, const char *text)
{
    shell_output_write(out, "[tls] ");
    shell_output_write(out, text ? text : "(null)");
    shell_output_write(out, "\n");
}

static void wget_tls_trace_label_value(shell_output_t *out, const char *label, const char *value)
{
    shell_output_write(out, "[tls] ");
    shell_output_write(out, label ? label : "(null)");
    shell_output_write(out, ": ");
    shell_output_write(out, value ? value : "(null)");
    shell_output_write(out, "\n");
}

static void wget_tls_trace_label_bool(shell_output_t *out, const char *label, bool value)
{
    wget_tls_trace_label_value(out, label, value ? "true" : "false");
}

static void wget_tls_trace_label_u64(shell_output_t *out, const char *label, uint64_t value)
{
    char buf[32];
    if (!format_decimal_u64(buf, sizeof(buf), value, NULL))
    {
        buf[0] = '?';
        buf[1] = '\0';
    }
    wget_tls_trace_label_value(out, label, buf);
}

static void wget_tls_trace_label_int(shell_output_t *out, const char *label, int value)
{
    char buf[24];
    if (value < 0)
    {
        unsigned magnitude = (unsigned)(-(value + 1)) + 1;
        buf[0] = '-';
        if (!format_decimal(buf + 1, sizeof(buf) - 1, magnitude, NULL))
        {
            buf[0] = '?';
            buf[1] = '\0';
        }
    }
    else
    {
        if (!format_decimal(buf, sizeof(buf), (unsigned)value, NULL))
        {
            buf[0] = '?';
            buf[1] = '\0';
        }
    }
    wget_tls_trace_label_value(out, label, buf);
}

static void wget_tls_trace_ipv4(shell_output_t *out, const char *label, uint32_t addr)
{
    char ipbuf[16];
    net_format_ipv4(addr, ipbuf);
    wget_tls_trace_label_value(out, label, ipbuf);
}

static void wget_tls_trace_hex(shell_output_t *out, const char *label,
                               const uint8_t *data, size_t len, size_t max_len)
{
    shell_output_write(out, "[tls] ");
    shell_output_write(out, label ? label : "(null)");
    shell_output_write(out, ": ");
    if (!data || len == 0)
    {
        shell_output_write(out, "(empty)\n");
        return;
    }
    size_t limit = len;
    if (max_len > 0 && limit > max_len)
    {
        limit = max_len;
    }
    static const char hex_digits[] = "0123456789abcdef";
    for (size_t i = 0; i < limit; ++i)
    {
        char hex[3];
        hex[0] = hex_digits[(data[i] >> 4) & 0xF];
        hex[1] = hex_digits[data[i] & 0xF];
        hex[2] = '\0';
        shell_output_write(out, hex);
        if (i + 1 < limit)
        {
            shell_output_write(out, " ");
        }
    }
    if (limit < len)
    {
        shell_output_write(out, " ...");
    }
    shell_output_write(out, "\n");
}

static size_t wget_tls_bignum_bits(const bignum_t *num)
{
    if (!num || num->length == 0)
    {
        return 0;
    }
    size_t idx = num->length;
    while (idx > 0 && num->words[idx - 1] == 0)
    {
        --idx;
    }
    if (idx == 0)
    {
        return 0;
    }
    size_t bits = idx * 32;
    uint32_t top = num->words[idx - 1];
    while ((top & 0x80000000U) == 0)
    {
        top <<= 1;
        if (bits == 0)
        {
            break;
        }
        --bits;
    }
    return bits;
}

static void wget_tls_trace_state(shell_output_t *out, const char *label, const tls_session_t *session)
{
    if (!session)
    {
        wget_tls_trace_line(out, "TLS state unavailable (null session)");
        return;
    }
    wget_tls_trace_line(out, label ? label : "TLS state");
    wget_tls_trace_label_bool(out, "handshake_complete", session->handshake_complete);
    wget_tls_trace_label_bool(out, "keys_ready", session->keys_ready);
    wget_tls_trace_label_u64(out, "client_seq", session->client_seq);
    wget_tls_trace_label_u64(out, "server_seq", session->server_seq);
    wget_tls_trace_label_int(out, "socket_fd", session->socket_fd);
}

static void wget_tls_trace_server_key(shell_output_t *out, const tls_session_t *session)
{
    if (!session)
    {
        return;
    }
    size_t modulus_bytes = rsa_public_key_size(&session->server_key);
    size_t modulus_bits = wget_tls_bignum_bits(&session->server_key.modulus);
    size_t exponent_bits = wget_tls_bignum_bits(&session->server_key.exponent);
    wget_tls_trace_label_u64(out, "server_rsa_modulus_bytes", modulus_bytes);
    wget_tls_trace_label_u64(out, "server_rsa_modulus_bits", modulus_bits);
    wget_tls_trace_label_u64(out, "server_rsa_exponent_bits", exponent_bits);
}

static void wget_tls_trace_socket_state(shell_output_t *out, const net_tcp_socket_t *socket)
{
    if (!socket)
    {
        wget_tls_trace_label_value(out, "tcp_state", "(null socket)");
        return;
    }
    const char *state = net_tcp_socket_state(socket);
    if (!state)
    {
        state = "(unknown)";
    }
    wget_tls_trace_label_value(out, "tcp_state", state);
}

static void wget_tls_trace_request(shell_output_t *out, const uint8_t *data, size_t len)
{
    if (!data || len == 0)
    {
        wget_tls_trace_line(out, "HTTPS request buffer empty");
        return;
    }
    wget_tls_trace_label_u64(out, "https_request_bytes", len);
    char line[96];
    size_t line_len = 0;
    while (line_len < len && line_len + 1 < sizeof(line))
    {
        char ch = (char)data[line_len];
        if (ch == '\r' || ch == '\n')
        {
            break;
        }
        line[line_len++] = ch;
    }
    line[line_len] = '\0';
    if (line_len > 0)
    {
        wget_tls_trace_label_value(out, "https_request_line", line);
    }
    wget_tls_trace_hex(out, "https_request_preview", data, len, 64);
}

static void wget_tls_trace_payload_preview(shell_output_t *out, const uint8_t *data, size_t len)
{
    wget_tls_trace_label_u64(out, "first_tls_payload_bytes", len);
    wget_tls_trace_hex(out, "first_tls_payload", data, len, 64);
}

static bool wget_tls_handshake(shell_output_t *out,
                               tls_session_t *session,
                               const char *hostname,
                               const net_interface_t *iface,
                               net_tcp_socket_t *socket,
                               uint32_t remote_ip,
                               uint16_t remote_port)
{
    if (!session)
    {
        wget_tls_trace_line(out, "No TLS session available for handshake");
        return false;
    }

    wget_tls_trace_label_value(out, "hostname", hostname && hostname[0] ? hostname : "(none)");
    char port_buf[16];
    if (!format_decimal(port_buf, sizeof(port_buf), remote_port, NULL))
    {
        port_buf[0] = '?';
        port_buf[1] = '\0';
    }
    wget_tls_trace_label_value(out, "port", port_buf);
    wget_tls_trace_ipv4(out, "remote_ip", remote_ip);

    if (iface)
    {
        char ifname[NET_IF_NAME_MAX + 1];
        size_t name_len = 0;
        while (name_len < NET_IF_NAME_MAX && iface->name[name_len] != '\0')
        {
            ifname[name_len] = iface->name[name_len];
            ++name_len;
        }
        if (name_len == NET_IF_NAME_MAX)
        {
            ifname[NET_IF_NAME_MAX] = '\0';
        }
        else
        {
            ifname[name_len] = '\0';
        }
        if (name_len == 0)
        {
            wget_tls_trace_label_value(out, "interface", "(unnamed)");
        }
        else
        {
            wget_tls_trace_label_value(out, "interface", ifname);
        }
        wget_tls_trace_ipv4(out, "interface_ipv4", iface->ipv4_addr);
    }
    else
    {
        wget_tls_trace_label_value(out, "interface", "(none)");
    }

    wget_tls_trace_socket_state(out, socket);

    uint64_t start = timer_ticks();
    bool ok = tls_session_handshake(session, hostname);
    uint64_t elapsed = timer_ticks() - start;
    uint32_t freq = timer_frequency();
    if (freq == 0)
    {
        freq = 100;
    }
    uint64_t elapsed_ms = (elapsed * 1000ULL) / (uint64_t)freq;

    wget_tls_trace_label_u64(out, "handshake_ticks", elapsed);
    wget_tls_trace_label_u64(out, "handshake_ms", elapsed_ms);

    if (ok)
    {
        wget_tls_trace_line(out, "handshake outcome: success");
        wget_tls_trace_state(out, "post-handshake state", session);
        wget_tls_trace_server_key(out, session);
        wget_tls_trace_hex(out, "client_random", session->client_random, sizeof(session->client_random), 32);
        wget_tls_trace_hex(out, "server_random", session->server_random, sizeof(session->server_random), 32);
    }
    else
    {
        wget_tls_trace_line(out, "handshake outcome: failure");
        wget_tls_trace_state(out, "failure snapshot", session);
        wget_tls_trace_socket_state(out, socket);
        wget_tls_trace_hex(out, "last_record_preview", session->record_buffer,
                           sizeof(session->record_buffer), 32);
    }

    return ok;
}
#endif

bool shell_cmd_wget(shell_state_t *shell, shell_output_t *out, const char *args)
{
    const char *cursor = args ? args : "";
    char tokens[3][256];
    size_t token_count = 0;

    while (token_count < 3 && read_token(&cursor, tokens[token_count], sizeof(tokens[token_count])))
    {
        token_count++;
    }

    cursor = skip_ws(cursor);
    if (*cursor != '\0')
    {
        return shell_output_error(out, "Usage: wget [iface] <url> [dest]");
    }

    if (token_count == 0)
    {
        return shell_output_error(out, "Usage: wget [iface] <url> [dest]");
    }

    bool have_iface = false;
    net_interface_t *iface = NULL;
    const char *url_arg = NULL;
    const char *dest_arg = NULL;

    if (token_count >= 2)
    {
        net_interface_t *candidate = net_if_by_name(tokens[0]);
        if (candidate)
        {
            size_t name_len = strlen(tokens[0]);
            if (name_len == 0 || name_len >= NET_IF_NAME_MAX)
            {
                return shell_output_error(out, "interface name too long");
            }
            have_iface = true;
            iface = candidate;
            url_arg = tokens[1];
            if (token_count == 3)
            {
                dest_arg = tokens[2];
            }
        }
    }

    if (!have_iface)
    {
        url_arg = tokens[0];
        if (token_count >= 2)
        {
            dest_arg = tokens[1];
        }
    }
    else if (token_count < 2)
    {
        return shell_output_error(out, "Usage: wget [iface] <url> [dest]");
    }

    if (!url_arg || url_arg[0] == '\0')
    {
        return shell_output_error(out, "url must be non-empty");
    }

    char dest_token[128];
    if (dest_arg)
    {
        size_t dest_len = strlen(dest_arg);
        if (dest_len == 0 || dest_len >= sizeof(dest_token))
        {
            return shell_output_error(out, "destination name invalid");
        }
        memcpy(dest_token, dest_arg, dest_len + 1);
    }

    if (have_iface)
    {
        if (!iface || !iface->present)
        {
            return shell_output_error(out, "interface not found");
        }
    }

    char host_name[128];
    char request_path[256];
    uint16_t remote_port = 80;
    bool tls_via_scheme = false;
    if (!parse_url(url_arg, host_name, sizeof(host_name), &remote_port,
                   request_path, sizeof(request_path), &tls_via_scheme))
    {
        return shell_output_error(out, "invalid url");
    }

    if (!dest_arg)
    {
        const char *fname = string_rchr(request_path, '/');
        if (fname)
        {
            fname++;
        }
        else
        {
            fname = request_path;
        }
        const char *query = string_chr(fname, '?');
        size_t name_len = query ? (size_t)(query - fname) : strlen(fname);
        if (name_len == 0)
        {
            fname = "index.html";
            name_len = strlen(fname);
        }
        if (name_len >= sizeof(dest_token))
        {
            return shell_output_error(out, "derived destination name too long");
        }
        memcpy(dest_token, fname, name_len);
        dest_token[name_len] = '\0';
    }

#if WGET_PROGRESS_LOG
    serial_printf("[wget] start url=%s dest=%s iface=%s\r\n",
                  url_arg,
                  dest_token,
                  (have_iface && iface) ? iface->name : "<auto>");
#endif

    bool use_tls = tls_via_scheme || (remote_port == 443);
#if WGET_TLS_TRACE_ENABLE
    if (use_tls)
    {
        wget_tls_trace_line(out, "HTTPS selected; supported cipher: TLS_RSA_WITH_AES_128_CBC_SHA256");
    }
#endif

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
#if WGET_PROGRESS_LOG
    {
        char ip_remote[32];
        char ip_next[32];
        net_format_ipv4(remote_ip, ip_remote);
        net_format_ipv4(next_hop_ip, ip_next);
        serial_printf("[wget] route iface=%s remote=%s:%u next_hop=%s\r\n",
                      iface ? iface->name : "<none>",
                      ip_remote,
                      (unsigned)remote_port,
                      ip_next);
    }
#endif

    net_tcp_socket_t *socket = net_tcp_socket_open(iface);
    if (!socket)
    {
        return shell_output_error(out, "no TCP sockets available");
    }
    int socket_fd = net_tcp_socket_fd(socket);
    if (socket_fd < 0)
    {
        shell_output_error(out, "failed to allocate socket descriptor");
        goto cleanup;
    }

    bool success = false;
    bool tls_active = false;
    tls_session_t *tls_session = NULL;
    vfs_node_t *file = NULL;
    size_t written = 0;
#if WGET_PROGRESS_LOG
    uint64_t log_start_ticks = timer_ticks();
    uint64_t last_wait_log = 0;
    size_t next_progress_bytes = 64 * 1024;
#endif
#if WGET_TLS_TRACE_ENABLE
    bool tls_trace_logged_first_payload = false;
#endif

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
        __asm__ volatile ("pause");
    }
#if WGET_PROGRESS_LOG
    {
        uint64_t connect_ms = wget_ticks_to_ms(timer_ticks() - start);
        serial_printf("[wget] tcp connected in %llums\r\n", (unsigned long long)connect_ms);
    }
#endif

    if (use_tls)
    {
        tls_session = (tls_session_t *)malloc(sizeof(tls_session_t));
        if (!tls_session)
        {
            shell_output_error(out, "TLS session alloc failed");
            goto cleanup;
        }
        memset(tls_session, 0, sizeof(*tls_session));
        if (!tls_session_init(tls_session, socket))
        {
            shell_output_error(out, "TLS session init failed");
            goto cleanup;
        }
        shell_output_write(out, "Negotiating TLS...\n");
#if WGET_PROGRESS_LOG
        serial_printf("%s", "[wget] tls handshake begin\r\n");
#endif
#if WGET_TLS_TRACE_ENABLE
        uint64_t tls_start = timer_ticks();
        if (!wget_tls_handshake(out, tls_session, host_name, iface, socket, remote_ip, remote_port))
#else
        uint64_t tls_start = timer_ticks();
        if (!tls_session_handshake(tls_session, host_name))
#endif
        {
            shell_output_error(out, "TLS handshake failed");
            goto cleanup;
        }
#if WGET_PROGRESS_LOG
        {
            uint64_t tls_ms = wget_ticks_to_ms(timer_ticks() - tls_start);
            serial_printf("[wget] tls handshake done in %llums\r\n", (unsigned long long)tls_ms);
        }
#endif
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
    if ((!use_tls && remote_port != 80) ||
        (use_tls && remote_port != 443))
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
#if WGET_TLS_TRACE_ENABLE
        wget_tls_trace_request(out, (const uint8_t *)request, req_len);
#endif
        if (!tls_session_send(tls_session, (const uint8_t *)request, req_len))
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
#if WGET_PROGRESS_LOG
    serial_printf("[wget] sent request bytes=%zu\r\n", req_len);
#endif
    shell_output_write(out, "Request sent, awaiting response...\n");

    char header_buf[WGET_HEADER_CAP];
    size_t header_len = 0;
    bool header_done = false;
    bool header_parsed = false;
    bool have_length = false;
    bool file_preallocated = false;
    size_t content_length = 0;
    bool is_chunked = false;
    chunked_state_t cstate;
    bool chunked_done = false;
    uint64_t last_progress = timer_ticks();

    uint8_t chunk[WGET_CHUNK_SIZE];

    while (1)
    {
        if (net_tcp_socket_has_error(socket))
        {
            shell_output_error(out, "TCP connection error");
            goto cleanup;
        }

        size_t bytes_read = 0;
        if (tls_active)
        {
            bytes_read = tls_session_recv(tls_session, chunk, sizeof(chunk));
#if WGET_TLS_TRACE_ENABLE
            if (bytes_read > 0 && !tls_trace_logged_first_payload)
            {
                tls_trace_logged_first_payload = true;
                wget_tls_trace_payload_preview(out, chunk, bytes_read);
            }
#endif
            if (bytes_read == 0)
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

                uint64_t now = timer_ticks();
#if WGET_PROGRESS_LOG
                if (now - last_wait_log >= timer_frequency())
                {
                    serial_printf("[wget] waiting for data... elapsed=%llums written=%zu\r\n",
                                  (unsigned long long)wget_ticks_to_ms(now - log_start_ticks),
                                  written);
                    last_wait_log = now;
                }
#endif

                if (now - last_progress >= data_timeout)
                {
                    shell_output_error(out, "no data received (timeout)");
                    goto cleanup;
                }
                continue;
            }
        }
        else
        {
            ssize_t got = read(socket_fd, chunk, sizeof(chunk));
            if (got < 0)
            {
                shell_output_error(out, "socket read failed");
                goto cleanup;
            }
            if (got == 0)
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

                uint64_t now = timer_ticks();
#if WGET_PROGRESS_LOG
                if (now - last_wait_log >= timer_frequency())
                {
                    serial_printf("[wget] waiting for data... elapsed=%llums written=%zu\r\n",
                                  (unsigned long long)wget_ticks_to_ms(now - log_start_ticks),
                                  written);
                    last_wait_log = now;
                }
#endif

                if (now - last_progress >= data_timeout)
                {
                    shell_output_error(out, "no data received (timeout)");
                    goto cleanup;
                }
                continue;
            }
            bytes_read = (size_t)got;
        }
        last_progress = timer_ticks();

        size_t offset = 0;
        if (!header_done)
        {
            while (!header_done && offset < bytes_read)
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
                shell_output_write(out, "HTTP headers received:\n");
                shell_output_write(out, header_buf);
                shell_output_write(out, "\n");
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
#if WGET_TRACE_ENABLE
                shell_output_write(out, "debug: content-length=");
                char len_buf[24];
                if (!format_decimal(len_buf, sizeof(len_buf), (unsigned)content_length, NULL))
                {
                    len_buf[0] = '\0';
                }
                shell_output_write(out, len_buf);
                shell_output_write(out, "\n");
#endif
                have_length = true;
                if (file && !file_preallocated)
                {
                    if (!vfs_reserve(file, content_length))
                    {
                        shell_output_error(out, "failed to reserve file storage");
                        goto cleanup;
                    }
                    file_preallocated = true;
                }
            }

                header_parsed = true;
            }
        }

        if (!header_done)
        {
            continue;
        }

        size_t body_offset = offset;
        if (bytes_read > body_offset)
        {
            size_t body_len = bytes_read - body_offset;

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
#if WGET_TRACE_ENABLE
                    shell_output_write(out, "debug: chunked complete, total ");
                    char size_buf[16];
                    if (!format_decimal(size_buf, sizeof(size_buf), (unsigned)written, NULL))
                    {
                        size_buf[0] = '\0';
                    }
                    shell_output_write(out, size_buf);
                    shell_output_write(out, "\n");
#endif
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

#if WGET_PROGRESS_LOG
        if (written >= next_progress_bytes)
        {
            serial_printf("[wget] progress=%zu bytes elapsed=%llums\r\n",
                          written,
                          (unsigned long long)wget_ticks_to_ms(timer_ticks() - log_start_ticks));
            next_progress_bytes += 64 * 1024;
        }
#endif

        if ((is_chunked && chunked_done) ||
            (have_length && written >= content_length))
        {
            break;
        }
    }

    success = true;
#if WGET_PROGRESS_LOG
    {
        uint64_t total_ms = wget_ticks_to_ms(timer_ticks() - log_start_ticks);
        serial_printf("[wget] complete bytes=%zu duration=%llums\r\n",
                      written,
                      (unsigned long long)total_ms);
    }
#endif
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
    if (tls_session)
    {
        tls_session_close(tls_session);
        free(tls_session);
        tls_session = NULL;
    }
    if (socket_fd >= 0)
    {
        close(socket_fd);
        socket_fd = -1;
    }
    else if (socket)
    {
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

static bool parse_url(const char *text,
                      char *host_out,
                      size_t host_cap,
                      uint16_t *port_out,
                      char *path_out,
                      size_t path_cap,
                      bool *use_tls_out)
{
    if (!text || !host_out || host_cap == 0 || !port_out || !path_out || path_cap == 0)
    {
        return false;
    }

    const char *cursor = text;
    bool tls = false;
    uint16_t port = 80;

    if (strncmp(cursor, "http://", 7) == 0)
    {
        cursor += 7;
    }
    else if (strncmp(cursor, "https://", 8) == 0)
    {
        cursor += 8;
        tls = true;
        port = 443;
    }

    if (*cursor == '\0')
    {
        return false;
    }

    const char *slash = string_chr(cursor, '/');
    const char *query = string_chr(cursor, '?');
    const char *host_end = slash ? slash : cursor + strlen(cursor);
    if (query && (!slash || query < slash))
    {
        host_end = query;
    }

    const char *colon = NULL;
    for (const char *p = cursor; p < host_end; ++p)
    {
        if (*p == ':')
        {
            colon = p;
            break;
        }
    }

    size_t host_len = colon ? (size_t)(colon - cursor) : (size_t)(host_end - cursor);
    if (host_len == 0 || host_len >= host_cap)
    {
        return false;
    }
    memcpy(host_out, cursor, host_len);
    host_out[host_len] = '\0';

    if (colon)
    {
        const char *port_start = colon + 1;
        if (port_start >= host_end)
        {
            return false;
        }
        char port_buf[6];
        size_t port_len = (size_t)(host_end - port_start);
        if (port_len == 0 || port_len >= sizeof(port_buf))
        {
            return false;
        }
        memcpy(port_buf, port_start, port_len);
        port_buf[port_len] = '\0';
        if (!parse_decimal_u16(port_buf, &port))
        {
            return false;
        }
    }

    const char *path_start = slash;

    if (path_start)
    {
        size_t remaining = strlen(path_start);
        if (remaining + 1 > path_cap)
        {
            return false;
        }
        memcpy(path_out, path_start, remaining + 1);
    }
    else
    {
        if (query)
        {
            size_t query_len = strlen(query);
            if (query_len + 2 > path_cap)
            {
                return false;
            }
            path_out[0] = '/';
            memcpy(path_out + 1, query, query_len + 1);
        }
        else
        {
            if (path_cap < 2)
            {
                return false;
            }
            path_out[0] = '/';
            path_out[1] = '\0';
        }
    }

    if (use_tls_out)
    {
        *use_tls_out = tls;
    }
    *port_out = port;
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

static const char *string_chr(const char *s, char ch)
{
    if (!s)
    {
        return NULL;
    }
    while (*s)
    {
        if (*s == ch)
        {
            return s;
        }
        ++s;
    }
    return NULL;
}

static const char *string_rchr(const char *s, char ch)
{
    if (!s)
    {
        return NULL;
    }
    const char *last = NULL;
    while (*s)
    {
        if (*s == ch)
        {
            last = s;
        }
        ++s;
    }
    return last;
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
        if (net_arp_lookup(next_hop_ip, mac))
        {
            return true;
        }
        __asm__ volatile ("pause");
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
#if WGET_TRACE_ENABLE
    shell_output_write(out, "debug: wrote ");
    char buf[24];
    if (!format_decimal(buf, sizeof(buf), (unsigned)len, NULL))
    {
        buf[0] = '\0';
    }
    shell_output_write(out, buf);
    shell_output_write(out, " bytes (total ");
    char total_buf[24];
    if (!format_decimal(total_buf, sizeof(total_buf), (unsigned)(*written), NULL))
    {
        total_buf[0] = '\0';
    }
    shell_output_write(out, total_buf);
    shell_output_write(out, ")\n");
#endif
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
