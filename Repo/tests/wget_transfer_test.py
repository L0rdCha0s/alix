#!/usr/bin/env python3
"""Run production wget against fragmented TCP replies and a faultable file sink."""

from pathlib import Path
import re
import sys

sys.dont_write_bytecode = True
from audio_stream_contract_test import compile_and_run, function_definition

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    program = r'''
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <sys/types.h>
#define CHECK(c, msg) do { if (!(c)) { fprintf(stderr, "%s (scenario=%s)\n", msg, scenario); exit(1); } } while (0)
#define WGET_TLS_TRACE_ENABLE 0
#define NET_IF_NAME_MAX 16
static const char *scenario;
typedef struct { int unused; } vfs_mount_t;
typedef struct { uint8_t *data; size_t size, capacity; vfs_mount_t *mount; } vfs_node_t;
typedef struct { vfs_node_t *cwd; } shell_state_t;
typedef struct { unsigned unused; } shell_output_t;
typedef struct { char name[NET_IF_NAME_MAX]; bool present, link_up; uint32_t ipv4_addr; } net_interface_t;
typedef struct { bool established, error; } net_tcp_socket_t;
typedef struct { net_tcp_socket_t *socket; } tls_session_t;
static net_interface_t iface = {.name = "igb0", .present = true, .link_up = true, .ipv4_addr = 1};
static net_tcp_socket_t socket_state;
static vfs_node_t destination;
static vfs_mount_t mounted;
static uint64_t ticks;
static char output[16384], trace[4096], sent_request[1024];
static size_t output_length, input_size, input_position, max_read;
static const uint8_t *input;
static size_t read_count, append_count, reserve_count, open_count, truncates, disk_flushes;
static size_t close_count, release_count, allocation_count, tls_closes;
static size_t fail_read_number, fail_append_number;
static bool flush_failure, reserve_failure, socket_fd_failure, send_failure, transport_error;
static bool is_ram, persisted, observed_saved;
static uint64_t timer_ticks(void) { return ticks; }
static uint32_t timer_frequency(void) { return 1000; }
static void process_sleep_ms(uint32_t ms) { ticks += ms; }
static bool shell_output_write(shell_output_t *out, const char *text)
{
    (void)out;
    if (!strcmp(text, "Saved "))
    {
        CHECK(is_ram || persisted, "Saved was emitted before durable file sync");
        observed_saved = true;
    }
    size_t len = strlen(text); CHECK(output_length + len < sizeof(output), "output overflow");
    memcpy(output + output_length, text, len + 1); output_length += len; return true;
}
static bool shell_output_error(shell_output_t *out, const char *text)
{ shell_output_write(out, "error: "); shell_output_write(out, text); shell_output_write(out, "\n"); return false; }
static void serial_printf(const char *fmt, ...)
{
    va_list ap; va_start(ap, fmt); int bytes = vsnprintf(trace + strlen(trace), sizeof(trace) - strlen(trace), fmt, ap); va_end(ap);
    CHECK(bytes >= 0 && (size_t)bytes < sizeof(trace), "trace overflow");
}
static void *wget_test_alloc(size_t bytes)
{ void *ptr = malloc(bytes); CHECK(ptr, "allocation failed"); allocation_count++; return ptr; }
static void wget_test_free(void *ptr)
{ if (ptr) { CHECK(allocation_count > 0, "free without allocation"); allocation_count--; } free(ptr); }
static net_interface_t *net_if_by_name(const char *name) { return !strcmp(name, iface.name) ? &iface : NULL; }
static bool net_route_get_default(net_interface_t **out, uint32_t *ip)
{ *out = &iface; *ip = 2; ticks++; return true; }
static bool net_route_next_hop(net_interface_t *hint, uint32_t ip, net_interface_t **out, uint32_t *next)
{ (void)hint; *out = &iface; *next = ip; ticks++; return true; }
static bool net_parse_ipv4(const char *name, uint32_t *ip)
{ if (strcmp(name, "10.0.2.2")) return false; *ip = 2; return true; }
static bool net_dns_resolve_ipv4(const char *host, net_interface_t *hint, uint32_t *ip)
{ (void)host; (void)hint; *ip = 2; ticks += 2; return true; }
static bool net_arp_lookup(uint32_t ip, uint8_t *mac)
{ (void)ip; memset(mac, 0x22, 6); ticks++; return true; }
static bool net_arp_send_request(net_interface_t *dev, uint32_t ip) { (void)dev; (void)ip; return true; }
static net_tcp_socket_t *net_tcp_socket_open(net_interface_t *dev) { (void)dev; return &socket_state; }
static int net_tcp_socket_fd(net_tcp_socket_t *socket) { (void)socket; return socket_fd_failure ? -1 : 27; }
static bool net_tcp_socket_connect(net_tcp_socket_t *socket, uint32_t ip, uint16_t port)
{ (void)ip; CHECK(port == 8000 || port == 443 || port == 80, "wrong remote port"); socket->established = true; ticks += 2; return true; }
static bool net_tcp_socket_is_established(net_tcp_socket_t *socket) { return socket->established; }
static bool net_tcp_socket_has_error(net_tcp_socket_t *socket) { return socket->error; }
static bool net_tcp_socket_remote_closed(net_tcp_socket_t *socket) { (void)socket; return input_position == input_size; }
static bool net_tcp_socket_send(net_tcp_socket_t *socket, const uint8_t *bytes, size_t count)
{
    (void)socket; CHECK(count < sizeof(sent_request), "request overflow");
    memcpy(sent_request, bytes, count); sent_request[count] = 0; ticks += 3; return !send_failure;
}
static ssize_t net_tcp_socket_read_blocking_timeout(net_tcp_socket_t *socket, uint8_t *out, size_t capacity, uint64_t timeout)
{
    (void)timeout; read_count++; ticks += 7;
    CHECK(read_count <= input_size + 3, "wget read loop failed to terminate");
    if (fail_read_number && read_count == fail_read_number) { socket->error = transport_error; return -1; }
    size_t count = input_size - input_position;
    if (count > max_read) count = max_read;
    if (count > capacity) count = capacity;
    memcpy(out, input + input_position, count); input_position += count; return (ssize_t)count;
}
static void net_tcp_log_state(net_tcp_socket_t *socket, const char *label) { (void)socket; (void)label; }
static void net_tcp_socket_release(net_tcp_socket_t *socket) { (void)socket; release_count++; }
static int close(int fd) { CHECK(fd == 27, "closed wrong descriptor"); close_count++; return 0; }
static bool tls_session_init(tls_session_t *tls, net_tcp_socket_t *socket) { tls->socket = socket; return true; }
static bool tls_session_handshake(tls_session_t *tls, const char *host) { (void)tls; (void)host; ticks += 5; return true; }
static bool tls_session_send(tls_session_t *tls, const uint8_t *data, size_t len) { return net_tcp_socket_send(tls->socket, data, len); }
static size_t tls_session_recv(tls_session_t *tls, uint8_t *data, size_t len)
{ ssize_t got = net_tcp_socket_read_blocking_timeout(tls->socket, data, len, 0); return got < 0 ? 0 : (size_t)got; }
static void tls_session_close(tls_session_t *tls) { (void)tls; tls_closes++; }
static void ensure_file_capacity(size_t size)
{
    if (size <= destination.capacity) return;
    destination.capacity = size * 2 + 1;
    destination.data = realloc(destination.data, destination.capacity); CHECK(destination.data, "file allocation failed");
}
static vfs_node_t *vfs_open_file(vfs_node_t *cwd, const char *path, bool create, bool truncate)
{
    (void)cwd; CHECK(create && truncate, "wget did not open with truncate exactly once");
    CHECK(!strcmp(path, "/tmp/out.bin") || !strcmp(path, "/root/out.bin") || !strcmp(path, "file.bin"), "wrong destination");
    open_count++; destination.size = 0; destination.mount = is_ram ? NULL : &mounted; return &destination;
}
static bool vfs_truncate(vfs_node_t *node) { CHECK(node == &destination, "wrong truncate target"); truncates++; node->size = 0; return true; }
static bool vfs_reserve(vfs_node_t *node, size_t size)
{ CHECK(node == &destination, "wrong reserve target"); reserve_count++; ticks += 13; if (reserve_failure) return false; ensure_file_capacity(size); return true; }
static bool vfs_append(vfs_node_t *node, const char *bytes, size_t count)
{
    CHECK(node == &destination, "wrong append target"); append_count++; ticks += 11;
    if (fail_append_number && append_count == fail_append_number) return false;
    ensure_file_capacity(node->size + count); memcpy(node->data + node->size, bytes, count); node->size += count; return true;
}
static bool vfs_mount_flush_single(vfs_node_t *node)
{
    CHECK(node == &destination && node->mount, "RAM destination invoked device persistence");
    CHECK(!observed_saved, "persistence occurred after Saved"); disk_flushes++; ticks += 17;
    if (flush_failure) return false; persisted = true; return true;
}
'''
    vfs = (ROOT / "src/kernel/vfs.c").read_text()
    for signature in ("static bool vfs_mount_sync_node", "bool vfs_flush_node"):
        program += function_definition(vfs, signature) + "\n"
    program += "#define malloc wget_test_alloc\n#define free wget_test_free\n"
    wget = (ROOT / "src/sbin/cmd_wget.c").read_text()
    program += re.sub(r"^#include[^\n]*\n", "", wget, flags=re.M).replace('__asm__ volatile ("pause");', "(void)0;")
    program += r'''
#undef malloc
#undef free
static void reset(const char *label, const uint8_t *reply, size_t len, size_t fragmentation, bool ram)
{
    CHECK(allocation_count == 0, "previous command leaked allocations"); scenario = label;
    input = reply; input_size = len; input_position = 0; max_read = fragmentation; ticks = 1000;
    output[0] = trace[0] = sent_request[0] = 0; output_length = 0;
    read_count = append_count = reserve_count = open_count = truncates = disk_flushes = 0;
    close_count = release_count = tls_closes = 0; fail_read_number = fail_append_number = 0;
    flush_failure = reserve_failure = socket_fd_failure = send_failure = transport_error = false;
    socket_state = (net_tcp_socket_t){0}; is_ram = ram; persisted = observed_saved = false;
    ensure_file_capacity(11); memset(destination.data, 0x99, 11); destination.size = 11;
}
static bool run(const char *args)
{
    shell_state_t shell = {0}; shell_output_t out = {0};
    bool ok = shell_cmd_wget(&shell, &out, args);
    CHECK(allocation_count == 0, "wget leaked buffers or TLS session");
    CHECK(close_count == 1 || (socket_fd_failure && release_count == 1), "wget leaked socket ownership");
    CHECK(close_count + release_count == 1, "wget released socket twice");
    return ok;
}
static void check_success(const uint8_t *body, size_t size, bool profile, bool chunked)
{
    CHECK(observed_saved && !strstr(output, "error:"), "successful transfer omitted Saved or printed error");
    CHECK(destination.size == size && !memcmp(destination.data, body, size), "download bytes were lost or changed");
    CHECK(open_count == 1 && truncates == 0, "successful transfer redundantly truncated the file");
    CHECK(disk_flushes == (is_ram ? 0u : 1u), "wrong persistence count");
    CHECK(!strstr(output, "HTTP headers received:"), "default download printed response headers");
    CHECK(strstr(sent_request, "GET /file.bin HTTP/1.1\r\n"), "wrong HTTP request");
    CHECK(reserve_count == (chunked ? 0u : 1u), "Content-Length preallocation was lost or repeated");
    if (profile)
    {
        size_t bytes, calls;
        unsigned long long setup, read_ms, append_ms, reserve_ms, flush_ms, total;
        CHECK(sscanf(trace, "[wget] profile bytes=%zu setup_ms=%llu read_ms=%llu append_ms=%llu reserve_ms=%llu flush_ms=%llu total_ms=%llu reads=%zu",
            &bytes, &setup, &read_ms, &append_ms, &reserve_ms, &flush_ms, &total, &calls) == 8, "profile record missing fields");
        CHECK(bytes == size && calls == read_count, "profile byte or read count is wrong");
        CHECK(read_ms == read_count * 7 && append_ms == append_count * 11, "profile receive/append time is wrong");
        CHECK(reserve_ms == reserve_count * 13 && flush_ms == disk_flushes * 17, "profile reserve/flush time is wrong");
        CHECK(setup + read_ms + append_ms + reserve_ms + flush_ms == total, "profile phases do not cover elapsed time");
    }
    else CHECK(trace[0] == 0, "unrequested profile output");
}
static void check_failure(const char *message)
{
    CHECK(!observed_saved && !strstr(output, "Saved "), "failed transfer reported Saved");
    CHECK(strstr(output, message), "missing expected failure diagnostic");
    CHECK(open_count == 0 || (truncates == 1 && destination.size == 0), "failure retained partial destination");
}
int main(void)
{
    scenario = "initialization";
    size_t body_size = 131101;
    uint8_t *body = malloc(body_size), *reply = malloc(body_size + 4096);
    CHECK(body && reply, "fixture allocation");
    for (size_t i = 0; i < body_size; i++) body[i] = (uint8_t)(i * 73u + i / 37u);
    size_t header = (size_t)sprintf((char *)reply, "HTTP/1.1 200 OK\r\nContent-Length: %zu\r\nContent-Type: application/octet-stream\r\n\r\n", body_size);
    memcpy(reply + header, body, body_size);
    const size_t fragments[] = {1, 2, 3, 7, 1460, 65536};
    for (size_t i = 0; i < sizeof(fragments) / sizeof(fragments[0]); ++i)
        for (unsigned profile = 0; profile < 2; ++profile)
        {
            reset("binary Content-Length", reply, header + body_size, fragments[i], false);
            CHECK(run(profile ? "--profile igb0 gateway:8000/file.bin /root/out.bin" : "igb0 gateway:8000/file.bin /root/out.bin"), "valid download failed");
            check_success(body, body_size, profile, false);
        }
    reset("RAM persistence no-op", reply, header + body_size, 123, true); flush_failure = true;
    CHECK(run("--profile gateway:8000/file.bin /tmp/out.bin"), "RAM destination depended on device flush");
    check_success(body, body_size, true, false);
    reset("HTTPS data path", reply, header + body_size, 123, false);
    CHECK(run("--profile https://gateway/file.bin /root/out.bin"), "HTTPS body transfer failed");
    check_success(body, body_size, true, false); CHECK(tls_closes == 1, "TLS session not closed");

    header = (size_t)sprintf((char *)reply, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 999999\r\n\r\n");
    size_t position = header, body_position = 0;
    while (body_position < body_size)
    {
        size_t count = body_size - body_position; if (count > 50003) count = 50003;
        position += (size_t)sprintf((char *)reply + position, "%zx;fixture=yes\r\n", count);
        memcpy(reply + position, body + body_position, count); position += count; body_position += count;
        memcpy(reply + position, "\r\n", 2); position += 2;
    }
    memcpy(reply + position, "0\r\nX-Fixture: done\r\n\r\n", 22); position += 22;
    for (size_t i = 0; i < sizeof(fragments) / sizeof(fragments[0]); ++i)
        for (unsigned profile = 0; profile < 2; ++profile)
        {
            reset("chunked with trailers", reply, position, fragments[i], false);
            CHECK(run(profile ? "--profile gateway:8000/file.bin /root/out.bin" : "gateway:8000/file.bin /root/out.bin"), "valid chunked download failed");
            check_success(body, body_size, profile, true);
        }
    const char *empty_chunk = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n";
    reset("empty chunked body without trailers", (const uint8_t *)empty_chunk, strlen(empty_chunk), 1, false);
    CHECK(run("--profile gateway:8000/file.bin"), "empty chunked response failed");
    check_success((const uint8_t *)"", 0, true, true);
    const char *empty_fixed = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
    reset("empty Content-Length body", (const uint8_t *)empty_fixed, strlen(empty_fixed), 1, false);
    CHECK(run("--profile gateway:8000/file.bin"), "empty fixed response failed");
    check_success((const uint8_t *)"", 0, true, false);
    const char *close_delimited = "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nabc";
    reset("close-delimited body", (const uint8_t *)close_delimited, strlen(close_delimited), 1, false);
    CHECK(run("gateway:8000/file.bin"), "complete close-delimited response failed");
    CHECK(destination.size == 3 && !memcmp(destination.data, "abc", 3) && observed_saved && persisted,
          "close-delimited bytes or persistence lost");
    CHECK(reserve_count == 0, "unknown length attempted preallocation");
    const char *extra_body = "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabcignore";
    reset("Content-Length boundary", (const uint8_t *)extra_body, strlen(extra_body), 65536, false);
    CHECK(run("gateway:8000/file.bin"), "extra transport bytes broke declared body");
    check_success((const uint8_t *)"abc", 3, false, false);
    const char *short_body = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nabc";
    reset("short body", (const uint8_t *)short_body, strlen(short_body), 1, false);
    CHECK(!run("gateway:8000/file.bin"), "short body succeeded"); check_failure("before full body");
    const char *short_header = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n";
    reset("incomplete headers", (const uint8_t *)short_header, strlen(short_header), 3, false);
    CHECK(!run("gateway:8000/file.bin"), "incomplete headers succeeded"); check_failure("incomplete HTTP response");
    reset("empty response", (const uint8_t *)"", 0, 1, false);
    CHECK(!run("gateway:8000/file.bin"), "empty response succeeded"); check_failure("incomplete HTTP response");
    const char *invalid_header = "Bad\r\n\r\nabc";
    reset("invalid HTTP status", (const uint8_t *)invalid_header, strlen(invalid_header), 2, false);
    CHECK(!run("gateway:8000/file.bin"), "invalid status succeeded"); check_failure("invalid HTTP status line");
    const char *incomplete_chunk = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n";
    reset("incomplete chunk trailer", (const uint8_t *)incomplete_chunk, strlen(incomplete_chunk), 2, false);
    CHECK(!run("gateway:8000/file.bin"), "incomplete chunked response succeeded"); check_failure("before complete chunked body");
    const char *valid = "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc";
    reset("flush failure", (const uint8_t *)valid, strlen(valid), 7, false); flush_failure = true;
    CHECK(!run("--profile gateway:8000/file.bin"), "device flush failure succeeded"); check_failure("failed to persist destination file");
    CHECK(disk_flushes == 1 && trace[0] == 0, "failed flush emitted success profile");
    for (unsigned error_flag = 0; error_flag < 2; ++error_flag)
    {
        reset("transport failure", (const uint8_t *)valid, strlen(valid), 1, false);
        fail_read_number = strlen(valid); transport_error = error_flag;
        CHECK(!run("gateway:8000/file.bin"), "TCP read error succeeded"); check_failure("TCP connection error");
        CHECK(disk_flushes == 0, "transport failure attempted success persistence");
    }
    reset("reserve failure", (const uint8_t *)valid, strlen(valid), 65536, false); reserve_failure = true;
    CHECK(!run("gateway:8000/file.bin"), "reserve failure succeeded"); check_failure("failed to reserve file storage");
    reset("append failure", (const uint8_t *)valid, strlen(valid), 1, false); fail_append_number = 2;
    CHECK(!run("gateway:8000/file.bin"), "append failure succeeded"); check_failure("failed to write to file");
    reset("send failure", (const uint8_t *)valid, strlen(valid), 1, false); send_failure = true;
    CHECK(!run("gateway:8000/file.bin"), "send failure succeeded"); check_failure("failed to send HTTP request");
    reset("descriptor failure", (const uint8_t *)valid, strlen(valid), 1, false); socket_fd_failure = true;
    CHECK(!run("gateway:8000/file.bin"), "descriptor failure succeeded"); check_failure("failed to allocate socket descriptor");
    free(destination.data); free(reply); free(body);
    puts("wget transfer behavior test passed");
    return 0;
}
'''
    compile_and_run("wget-transfer", program)
    print("wget transfer behavior test passed")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AssertionError as error:
        print(f"wget transfer behavior test failed: {error}", file=sys.stderr)
        raise SystemExit(1)
