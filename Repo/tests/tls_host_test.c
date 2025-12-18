#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "net/tls.h"

#define ARRAY_LEN(a) (sizeof(a) / sizeof((a)[0]))

static bool g_verbose = false;

void serial_printf(const char *format, ...)
{
    if (!g_verbose)
    {
        return;
    }
    va_list ap;
    va_start(ap, format);
    vfprintf(stderr, format, ap);
    va_end(ap);
}

static uint64_t host_now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)(ts.tv_nsec / 1000000L);
}

static void sleep_ms(uint32_t ms)
{
    struct timespec ts;
    ts.tv_sec = (time_t)(ms / 1000U);
    ts.tv_nsec = (long)(ms % 1000U) * 1000000L;
    nanosleep(&ts, NULL);
}

static int hex_nibble(char c)
{
    if (c >= '0' && c <= '9')
    {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f')
    {
        return 10 + (c - 'a');
    }
    if (c >= 'A' && c <= 'F')
    {
        return 10 + (c - 'A');
    }
    return -1;
}

static bool parse_hex(const char *hex, uint8_t *out, size_t out_len)
{
    if (!hex || !out)
    {
        return false;
    }
    for (size_t i = 0; i < out_len; ++i)
    {
        int hi = hex_nibble(hex[i * 2]);
        int lo = hex_nibble(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0)
        {
            return false;
        }
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return true;
}

static void format_hex(const uint8_t *data, size_t len, char *out, size_t out_cap)
{
    static const char digits[] = "0123456789abcdef";
    if (!out || out_cap == 0)
    {
        return;
    }
    size_t needed = len * 2 + 1;
    if (needed > out_cap)
    {
        out[0] = '\0';
        return;
    }
    for (size_t i = 0; i < len; ++i)
    {
        out[i * 2] = digits[(data[i] >> 4) & 0xF];
        out[i * 2 + 1] = digits[data[i] & 0xF];
    }
    out[len * 2] = '\0';
}

static bool read_keylog_master_secret(const char *path,
                                      const uint8_t client_random[32],
                                      uint8_t out_master[48])
{
    FILE *fp = fopen(path, "r");
    if (!fp)
    {
        return false;
    }

    char line[512];
    while (fgets(line, sizeof(line), fp))
    {
        if (strncmp(line, "CLIENT_RANDOM ", 14) != 0)
        {
            continue;
        }

        char *cursor = line + 14;
        while (*cursor == ' ')
        {
            cursor++;
        }
        char *rand_hex = cursor;
        while (*cursor && *cursor != ' ' && *cursor != '\r' && *cursor != '\n')
        {
            cursor++;
        }
        if (*cursor == '\0')
        {
            continue;
        }
        *cursor++ = '\0';
        while (*cursor == ' ')
        {
            cursor++;
        }
        char *ms_hex = cursor;
        while (*cursor && *cursor != ' ' && *cursor != '\r' && *cursor != '\n')
        {
            cursor++;
        }
        *cursor = '\0';

        if (strlen(rand_hex) != 64 || strlen(ms_hex) != 96)
        {
            continue;
        }

        uint8_t rand_bytes[32];
        uint8_t ms_bytes[48];
        if (!parse_hex(rand_hex, rand_bytes, sizeof(rand_bytes)) ||
            !parse_hex(ms_hex, ms_bytes, sizeof(ms_bytes)))
        {
            continue;
        }

        if (memcmp(rand_bytes, client_random, sizeof(rand_bytes)) != 0)
        {
            continue;
        }

        memcpy(out_master, ms_bytes, sizeof(ms_bytes));
        fclose(fp);
        return true;
    }

    fclose(fp);
    return false;
}

static bool set_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0)
    {
        return false;
    }
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
    {
        return false;
    }
    return true;
}

static int connect_localhost(uint16_t port, uint32_t timeout_ms)
{
    uint64_t start = host_now_ms();
    while (host_now_ms() - start < timeout_ms)
    {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0)
        {
            return -1;
        }

        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

        if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0)
        {
            return fd;
        }

        close(fd);
        sleep_ms(10);
    }
    return -1;
}

static bool run_command_wait(const char *const argv[], const char *log_path)
{
    pid_t pid = fork();
    if (pid < 0)
    {
        return false;
    }
    if (pid == 0)
    {
        if (log_path)
        {
            int fd = open(log_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (fd >= 0)
            {
                dup2(fd, STDOUT_FILENO);
                dup2(fd, STDERR_FILENO);
                close(fd);
            }
        }
        execvp(argv[0], (char *const *)argv);
        _exit(127);
    }

    int status = 0;
    if (waitpid(pid, &status, 0) < 0)
    {
        return false;
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
    {
        return false;
    }
    return true;
}

static pid_t spawn_s_server(const char *cert_path,
                            const char *key_path,
                            const char *cipher,
                            const char *groups,
                            const char *keylog_path,
                            const char *log_path,
                            uint16_t port)
{
    pid_t pid = fork();
    if (pid < 0)
    {
        return -1;
    }

    if (pid == 0)
    {
        if (log_path)
        {
            int fd = open(log_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (fd >= 0)
            {
                dup2(fd, STDOUT_FILENO);
                dup2(fd, STDERR_FILENO);
                close(fd);
            }
        }

        char accept_arg[64];
        snprintf(accept_arg, sizeof(accept_arg), "127.0.0.1:%u", (unsigned)port);

        const char *argv[32];
        size_t argc = 0;
        argv[argc++] = "openssl";
        argv[argc++] = "s_server";
        argv[argc++] = "-accept";
        argv[argc++] = accept_arg;
        argv[argc++] = "-tls1_2";
        argv[argc++] = "-cert";
        argv[argc++] = cert_path;
        argv[argc++] = "-key";
        argv[argc++] = key_path;
        argv[argc++] = "-cipher";
        argv[argc++] = cipher;
        if (groups && groups[0])
        {
            argv[argc++] = "-groups";
            argv[argc++] = groups;
        }
        argv[argc++] = "-keylogfile";
        argv[argc++] = keylog_path;
        argv[argc++] = "-naccept";
        argv[argc++] = "1";
        argv[argc++] = "-www";
        argv[argc++] = NULL;

        execvp(argv[0], (char *const *)argv);
        _exit(127);
    }

    return pid;
}

static bool wait_process_exit(pid_t pid, uint32_t timeout_ms)
{
    uint64_t start = host_now_ms();
    while (host_now_ms() - start < timeout_ms)
    {
        int status = 0;
        pid_t got = waitpid(pid, &status, WNOHANG);
        if (got < 0)
        {
            return false;
        }
        if (got == pid)
        {
            return WIFEXITED(status) && WEXITSTATUS(status) == 0;
        }
        sleep_ms(10);
    }
    kill(pid, SIGTERM);
    return false;
}

typedef struct
{
    const char *name;
    const char *cert_path;
    const char *key_path;
    const char *cipher;
    const char *groups;
    uint16_t expected_cipher_suite;
    tls_key_exchange_t expected_kx;
    uint16_t expected_curve;
    size_t expected_ecdsa_pub_len;
} tls_case_t;

static bool run_tls_case(const tls_case_t *test, const char *tmpdir)
{
    char keylog_path[512];
    char server_log_path[512];
    snprintf(keylog_path, sizeof(keylog_path), "%s/%s.keylog", tmpdir, test->name);
    snprintf(server_log_path, sizeof(server_log_path), "%s/%s.server.log", tmpdir, test->name);

    uint16_t port = 42000;
    port = (uint16_t)(42000U + (getpid() % 1000U));

    pid_t server_pid = -1;
    for (int attempt = 0; attempt < 10; ++attempt)
    {
        server_pid = spawn_s_server(test->cert_path,
                                    test->key_path,
                                    test->cipher,
                                    test->groups,
                                    keylog_path,
                                    server_log_path,
                                    (uint16_t)(port + (uint16_t)attempt));
        if (server_pid < 0)
        {
            continue;
        }

        int fd = connect_localhost((uint16_t)(port + (uint16_t)attempt), 2000);
        if (fd < 0)
        {
            wait_process_exit(server_pid, 2000);
            server_pid = -1;
            continue;
        }

        if (!set_nonblocking(fd))
        {
            close(fd);
            wait_process_exit(server_pid, 2000);
            return false;
        }

        tls_session_t session;
        if (!tls_session_init_fd(&session, fd))
        {
            close(fd);
            wait_process_exit(server_pid, 2000);
            return false;
        }

        if (!tls_session_handshake(&session, "localhost"))
        {
            close(fd);
            wait_process_exit(server_pid, 5000);

            uint8_t openssl_master[48];
            if (read_keylog_master_secret(keylog_path, session.client_random, openssl_master))
            {
                char ours_hex[97];
                char theirs_hex[97];
                format_hex(session.master_secret, sizeof(session.master_secret), ours_hex, sizeof(ours_hex));
                format_hex(openssl_master, sizeof(openssl_master), theirs_hex, sizeof(theirs_hex));
                printf("tls_host_test: %s: handshake failed (master secret compare)\n", test->name);
                printf("  ours:   %s\n", ours_hex);
                printf("  openssl:%s\n", theirs_hex);
            }
            return false;
        }

        if (session.cipher_suite != test->expected_cipher_suite)
        {
            printf("tls_host_test: %s: cipher mismatch (got 0x%04x expected 0x%04x)\n",
                   test->name,
                   session.cipher_suite,
                   test->expected_cipher_suite);
            close(fd);
            wait_process_exit(server_pid, 2000);
            return false;
        }

        if (session.key_exchange != test->expected_kx)
        {
            printf("tls_host_test: %s: key_exchange mismatch (got %d expected %d)\n",
                   test->name,
                   (int)session.key_exchange,
                   (int)test->expected_kx);
            close(fd);
            wait_process_exit(server_pid, 2000);
            return false;
        }

        if (test->expected_curve != 0 && session.ecdhe_named_curve != test->expected_curve)
        {
            printf("tls_host_test: %s: curve mismatch (got %u expected %u)\n",
                   test->name,
                   (unsigned)session.ecdhe_named_curve,
                   (unsigned)test->expected_curve);
            close(fd);
            wait_process_exit(server_pid, 2000);
            return false;
        }

        if (test->expected_ecdsa_pub_len != 0 && session.server_ecdsa_public_len != test->expected_ecdsa_pub_len)
        {
            printf("tls_host_test: %s: ECDSA pubkey len mismatch (got %zu expected %zu)\n",
                   test->name,
                   session.server_ecdsa_public_len,
                   test->expected_ecdsa_pub_len);
            close(fd);
            wait_process_exit(server_pid, 2000);
            return false;
        }

        const char request[] =
            "GET / HTTP/1.1\r\n"
            "Host: localhost\r\n"
            "Connection: close\r\n"
            "\r\n";
        if (!tls_session_send(&session, (const uint8_t *)request, strlen(request)))
        {
            printf("tls_host_test: %s: failed to send HTTP request\n", test->name);
            close(fd);
            wait_process_exit(server_pid, 2000);
            return false;
        }

        char response[256];
        size_t response_len = 0;
        uint64_t start = host_now_ms();
        while (host_now_ms() - start < 3000 && response_len < sizeof(response) - 1)
        {
            uint8_t buf[128];
            size_t got = tls_session_recv(&session, buf, sizeof(buf));
            if (got == 0)
            {
                sleep_ms(10);
                continue;
            }
            size_t copy = got;
            if (copy > sizeof(response) - 1 - response_len)
            {
                copy = sizeof(response) - 1 - response_len;
            }
            memcpy(response + response_len, buf, copy);
            response_len += copy;
            if (response_len >= 8)
            {
                break;
            }
        }
        response[response_len] = '\0';
        if (response_len == 0 || strncmp(response, "HTTP/", 5) != 0)
        {
            printf("tls_host_test: %s: unexpected HTTP response prefix: '%s'\n",
                   test->name,
                   response_len ? response : "<empty>");
            close(fd);
            wait_process_exit(server_pid, 2000);
            return false;
        }

        close(fd);

        if (!wait_process_exit(server_pid, 5000))
        {
            printf("tls_host_test: %s: openssl s_server did not exit cleanly\n", test->name);
            return false;
        }

        uint8_t openssl_master[48];
        if (!read_keylog_master_secret(keylog_path, session.client_random, openssl_master))
        {
            printf("tls_host_test: %s: failed to read master secret from %s\n", test->name, keylog_path);
            return false;
        }

        if (memcmp(openssl_master, session.master_secret, sizeof(openssl_master)) != 0)
        {
            char ours_hex[97];
            char theirs_hex[97];
            format_hex(session.master_secret, sizeof(session.master_secret), ours_hex, sizeof(ours_hex));
            format_hex(openssl_master, sizeof(openssl_master), theirs_hex, sizeof(theirs_hex));
            printf("tls_host_test: %s: master secret mismatch\n", test->name);
            printf("  ours:   %s\n", ours_hex);
            printf("  openssl:%s\n", theirs_hex);
            return false;
        }

        printf("tls_host_test: %s: ok\n", test->name);
        return true;
    }

    printf("tls_host_test: %s: failed to start/connect to openssl s_server\n", test->name);
    return false;
}

int main(void)
{
    signal(SIGPIPE, SIG_IGN);

    if (getenv("ALIX_TLS_HOST_TEST_VERBOSE"))
    {
        g_verbose = true;
    }

    char tmp_template[] = "/tmp/alix_tls_host_test.XXXXXX";
    char *tmpdir = mkdtemp(tmp_template);
    if (!tmpdir)
    {
        printf("tls_host_test: mkdtemp failed: %s\n", strerror(errno));
        return 1;
    }

    char gen_log[512];
    snprintf(gen_log, sizeof(gen_log), "%s/gen.log", tmpdir);

    char rsa_key[512];
    char rsa_cert[512];
    char ecdsa256_key[512];
    char ecdsa256_cert[512];
    char ecdsa384_key[512];
    char ecdsa384_cert[512];
    snprintf(rsa_key, sizeof(rsa_key), "%s/rsa.key", tmpdir);
    snprintf(rsa_cert, sizeof(rsa_cert), "%s/rsa.crt", tmpdir);
    snprintf(ecdsa256_key, sizeof(ecdsa256_key), "%s/ecdsa256.key", tmpdir);
    snprintf(ecdsa256_cert, sizeof(ecdsa256_cert), "%s/ecdsa256.crt", tmpdir);
    snprintf(ecdsa384_key, sizeof(ecdsa384_key), "%s/ecdsa384.key", tmpdir);
    snprintf(ecdsa384_cert, sizeof(ecdsa384_cert), "%s/ecdsa384.crt", tmpdir);

    {
        const char *const argv[] = {
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-sha256", "-nodes",
            "-keyout", rsa_key,
            "-out", rsa_cert,
            "-subj", "/CN=localhost",
            "-days", "1",
            NULL
        };
        if (!run_command_wait(argv, gen_log))
        {
            printf("tls_host_test: failed to generate RSA cert (see %s)\n", gen_log);
            return 1;
        }
    }

    {
        const char *const argv[] = {
            "openssl", "req", "-x509", "-newkey", "ec",
            "-pkeyopt", "ec_paramgen_curve:prime256v1",
            "-pkeyopt", "ec_param_enc:named_curve",
            "-sha256", "-nodes",
            "-keyout", ecdsa256_key,
            "-out", ecdsa256_cert,
            "-subj", "/CN=localhost",
            "-days", "1",
            NULL
        };
        if (!run_command_wait(argv, gen_log))
        {
            printf("tls_host_test: failed to generate ECDSA P-256 cert (see %s)\n", gen_log);
            return 1;
        }
    }

    {
        const char *const argv[] = {
            "openssl", "req", "-x509", "-newkey", "ec",
            "-pkeyopt", "ec_paramgen_curve:secp384r1",
            "-pkeyopt", "ec_param_enc:named_curve",
            "-sha256", "-nodes",
            "-keyout", ecdsa384_key,
            "-out", ecdsa384_cert,
            "-subj", "/CN=localhost",
            "-days", "1",
            NULL
        };
        if (!run_command_wait(argv, gen_log))
        {
            printf("tls_host_test: failed to generate ECDSA P-384 cert (see %s)\n", gen_log);
            return 1;
        }
    }

    const tls_case_t cases[] = {
        {
            .name = "ecdhe_ecdsa_p256_gcm",
            .cert_path = ecdsa256_cert,
            .key_path = ecdsa256_key,
            .cipher = "ECDHE-ECDSA-AES128-GCM-SHA256",
            .groups = "secp256r1",
            .expected_cipher_suite = 0xC02B,
            .expected_kx = TLS_KEY_EXCHANGE_ECDHE_ECDSA,
            .expected_curve = 23,
            .expected_ecdsa_pub_len = 65,
        },
        {
            .name = "ecdhe_ecdsa_p384_gcm",
            .cert_path = ecdsa384_cert,
            .key_path = ecdsa384_key,
            .cipher = "ECDHE-ECDSA-AES128-GCM-SHA256",
            .groups = "secp384r1",
            .expected_cipher_suite = 0xC02B,
            .expected_kx = TLS_KEY_EXCHANGE_ECDHE_ECDSA,
            .expected_curve = 24,
            .expected_ecdsa_pub_len = 97,
        },
        {
            .name = "ecdhe_rsa_p384_gcm",
            .cert_path = rsa_cert,
            .key_path = rsa_key,
            .cipher = "ECDHE-RSA-AES128-GCM-SHA256",
            .groups = "secp384r1",
            .expected_cipher_suite = 0xC02F,
            .expected_kx = TLS_KEY_EXCHANGE_ECDHE_RSA,
            .expected_curve = 24,
            .expected_ecdsa_pub_len = 0,
        },
        {
            .name = "rsa_aes128_sha256",
            .cert_path = rsa_cert,
            .key_path = rsa_key,
            .cipher = "AES128-SHA256",
            .groups = NULL,
            .expected_cipher_suite = 0x003C,
            .expected_kx = TLS_KEY_EXCHANGE_RSA,
            .expected_curve = 0,
            .expected_ecdsa_pub_len = 0,
        },
    };

    for (size_t i = 0; i < ARRAY_LEN(cases); ++i)
    {
        if (!run_tls_case(&cases[i], tmpdir))
        {
            printf("tls_host_test: failed (tmpdir=%s)\n", tmpdir);
            return 1;
        }
    }

    printf("tls_host_test: success\n");
    return 0;
}

