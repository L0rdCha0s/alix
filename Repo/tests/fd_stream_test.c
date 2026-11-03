#include "stdio.h"
#include "unistd.h"
#include "fcntl.h"
#include "stdlib.h"
#include "string.h"
#include "errno.h"
#include "serial.h"

#define CHECK(c,label) do{if(!(c)){serial_printf("FD_STREAM_TEST: FAIL %s line=%u errno=%d\n",label,__LINE__,errno);return 1;}}while(0)
typedef struct
{
    int pipes[2];
    char bytes[32768];
    FILE *stream;
} fixture_t;
int main(void)
{
    fixture_t *test = calloc(1, sizeof(*test)); CHECK(test, "heap fixture");
    CHECK(!pipe2(test->pipes, O_NONBLOCK | O_CLOEXEC), "atomic nonblocking pipe creation");
    CHECK(fcntl(test->pipes[0], F_GETFL) == (O_RDONLY | O_NONBLOCK) &&
          fcntl(test->pipes[1], F_GETFL) == (O_WRONLY | O_NONBLOCK), "pipe access/nonblock flags");
    CHECK(read(test->pipes[0], test->bytes, 1) == -1 && errno == EAGAIN, "empty pipe is nonblocking");
    int alias = dup(test->pipes[0]); CHECK(alias >= 0, "pipe alias");
    CHECK(!fcntl(alias, F_SETFL, O_WRONLY) && fcntl(test->pipes[0], F_GETFL) == O_RDONLY &&
          fcntl(test->pipes[0], F_GETFD) == FD_CLOEXEC && fcntl(alias, F_GETFD) == 0,
          "shared status preserves immutable access and independent slot flags");
    CHECK(!fcntl(alias, F_SETFL, O_NONBLOCK) &&
          fcntl(alias, F_SETFL, 0x40000000) == -1 && errno == EINVAL &&
          fcntl(test->pipes[0], F_GETFL) == (O_RDONLY | O_NONBLOCK), "unsupported flags leave status intact");
    CHECK(write(test->pipes[1], test->bytes, 16384) == 16384 &&
          write(test->pipes[1], "x", 1) == -1 && errno == EAGAIN, "nonblocking full pipe");
    CHECK(read(alias, test->bytes, 2048) == 2048 &&
          write(test->pipes[1], test->bytes, 4096) == -1 && errno == EAGAIN &&
          read(alias, test->bytes, 2048) == 2048 &&
          write(test->pipes[1], test->bytes, 4096) == 4096, "nonblocking atomic write admission");
    CHECK(!close(alias) && !close(test->pipes[0]) && !close(test->pipes[1]), "close pipe aliases");
    int descriptor = open("/tmp/fd-stream", O_RDWR | O_CREAT | O_TRUNC, 0666);
    CHECK(descriptor >= 0 && write(descriptor, "abcd", 4) == 4 && lseek(descriptor, 1, SEEK_SET) == 1,
          "initial descriptor content/position");
    test->stream = fdopen(descriptor, "w+");
    CHECK(test->stream && ftello(test->stream) == 1 && fgetc(test->stream) == 'b' && ftello(test->stream) == 2,
          "fdopen preserves content and current position");
    CHECK(!fseeko(test->stream, ((off_t)1 << 33) + 7, SEEK_SET) &&
          ftello(test->stream) == ((off_t)1 << 33) + 7, "native 64-bit stream positions");
    CHECK(!fclose(test->stream) && fcntl(descriptor, F_GETFL) == -1 && errno == EBADF,
          "successful fdopen transfers descriptor lifetime");
    descriptor = open("/tmp/fd-stream", O_RDONLY);
    CHECK(descriptor >= 0 && !fdopen(descriptor, "w") && errno == EINVAL &&
          read(descriptor, test->bytes, 4) == 4 && !memcmp(test->bytes, "abcd", 4) && !close(descriptor),
          "failed fdopen preserves descriptor and data");
    descriptor = open("/tmp/fd-stream", O_RDWR);
    alias = dup(descriptor);
    CHECK(descriptor >= 0 && alias >= 0 && lseek(alias, 0, SEEK_SET) == 0, "append alias");
    test->stream = fdopen(descriptor, "a");
    CHECK(test->stream && (fcntl(alias, F_GETFL) & O_APPEND) &&
          fputc('!', test->stream) == '!' && !fflush(test->stream) && ftello(test->stream) == 5,
          "fdopen enables shared atomic append");
    CHECK(!fseeko(test->stream, 0, SEEK_SET) && fputc('?', test->stream) == '?' && !fflush(test->stream) &&
          pread(alias, test->bytes, 6, 0) == 6 && !memcmp(test->bytes, "abcd!?", 6), "append ignores an earlier seek for writes");
    CHECK(!fclose(test->stream) && fcntl(alias, F_GETFL) >= 0 && !close(alias), "append alias remains alive");
    CHECK(!pipe(test->pipes), "pipe stream");
    test->stream = fdopen(test->pipes[1], "a");
    CHECK(test->stream && fputs("pipe", test->stream) >= 0 && !fflush(test->stream) &&
          read(test->pipes[0], test->bytes, 4) == 4 && !memcmp(test->bytes, "pipe", 4) &&
          !fclose(test->stream) && !close(test->pipes[0]), "append-mode pipe stream does not seek");
    CHECK(!unlink("/tmp/fd-stream"), "remove fixture file");
    free(test);
    serial_printf("FD_STREAM_TEST: PASS aliases=1 nonblock=1 pipe_atomic=1 fdopen=1 append=1 offset64=1\n");
    return 0;
}
