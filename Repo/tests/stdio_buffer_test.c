#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "errno.h"
#include "pthread.h"
#include "unistd.h"
#include "usyscall.h"
#include "sys/stat.h"
#include "serial.h"
#include "wchar.h"

#define CHECK(c, label) do { if (!(c)) { serial_printf("STDIO_BUFFER_TEST: FAIL %s\n", label); return 1; } } while (0)

/* The implementation deliberately ignores caller storage. Check that contract
 * before this private stack frame ceases to exist; no stack address is shared
 * with the later flushing thread. */
static bool configure_owned_buffer(FILE *stream, int mode, size_t size)
{
    char caller_storage[64];
    memset(caller_storage, 0x5a, sizeof(caller_storage));
    if (setvbuf(stream, caller_storage, mode, size) != 0) return false;
    bool owned = stream->buffer != (unsigned char *)caller_storage;
    memset(caller_storage, 0xa5, sizeof(caller_storage));
    return owned;
}

static bool file_size(FILE *stream, uint64_t expected)
{
    struct stat info;
    return fstat(fileno(stream), &info) == 0 && info.st_size == expected;
}

typedef struct { uint32_t stop, failed, passes; } flusher_t;
static void *flush_concurrently(void *argument)
{
    flusher_t *flusher = argument;
    if (sys_thread_set_affinity(1) != 0) __atomic_store_n(&flusher->failed, 1, __ATOMIC_RELEASE);
    while (!__atomic_load_n(&flusher->stop, __ATOMIC_ACQUIRE))
    {
        if (fflush(NULL) != 0) __atomic_store_n(&flusher->failed, 1, __ATOMIC_RELEASE);
        __atomic_add_fetch(&flusher->passes, 1, __ATOMIC_RELAXED);
        sys_yield();
    }
    return NULL;
}

int main(int argc, char **argv)
{
    if (argc > 1 && strcmp(argv[1], "exit") == 0)
    {
        static const char marker[] = "STDIO_BUFFER_EXIT_TEST: PASS buffered=1\n";
        CHECK(setvbuf(stdout, NULL, _IOFBF, 128) == 0, "exit buffer");
        CHECK(fwrite(marker, 1, sizeof(marker) - 1, stdout) == sizeof(marker) - 1,
              "exit queued output");
        CHECK(stdout->write_length == sizeof(marker) - 1, "exit output still queued");
        /* The marker is emitted only by libc's exit-time global flush. */
        return 0;
    }

    char *path = malloc(128), *scratch = calloc(1, 128);
    CHECK(path && scratch, "allocation");
    snprintf(path, 128, "/tmp/stdio-buffer-%ld", (long)getpid());
    FILE *stream = fopen(path, "w+");
    CHECK(stream && configure_owned_buffer(stream, _IOFBF, 32), "owned full buffer");
    CHECK(fwrite("abcdefghij", 1, 10, stream) == 10 && ftell(stream) == 10,
          "buffered logical position");
    CHECK(file_size(stream, 0), "output not prematurely flushed");
    CHECK(fflush(NULL) == 0 && file_size(stream, 10), "global output flush");
    errno = 0; CHECK(setvbuf(stream, NULL, _IONBF, 0) == -1 && errno == EBUSY,
                     "late buffer change rejected");
    CHECK(fseek(stream, 0, SEEK_SET) == 0 && fgetc(stream) == 'a' && ftell(stream) == 1,
          "read ahead logical position");
    CHECK(ungetc('Z', stream) == 'Z' && ftell(stream) == 0 && fgetc(stream) == 'Z',
          "buffered pushback position");
    CHECK(fseek(stream, 2, SEEK_CUR) == 0 && ftell(stream) == 3 && fgetc(stream) == 'd',
          "relative seek accounts read ahead");
    CHECK(fseek(stream, 2, SEEK_SET) == 0 && fgetc(stream) == 'c' && fflush(stream) == 0,
          "input flush resynchronizes position");
    CHECK(fwrite("XY", 1, 2, stream) == 2 && ftell(stream) == 5,
          "update stream writes at logical position");
    CHECK(fseek(stream, 0, SEEK_SET) == 0 && fread(scratch, 1, 10, stream) == 10 &&
          memcmp(scratch, "abcXYfghij", 10) == 0, "update stream data");
    CHECK(fgetc(stream) == EOF && feof(stream), "buffered EOF");
    rewind(stream); CHECK(!feof(stream) && fgetc(stream) == 'a', "rewind clears EOF");
    CHECK(fclose(stream) == 0, "full close");

    stream = fopen(path, "w+");
    CHECK(stream && configure_owned_buffer(stream, _IOLBF, 16), "line buffer");
    CHECK(fwrite("abc", 1, 3, stream) == 3 && file_size(stream, 0), "line prefix queued");
    FILE *input = fopen(path, "r");
    /* Prompt flushing is an interactive/unbuffered input rule. A regular
     * file now defaults to full buffering and must not flush other streams. */
    CHECK(input && setvbuf(input, NULL, _IONBF, 0) == 0 && fgetc(input) == 'a' &&
          file_size(stream, 3) && fclose(input) == 0,
          "unbuffered input request flushes line output");
    CHECK(fwrite("\ndef", 1, 4, stream) == 4 && file_size(stream, 4) && ftell(stream) == 7,
          "newline flush leaves suffix queued");
    CHECK(fclose(stream) == 0, "close flushes suffix");
    stream = fopen(path, "r");
    CHECK(stream && setvbuf(stream, NULL, _IOLBF, 16) == 0 &&
          fgets(scratch, 128, stream) == scratch && strcmp(scratch, "abc\n") == 0 &&
          fgets(scratch, 128, stream) == scratch && strcmp(scratch, "def") == 0,
          "line buffered input");
    CHECK(fclose(stream) == 0, "line input close");

    stream = fopen(path, "w+");
    CHECK(stream && setvbuf(stream, NULL, _IONBF, 0) == 0 &&
          fwrite("raw", 1, 3, stream) == 3 && file_size(stream, 3), "unbuffered output");
    CHECK(fseek(stream, 0, SEEK_SET) == 0 && fread(scratch, 1, 3, stream) == 3 &&
          memcmp(scratch, "raw", 3) == 0 && fclose(stream) == 0, "unbuffered input");

    wchar_t *wide = calloc(16, sizeof(*wide));
    stream = fopen(path, "w+");
    CHECK(wide && stream && setvbuf(stream, NULL, _IOFBF, 16) == 0 &&
          fputws(L"wide\n", stream) == 0 && file_size(stream, 0) && ftell(stream) == 5,
          "wide buffered output");
    CHECK(fseek(stream, 0, SEEK_SET) == 0 && fputc('x', stream) == EOF,
          "wide orientation retained across seek");
    clearerr(stream);
    CHECK(fgetws(wide, 16, stream) == wide && wcscmp(wide, L"wide\n") == 0 &&
          fclose(stream) == 0, "wide buffered input");
    free(wide);

    flusher_t *flusher = calloc(1, sizeof(*flusher));
    pthread_t *thread = calloc(1, sizeof(*thread));
    CHECK(flusher && thread && pthread_create(thread, NULL, flush_concurrently, flusher) == 0,
          "flush thread");
    bool okay = true;
    for (unsigned index = 0; index < 128; ++index)
    {
        stream = fopen(path, "w");
        if (!stream) { okay = false; break; }
        if (!configure_owned_buffer(stream, _IOFBF, 32) || fwrite("owned", 1, 5, stream) != 5)
            okay = false;
        sys_yield();
        if (fclose(stream) != 0) okay = false;
        if (!okay) break;
    }
    __atomic_store_n(&flusher->stop, 1, __ATOMIC_RELEASE);
    CHECK(pthread_join(*thread, NULL) == 0 && okay &&
          !__atomic_load_n(&flusher->failed, __ATOMIC_ACQUIRE) &&
          __atomic_load_n(&flusher->passes, __ATOMIC_RELAXED) > 0, "flush-close lifetime");
    free(thread); free(flusher); free(scratch); free(path);
    serial_printf("STDIO_BUFFER_TEST: PASS modes=3 positions=1 owned_buffer=1 wide=1 flush_close=128\n");
    return 0;
}
