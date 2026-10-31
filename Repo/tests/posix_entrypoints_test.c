#include "errno.h"
#include "serial.h"
#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "sys/mman.h"
#include "sys/stat.h"
#include "sys/resource.h"
#include <stdarg.h>

#define CHECK(value, label) do { if (!(value)) { \
    serial_printf("POSIX_ENTRYPOINTS_TEST: FAIL %s\n", label); return 1; } } while (0)

static int print_arguments(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    int result = vprintf(format, args);
    va_end(args);
    return result;
}

int main(void)
{
    struct rlimit limit = { 123, 456 };
    errno = EDOM;
    CHECK(getrlimit(RLIMIT_AS, &limit) == 0 && limit.rlim_cur == RLIM_INFINITY &&
          limit.rlim_max == RLIM_INFINITY && errno == EDOM, "actual address-space quota policy");
    limit.rlim_cur = 123;
    limit.rlim_max = 456;
    CHECK(getrlimit(-1, &limit) == -1 && errno == EINVAL && limit.rlim_cur == 123 &&
          limit.rlim_max == 456, "unsupported limit rejected without mutation");
    CHECK(getrlimit(RLIMIT_AS, NULL) == -1 && errno == EFAULT, "null resource output");
    char *source = malloc(32);
    CHECK(source != NULL, "source allocation");
    strcpy(source, "Alix \xc3\xa9 bytes");
    char *copy = strdup(source);
    char *empty = strdup("");
    CHECK(copy && empty && copy != source && strcmp(copy, source) == 0 && empty[0] == 0,
          "owned string copies");
    source[0] = 'X';
    CHECK(copy[0] == 'A', "copy independence");
    free(source);
    free(copy);
    free(empty);

    FILE *stream = fopen("/tmp/posix-entrypoints-output", "w+");
    CHECK(stream != NULL, "open output");
    FILE *saved_stdout = stdout;
    stdout = stream;
    int printed = print_arguments("%s %d %.2f\n", "entry", -17, 1.25);
    stdout = saved_stdout;
    CHECK(printed == (int)strlen("entry -17 1.25\n"), "vprintf count");
    FILE *saved_stderr = stderr;
    stderr = stream;
    errno = ENOENT;
    perror("lookup");
    errno = EINVAL;
    perror("");
    errno = EIO;
    perror(NULL);
    stderr = saved_stderr;
    CHECK(fflush(stream) == 0, "flush diagnostics");

    char *expected = calloc(1, 512);
    char *actual = calloc(1, 512);
    CHECK(expected && actual, "capture allocation");
    int count = snprintf(expected, 512, "entry -17 1.25\nlookup: %s\n%s\n%s\n",
                         strerror(ENOENT), strerror(EINVAL), strerror(EIO));
    struct stat info;
    CHECK(count > 0 && count < 512 && fstat(fileno(stream), &info) == 0,
          "native file stat");
    CHECK(S_ISREG(info.st_mode) && !S_ISDIR(info.st_mode) && !S_ISLNK(info.st_mode) &&
          info.st_size == (uint64_t)count, "native type and size");
    CHECK(fseek(stream, 0, SEEK_SET) == 0 && fread(actual, 1, 511, stream) == (size_t)count &&
          strcmp(actual, expected) == 0, "captured formatting and diagnostics");
    CHECK(fclose(stream) == 0, "close output");
    free(expected);
    free(actual);

    unsigned char *page = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(page != MAP_FAILED, "map advice page");
    page[0] = 0x5a;
    page[4095] = 0xa5;
    CHECK(madvise(page, 4096, MADV_NORMAL) == 0 && page[0] == 0x5a && page[4095] == 0xa5,
          "normal advice preserves contents");
    CHECK(mprotect(page, 4096, PROT_NONE) == 0 && madvise(page, 4096, MADV_NORMAL) == 0 &&
          mprotect(page, 4096, PROT_READ | PROT_WRITE) == 0 &&
          page[0] == 0x5a && page[4095] == 0xa5, "normal advice on protected reservation");
    CHECK(munmap(page, 4096) == 0, "unmap advice page");
    errno = 0;
    CHECK(madvise(page, 4096, MADV_NORMAL) == -1 && errno != 0, "unowned advice rejected");
    serial_printf("POSIX_ENTRYPOINTS_TEST: PASS strdup=1 vprintf=1 perror=1 fstat_type=1 madv_normal=1 rlimit_as=1\n");
    return 0;
}
