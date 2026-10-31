#include "stdio.h"
#include "wchar.h"
#include "stdlib.h"
#include "string.h"
#include "pthread.h"
#include "unistd.h"
#include "errno.h"
#include "serial.h"
#include <float.h>

#define CHECK(condition, label) do { if (!(condition)) { \
    serial_printf("WIDE_STDIO_TEST: FAIL %s\n", label); return 1; } } while (0)
#define WORKERS 8u
#define RECORDS 64u

typedef struct { FILE *stream; pthread_t thread; unsigned index, failed; } writer_t;

static void *write_records(void *argument)
{
    writer_t *writer = argument;
    for (unsigned index = 0; index < RECORDS; ++index)
        if (fwprintf(writer->stream, L"[%08u]", writer->index) != 10) writer->failed = 1;
    return NULL;
}

int main(void)
{
    CHECK(sizeof(wchar_t) == 2 && LDBL_MANT_DIG == 64, "native wide/x87 ABI");
    wchar_t *output = calloc(128, sizeof(*output));
    char *bytes = malloc(128);
    char *path = malloc(96);
    CHECK(output && bytes && path, "buffers");
    static const wchar_t units[] = {0x03a9, 0xd83d, 0xde00, 0};
    int count = -1;
    CHECK(swprintf(output, 128, L"\u2603:%ls%n", units, &count) == 5 && count == 5, "wide unit count");
    CHECK(output[0] == 0x2603 && output[2] == 0x03a9 && output[3] == 0xd83d && output[4] == 0xde00, "Unicode units");
    CHECK(swprintf(output, 128, L"%.21Lf", 1.0L + 0x1p-60L) == 23, "long double count");
    CHECK(wcscmp(output, L"1.000000000000000000867") == 0, "long double precision");
    CHECK(swprintf(output, 4, L"abcdef") < 0 && output[3] == 0, "bounded output");
    CHECK(swprintf(output, 128, L"%s", "\xc3\xa9") < 0 && errno == EILSEQ, "ASCII conversion");
    CHECK(snprintf(bytes, 128, "%ls", units) < 0 && errno == EILSEQ, "narrow wide-string conversion");
    CHECK(snprintf(bytes, 128, "%lc", (wint_t)0x10041) < 0 && errno == EILSEQ, "wint no truncation");

    snprintf(path, 96, "/tmp/wide-stdio-%ld.bin", (long)getpid());
    FILE *stream = fopen(path, "w+");
    CHECK(stream && fwide(stream, 0) == 0 && fwide(stream, 1) > 0, "wide orientation");
    CHECK(fputws(L"ABC\n", stream) == 0 && fwprintf(stream, L"%d:%.2Lf\n", 17, 1.25L) == 8, "wide output");
    CHECK(fprintf(stream, "") < 0 && errno == EINVAL && ferror(stream), "byte orientation rejected");
    clearerr(stream);
    CHECK(fseek(stream, 0, SEEK_SET) == 0 && fwide(stream, -1) > 0, "orientation survives seek");
    CHECK(fgetws(output, 128, stream) == output && wcscmp(output, L"ABC\n") == 0, "wide input line");
    CHECK(ungetwc(L'Z', stream) == L'Z' && ftell(stream) == 3 && getwc(stream) == L'Z', "wide pushback");
    CHECK(fgetws(output, 128, stream) == output && wcscmp(output, L"17:1.25\n") == 0, "wide formatted line");
    CHECK(getwc(stream) == WEOF && feof(stream), "wide EOF");
    CHECK(ungetwc(WEOF, stream) == WEOF && feof(stream), "WEOF preserves state");
    CHECK(ungetwc(L'Q', stream) == L'Q' && !feof(stream) && getwc(stream) == L'Q', "wide EOF recovery");
    CHECK(fclose(stream) == 0, "close first");

    stream = fopen(path, "wb");
    CHECK(stream && fputc(255, stream) == 255 && fclose(stream) == 0, "seed invalid byte");
    stream = fopen(path, "rb");
    CHECK(stream && fgetwc(stream) == WEOF && errno == EILSEQ && ferror(stream) && !feof(stream), "reject invalid byte");
    CHECK(fclose(stream) == 0, "close invalid input");

    stream = fopen(path, "w+");
    CHECK(stream != NULL, "open records");
    writer_t *writers = calloc(WORKERS, sizeof(*writers));
    CHECK(writers != NULL, "worker records");
    for (unsigned index = 0; index < WORKERS; ++index)
    {
        writers[index].stream = stream;
        writers[index].index = index;
        CHECK(pthread_create(&writers[index].thread, NULL, write_records, &writers[index]) == 0, "create");
    }
    for (unsigned index = 0; index < WORKERS; ++index)
        CHECK(pthread_join(writers[index].thread, NULL) == 0 && !writers[index].failed, "join");
    CHECK(ftell(stream) == WORKERS * RECORDS * 10 && fseek(stream, 0, SEEK_SET) == 0, "record position");
    for (unsigned index = 0; index < WORKERS * RECORDS; ++index)
    {
        CHECK(fgetwc(stream) == L'[', "record start");
        for (unsigned digit = 0; digit < 7; ++digit) CHECK(fgetwc(stream) == L'0', "record digits");
        wint_t owner = fgetwc(stream);
        CHECK(owner >= L'0' && owner < L'0' + WORKERS && fgetwc(stream) == L']', "record owner");
    }
    CHECK(fclose(stream) == 0, "close records");
    free(writers);
    free(path);
    free(bytes);
    free(output);
    serial_printf("WIDE_STDIO_TEST: PASS wchar=16 longdouble=64 orientation=1 records=512\n");
    return 0;
}
