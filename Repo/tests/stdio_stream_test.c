#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "pthread.h"
#include "unistd.h"
#include "serial.h"

extern uint64_t __alix_stdio_cached_tells;
extern uint64_t __alix_stdio_buffered_seeks;

#define WORKERS 8u
#define RECORDS 64u
#define RECORD_BYTES 32u
#define CHECK(condition, label) do { if (!(condition)) { \
    serial_printf("STDIO_STREAM_TEST: FAIL %s\n", label); return 1; } } while (0)

typedef struct
{
    FILE *stream;
    pthread_t thread;
    char record[RECORD_BYTES];
    unsigned failed;
} writer_t;

static void *write_records(void *argument)
{
    writer_t *writer = argument;
    for (unsigned index = 0; index < RECORDS; ++index)
    {
        if (fwrite(writer->record, 1, sizeof(writer->record), writer->stream) != sizeof(writer->record))
        {
            writer->failed = 1;
            break;
        }
    }
    return NULL;
}

int main(void)
{
    char *path = malloc(96);
    CHECK(path != NULL, "path allocation");
    snprintf(path, 96, "/tmp/stdio-stream-%ld.bin", (long)getpid());
    FILE *stream = fopen(path, "w+");
    CHECK(stream != NULL, "open");
    CHECK(fputs("abc\ndef", stream) == 0 && fseek(stream, 0, SEEK_SET) == 0, "seed");
    CHECK(fgetc(stream) == 'a' && ungetc('Z', stream) == 'Z' && ftell(stream) == 0, "pushback position");
    CHECK(ungetc('Y', stream) == 'Y' && fflush(NULL) == 0 &&
          fgetc(stream) == 'Y' && fgetc(stream) == 'Z', "multiple pushback order");
    CHECK(fgetc(stream) == 'b' && ungetc('X', stream) == 'X' && fflush(stream) == 0, "input flush");
    CHECK(ftell(stream) == 1 && fgetc(stream) == 'b', "input offset");
    fpos_t position = 0;
    CHECK(fgetpos(stream, &position) == 0 && fgetc(stream) == 'c', "get position");
    CHECK(fsetpos(stream, &position) == 0 && fgetc(stream) == 'c', "set position");
    CHECK(ungetc('c', stream) == 'c' && ungetc('b', stream) == 'b' &&
          ungetc('a', stream) == 'a' && ftell(stream) == 0, "three-byte BOM lookahead position");
    CHECK(fgetc(stream) == 'a' && fgetc(stream) == 'b' && fgetc(stream) == 'c', "three-byte BOM lookahead restore");
    while (fgetc(stream) != EOF) { }
    CHECK(feof(stream) && ungetc(255, stream) == 255 && !feof(stream) && fgetc(stream) == 255, "EOF recovery");
    rewind(stream);
    CHECK(!feof(stream) && !ferror(stream) && fgetc(stream) == 'a', "rewind");
    CHECK(fclose(stream) == 0, "close seed");

    stream = fopen(path, "w+");
    CHECK(stream != NULL, "open concurrent");
    writer_t *writers = calloc(WORKERS, sizeof(*writers));
    unsigned char *record = malloc(RECORD_BYTES);
    CHECK(writers != NULL && record != NULL, "worker storage");
    for (unsigned index = 0; index < WORKERS; ++index)
    {
        writers[index].stream = stream;
        memset(writers[index].record, (int)('A' + index), RECORD_BYTES);
        writers[index].record[RECORD_BYTES - 1] = '\n';
        CHECK(pthread_create(&writers[index].thread, NULL, write_records, &writers[index]) == 0, "create");
    }
    for (unsigned index = 0; index < WORKERS; ++index)
    {
        CHECK(pthread_join(writers[index].thread, NULL) == 0 && !writers[index].failed, "join");
    }
    CHECK(ftell(stream) == WORKERS * RECORDS * RECORD_BYTES && !ferror(stream), "written length");
    CHECK(fseek(stream, 0, SEEK_SET) == 0, "read records");
    for (unsigned index = 0; index < WORKERS * RECORDS; ++index)
    {
        CHECK(fread(record, 1, RECORD_BYTES, stream) == RECORD_BYTES, "record read");
        CHECK(record[0] >= 'A' && record[0] < 'A' + WORKERS, "record owner");
        for (unsigned offset = 1; offset < RECORD_BYTES - 1; ++offset)
            CHECK(record[offset] == record[0], "record interleaving");
        CHECK(record[RECORD_BYTES - 1] == '\n', "record newline");
    }
    CHECK(fgetc(stream) == EOF && feof(stream), "record EOF");
    CHECK(fclose(stream) == 0, "close concurrent");
    free(record);
    free(writers);
    free(path);
    CHECK(__alix_stdio_cached_tells && __alix_stdio_buffered_seeks, "private stream position cache");
    serial_printf("STDIO_STREAM_TEST: PASS pushback=1 position=1 workers=8 records=512 cached_tells=%llu buffered_seeks=%llu\n",
                  (unsigned long long)__alix_stdio_cached_tells,
                  (unsigned long long)__alix_stdio_buffered_seeks);
    return 0;
}
