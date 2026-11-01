#ifndef STDIO_H
#define STDIO_H

#include <stdarg.h>
#include "types.h"
#include "sys/types.h"

#ifndef KERNEL_BUILD
#ifdef TTF_HOST_BUILD
#include <stdio.h>
#else
#include "alix_mutex.h"
#ifdef __cplusplus
extern "C" {
#endif

typedef struct FILE
{
    int fd;
    int error;
    int eof;
    int orientation; /* 0 undecided, -1 byte, +1 wide; unchanged by seeking. */
    alix_mutex_t mutex;
    uint64_t access_flags;
    bool append;
    bool pushback_pending;
    unsigned char pushback;
    /* Buffers are always heap owned; caller-provided setvbuf storage is not
     * retained, since streams may be shared by threads on different CPUs. */
    unsigned char *buffer;
    size_t buffer_capacity, read_position, read_end, write_length;
    int buffering;
    bool io_started;
    struct FILE *registry_next;
    uint64_t registry_id;
    uint32_t flush_pins;
    /* Additional pushback is heap owned and protected by the stream mutex.
     * The inline byte above guarantees the first push without allocation. */
    unsigned char *pushback_buffer;
    size_t pushback_length, pushback_capacity;
} FILE;
typedef int64_t fpos_t;

extern FILE *stdout;
extern FILE *stderr;
extern FILE *stdin;

#ifndef EOF
#define EOF (-1)
#endif
#define _IONBF 0
#define _IOFBF 1
#define _IOLBF 2
#define BUFSIZ 4096
#define FOPEN_MAX 16
#define FILENAME_MAX 4096
#define L_tmpnam 64
#define TMP_MAX 2147483647

int printf(const char *format, ...);
int vprintf(const char *format, va_list args);
void perror(const char *prefix);
int fprintf(FILE *stream, const char *format, ...);
int vfprintf(FILE *stream, const char *format, va_list args);
int sprintf(char *buf, const char *format, ...);
int snprintf(char *buf, size_t size, const char *format, ...);
int vsprintf(char *buf, const char *format, va_list args);
int vsnprintf(char *buf, size_t size, const char *format, va_list args);
int asprintf(char **out, const char *format, ...);
int vasprintf(char **out, const char *format, va_list args);
int getchar(void);
int fgetc(FILE *stream);
int getc(FILE *stream);
int ungetc(int ch, FILE *stream);
char *fgets(char *s, int size, FILE *stream);
int feof(FILE *stream);
int ferror(FILE *stream);
void clearerr(FILE *stream);
int fileno(FILE *stream);
void setbuf(FILE *stream, char *buf);
int setvbuf(FILE *stream, char *buf, int mode, size_t size);
int sscanf(const char *str, const char *format, ...);
int fscanf(FILE *stream, const char *format, ...);
int scanf(const char *format, ...);
int vfscanf(FILE *stream, const char *format, va_list arguments);
int vscanf(const char *format, va_list arguments);
int vsscanf(const char *text, const char *format, va_list arguments);

FILE *fopen(const char *path, const char *mode);
FILE *fdopen(int descriptor, const char *mode);
FILE *freopen(const char *path, const char *mode, FILE *stream);
FILE *tmpfile(void);
char *tmpnam(char *output);
int rename(const char *old_path, const char *new_path);
int fclose(FILE *stream);
size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream);
size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream);
int fflush(FILE *stream);
int fseek(FILE *stream, long offset, int whence);
long ftell(FILE *stream);
int fseeko(FILE *stream, off_t offset, int whence);
off_t ftello(FILE *stream);
int fgetpos(FILE *stream, fpos_t *position);
int fsetpos(FILE *stream, const fpos_t *position);
void rewind(FILE *stream);
int fputc(int ch, FILE *stream);
int putc(int ch, FILE *stream);
int putchar(int ch);
int fputs(const char *s, FILE *stream);
int puts(const char *s);
int remove(const char *path);
#ifdef __cplusplus
}
#endif
#endif /* TTF_HOST_BUILD */
#endif /* KERNEL_BUILD */

#ifndef SEEK_SET
#define SEEK_SET 0
#endif
#ifndef SEEK_CUR
#define SEEK_CUR 1
#endif
#ifndef SEEK_END
#define SEEK_END 2
#endif

#endif /* STDIO_H */
