#ifndef STDIO_H
#define STDIO_H

#include <stdarg.h>
#include "types.h"

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

FILE *fopen(const char *path, const char *mode);
int fclose(FILE *stream);
size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream);
size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream);
int fflush(FILE *stream);
int fseek(FILE *stream, long offset, int whence);
long ftell(FILE *stream);
int fgetpos(FILE *stream, fpos_t *position);
int fsetpos(FILE *stream, const fpos_t *position);
void rewind(FILE *stream);
int fputc(int ch, FILE *stream);
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
