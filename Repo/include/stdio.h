#ifndef STDIO_H
#define STDIO_H

#include <stdarg.h>
#include "types.h"

#ifndef KERNEL_BUILD
#ifdef TTF_HOST_BUILD
#include <stdio.h>
#else
typedef struct FILE
{
    int fd;
    int error;
    int eof;
} FILE;

extern FILE *stdout;
extern FILE *stderr;
extern FILE *stdin;

#ifndef EOF
#define EOF (-1)
#endif

int printf(const char *format, ...);
int fprintf(FILE *stream, const char *format, ...);
int vfprintf(FILE *stream, const char *format, va_list args);
int sprintf(char *buf, const char *format, ...);
int snprintf(char *buf, size_t size, const char *format, ...);
int vsprintf(char *buf, const char *format, va_list args);
int vsnprintf(char *buf, size_t size, const char *format, va_list args);
int getchar(void);
int fgetc(FILE *stream);
int getc(FILE *stream);
char *fgets(char *s, int size, FILE *stream);
int feof(FILE *stream);
void setbuf(FILE *stream, char *buf);
int sscanf(const char *str, const char *format, ...);
int fscanf(FILE *stream, const char *format, ...);

FILE *fopen(const char *path, const char *mode);
int fclose(FILE *stream);
size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream);
size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream);
int fflush(FILE *stream);
int fseek(FILE *stream, long offset, int whence);
long ftell(FILE *stream);
int fputc(int ch, FILE *stream);
int fputs(const char *s, FILE *stream);
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
