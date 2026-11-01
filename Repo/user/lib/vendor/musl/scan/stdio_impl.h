#ifndef ALIX_SCAN_PRIVATE_H
#define ALIX_SCAN_PRIVATE_H
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdarg.h>
#include <wchar.h>
#define hidden __attribute__((visibility("hidden")))
#define F_ERR 1
#define F_EOF 2
#define FLOCK(f) ((void)0)
#define FUNLOCK(f) ((void)0)
typedef long off_t;
typedef struct alix_scan_stream {
    unsigned char *buf, *rpos, *rend, *shend;
    off_t shlim, shcnt;
    unsigned flags;
    unsigned char storage[9];
    uint32_t units[9];
    FILE *stream;
    const char *text;
    const wchar_t *wide;
    size_t position;
} alix_scan_stream;
void __alix_scan_init(alix_scan_stream *);
int __uflow(alix_scan_stream *);
int __toread(alix_scan_stream *);
int __alix_scan_getwc(alix_scan_stream *);
int __alix_scan_ungetwc(int, alix_scan_stream *);
int __alix_scan_fscanf(alix_scan_stream *, const char *, ...);
int __alix_scan_bytes(alix_scan_stream *, const char *, va_list);
int __alix_scan_wide(alix_scan_stream *, const wchar_t *, va_list);
#endif
