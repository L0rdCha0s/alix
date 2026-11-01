#ifndef ALIX_DIRENT_H
#define ALIX_DIRENT_H

#include "sys/types.h"

#define DT_UNKNOWN 0
#define DT_DIR 4
#define DT_REG 8
#define DT_LNK 10
#define DT_BLK 6
#define _DIRENT_HAVE_D_TYPE 1

typedef struct alix_directory DIR;
struct dirent
{
    ino_t d_ino;
    unsigned char d_type;
    char d_name[4096];
};

#ifdef __cplusplus
extern "C" {
#endif
DIR *opendir(const char *path);
struct dirent *readdir(DIR *directory);
int closedir(DIR *directory);
void rewinddir(DIR *directory);
#ifdef __cplusplus
}
#endif
#endif
