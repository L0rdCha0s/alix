#ifndef ALIX_SYS_PARAM_H
#define ALIX_SYS_PARAM_H
#include "limits.h"
#include "endian.h"

#ifndef MAXPATHLEN
#define MAXPATHLEN PATH_MAX
#endif
#ifndef NBBY
#define NBBY CHAR_BIT
#endif
#ifndef MAX
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif
#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif
#endif
