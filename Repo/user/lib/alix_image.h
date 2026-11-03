#ifndef ALIX_IMAGE_H
#define ALIX_IMAGE_H
#include "syscall_defs.h"
/* Immutable process-lifetime user copy of the running ELF's captured headers. */
const syscall_elf_info_t *__alix_main_image(void);
#endif
