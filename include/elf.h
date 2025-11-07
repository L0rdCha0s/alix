#ifndef ELF_H
#define ELF_H

#include "types.h"
#include "process.h"

bool elf_load_process(process_t *process, const uint8_t *image, size_t size, uintptr_t *entry_out);

#endif
