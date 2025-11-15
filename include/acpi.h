#ifndef ACPI_H
#define ACPI_H

#include "types.h"

bool acpi_init(void);
bool acpi_shutdown(void);
const void *acpi_find_table_cached(const char *signature, size_t *length_out);

#endif
