#ifndef ACPI_H
#define ACPI_H

#include "types.h"

bool acpi_init(void);
bool acpi_shutdown(void);
bool acpi_has_i8042(void);
bool acpi_pm_timer_port(uint16_t *port, uint32_t *mask);
const void *acpi_find_table_cached(const char *signature, size_t *length_out);

#endif
