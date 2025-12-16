#ifndef TZDB_H
#define TZDB_H

#include "types.h"
#include "tz_format.h"

typedef struct
{
    const char *name;
    const tzdb_transition_record_t *transitions;
    size_t transition_count;
    int initial_offset_minutes;
    bool initial_is_dst;
} tzdb_zone_t;

bool tzdb_load(void);
const tzdb_zone_t *tzdb_find_zone(const char *name);
const tzdb_zone_t *tzdb_zones(size_t *count_out);
const char *tzdb_release(void);

#endif
