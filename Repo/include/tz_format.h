#ifndef TZ_FORMAT_H
#define TZ_FORMAT_H

#include "types.h"

#define TZDB_FILE_MAGIC   "ATZD"
#define TZDB_FILE_VERSION 1

typedef struct __attribute__((packed))
{
    char magic[4];
    uint16_t version;
    uint16_t flags;
    uint32_t zone_count;
    uint32_t transition_count;
    uint32_t name_table_size;
    int64_t range_start;
    int64_t range_end;
    char release[32];
} tzdb_header_t;

typedef struct __attribute__((packed))
{
    uint32_t name_offset;
    uint32_t transition_index;
    uint32_t transition_count;
    int32_t initial_offset;
    uint8_t initial_is_dst;
    uint8_t reserved[3];
} tzdb_zone_record_t;

typedef struct __attribute__((packed))
{
    int64_t utc_seconds;
    int32_t offset_minutes;
    uint8_t is_dst;
    uint8_t reserved[3];
} tzdb_transition_record_t;

#endif
