#include "tzdb.h"

#include "libc.h"
#include "timezone_paths.h"
#include "vfs.h"

static bool g_tzdb_loaded = false;
static char *g_tzdb_buffer = NULL;
static size_t g_tzdb_size = 0;
static tzdb_zone_t *g_tzdb_zones = NULL;
static size_t g_tzdb_zone_count = 0;
static tzdb_header_t g_tzdb_header;

static tzdb_zone_t *tzdb_allocate_zones(uint32_t count)
{
    tzdb_zone_t *zones = (tzdb_zone_t *)malloc(sizeof(tzdb_zone_t) * count);
    if (zones)
    {
        memset(zones, 0, sizeof(tzdb_zone_t) * count);
    }
    return zones;
}

bool tzdb_load(void)
{
    if (g_tzdb_loaded)
    {
        return true;
    }

    vfs_node_t *file = vfs_open_file(vfs_root(), TZDB_DATABASE_PATH, false, false);
    if (!file)
    {
        return false;
    }
    size_t size = 0;
    const char *data = vfs_data(file, &size);
    if (!data || size < sizeof(tzdb_header_t))
    {
        return false;
    }

    char *buffer = (char *)malloc(size);
    if (!buffer)
    {
        return false;
    }
    memcpy(buffer, data, size);

    tzdb_header_t *header = (tzdb_header_t *)buffer;
    if (memcmp(header->magic, TZDB_FILE_MAGIC, 4) != 0 ||
        header->version != TZDB_FILE_VERSION)
    {
        free(buffer);
        return false;
    }

    size_t expected_size = sizeof(tzdb_header_t) +
                           header->zone_count * sizeof(tzdb_zone_record_t) +
                           header->transition_count * sizeof(tzdb_transition_record_t) +
                           header->name_table_size;
    if (size < expected_size)
    {
        free(buffer);
        return false;
    }

    tzdb_zone_record_t *zone_records =
        (tzdb_zone_record_t *)(buffer + sizeof(tzdb_header_t));
    tzdb_transition_record_t *transition_records =
        (tzdb_transition_record_t *)((char *)zone_records +
                                     header->zone_count * sizeof(tzdb_zone_record_t));
    char *name_table = (char *)transition_records +
                       header->transition_count * sizeof(tzdb_transition_record_t);

    tzdb_zone_t *zones = tzdb_allocate_zones(header->zone_count);
    if (!zones)
    {
        free(buffer);
        return false;
    }

    for (uint32_t i = 0; i < header->zone_count; ++i)
    {
        const tzdb_zone_record_t *record = &zone_records[i];
        tzdb_zone_t *zone = &zones[i];
        if (record->name_offset >= header->name_table_size)
        {
            free(zones);
            free(buffer);
            return false;
        }
        zone->name = name_table + record->name_offset;
        if ((uint64_t)record->transition_index + record->transition_count > header->transition_count)
        {
            free(zones);
            free(buffer);
            return false;
        }
        zone->transitions = transition_records + record->transition_index;
        zone->transition_count = record->transition_count;
        zone->initial_offset_minutes = record->initial_offset;
        zone->initial_is_dst = (record->initial_is_dst != 0);
    }

    g_tzdb_buffer = buffer;
    g_tzdb_size = size;
    g_tzdb_zones = zones;
    g_tzdb_zone_count = header->zone_count;
    g_tzdb_header = *header;
    g_tzdb_loaded = true;
    return true;
}

const tzdb_zone_t *tzdb_find_zone(const char *name)
{
    if (!g_tzdb_loaded || !name)
    {
        return NULL;
    }
    for (size_t i = 0; i < g_tzdb_zone_count; ++i)
    {
        if (strcmp(g_tzdb_zones[i].name, name) == 0)
        {
            return &g_tzdb_zones[i];
        }
    }
    return NULL;
}

const tzdb_zone_t *tzdb_zones(size_t *count_out)
{
    if (count_out)
    {
        *count_out = g_tzdb_zone_count;
    }
    return g_tzdb_zones;
}

const char *tzdb_release(void)
{
    if (!g_tzdb_loaded)
    {
        return NULL;
    }
    return g_tzdb_header.release;
}
