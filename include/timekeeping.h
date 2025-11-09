#ifndef TIMEKEEPING_H
#define TIMEKEEPING_H

#include "types.h"

typedef struct
{
    int hour;
    int minute;
    int second;
} timekeeping_time_of_day_t;

typedef struct
{
    uint8_t month;
    uint8_t week;
    uint8_t weekday; /* 0 = Sunday */
    uint16_t minute; /* minutes past midnight */
} timekeeping_dst_rule_t;

typedef struct
{
    const char *name;
    int standard_offset_minutes;
    bool dst_enabled;
    int dst_offset_minutes;
    timekeeping_dst_rule_t dst_start;
    timekeeping_dst_rule_t dst_end;
} timekeeping_timezone_spec_t;

void timekeeping_init(void);
uint64_t timekeeping_now_seconds(void);
uint64_t timekeeping_now_millis(void);
bool timekeeping_set_utc_seconds(uint64_t seconds);
bool timekeeping_save_timezone_spec(const timekeeping_timezone_spec_t *spec);
bool timekeeping_save_timezone(const char *name, int offset_minutes);
bool timekeeping_reload_timezone(void);
bool timekeeping_ensure_timezone_config(void);
const char *timekeeping_timezone_name(void);
int timekeeping_timezone_offset_minutes(void);
bool timekeeping_local_time(timekeeping_time_of_day_t *out);
void timekeeping_format_time(char *buffer, size_t length);
bool timekeeping_is_valid_timezone_offset(int offset_minutes);

#endif
