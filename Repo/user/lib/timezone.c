#include "time.h"
#include "errno.h"
#include "limits.h"
#include "stdint.h"
#include "stdlib.h"
#include "string.h"
#include "strings.h"
#include "stdio.h"
#include "timezone_platform.h"

#define TZ_MAX_FILE (1024u * 1024u)
#define TZ_MAX_SELECTOR 1024u
#define TZ_MAX_ABBREVIATION 255u

typedef struct { int32_t offset; int is_dst; const char *name; } zone_type_t;
typedef struct { int kind, day, month, week, weekday, seconds, basis; } zone_rule_t;
typedef struct
{
    zone_type_t standard, summer;
    zone_rule_t start, end;
    int has_dst;
} zone_posix_t;
typedef struct zone_name
{
    struct zone_name *next;
    char text[];
} zone_name_t;
typedef struct zone_state
{
    unsigned references;
    uint64_t generation;
    char *selector;
    zone_posix_t posix;
    int direct_rules, has_footer;
    size_t count, type_count;
    int64_t *transitions;
    unsigned char *indices;
    zone_type_t *types;
    zone_name_t *pending_names;
} zone_state_t;

static alix_mutex_t zone_lock;
static zone_state_t *zone_current;
static zone_name_t *zone_names;
static char zone_utc[] = "UTC";
long timezone;
int daylight;
char *tzname[2] = {zone_utc, zone_utc};

/* Designations live for the process lifetime, as do the exported tzname and
 * returned tm_zone pointers. State objects and file buffers are reclaimable. */
static const char *zone_stage_name(zone_state_t *state, const char *text, size_t length)
{
    if (length > TZ_MAX_ABBREVIATION) { errno = EINVAL; return NULL; }
    for (zone_name_t *entry = state->pending_names; entry; entry = entry->next)
    {
        if (strlen(entry->text) == length && !memcmp(entry->text, text, length))
        {
            return entry->text;
        }
    }
    zone_name_t *entry = malloc(sizeof(*entry) + length + 1);
    if (!entry) { errno = ENOMEM; return NULL; }
    memcpy(entry->text, text, length);
    entry->text[length] = 0;
    entry->next = state->pending_names;
    state->pending_names = entry;
    return entry->text;
}

static int zone_replace_name(zone_state_t *state, const char *from, const char *to)
{
    int used = 0;
    if (state->posix.standard.name == from) { state->posix.standard.name = to; used = 1; }
    if (state->posix.summer.name == from) { state->posix.summer.name = to; used = 1; }
    for (size_t i = 0; i < state->type_count; ++i)
        if (state->types[i].name == from) { state->types[i].name = to; used = 1; }
    return used;
}

static void zone_commit_names(zone_state_t *state)
{
    zone_name_t *retired = NULL;
    alix_mutex_lock(&zone_lock);
    while (state->pending_names)
    {
        zone_name_t *entry = state->pending_names;
        state->pending_names = entry->next;
        zone_name_t *existing = zone_names;
        while (existing && strcmp(existing->text, entry->text)) existing = existing->next;
        int used = zone_replace_name(state, entry->text, existing ? existing->text : entry->text);
        if (!used || existing) { entry->next = retired; retired = entry; }
        else { entry->next = zone_names; zone_names = entry; }
    }
    alix_mutex_unlock(&zone_lock);
    while (retired) { zone_name_t *next = retired->next; free(retired); retired = next; }
}

static void zone_release(zone_state_t *state)
{
    if (state && __atomic_sub_fetch(&state->references, 1, __ATOMIC_ACQ_REL) == 0)
    {
        while (state->pending_names)
        {
            zone_name_t *entry = state->pending_names;
            state->pending_names = entry->next; free(entry);
        }
        free(state->selector); free(state->transitions); free(state->indices);
        free(state->types); free(state);
    }
}

static int zone_digit(char c) { return c >= '0' && c <= '9'; }
static int zone_alpha(char c) { return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'); }

static int zone_number(const char **cursor, unsigned maximum, int *result)
{
    const char *p = *cursor;
    unsigned value = 0;
    if (!zone_digit(*p)) return 0;
    do {
        unsigned digit = (unsigned)(*p++ - '0');
        if (digit > maximum || value > (maximum - digit) / 10) return 0;
        value = value * 10 + digit;
    } while (zone_digit(*p));
    if (value > maximum) return 0;
    *cursor = p; *result = (int)value; return 1;
}

static int zone_hms(const char **cursor, unsigned max_hours, int *result)
{
    const char *p = *cursor;
    int sign = 1, hours, minutes = 0, seconds = 0;
    if (*p == '-' || *p == '+') { if (*p == '-') sign = -1; ++p; }
    if (!zone_number(&p, max_hours, &hours)) return 0;
    if (*p == ':') { ++p; if (!zone_number(&p, 59, &minutes)) return 0; }
    if (*p == ':') { ++p; if (!zone_number(&p, 59, &seconds)) return 0; }
    *result = sign * (hours * 3600 + minutes * 60 + seconds);
    *cursor = p; return 1;
}

static const char *zone_parse_name(zone_state_t *state, const char **cursor)
{
    const char *p = *cursor, *start;
    size_t length;
    if (*p == '<')
    {
        start = ++p;
        while (zone_alpha(*p) || zone_digit(*p) || *p == '+' || *p == '-') ++p;
        length = (size_t)(p - start);
        if (*p++ != '>') return NULL;
    }
    else
    {
        start = p;
        while (zone_alpha(*p)) ++p;
        length = (size_t)(p - start);
    }
    if (length < 3 || length > TZ_MAX_ABBREVIATION) return NULL;
    const char *name = zone_stage_name(state, start, length);
    if (name) *cursor = p;
    return name;
}

static int zone_parse_rule(const char **cursor, zone_rule_t *rule)
{
    const char *p = *cursor;
    memset(rule, 0, sizeof(*rule));
    rule->seconds = 7200;
    if (*p == 'M')
    {
        rule->kind = 2; ++p;
        if (!zone_number(&p, 12, &rule->month) || rule->month == 0 || *p++ != '.' ||
            !zone_number(&p, 5, &rule->week) || rule->week == 0 || *p++ != '.' ||
            !zone_number(&p, 6, &rule->weekday)) return 0;
    }
    else
    {
        if (*p == 'J') { rule->kind = 1; ++p; }
        if (!zone_number(&p, 365, &rule->day) || (rule->kind == 1 && rule->day == 0)) return 0;
    }
    if (*p == '/')
    {
        ++p;
        if (!zone_hms(&p, 167, &rule->seconds)) return 0;
        if (*p == 's') { rule->basis = 1; ++p; }
        else if (*p == 'u' || *p == 'g' || *p == 'z') { rule->basis = 2; ++p; }
        else if (*p == 'w') ++p;
    }
    *cursor = p; return 1;
}

static int zone_parse_posix(zone_state_t *state, const char *text, zone_posix_t *zone)
{
    const char *p = text;
    memset(zone, 0, sizeof(*zone));
    zone->standard.name = zone_parse_name(state, &p);
    int west;
    if (!zone->standard.name || !zone_hms(&p, 24, &west)) return 0;
    zone->standard.offset = -west;
    zone->summer = zone->standard;
    if (!*p) return 1;
    zone->summer.name = zone_parse_name(state, &p);
    if (!zone->summer.name) return 0;
    zone->summer.offset = zone->standard.offset + 3600;
    zone->summer.is_dst = 1;
    zone->has_dst = 1;
    if (*p && *p != ',')
    {
        if (!zone_hms(&p, 24, &west)) return 0;
        zone->summer.offset = -west;
    }
    /* POSIX leaves omitted DST rules implementation-defined. Alix's default
     * is the current US rule; named TZif zones always carry their own rules. */
    zone->start = (zone_rule_t){.kind=2, .month=3, .week=2, .weekday=0, .seconds=7200};
    zone->end = (zone_rule_t){.kind=2, .month=11, .week=1, .weekday=0, .seconds=7200};
    if (!*p) return 1;
    if (*p++ != ',' || !zone_parse_rule(&p, &zone->start) || *p++ != ',' ||
        !zone_parse_rule(&p, &zone->end) || *p) return 0;
    return 1;
}

static int zone_leap(int64_t year) { return year % 4 == 0 && (year % 100 != 0 || year % 400 == 0); }

static int64_t zone_floor_div(int64_t value, int64_t divisor)
{
    return value / divisor - (value % divisor < 0);
}

static int zone_rule_time(int64_t year, const zone_rule_t *rule, const zone_posix_t *zone,
                          int ending, time_t *result)
{
    static const int month_start[] = {0,31,59,90,120,151,181,212,243,273,304,334};
    int64_t prior = year - 1;
    int64_t days = 365 * (year - 1970) + zone_floor_div(prior, 4) - 492 -
                   zone_floor_div(prior, 100) + 19 + zone_floor_div(prior, 400) - 4;
    int day;
    if (rule->kind == 2)
    {
        days += month_start[rule->month - 1] + (rule->month > 2 && zone_leap(year));
        int weekday = (int)((days + 4) % 7);
        if (weekday < 0) weekday += 7;
        day = 1 + (rule->weekday - weekday + 7) % 7 + 7 * (rule->week - 1);
        static const int lengths[] = {31,28,31,30,31,30,31,31,30,31,30,31};
        int length = lengths[rule->month - 1] + (rule->month == 2 && zone_leap(year));
        if (day > length) day -= 7;
        days += day - 1;
    }
    else
    {
        day = rule->day;
        if (rule->kind == 1) day = day - 1 + (zone_leap(year) && day >= 60);
        days += day;
    }
    time_t base = days * 86400;
    int offset = rule->basis == 2 ? 0 :
                 (rule->basis == 1 || !ending ? zone->standard.offset : zone->summer.offset);
    if (__builtin_add_overflow(base, (time_t)rule->seconds - offset, result)) return 0;
    return 1;
}

static const zone_type_t *zone_posix_type(const zone_posix_t *zone, time_t value)
{
    if (!zone->has_dst) return &zone->standard;
    struct tm utc;
    if (!gmtime_r(&value, &utc)) return NULL;
    int64_t year = (int64_t)utc.tm_year + 1900;
    for (int shift = -1; shift <= 1; ++shift)
    {
        time_t start, end;
        if (!zone_rule_time(year + shift, &zone->start, zone, 0, &start) ||
            !zone_rule_time(year + shift, &zone->end, zone, 1, &end)) continue;
        if (end <= start && !zone_rule_time(year + shift + 1, &zone->end, zone, 1, &end)) continue;
        if (value >= start && value < end) return &zone->summer;
    }
    return &zone->standard;
}

static uint32_t zone_u32(const unsigned char *p)
{
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}

typedef struct { uint32_t ut, standard, leap, count, types, names; unsigned width; } zone_counts_t;

static int zone_header(const unsigned char *bytes, size_t size, zone_counts_t *count,
                       unsigned width, size_t *block_size)
{
    if (size < 44 || memcmp(bytes, "TZif", 4) ||
        (bytes[4] != 0 && bytes[4] != '2' && bytes[4] != '3' && bytes[4] != '4')) return 0;
    count->ut = zone_u32(bytes + 20); count->standard = zone_u32(bytes + 24);
    count->leap = zone_u32(bytes + 28); count->count = zone_u32(bytes + 32);
    count->types = zone_u32(bytes + 36); count->names = zone_u32(bytes + 40);
    count->width = width;
    if (!count->types || count->types > 256 || !count->names || count->names > TZ_MAX_FILE ||
        count->count > TZ_MAX_FILE / 8 || count->leap > TZ_MAX_FILE / 8 ||
        (count->ut && count->ut != count->types) ||
        (count->standard && count->standard != count->types)) return 0;
    uint64_t needed = (uint64_t)count->count * (width + 1) + count->types * 6ULL +
                      count->names + (uint64_t)count->leap * (width + 4) + count->standard + count->ut;
    if (needed > size - 44) return 0;
    *block_size = (size_t)needed;
    return 1;
}

static int zone_parse_tzif(zone_state_t *state, const unsigned char *bytes, size_t size)
{
    zone_counts_t count;
    size_t block;
    if (!zone_header(bytes, size, &count, 4, &block)) goto malformed;
    unsigned version = bytes[4];
    if (version)
    {
        bytes += 44 + block; size -= 44 + block;
        if (!zone_header(bytes, size, &count, 8, &block) || bytes[4] != version) goto malformed;
    }
    /* The native wall clock is POSIX seconds. Leap-aware right/ data uses a
     * different timestamp scale and is rejected instead of misinterpreted. */
    if (count.leap) { errno = ENOTSUP; return 0; }
    state->count = count.count; state->type_count = count.types;
    state->transitions = malloc((count.count ? count.count : 1) * sizeof(*state->transitions));
    state->indices = malloc(count.count ? count.count : 1);
    state->types = calloc(count.types, sizeof(*state->types));
    if (!state->transitions || !state->indices || !state->types) { errno = ENOMEM; return 0; }
    const unsigned char *p = bytes + 44;
    for (uint32_t i = 0; i < count.count; ++i)
    {
        uint64_t bits = zone_u32(p);
        if (count.width == 8) bits = bits << 32 | zone_u32(p + 4);
        state->transitions[i] = count.width == 8 ? (int64_t)bits : (int32_t)bits;
        if (i && state->transitions[i] <= state->transitions[i - 1]) goto malformed;
        p += count.width;
    }
    for (uint32_t i = 0; i < count.count; ++i)
    {
        if (p[i] >= count.types) goto malformed;
        state->indices[i] = p[i];
    }
    p += count.count;
    const unsigned char *names = p + count.types * 6;
    for (uint32_t i = 0; i < count.types; ++i, p += 6)
    {
        int32_t offset = (int32_t)zone_u32(p);
        if (offset == INT32_MIN || p[4] > 1 || p[5] >= count.names) goto malformed;
        const char *name = (const char *)names + p[5];
        const char *end = memchr(name, 0, count.names - p[5]);
        if (!end || (size_t)(end - name) > TZ_MAX_ABBREVIATION) goto malformed;
        const char *interned = zone_stage_name(state, name, (size_t)(end - name));
        if (!interned) return 0;
        state->types[i] = (zone_type_t){offset, p[4], interned};
    }
    p = names + count.names;
    for (uint32_t i = 0; i < count.standard; ++i) if (p[i] > 1) goto malformed;
    for (uint32_t i = 0; i < count.ut; ++i)
        if (p[count.standard + i] > 1 ||
            (p[count.standard + i] && (!count.standard || !p[i]))) goto malformed;
    const unsigned char *footer = bytes + 44 + block;
    size_t remaining = size - 44 - block;
    if (version)
    {
        if (remaining < 2 || footer[0] != '\n' || footer[remaining - 1] != '\n' ||
            memchr(footer + 1, 0, remaining - 2) || memchr(footer + 1, '\n', remaining - 2)) goto malformed;
        if (remaining > 2)
        {
            char *text = malloc(remaining - 1);
            if (!text) { errno = ENOMEM; return 0; }
            memcpy(text, footer + 1, remaining - 2); text[remaining - 2] = 0;
            int okay = zone_parse_posix(state, text, &state->posix);
            free(text);
            if (!okay) goto malformed;
            state->has_footer = 1;
        }
    }
    else if (remaining) goto malformed;
    return 1;
malformed:
    errno = EINVAL; return 0;
}

static int zone_load_file(zone_state_t *state, const char *name)
{
    size_t length = strlen(name);
    if (!length || length > TZ_MAX_SELECTOR) { errno = EINVAL; return 0; }
    char *path = malloc(length + sizeof("/usr/share/zoneinfo/"));
    if (!path) { errno = ENOMEM; return 0; }
    if (name[0] == '/') memcpy(path, name, length + 1);
    else
    {
        const char *component = name;
        for (const char *p = name;; ++p)
        {
            if (*p == '/' || !*p)
            {
                size_t n = (size_t)(p - component);
                if (!n || (n == 1 && *component == '.') || (n == 2 && !memcmp(component, "..", 2)))
                { free(path); errno = EINVAL; return 0; }
                component = p + 1;
            }
            else if (!(zone_alpha(*p) || zone_digit(*p) || *p == '_' || *p == '-' || *p == '+' || *p == '.'))
            { free(path); errno = EINVAL; return 0; }
            if (!*p) break;
        }
        memcpy(path, "/usr/share/zoneinfo/", sizeof("/usr/share/zoneinfo/") - 1);
        memcpy(path + sizeof("/usr/share/zoneinfo/") - 1, name, length + 1);
    }
    int fd = sys_open(path, SYSCALL_OPEN_READ);
    free(path);
    if (fd < 0) { errno = fd < -1 ? -fd : EIO; return 0; }
    unsigned char *bytes = malloc(TZ_MAX_FILE + 1);
    if (!bytes) { sys_close(fd); errno = ENOMEM; return 0; }
    size_t length_read = 0;
    int okay = 0;
    while (length_read <= TZ_MAX_FILE)
    {
        ssize_t got = sys_read(fd, bytes + length_read, TZ_MAX_FILE + 1 - length_read);
        if (got < 0) { if (got == -EINTR) continue; errno = got < -1 ? (int)-got : EIO; goto done; }
        if (got == 0) break;
        if ((size_t)got > TZ_MAX_FILE + 1 - length_read) { errno = EIO; goto done; }
        length_read += (size_t)got;
    }
    if (length_read > TZ_MAX_FILE) { errno = EFBIG; goto done; }
    okay = zone_parse_tzif(state, bytes, length_read);
done:
    {
        int saved = errno;
        sys_close(fd); free(bytes); errno = saved;
    }
    return okay;
}

static const char *zone_offset_name(zone_state_t *state, int offset)
{
    if (!offset) return zone_utc;
    char text[32];
    unsigned magnitude = offset < 0 ? (unsigned)-offset : (unsigned)offset;
    int length = snprintf(text, sizeof(text), "UTC%c%02u:%02u:%02u", offset < 0 ? '-' : '+',
                          magnitude / 3600, magnitude / 60 % 60, magnitude % 60);
    return length > 0 && (size_t)length < sizeof(text) ? zone_stage_name(state, text, (size_t)length) : NULL;
}

static int zone_native_rule(zone_rule_t *out, const syscall_timezone_rule_t *in)
{
    if (in->month < 1 || in->month > 12 || in->week < 1 || in->week > 5 ||
        in->weekday < 0 || in->weekday > 6 || in->time_seconds < 0 || in->time_seconds >= 86400 ||
        in->clock_basis != SYSCALL_TIMEZONE_CLOCK_WALL) return 0;
    *out = (zone_rule_t){.kind=2, .month=in->month, .week=in->week, .weekday=in->weekday,
                         .seconds=in->time_seconds, .basis=0};
    return 1;
}

static int zone_build(zone_state_t *state, const syscall_timezone_info_t *native)
{
    if (native)
    {
        if (native->version != SYSCALL_TIMEZONE_VERSION || native->size != sizeof(*native) ||
            native->flags || native->kind > SYSCALL_TIMEZONE_IANA ||
            !memchr(native->zone_id, 0, sizeof(native->zone_id)) ||
            !memchr(native->display_name, 0, sizeof(native->display_name))) { errno = EINVAL; return 0; }
        if (native->kind == SYSCALL_TIMEZONE_IANA) return zone_load_file(state, native->zone_id);
        if (native->standard_offset_seconds < -86400 || native->standard_offset_seconds > 86400 ||
            native->dst_offset_seconds < -86400 || native->dst_offset_seconds > 86400) { errno = EINVAL; return 0; }
        state->direct_rules = 1;
        state->posix.standard = (zone_type_t){native->standard_offset_seconds, 0,
                                            zone_offset_name(state, native->standard_offset_seconds)};
        state->posix.summer = (zone_type_t){native->dst_offset_seconds, 1,
                                          zone_offset_name(state, native->dst_offset_seconds)};
        if (!state->posix.standard.name || !state->posix.summer.name) { errno = ENOMEM; return 0; }
        state->posix.has_dst = native->kind == SYSCALL_TIMEZONE_RULE;
        if (state->posix.has_dst && (!zone_native_rule(&state->posix.start, &native->start) ||
                                    !zone_native_rule(&state->posix.end, &native->end))) { errno = EINVAL; return 0; }
        return 1;
    }
    const char *text = state->selector;
    if (!*text || !strcmp(text, "UTC") || !strcmp(text, "GMT")) text = "UTC0";
    if (*text == ':') return zone_load_file(state, text + 1);
    if (zone_parse_posix(state, text, &state->posix)) { state->direct_rules = 1; return 1; }
    memset(&state->posix, 0, sizeof(state->posix));
    return zone_load_file(state, text);
}

static void zone_publish_metadata(const zone_state_t *state)
{
    const zone_type_t *standard, *summer;
    int has_dst = 0;
    if (state->direct_rules || state->has_footer)
    {
        standard = &state->posix.standard; summer = &state->posix.summer;
        has_dst = state->posix.has_dst;
    }
    else
    {
        standard = summer = &state->types[0];
        for (size_t i = 0; i < state->type_count; ++i)
        {
            if (state->types[i].is_dst) { summer = &state->types[i]; has_dst = 1; }
            else standard = &state->types[i];
        }
    }
    __atomic_store_n(&timezone, -(long)standard->offset, __ATOMIC_RELEASE);
    __atomic_store_n(&daylight, has_dst, __ATOMIC_RELEASE);
    __atomic_store_n(&tzname[0], (char *)standard->name, __ATOMIC_RELEASE);
    __atomic_store_n(&tzname[1], (char *)(has_dst ? summer->name : standard->name), __ATOMIC_RELEASE);
}

static zone_state_t *zone_acquire(int refresh)
{
    const char *environment = getenv("TZ");
    size_t length = environment ? strlen(environment) : 0;
    if (length > TZ_MAX_SELECTOR) { errno = EINVAL; return NULL; }
    char *selector = malloc(length + 1);
    if (!selector) { errno = ENOMEM; return NULL; }
    if (environment) memcpy(selector, environment, length + 1); else selector[0] = 0;
    syscall_timezone_info_t *native = NULL;
    uint64_t generation = 0;
    if (!environment)
    {
        native = malloc(sizeof(*native));
        if (!native) { free(selector); errno = ENOMEM; return NULL; }
        int status = sys_timezone_info(native, sizeof(*native));
        if (status < 0) { free(native); free(selector); errno = -status; return NULL; }
        generation = native->generation;
        if (!generation) { free(native); free(selector); errno = EINVAL; return NULL; }
    }
    alix_mutex_lock(&zone_lock);
    if (!refresh && zone_current && zone_current->generation == generation &&
        !strcmp(zone_current->selector, selector))
    {
        zone_state_t *result = zone_current;
        if (__atomic_load_n(&result->references, __ATOMIC_RELAXED) == UINT_MAX)
        {
            alix_mutex_unlock(&zone_lock); free(selector); free(native); errno = EOVERFLOW; return NULL;
        }
        __atomic_add_fetch(&result->references, 1, __ATOMIC_RELAXED);
        alix_mutex_unlock(&zone_lock);
        free(selector); free(native); return result;
    }
    alix_mutex_unlock(&zone_lock);
    zone_state_t *state = calloc(1, sizeof(*state));
    if (!state) { free(selector); free(native); errno = ENOMEM; return NULL; }
    state->references = 1; state->selector = selector; state->generation = generation;
    int okay = zone_build(state, native);
    free(native);
    if (!okay)
    {
        int error = errno;
        alix_mutex_lock(&zone_lock);
        zone_state_t *obsolete = NULL;
        if (refresh && zone_current && zone_current->generation == generation &&
            !strcmp(zone_current->selector, selector))
        { obsolete = zone_current; zone_current = NULL; }
        alix_mutex_unlock(&zone_lock);
        zone_release(obsolete); zone_release(state); errno = error; return NULL;
    }
    zone_commit_names(state);
    alix_mutex_lock(&zone_lock);
    if (generation && zone_current && zone_current->generation > generation)
    {
        /* A slow reader may finish loading an older coherent system snapshot.
         * It can use that state, but must not roll the shared cache backward. */
        alix_mutex_unlock(&zone_lock);
        return state;
    }
    zone_state_t *old = zone_current;
    zone_current = state;
    __atomic_add_fetch(&state->references, 1, __ATOMIC_RELAXED);
    zone_publish_metadata(state);
    alix_mutex_unlock(&zone_lock);
    zone_release(old);
    return state;
}

void tzset(void)
{
    int saved = errno;
    zone_state_t *state = zone_acquire(1);
    if (state) { zone_release(state); errno = saved; }
}

static const zone_type_t *zone_type_at(const zone_state_t *state, time_t value)
{
    const zone_type_t *type;
    if (state->direct_rules) type = zone_posix_type(&state->posix, value);
    else if (state->has_footer && (!state->count || value >= state->transitions[state->count - 1]))
        type = zone_posix_type(&state->posix, value);
    else
    {
        if (state->count && value >= state->transitions[state->count - 1]) { errno = EOVERFLOW; return NULL; }
        size_t low = 0, high = state->count;
        while (low < high)
        {
            size_t middle = low + (high - low) / 2;
            if (state->transitions[middle] <= value) low = middle + 1; else high = middle;
        }
        type = &state->types[low ? state->indices[low - 1] : 0];
    }
    if (type && !strcmp(type->name, "-00")) { errno = EOVERFLOW; return NULL; }
    return type;
}

static int zone_convert(const zone_state_t *state, time_t value, struct tm *result)
{
    const zone_type_t *type = zone_type_at(state, value);
    time_t shifted;
    if (!type) return 0;
    if (__builtin_add_overflow(value, (time_t)type->offset, &shifted)) { errno = EOVERFLOW; return 0; }
    if (!gmtime_r(&shifted, result)) return 0;
    result->tm_isdst = type->is_dst;
    result->tm_gmtoff = type->offset;
    result->tm_zone = (char *)type->name;
    return 1;
}

/* Parse against an owned immutable state, rather than racing independent
 * timezone/tzname globals or inventing an offset from an abbreviation. */
size_t __alix_timezone_parse_name(const char *input, struct tm *date)
{
    static const char *const universal[] = {"UTC", "GMT"};
    for (unsigned i = 0; i < 2; ++i)
    {
        if (!strncasecmp(input, universal[i], 3))
        {
            date->tm_gmtoff = 0; date->tm_isdst = 0; date->tm_zone = (char *)universal[i];
            return 3;
        }
    }
    zone_state_t *state = zone_acquire(0);
    if (!state) return 0;
    const zone_type_t *best = NULL;
    size_t length = 0;
    for (size_t i = 0; i < state->type_count + 2; ++i)
    {
        const zone_type_t *type = i < state->type_count ? &state->types[i] :
            i == state->type_count ? &state->posix.standard : &state->posix.summer;
        if (!type->name || !*type->name) continue;
        size_t size = strlen(type->name);
        if (size > length && !strncasecmp(input, type->name, size)) { best = type; length = size; }
    }
    if (best && date->tm_year >= -1900 && date->tm_year <= 8099 &&
        date->tm_mon >= 0 && date->tm_mon < 12 && date->tm_mday > 0 && date->tm_mday <= 31)
    {
        struct tm civil = {.tm_year = date->tm_year, .tm_mon = date->tm_mon,
                           .tm_mday = date->tm_mday, .tm_hour = 12};
        const zone_type_t *active = zone_type_at(state, timegm(&civil));
        if (active && strlen(active->name) == length && !strncasecmp(input, active->name, length)) best = active;
    }
    if (best)
    {
        date->tm_gmtoff = best->offset; date->tm_isdst = best->is_dst; date->tm_zone = (char *)best->name;
    }
    zone_release(state);
    return length;
}

struct tm *localtime_r(const time_t *value, struct tm *result)
{
    if (!value || !result) { errno = EINVAL; return NULL; }
    int saved = errno;
    zone_state_t *state = zone_acquire(0);
    if (!state) return NULL;
    int okay = zone_convert(state, *value, result);
    zone_release(state);
    if (okay) errno = saved;
    return okay ? result : NULL;
}

struct tm *localtime(const time_t *value)
{
    static _Thread_local struct tm result;
    return localtime_r(value, &result);
}

char *ctime_r(const time_t *value, char *output)
{
    struct tm date;
    return localtime_r(value, &date) ? asctime_r(&date, output) : NULL;
}

char *ctime(const time_t *value)
{
    static _Thread_local char output[26];
    return ctime_r(value, output);
}

static const zone_type_t *zone_nearby_kind(const zone_state_t *state, time_t value, int is_dst)
{
    if (state->direct_rules || (state->has_footer &&
        (!state->count || value >= state->transitions[state->count - 1])))
        return is_dst ? (state->posix.has_dst ? &state->posix.summer : NULL) : &state->posix.standard;
    size_t low = 0, high = state->count;
    while (low < high)
    {
        size_t middle = low + (high - low) / 2;
        if (state->transitions[middle] <= value) low = middle + 1; else high = middle;
    }
    for (size_t index = low; index; --index)
    {
        const zone_type_t *type = &state->types[state->indices[index - 1]];
        if (type->is_dst == is_dst) return type;
    }
    if (state->types[0].is_dst == is_dst) return &state->types[0];
    for (size_t index = low; index < state->count; ++index)
    {
        const zone_type_t *type = &state->types[state->indices[index]];
        if (type->is_dst == is_dst) return type;
    }
    return NULL;
}

time_t mktime(struct tm *value)
{
    if (!value) { errno = EINVAL; return -1; }
    int saved = errno, requested_dst = value->tm_isdst;
    struct tm normalized = *value;
    errno = 0;
    time_t naive = timegm(&normalized);
    if (naive == -1 && errno) return -1;
    zone_state_t *state = zone_acquire(0);
    if (!state) return -1;
    int found = 0, exact = 0, matched_hint = 0;
    time_t best = 0;
    int64_t best_delta = 0;
    struct tm best_date;
    size_t candidates = state->type_count + ((state->direct_rules || state->has_footer) ? 2 : 0);
    for (size_t i = 0; i < candidates; ++i)
    {
        const zone_type_t *candidate = i < state->type_count ? &state->types[i] :
            (i == state->type_count ? &state->posix.standard : &state->posix.summer);
        if (i == state->type_count + 1 && !state->posix.has_dst) continue;
        time_t utc;
        if (__builtin_sub_overflow(naive, (time_t)candidate->offset, &utc)) continue;
        struct tm actual;
        if (!zone_convert(state, utc, &actual)) continue;
        struct tm actual_utc = actual;
        int64_t delta = timegm(&actual_utc) - naive;
        int this_exact = delta == 0;
        int this_hint = requested_dst < 0 ||
                        (this_exact ? actual.tm_isdst : candidate->is_dst) == (requested_dst != 0);
        if (!this_exact && requested_dst >= 0 && this_hint)
        {
            const zone_type_t *nearby = zone_nearby_kind(state, naive, requested_dst != 0);
            if (!nearby || candidate->offset != nearby->offset) continue;
        }
        if (!this_exact && requested_dst < 0)
        {
            /* A gap is bounded by two actual adjacent offsets. Obsolete
             * historical offsets (such as LMT) must not partially bridge it. */
            time_t reciprocal;
            if (__builtin_sub_overflow(naive, (time_t)actual.tm_gmtoff, &reciprocal)) continue;
            const zone_type_t *other = zone_type_at(state, reciprocal);
            if (!other || other->offset != candidate->offset) continue;
        }
        int prefer = !found || this_hint > matched_hint ||
            (this_hint == matched_hint && (this_exact > exact ||
             (this_exact == exact && (this_exact ? utc < best :
              ((delta >= 0) > (best_delta >= 0) ||
               ((delta >= 0) == (best_delta >= 0) &&
                (delta >= 0 ? delta < best_delta : delta > best_delta)))))));
        if (prefer)
        {
            found = 1; exact = this_exact; matched_hint = this_hint;
            best = utc; best_delta = delta; best_date = actual;
        }
    }
    zone_release(state);
    if (!found) { errno = EOVERFLOW; return -1; }
    *value = best_date; errno = saved; return best;
}
