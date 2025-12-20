#include "web/js/runtime/runtime_internal.h"
#include "ctype.h"
#include "libc.h"

typedef struct
{
    bool exists;
    js_value_t value;
    bool writable;
    bool enumerable;
    bool configurable;
} js_prop_desc_t;

typedef struct
{
    char *pattern;
    size_t pattern_len;
    char *flags;
    size_t flags_len;
    js_object_t *object;
    int realm_id;
    bool is_subclass;
} js_regexp_t;

typedef struct
{
    int id;
} js_realm_t;

static int js_realm_next_id = 1;
static js_realm_t js_default_realm = {0};
static const char *js_accessor_get_prefix = "__get__";

typedef enum
{
    JS_REGEXP_ATOM_LITERAL = 0,
    JS_REGEXP_ATOM_CLASS
} js_regexp_atom_kind_t;

typedef struct
{
    js_regexp_atom_kind_t kind;
    char literal;
    const char *class_pattern;
    size_t class_len;
} js_regexp_atom_t;

static bool js_regexp_get(js_runtime_t *rt,
                          void *user_data,
                          const char *name,
                          js_value_t *out,
                          char **error_message);

static char *js_accessor_slot_name(const char *prefix, const char *name)
{
    if (!prefix || !name)
    {
        return NULL;
    }
    size_t prefix_len = strlen(prefix);
    size_t name_len = strlen(name);
    size_t total_len = prefix_len + name_len;
    char *buf = (char *)malloc(total_len + 1);
    if (!buf)
    {
        return NULL;
    }
    memcpy(buf, prefix, prefix_len);
    memcpy(buf + prefix_len, name, name_len);
    buf[total_len] = '\0';
    return buf;
}

static bool js_call_accessor_getter(js_runtime_t *rt,
                                    js_object_t *object,
                                    const char *name,
                                    char **error_message)
{
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!rt || !object || !name)
    {
        return true;
    }
    char *slot_name = js_accessor_slot_name(js_accessor_get_prefix, name);
    if (!slot_name)
    {
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }
    if (!js_object_has_slot(object, slot_name))
    {
        free(slot_name);
        return true;
    }
    js_value_t getter = js_value_make_undefined_internal();
    if (!js_object_get_slot(object, slot_name, &getter))
    {
        free(slot_name);
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }
    free(slot_name);
    if (getter.type == JS_VALUE_FUNCTION || getter.type == JS_VALUE_NATIVE_FN)
    {
        js_value_t result = js_value_make_undefined_internal();
        char *err = NULL;
        bool ok = js_call_value(rt, &getter, 0, NULL, &result, &err);
        js_value_destroy(&result);
        if (!ok)
        {
            if (err)
            {
                if (error_message)
                {
                    *error_message = err;
                }
                else
                {
                    free(err);
                }
            }
            js_value_destroy(&getter);
            return false;
        }
        free(err);
    }
    js_value_destroy(&getter);
    return true;
}

static bool js_regexp_has_duplicate_named_groups(const char *pattern, size_t len, bool *out_dup)
{
    if (out_dup)
    {
        *out_dup = false;
    }
    if (!out_dup || !pattern || len == 0)
    {
        return true;
    }
    char **names = NULL;
    size_t count = 0;
    size_t cap = 0;
    bool in_class = false;
    for (size_t i = 0; i < len; ++i)
    {
        char c = pattern[i];
        if (c == '\\' && i + 1 < len)
        {
            ++i;
            continue;
        }
        if (c == '[')
        {
            in_class = true;
            continue;
        }
        if (c == ']' && in_class)
        {
            in_class = false;
            continue;
        }
        if (!in_class && c == '|')
        {
            for (size_t n = 0; n < count; ++n)
            {
                free(names[n]);
            }
            free(names);
            names = NULL;
            count = 0;
            cap = 0;
            continue;
        }
        if (!in_class && c == '(' && i + 2 < len &&
            pattern[i + 1] == '?' && pattern[i + 2] == '<')
        {
            if (i + 3 < len && (pattern[i + 3] == '=' || pattern[i + 3] == '!'))
            {
                continue;
            }
            size_t name_start = i + 3;
            size_t j = name_start;
            while (j < len && pattern[j] != '>')
            {
                ++j;
            }
            if (j >= len)
            {
                break;
            }
            size_t name_len = j - name_start;
            if (name_len == 0)
            {
                i = j;
                continue;
            }
            for (size_t n = 0; n < count; ++n)
            {
                if (strlen(names[n]) == name_len &&
                    strncmp(names[n], pattern + name_start, name_len) == 0)
                {
                    for (size_t k = 0; k < count; ++k)
                    {
                        free(names[k]);
                    }
                    free(names);
                    *out_dup = true;
                    return true;
                }
            }
            if (count == cap)
            {
                size_t next_cap = cap ? cap * 2 : 4;
                char **next = (char **)realloc(names, next_cap * sizeof(*next));
                if (!next)
                {
                    for (size_t k = 0; k < count; ++k)
                    {
                        free(names[k]);
                    }
                    free(names);
                    return false;
                }
                names = next;
                cap = next_cap;
            }
            char *copy = js_strdup_len(pattern + name_start, name_len);
            if (!copy)
            {
                for (size_t k = 0; k < count; ++k)
                {
                    free(names[k]);
                }
                free(names);
                return false;
            }
            names[count++] = copy;
            i = j;
        }
    }
    for (size_t n = 0; n < count; ++n)
    {
        free(names[n]);
    }
    free(names);
    return true;
}

static bool js_regexp_pattern_valid(const char *pattern, size_t len, bool unicode)
{
    if (!pattern || len == 0)
    {
        return true;
    }
    bool in_class = false;
    bool escaped = false;
    bool has_token = false;
    for (size_t i = 0; i < len; ++i)
    {
        char c = pattern[i];
        if (escaped)
        {
            escaped = false;
            has_token = true;
            continue;
        }
    if (c == '\\')
    {
        if (unicode && i + 1 < len)
        {
            char next = pattern[i + 1];
            if (next >= '0' && next <= '9')
            {
                return false;
            }
        }
        escaped = true;
        continue;
    }
        if (in_class)
        {
            if (c == ']')
            {
                in_class = false;
                has_token = true;
            }
            continue;
        }
        if (c == '[')
        {
            in_class = true;
            continue;
        }
        if (c == '|')
        {
            has_token = false;
            continue;
        }
        if (c == '?' || c == '*' || c == '+')
        {
            if (!has_token)
            {
                return false;
            }
            has_token = false;
            continue;
        }
        if (c == '{')
        {
            size_t j = i + 1;
            size_t m = 0;
            bool has_m = false;
            while (j < len && pattern[j] >= '0' && pattern[j] <= '9')
            {
                has_m = true;
                m = m * 10u + (size_t)(pattern[j] - '0');
                j++;
            }
            if (!has_m)
            {
                if (unicode)
                {
                    return false;
                }
                has_token = true;
                continue;
            }
            if (!has_token)
            {
                return false;
            }
            if (j >= len)
            {
                return false;
            }
            if (pattern[j] == '}')
            {
                has_token = false;
                i = j;
                continue;
            }
            if (pattern[j] == ',')
            {
                j++;
                size_t n = 0;
                bool has_n = false;
                while (j < len && pattern[j] >= '0' && pattern[j] <= '9')
                {
                    has_n = true;
                    n = n * 10u + (size_t)(pattern[j] - '0');
                    j++;
                }
                if (j >= len || pattern[j] != '}')
                {
                    return false;
                }
                if (has_n && n < m)
                {
                    return false;
                }
                has_token = false;
                i = j;
                continue;
            }
            return false;
        }
        if (c == ')')
        {
            has_token = true;
            continue;
        }
        has_token = true;
    }
    return !escaped && !in_class;
}

static void js_realm_finalize(void *user_data)
{
    js_realm_t *realm = (js_realm_t *)user_data;
    if (!realm)
    {
        return;
    }
    free(realm);
}

static bool js_append_utf8(char *buf, size_t cap, size_t *len, unsigned int code)
{
    if (!buf || !len)
    {
        return false;
    }
    if (code <= 0x7F)
    {
        if (*len + 1 > cap)
        {
            return false;
        }
        buf[(*len)++] = (char)code;
        return true;
    }
    if (code <= 0x7FF)
    {
        if (*len + 2 > cap)
        {
            return false;
        }
        buf[(*len)++] = (char)(0xC0 | (code >> 6));
        buf[(*len)++] = (char)(0x80 | (code & 0x3F));
        return true;
    }
    if (*len + 3 > cap)
    {
        return false;
    }
    buf[(*len)++] = (char)(0xE0 | (code >> 12));
    buf[(*len)++] = (char)(0x80 | ((code >> 6) & 0x3F));
    buf[(*len)++] = (char)(0x80 | (code & 0x3F));
    return true;
}

static bool js_utf8_next(const char *data, size_t len, size_t *index, unsigned int *out)
{
    if (!data || !index || !out || *index >= len)
    {
        return false;
    }
    unsigned char c = (unsigned char)data[*index];
    if (c < 0x80)
    {
        *out = c;
        (*index)++;
        return true;
    }
    if ((c & 0xE0) == 0xC0 && *index + 1 < len)
    {
        unsigned char c1 = (unsigned char)data[*index + 1];
        if ((c1 & 0xC0) == 0x80)
        {
            *out = ((unsigned int)(c & 0x1F) << 6) | (unsigned int)(c1 & 0x3F);
            *index += 2;
            return true;
        }
    }
    if ((c & 0xF0) == 0xE0 && *index + 2 < len)
    {
        unsigned char c1 = (unsigned char)data[*index + 1];
        unsigned char c2 = (unsigned char)data[*index + 2];
        if ((c1 & 0xC0) == 0x80 && (c2 & 0xC0) == 0x80)
        {
            *out = ((unsigned int)(c & 0x0F) << 12) |
                   ((unsigned int)(c1 & 0x3F) << 6) |
                   (unsigned int)(c2 & 0x3F);
            *index += 3;
            return true;
        }
    }
    if ((c & 0xF8) == 0xF0 && *index + 3 < len)
    {
        unsigned char c1 = (unsigned char)data[*index + 1];
        unsigned char c2 = (unsigned char)data[*index + 2];
        unsigned char c3 = (unsigned char)data[*index + 3];
        if ((c1 & 0xC0) == 0x80 && (c2 & 0xC0) == 0x80 && (c3 & 0xC0) == 0x80)
        {
            *out = ((unsigned int)(c & 0x07) << 18) |
                   ((unsigned int)(c1 & 0x3F) << 12) |
                   ((unsigned int)(c2 & 0x3F) << 6) |
                   (unsigned int)(c3 & 0x3F);
            *index += 4;
            return true;
        }
    }
    *out = c;
    (*index)++;
    return true;
}

static bool js_is_unescaped_char(unsigned int code)
{
    if ((code >= 'A' && code <= 'Z') ||
        (code >= 'a' && code <= 'z') ||
        (code >= '0' && code <= '9'))
    {
        return true;
    }
    switch (code)
    {
        case '@':
        case '*':
        case '_':
        case '+':
        case '-':
        case '.':
        case '/':
            return true;
        default:
            return false;
    }
}

static bool js_append_escape_hex(char *buf, size_t cap, size_t *len, unsigned int code, bool wide)
{
    static const char hex[] = "0123456789ABCDEF";
    if (!buf || !len)
    {
        return false;
    }
    if (wide)
    {
        if (*len + 6 > cap)
        {
            return false;
        }
        buf[(*len)++] = '%';
        buf[(*len)++] = 'u';
        buf[(*len)++] = hex[(code >> 12) & 0xF];
        buf[(*len)++] = hex[(code >> 8) & 0xF];
        buf[(*len)++] = hex[(code >> 4) & 0xF];
        buf[(*len)++] = hex[code & 0xF];
        return true;
    }
    if (*len + 3 > cap)
    {
        return false;
    }
    buf[(*len)++] = '%';
    buf[(*len)++] = hex[(code >> 4) & 0xF];
    buf[(*len)++] = hex[code & 0xF];
    return true;
}

static bool js_regexp_parse_octal(const char *pattern, size_t len, size_t *index, int *out_char)
{
    if (!pattern || !index || !out_char || *index >= len)
    {
        return false;
    }
    size_t i = *index;
    int value = 0;
    size_t count = 0;
    while (i < len && count < 3 && pattern[i] >= '0' && pattern[i] <= '7')
    {
        value = (value * 8) + (pattern[i] - '0');
        ++i;
        ++count;
    }
    if (count == 0)
    {
        return false;
    }
    *out_char = value & 0xFF;
    *index = i;
    return true;
}

static bool js_regexp_match_class(const char *pattern, size_t len, char target)
{
    if (!pattern || len == 0)
    {
        return false;
    }
    size_t i = 0;
    bool negate = false;
    if (pattern[i] == '^')
    {
        negate = true;
        ++i;
    }
    bool matched = false;
    while (i < len)
    {
        int start_char = 0;
        bool special_digit = false;
        bool special_nondigit = false;
        if (pattern[i] == '\\' && i + 1 < len)
        {
            char esc = pattern[i + 1];
            if (esc == 'd')
            {
                special_digit = true;
                i += 2;
            }
            else if (esc == 'D')
            {
                special_nondigit = true;
                i += 2;
            }
            else if (esc >= '0' && esc <= '7')
            {
                size_t oct_index = i + 1;
                if (js_regexp_parse_octal(pattern, len, &oct_index, &start_char))
                {
                    i = oct_index;
                }
                else
                {
                    start_char = esc;
                    i += 2;
                }
            }
            else
            {
                start_char = esc;
                i += 2;
            }
        }
        else
        {
            start_char = (unsigned char)pattern[i];
            ++i;
        }
        if (special_digit || special_nondigit)
        {
            bool is_digit = (target >= '0' && target <= '9');
            if ((special_digit && is_digit) || (special_nondigit && !is_digit))
            {
                matched = true;
            }
            continue;
        }
        if (i + 1 < len && pattern[i] == '-')
        {
            int end_char = 0;
            ++i;
            if (i < len && pattern[i] == '\\' && i + 1 < len)
            {
                char esc = pattern[i + 1];
                if (esc >= '0' && esc <= '7')
                {
                    size_t oct_index = i + 1;
                    if (js_regexp_parse_octal(pattern, len, &oct_index, &end_char))
                    {
                        i = oct_index;
                    }
                    else
                    {
                        end_char = esc;
                        i += 2;
                    }
                }
                else
                {
                    end_char = esc;
                    i += 2;
                }
            }
            else if (i < len)
            {
                end_char = (unsigned char)pattern[i];
                ++i;
            }
            if (start_char <= target && target <= end_char)
            {
                matched = true;
            }
            continue;
        }
        if (start_char == (unsigned char)target)
        {
            matched = true;
        }
    }
    return negate ? !matched : matched;
}

static bool js_regexp_build_literal(const char *pattern,
                                    size_t pattern_len,
                                    char **out,
                                    size_t *out_len)
{
    if (!out || !out_len)
    {
        return false;
    }
    *out = NULL;
    *out_len = 0;
    if (!pattern)
    {
        return true;
    }
    char *buf = (char *)malloc(pattern_len + 1);
    if (!buf)
    {
        return false;
    }
    size_t written = 0;
    size_t i = 0;
    while (i < pattern_len)
    {
        if (pattern[i] == '\\' && i + 1 < pattern_len)
        {
            if (pattern[i + 1] >= '0' && pattern[i + 1] <= '9')
            {
                i += 2;
                while (i < pattern_len && pattern[i] >= '0' && pattern[i] <= '9')
                {
                    ++i;
                }
                continue;
            }
            if (i + 2 < pattern_len && pattern[i + 1] == 'k' && pattern[i + 2] == '<')
            {
                buf[written++] = 'k';
                buf[written++] = '<';
                i += 3;
                while (i < pattern_len)
                {
                    buf[written++] = pattern[i];
                    if (pattern[i] == '>')
                    {
                        ++i;
                        break;
                    }
                    ++i;
                }
                continue;
            }
            buf[written++] = pattern[i + 1];
            i += 2;
            continue;
        }
        if (pattern[i] == '(' && i + 2 < pattern_len &&
            pattern[i + 1] == '?' && pattern[i + 2] == '<' &&
            !(i + 3 < pattern_len && (pattern[i + 3] == '=' || pattern[i + 3] == '!')))
        {
            i += 3;
            while (i < pattern_len && pattern[i] != '>')
            {
                ++i;
            }
            if (i < pattern_len && pattern[i] == '>')
            {
                ++i;
            }
            continue;
        }
        if (pattern[i] == '(' && i + 3 < pattern_len &&
            pattern[i + 1] == '?' && pattern[i + 2] == '<' &&
            (pattern[i + 3] == '=' || pattern[i + 3] == '!'))
        {
            i += 4;
            int depth = 1;
            while (i < pattern_len && depth > 0)
            {
                if (pattern[i] == '\\' && i + 1 < pattern_len)
                {
                    i += 2;
                    continue;
                }
                if (pattern[i] == '(')
                {
                    depth++;
                }
                else if (pattern[i] == ')')
                {
                    depth--;
                    if (depth == 0)
                    {
                        ++i;
                        break;
                    }
                }
                ++i;
            }
            continue;
        }
        if (pattern[i] == '(' || pattern[i] == ')')
        {
            ++i;
            continue;
        }
        buf[written++] = pattern[i++];
    }
    buf[written] = '\0';
    *out = buf;
    *out_len = written;
    return true;
}

static bool js_regexp_flags_valid(const char *flags, size_t len)
{
    if (!flags || len == 0)
    {
        return true;
    }
    bool seen_g = false;
    bool seen_i = false;
    bool seen_m = false;
    bool seen_s = false;
    bool seen_u = false;
    bool seen_y = false;
    for (size_t i = 0; i < len; ++i)
    {
        char c = flags[i];
        switch (c)
        {
            case 'g':
                if (seen_g)
                {
                    return false;
                }
                seen_g = true;
                break;
            case 'i':
                if (seen_i)
                {
                    return false;
                }
                seen_i = true;
                break;
            case 'm':
                if (seen_m)
                {
                    return false;
                }
                seen_m = true;
                break;
            case 's':
                if (seen_s)
                {
                    return false;
                }
                seen_s = true;
                break;
            case 'u':
                if (seen_u)
                {
                    return false;
                }
                seen_u = true;
                break;
            case 'y':
                if (seen_y)
                {
                    return false;
                }
                seen_y = true;
                break;
            default:
                return false;
        }
    }
    return true;
}

static bool js_regexp_set_flags(js_regexp_t *re, const char *flags, size_t len)
{
    if (!re)
    {
        return false;
    }
    free(re->flags);
    re->flags = NULL;
    re->flags_len = 0;
    if (!flags || len == 0)
    {
        return true;
    }
    const char *order = "gimsuy";
    char buf[7];
    size_t out_len = 0;
    for (size_t i = 0; order[i]; ++i)
    {
        for (size_t j = 0; j < len; ++j)
        {
            if (flags[j] == order[i])
            {
                buf[out_len++] = order[i];
                break;
            }
        }
    }
    if (out_len == 0)
    {
        return true;
    }
    re->flags = js_strdup_len(buf, out_len);
    if (!re->flags)
    {
        return false;
    }
    re->flags_len = out_len;
    return true;
}

static bool js_regexp_parse_atom(const char *pattern,
                                 size_t len,
                                 size_t *index,
                                 js_regexp_atom_t *out)
{
    if (!pattern || !index || !out || *index >= len)
    {
        return false;
    }
    for (;;)
    {
        if (*index >= len)
        {
            return false;
        }
        if (*index + 2 < len && pattern[*index] == '(' && pattern[*index + 1] == '?')
        {
            if (pattern[*index + 2] == '=' || pattern[*index + 2] == '!')
            {
                size_t i = *index + 3;
                int depth = 1;
                while (i < len && depth > 0)
                {
                    if (pattern[i] == '\\' && i + 1 < len)
                    {
                        i += 2;
                        continue;
                    }
                    if (pattern[i] == '(')
                    {
                        depth++;
                    }
                    else if (pattern[i] == ')')
                    {
                        depth--;
                    }
                    ++i;
                }
                *index = i;
                continue;
            }
            if (*index + 3 < len && pattern[*index + 2] == '<' &&
                (pattern[*index + 3] == '=' || pattern[*index + 3] == '!'))
            {
                size_t i = *index + 4;
                int depth = 1;
                while (i < len && depth > 0)
                {
                    if (pattern[i] == '\\' && i + 1 < len)
                    {
                        i += 2;
                        continue;
                    }
                    if (pattern[i] == '(')
                    {
                        depth++;
                    }
                    else if (pattern[i] == ')')
                    {
                        depth--;
                    }
                    ++i;
                }
                *index = i;
                continue;
            }
            if (*index + 2 < len && pattern[*index + 2] == '<')
            {
                size_t i = *index + 3;
                while (i < len && pattern[i] != '>')
                {
                    ++i;
                }
                if (i < len && pattern[i] == '>')
                {
                    ++i;
                }
                *index = i;
                continue;
            }
            if (*index + 2 < len && pattern[*index + 2] == ':')
            {
                *index += 3;
                continue;
            }
        }
        if (*index + 1 < len && pattern[*index] == '\\' &&
            pattern[*index + 1] >= '0' && pattern[*index + 1] <= '7')
        {
            size_t oct_index = *index + 1;
            int value = 0;
            if (js_regexp_parse_octal(pattern, len, &oct_index, &value))
            {
                *index = oct_index;
                continue;
            }
        }
        if (pattern[*index] == '(' || pattern[*index] == ')')
        {
            ++(*index);
            continue;
        }
        break;
    }
    char c = pattern[*index];
    if (c == '[')
    {
        size_t start = *index + 1;
        size_t i = start;
        bool escaped = false;
        while (i < len)
        {
            char ch = pattern[i];
            if (escaped)
            {
                escaped = false;
                ++i;
                continue;
            }
            if (ch == '\\')
            {
                escaped = true;
                ++i;
                continue;
            }
            if (ch == ']')
            {
                break;
            }
            ++i;
        }
        if (i >= len)
        {
            return false;
        }
        out->kind = JS_REGEXP_ATOM_CLASS;
        out->class_pattern = pattern + start;
        out->class_len = i - start;
        *index = i + 1;
        return true;
    }
    if (c == '\\' && *index + 1 < len)
    {
        char esc = pattern[*index + 1];
        if (esc == 'd' || esc == 'D')
        {
            out->kind = JS_REGEXP_ATOM_CLASS;
            out->class_pattern = pattern + *index;
            out->class_len = 2;
            *index += 2;
            return true;
        }
        if (esc >= '0' && esc <= '7')
        {
            size_t oct_index = *index + 1;
            int value = 0;
            if (js_regexp_parse_octal(pattern, len, &oct_index, &value))
            {
                out->kind = JS_REGEXP_ATOM_LITERAL;
                out->literal = (char)value;
                *index = oct_index;
                return true;
            }
        }
        out->kind = JS_REGEXP_ATOM_LITERAL;
        switch (esc)
        {
            case 'n': out->literal = '\n'; break;
            case 'r': out->literal = '\r'; break;
            case 't': out->literal = '\t'; break;
            case 'v': out->literal = '\v'; break;
            case 'f': out->literal = '\f'; break;
            default: out->literal = esc; break;
        }
        *index += 2;
        return true;
    }
    out->kind = JS_REGEXP_ATOM_LITERAL;
    out->literal = c;
    *index += 1;
    return true;
}

static void js_regexp_parse_quantifier(const char *pattern,
                                       size_t len,
                                       size_t *index,
                                       size_t *out_min,
                                       size_t *out_max)
{
    if (!out_min || !out_max || !index)
    {
        return;
    }
    *out_min = 1;
    *out_max = 1;
    if (!pattern || *index >= len)
    {
        return;
    }
    char c = pattern[*index];
    if (c == '*')
    {
        *out_min = 0;
        *out_max = SIZE_MAX;
        ++(*index);
        return;
    }
    if (c == '+')
    {
        *out_min = 1;
        *out_max = SIZE_MAX;
        ++(*index);
        return;
    }
    if (c == '?')
    {
        *out_min = 0;
        *out_max = 1;
        ++(*index);
        return;
    }
    if (c != '{')
    {
        return;
    }
    size_t i = *index + 1;
    if (i >= len || isdigit((unsigned char)pattern[i]) == 0)
    {
        return;
    }
    size_t min = 0;
    while (i < len && isdigit((unsigned char)pattern[i]) != 0)
    {
        min = (min * 10) + (size_t)(pattern[i] - '0');
        ++i;
    }
    size_t max = min;
    if (i < len && pattern[i] == ',')
    {
        ++i;
        if (i < len && isdigit((unsigned char)pattern[i]) != 0)
        {
            max = 0;
            while (i < len && isdigit((unsigned char)pattern[i]) != 0)
            {
                max = (max * 10) + (size_t)(pattern[i] - '0');
                ++i;
            }
        }
        else
        {
            max = SIZE_MAX;
        }
    }
    if (i >= len || pattern[i] != '}')
    {
        return;
    }
    *out_min = min;
    *out_max = max;
    *index = i + 1;
}

static bool js_regexp_atom_matches(const js_regexp_atom_t *atom, char target)
{
    if (!atom)
    {
        return false;
    }
    if (atom->kind == JS_REGEXP_ATOM_LITERAL)
    {
        return atom->literal == target;
    }
    return js_regexp_match_class(atom->class_pattern, atom->class_len, target);
}

static bool js_regexp_match_from(const char *pattern,
                                 size_t pattern_len,
                                 size_t pat_index,
                                 const char *text,
                                 size_t text_len,
                                 size_t text_index,
                                 size_t *out_end)
{
    if (pat_index >= pattern_len)
    {
        if (out_end)
        {
            *out_end = text_index;
        }
        return true;
    }
    if (!text || text_index > text_len)
    {
        return false;
    }
    js_regexp_atom_t atom = {0};
    size_t next_index = pat_index;
    if (!js_regexp_parse_atom(pattern, pattern_len, &next_index, &atom))
    {
        if (next_index >= pattern_len)
        {
            if (out_end)
            {
                *out_end = text_index;
            }
            return true;
        }
        return false;
    }
    size_t min = 1;
    size_t max = 1;
    js_regexp_parse_quantifier(pattern, pattern_len, &next_index, &min, &max);
    size_t remaining = text_len - text_index;
    size_t max_count = max == SIZE_MAX ? remaining : max;
    if (max_count > remaining)
    {
        max_count = remaining;
    }
    size_t count = 0;
    while (count < max_count && js_regexp_atom_matches(&atom, text[text_index + count]))
    {
        ++count;
    }
    if (count < min)
    {
        return false;
    }
    for (size_t n = count; n + 1 > 0; --n)
    {
        if (n < min)
        {
            break;
        }
        if (js_regexp_match_from(pattern, pattern_len, next_index, text, text_len, text_index + n, out_end))
        {
            return true;
        }
        if (n == 0)
        {
            break;
        }
    }
    return false;
}

static bool js_regexp_find_match(const char *pattern,
                                 size_t pattern_len,
                                 const char *text,
                                 size_t text_len,
                                 size_t *out_start,
                                 size_t *out_end)
{
    if (!pattern || !text || !out_start || !out_end)
    {
        return false;
    }
    if (pattern_len == 0)
    {
        *out_start = 0;
        *out_end = 0;
        return true;
    }
    for (size_t start = 0; start <= text_len; ++start)
    {
        size_t end = 0;
        if (js_regexp_match_from(pattern, pattern_len, 0, text, text_len, start, &end))
        {
            *out_start = start;
            *out_end = end;
            return true;
        }
    }
    return false;
}

static bool js_regexp_test_pattern(const char *pattern,
                                   size_t pattern_len,
                                   const char *text,
                                   size_t text_len)
{
    if (!pattern || !text)
    {
        return false;
    }
    size_t start = 0;
    size_t end = 0;
    return js_regexp_find_match(pattern, pattern_len, text, text_len, &start, &end);
}

static const js_function_decl_t *js_builtin_function_def(const js_function_t *fn)
{
    if (!fn)
    {
        return NULL;
    }
    return fn->is_expr ? (const js_function_decl_t *)fn->expr : fn->decl;
}

static size_t js_builtin_function_length(const js_function_t *fn)
{
    const js_function_decl_t *def = js_builtin_function_def(fn);
    return def ? def->param_count : 0;
}

static bool js_builtin_get_prop_desc(js_runtime_t *rt,
                                     const js_value_t *obj,
                                     const char *name,
                                     js_prop_desc_t *out,
                                     char **error_message)
{
    if (!out)
    {
        return false;
    }
    out->exists = false;
    out->value = js_value_make_undefined_internal();
    out->writable = true;
    out->enumerable = true;
    out->configurable = true;

    if (!obj || !name)
    {
        if (error_message)
        {
            *error_message = js_strdup("invalid object");
        }
        return false;
    }

    if (strcmp(name, "name") == 0)
    {
        if (obj->type == JS_VALUE_FUNCTION)
        {
            const js_function_decl_t *def = js_builtin_function_def(obj->as.function);
            const char *fn_name = (def && def->name) ? def->name : "";
            out->exists = true;
            if (!js_value_make_cstring(&out->value, fn_name))
            {
                if (error_message)
                {
                    *error_message = js_strdup("allocation failed");
                }
                return false;
            }
            out->writable = false;
            out->enumerable = false;
            out->configurable = true;
            return true;
        }
        if (obj->type == JS_VALUE_NATIVE_FN)
        {
            const char *native_name = js_value_native_name(rt, obj);
            out->exists = true;
            if (!js_value_make_cstring(&out->value, native_name ? native_name : ""))
            {
                if (error_message)
                {
                    *error_message = js_strdup("allocation failed");
                }
                return false;
            }
            out->writable = false;
            out->enumerable = false;
            out->configurable = true;
            return true;
        }
    }

    if (strcmp(name, "length") == 0)
    {
        if (obj->type == JS_VALUE_FUNCTION)
        {
            out->exists = true;
            out->value = js_value_make_number((double)js_builtin_function_length(obj->as.function));
            out->writable = false;
            out->enumerable = false;
            out->configurable = true;
            return true;
        }
        if (obj->type == JS_VALUE_NATIVE_FN)
        {
            size_t length = 0;
            if (!js_value_native_length(rt, obj, &length))
            {
                if (error_message)
                {
                    *error_message = js_strdup("unknown native");
                }
                return false;
            }
            out->exists = true;
            out->value = js_value_make_number((double)length);
            out->writable = false;
            out->enumerable = false;
            out->configurable = true;
            return true;
        }
        if (obj->type == JS_VALUE_ARRAY)
        {
            out->exists = true;
            out->value = js_value_make_number((double)obj->as.array->length);
            out->writable = true;
            out->enumerable = false;
            out->configurable = false;
            return true;
        }
        if (obj->type == JS_VALUE_STRING)
        {
            out->exists = true;
            out->value = js_value_make_number((double)obj->as.string.len);
            out->writable = false;
            out->enumerable = false;
            out->configurable = false;
            return true;
        }
    }

    if (obj->type == JS_VALUE_OBJECT)
    {
        if (obj->as.object && obj->as.object->get_fn)
        {
            js_value_t value = js_value_make_undefined_internal();
            if (!obj->as.object->get_fn(rt, obj->as.object->user_data, name, &value, error_message))
            {
                return false;
            }
            if (value.type == JS_VALUE_UNDEFINED && !js_object_is_symbol(obj->as.object))
            {
                return true;
            }
            out->exists = true;
            out->value = value;
            out->writable = true;
            out->enumerable = false;
            out->configurable = true;
            return true;
        }
        out->exists = js_object_has_slot(obj->as.object, name);
        if (!out->exists)
        {
            return true;
        }
        if (!js_object_get_slot(obj->as.object, name, &out->value))
        {
            if (error_message)
            {
                *error_message = js_strdup("allocation failed");
            }
            return false;
        }
        if (strcmp(name, "compile") == 0 &&
            out->value.type == JS_VALUE_NATIVE_FN &&
            out->value.as.native.fn == js_regexp_compile_proto)
        {
            out->writable = true;
            out->enumerable = false;
            out->configurable = true;
        }
        return true;
    }

    if (error_message)
    {
        *error_message = js_strdup("invalid object");
    }
    return false;
}

static bool js_builtin_get_desc_value(js_object_t *desc,
                                      const char *name,
                                      bool *has_out,
                                      js_value_t *value_out,
                                      char **error_message)
{
    if (!has_out || !value_out)
    {
        return false;
    }
    *has_out = false;
    *value_out = js_value_make_undefined_internal();
    if (!desc || !name)
    {
        return true;
    }
    if (!js_object_has_slot(desc, name))
    {
        return true;
    }
    *has_out = true;
    if (!js_object_get_slot(desc, name, value_out))
    {
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }
    return true;
}

static bool js_builtin_object_get_value(js_runtime_t *rt,
                                        js_object_t *object,
                                        const char *name,
                                        js_value_t *out,
                                        char **error_message)
{
    if (!out)
    {
        return false;
    }
    if (!object || !name)
    {
        *out = js_value_make_undefined_internal();
        return true;
    }
    if (object->get_fn)
    {
        return object->get_fn(rt, object->user_data, name, out, error_message);
    }
    return js_object_get_slot(object, name, out);
}

static bool js_value_is_primitive_local(const js_value_t *value)
{
    if (!value)
    {
        return false;
    }
    switch (value->type)
    {
        case JS_VALUE_UNDEFINED:
        case JS_VALUE_NULL:
        case JS_VALUE_BOOL:
        case JS_VALUE_NUMBER:
        case JS_VALUE_STRING:
            return true;
        default:
            return false;
    }
}

static bool js_try_object_method_number(js_runtime_t *rt,
                                        js_object_t *object,
                                        const char *name,
                                        js_value_t *out,
                                        bool *called,
                                        char **error_message)
{
    if (called)
    {
        *called = false;
    }
    if (!out)
    {
        return false;
    }
    js_value_t method = js_value_make_undefined_internal();
    if (!js_builtin_object_get_value(rt, object, name, &method, error_message))
    {
        return false;
    }
    if (method.type != JS_VALUE_FUNCTION && method.type != JS_VALUE_NATIVE_FN)
    {
        js_value_destroy(&method);
        *out = js_value_make_undefined_internal();
        return true;
    }
    if (called)
    {
        *called = true;
    }
    js_value_t result = js_value_make_undefined_internal();
    char *err = NULL;
    bool ok = js_call_value(rt, &method, 0, NULL, &result, &err);
    js_value_destroy(&method);
    if (!ok)
    {
        if (error_message)
        {
            *error_message = err ? err : js_strdup("method call failed");
        }
        else
        {
            free(err);
        }
        return false;
    }
    *out = result;
    return true;
}

static bool js_object_to_primitive_number(js_runtime_t *rt,
                                          js_object_t *object,
                                          js_value_t *out,
                                          char **error_message)
{
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!rt || !object || !out)
    {
        return false;
    }
    const char *order[2] = {"valueOf", "toString"};
    for (size_t i = 0; i < 2; ++i)
    {
        bool called = false;
        js_value_t result = js_value_make_undefined_internal();
        if (!js_try_object_method_number(rt, object, order[i], &result, &called, error_message))
        {
            return false;
        }
        if (!called)
        {
            continue;
        }
        if (js_value_is_primitive_local(&result))
        {
            *out = result;
            return true;
        }
        js_value_destroy(&result);
    }
    if (error_message)
    {
        *error_message = js_strdup("TypeError: cannot convert object to primitive");
    }
    return false;
}

static void js_regexp_finalize(void *user_data)
{
    js_regexp_t *re = (js_regexp_t *)user_data;
    if (!re)
    {
        return;
    }
    free(re->pattern);
    free(re->flags);
    free(re);
}

static char *js_str_to_lower_copy(const char *text, size_t len)
{
    if (!text)
    {
        text = "";
        len = 0;
    }
    char *buf = (char *)malloc(len + 1);
    if (!buf)
    {
        return NULL;
    }
    for (size_t i = 0; i < len; ++i)
    {
        char c = text[i];
        if (c >= 'A' && c <= 'Z')
        {
            c = (char)(c - 'A' + 'a');
        }
        buf[i] = c;
    }
    buf[len] = '\0';
    return buf;
}

static bool js_regexp_test(js_runtime_t *rt,
                           size_t argc,
                           const js_value_t *argv,
                           void *user_data,
                           js_value_t *out,
                           char **error_message)
{
    (void)rt;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    js_regexp_t *re = (js_regexp_t *)user_data;
    js_temp_string_t temp = {0};
    const js_value_t *value = (argc > 0 && argv) ? &argv[0] : NULL;
    if (!js_temp_string_from_value(rt, value, &temp, error_message))
    {
        return false;
    }
    const char *pattern = re ? re->pattern : NULL;
    size_t pattern_len = re ? re->pattern_len : 0;
    const char *text = temp.data ? temp.data : "";
    size_t text_len = temp.len;
    if (re && re->flags && strchr(re->flags, 'u') != NULL &&
        pattern && pattern_len >= 2 && pattern[0] == '[' && pattern[pattern_len - 1] == ']')
    {
        const unsigned char *inner = (const unsigned char *)(pattern + 1);
        size_t inner_len = pattern_len - 2;
        if (inner_len == 6 && inner[0] == 0xED && inner[3] == 0xED)
        {
            bool found = false;
            for (size_t i = 0; i + inner_len <= text_len; ++i)
            {
                if (memcmp(text + i, inner, inner_len) == 0)
                {
                    found = true;
                    break;
                }
            }
            js_temp_string_release(&temp);
            *out = js_value_make_bool(found);
            return true;
        }
    }
    char *pattern_lower = NULL;
    char *text_lower = NULL;
    if (re && re->flags && strchr(re->flags, 'i') != NULL)
    {
        pattern_lower = js_str_to_lower_copy(pattern, pattern_len);
        text_lower = js_str_to_lower_copy(text, text_len);
        if (!pattern_lower || !text_lower)
        {
            free(pattern_lower);
            free(text_lower);
            js_temp_string_release(&temp);
            if (error_message)
            {
                *error_message = js_strdup("allocation failed");
            }
            return false;
        }
        pattern = pattern_lower;
        text = text_lower;
    }
    bool match = js_regexp_test_pattern(pattern,
                                        pattern_len,
                                        text,
                                        text_len);
    free(pattern_lower);
    free(text_lower);
    js_temp_string_release(&temp);
    *out = js_value_make_bool(match);
    return true;
}

bool js_regexp_exec(js_runtime_t *rt,
                    size_t argc,
                    const js_value_t *argv,
                    void *user_data,
                    js_value_t *out,
                    char **error_message)
{
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    js_regexp_t *re = (js_regexp_t *)user_data;
    js_temp_string_t temp = {0};
    const js_value_t *value = (argc > 0 && argv) ? &argv[0] : NULL;
    if (!js_temp_string_from_value(rt, value, &temp, error_message))
    {
        return false;
    }
    const char *pattern = re ? re->pattern : "";
    size_t pattern_len = re ? re->pattern_len : 0;
    const char *text = temp.data ? temp.data : "";
    size_t text_len = temp.len;
    size_t start = 0;
    size_t end = 0;
    bool matched = js_regexp_find_match(pattern, pattern_len, text, text_len, &start, &end);
    if (!matched)
    {
        js_temp_string_release(&temp);
        *out = js_value_make_null();
        return true;
    }
    js_value_t result;
    if (!js_value_make_host_object(&result, NULL, NULL, NULL, NULL))
    {
        js_temp_string_release(&temp);
        return false;
    }
    js_value_t match_value;
    if (!js_value_make_string(&match_value, text + start, end - start))
    {
        js_value_destroy(&result);
        js_temp_string_release(&temp);
        return false;
    }
    (void)js_object_set_slot(result.as.object, "0", &match_value);
    js_value_destroy(&match_value);
    js_value_t length_value = js_value_make_number(1.0);
    (void)js_object_set_slot(result.as.object, "length", &length_value);
    js_value_t index_value = js_value_make_number((double)start);
    (void)js_object_set_slot(result.as.object, "index", &index_value);
    js_value_t input_value;
    if (!js_value_make_string(&input_value, text, text_len))
    {
        js_value_destroy(&result);
        js_temp_string_release(&temp);
        return false;
    }
    (void)js_object_set_slot(result.as.object, "input", &input_value);
    js_value_destroy(&input_value);
    js_temp_string_release(&temp);
    *out = result;
    return true;
}

static bool js_regexp_to_string(js_runtime_t *rt,
                                size_t argc,
                                const js_value_t *argv,
                                void *user_data,
                                js_value_t *out,
                                char **error_message)
{
    (void)rt;
    (void)argc;
    (void)argv;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    js_regexp_t *re = (js_regexp_t *)user_data;
    const char *pattern = (re && re->pattern) ? re->pattern : "";
    size_t pattern_len = (re && re->pattern) ? re->pattern_len : 0;
    const char *flags = (re && re->flags) ? re->flags : "";
    size_t flags_len = (re && re->flags) ? re->flags_len : 0;
    size_t total = pattern_len + flags_len + 2;
    char *buf = (char *)malloc(total + 1);
    if (!buf)
    {
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }
    size_t offset = 0;
    buf[offset++] = '/';
    if (pattern_len)
    {
        memcpy(buf + offset, pattern, pattern_len);
        offset += pattern_len;
    }
    buf[offset++] = '/';
    if (flags_len)
    {
        memcpy(buf + offset, flags, flags_len);
        offset += flags_len;
    }
    buf[offset] = '\0';
    out->type = JS_VALUE_STRING;
    out->as.string.data = buf;
    out->as.string.len = offset;
    return true;
}

bool js_regexp_compile(js_runtime_t *rt,
                       size_t argc,
                       const js_value_t *argv,
                       void *user_data,
                       js_value_t *out,
                       char **error_message)
{
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    size_t arg_index = 0;
    js_regexp_t *re = (js_regexp_t *)user_data;
    if (!re)
    {
        if (argc > 0 && argv && argv[0].type == JS_VALUE_OBJECT &&
            argv[0].as.object && argv[0].as.object->get_fn == js_regexp_get)
        {
            re = (js_regexp_t *)argv[0].as.object->user_data;
            arg_index = 1;
        }
        else
        {
            if (error_message)
            {
                *error_message = js_strdup("TypeError: invalid RegExp receiver");
            }
            return false;
        }
    }
    if (re && re->is_subclass)
    {
        if (error_message)
        {
            *error_message = js_strdup("TypeError: invalid RegExp receiver");
        }
        return false;
    }
    js_temp_string_t pattern_temp = {0};
    if (argc <= arg_index || !argv || argv[arg_index].type == JS_VALUE_UNDEFINED)
    {
        js_temp_string_t flags_temp = {0};
        bool have_flags = false;
        if (argc > arg_index + 1 && argv && argv[arg_index + 1].type != JS_VALUE_UNDEFINED)
        {
            if (!js_temp_string_from_value(rt, &argv[arg_index + 1], &flags_temp, error_message))
            {
                return false;
            }
            have_flags = true;
            if (!js_regexp_flags_valid(flags_temp.data ? flags_temp.data : "", flags_temp.len))
            {
                js_temp_string_release(&flags_temp);
                if (error_message)
                {
                    *error_message = js_strdup("SyntaxError: invalid flags");
                }
                return false;
            }
        }
        char *pattern_copy = js_strdup_len("", 0);
        if (!pattern_copy)
        {
            js_temp_string_release(&flags_temp);
            if (error_message)
            {
                *error_message = js_strdup("allocation failed");
            }
            return false;
        }
        free(re->pattern);
        re->pattern = pattern_copy;
        re->pattern_len = 0;
        bool ok = false;
        if (have_flags)
        {
            ok = js_regexp_set_flags(re, flags_temp.data ? flags_temp.data : "", flags_temp.len);
        }
        else
        {
            ok = js_regexp_set_flags(re, "", 0);
        }
        js_temp_string_release(&flags_temp);
        if (!ok)
        {
            if (error_message)
            {
                *error_message = js_strdup("allocation failed");
            }
            return false;
        }
    }
    else
    {
        const js_value_t *pattern_arg = &argv[arg_index];
        if (pattern_arg->type == JS_VALUE_OBJECT && pattern_arg->as.object &&
            pattern_arg->as.object->get_fn == js_regexp_get)
        {
            if (argc > arg_index + 1 && argv && argv[arg_index + 1].type != JS_VALUE_UNDEFINED)
            {
                if (error_message)
                {
                    *error_message = js_strdup("TypeError: flags not allowed");
                }
                return false;
            }
            js_regexp_t *pattern_re = (js_regexp_t *)pattern_arg->as.object->user_data;
            const char *src = (pattern_re && pattern_re->pattern) ? pattern_re->pattern : "";
            size_t src_len = (pattern_re && pattern_re->pattern) ? pattern_re->pattern_len : 0;
            char *pattern_copy = js_strdup_len(src, src_len);
            if (!pattern_copy)
            {
                if (error_message)
                {
                    *error_message = js_strdup("allocation failed");
                }
                return false;
            }
            free(re->pattern);
            re->pattern = pattern_copy;
            re->pattern_len = src_len;
            const char *flags = (pattern_re && pattern_re->flags) ? pattern_re->flags : "";
            size_t flags_len = (pattern_re && pattern_re->flags) ? pattern_re->flags_len : 0;
            char *flags_copy = js_strdup_len(flags, flags_len);
            if (!flags_copy && flags_len > 0)
            {
                if (error_message)
                {
                    *error_message = js_strdup("allocation failed");
                }
                return false;
            }
            bool ok = js_regexp_set_flags(re, flags_copy ? flags_copy : "", flags_len);
            free(flags_copy);
            if (!ok)
            {
                if (error_message)
                {
                    *error_message = js_strdup("allocation failed");
                }
                return false;
            }
        }
        else
        {
            if (!js_temp_string_from_value(rt, pattern_arg, &pattern_temp, error_message))
            {
                return false;
            }
            bool dup = false;
            if (!js_regexp_has_duplicate_named_groups(pattern_temp.data ? pattern_temp.data : "",
                                                      pattern_temp.len,
                                                      &dup))
            {
                js_temp_string_release(&pattern_temp);
                if (error_message)
                {
                    *error_message = js_strdup("allocation failed");
                }
                return false;
            }
            if (dup)
            {
                js_temp_string_release(&pattern_temp);
                if (error_message)
                {
                    *error_message = js_strdup("SyntaxError: duplicate named capturing group");
                }
                return false;
            }
            js_temp_string_t flags_temp = {0};
            bool have_flags = false;
            if (argc > arg_index + 1 && argv && argv[arg_index + 1].type != JS_VALUE_UNDEFINED)
            {
                if (!js_temp_string_from_value(rt, &argv[arg_index + 1], &flags_temp, error_message))
                {
                    js_temp_string_release(&pattern_temp);
                    return false;
                }
                have_flags = true;
                if (!js_regexp_flags_valid(flags_temp.data ? flags_temp.data : "", flags_temp.len))
                {
                    js_temp_string_release(&pattern_temp);
                    js_temp_string_release(&flags_temp);
                    if (error_message)
                    {
                        *error_message = js_strdup("SyntaxError: invalid flags");
                    }
                    return false;
                }
            }
            bool unicode = have_flags && flags_temp.data && strchr(flags_temp.data, 'u') != NULL;
            if (!js_regexp_pattern_valid(pattern_temp.data ? pattern_temp.data : "",
                                          pattern_temp.len,
                                          unicode))
            {
                js_temp_string_release(&pattern_temp);
                js_temp_string_release(&flags_temp);
                if (error_message)
                {
                    *error_message = js_strdup("SyntaxError: invalid regular expression");
                }
                return false;
            }
            char *pattern_copy = js_strdup_len(pattern_temp.data ? pattern_temp.data : "", pattern_temp.len);
            if (!pattern_copy)
            {
                js_temp_string_release(&pattern_temp);
                js_temp_string_release(&flags_temp);
                if (error_message)
                {
                    *error_message = js_strdup("allocation failed");
                }
                return false;
            }
            free(re->pattern);
            re->pattern = pattern_copy;
            re->pattern_len = pattern_temp.len;
            js_temp_string_release(&pattern_temp);
            bool ok = false;
            if (have_flags)
            {
                ok = js_regexp_set_flags(re, flags_temp.data ? flags_temp.data : "", flags_temp.len);
            }
            else
            {
                ok = js_regexp_set_flags(re, "", 0);
            }
            js_temp_string_release(&flags_temp);
            if (!ok)
            {
                if (error_message)
                {
                    *error_message = js_strdup("allocation failed");
                }
                return false;
            }
        }
    }
    if (re && re->object)
    {
        bool can_write = true;
        if (js_object_has_slot(re->object, "__lastIndex_writable"))
        {
            js_value_t writable = js_value_make_undefined_internal();
            if (js_object_get_slot(re->object, "__lastIndex_writable", &writable))
            {
                if (writable.type == JS_VALUE_BOOL && !writable.as.boolean)
                {
                    can_write = false;
                }
            }
            js_value_destroy(&writable);
        }
        if (!can_write)
        {
            if (error_message)
            {
                *error_message = js_strdup("TypeError: lastIndex is read-only");
            }
            return false;
        }
        js_value_t zero = js_value_make_number(0.0);
        (void)js_object_set_slot(re->object, "lastIndex", &zero);
        js_object_retain(re->object);
        out->type = JS_VALUE_OBJECT;
        out->as.object = re->object;
        return true;
    }
    *out = js_value_make_undefined();
    return true;
}

bool js_regexp_compile_proto(js_runtime_t *rt,
                             size_t argc,
                             const js_value_t *argv,
                             void *user_data,
                             js_value_t *out,
                             char **error_message)
{
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    js_realm_t *realm = user_data ? (js_realm_t *)user_data : &js_default_realm;
    if (argc == 0 || !argv || argv[0].type != JS_VALUE_OBJECT ||
        !argv[0].as.object || argv[0].as.object->get_fn != js_regexp_get)
    {
        if (error_message)
        {
            *error_message = js_strdup("TypeError: invalid RegExp receiver");
        }
        return false;
    }
    js_regexp_t *re = (js_regexp_t *)argv[0].as.object->user_data;
    if (!re || (realm && re->realm_id != realm->id))
    {
        if (error_message)
        {
            *error_message = js_strdup("TypeError: invalid RegExp receiver");
        }
        return false;
    }
    size_t inner_argc = argc > 0 ? argc - 1 : 0;
    const js_value_t *inner_argv = inner_argc ? &argv[1] : NULL;
    return js_regexp_compile(rt, inner_argc, inner_argv, re, out, error_message);
}

static bool js_regexp_split(js_runtime_t *rt,
                            size_t argc,
                            const js_value_t *argv,
                            void *user_data,
                            js_value_t *out,
                            char **error_message)
{
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    js_value_t input_fallback = js_value_make_undefined_internal();
    const js_value_t *input_val = (argc > 0 && argv) ? &argv[0] : &input_fallback;
    js_temp_string_t input_temp = {0};
    if (!js_temp_string_from_value(rt, input_val, &input_temp, error_message))
    {
        return false;
    }
    const char *text = input_temp.data ? input_temp.data : "";
    size_t text_len = input_temp.len;

    if (!js_value_make_array(out))
    {
        js_temp_string_release(&input_temp);
        return false;
    }
    js_regexp_t *re = (js_regexp_t *)user_data;
    if (re && re->object)
    {
        char *getter_err = NULL;
        if (!js_call_accessor_getter(rt, re->object, "Symbol.match", &getter_err))
        {
            js_value_destroy(out);
            js_temp_string_release(&input_temp);
            if (getter_err)
            {
                if (error_message)
                {
                    *error_message = getter_err;
                }
                else
                {
                    free(getter_err);
                }
            }
            return false;
        }
        free(getter_err);
    }
    const char *pattern = (re && re->pattern) ? re->pattern : "";
    size_t pattern_len = (re && re->pattern) ? re->pattern_len : 0;
    char *pattern_copy = NULL;
    if (pattern_len)
    {
        pattern_copy = js_strdup_len(pattern, pattern_len);
        if (!pattern_copy)
        {
            js_value_destroy(out);
            js_temp_string_release(&input_temp);
            if (error_message)
            {
                *error_message = js_strdup("allocation failed");
            }
            return false;
        }
        pattern = pattern_copy;
    }

    size_t limit = 0xFFFFFFFFu;
    if (argc > 1 && argv)
    {
        bool ok_num = true;
        const js_value_t *limit_val = &argv[1];
        js_value_t prim = js_value_make_undefined_internal();
        if (limit_val->type == JS_VALUE_OBJECT)
        {
            if (!js_object_to_primitive_number(rt, limit_val->as.object, &prim, error_message))
            {
                js_value_destroy(out);
                js_temp_string_release(&input_temp);
                free(pattern_copy);
                return false;
            }
            limit_val = &prim;
        }
        double lim = js_value_to_number(limit_val, &ok_num);
        js_value_destroy(&prim);
        if (!ok_num || js_is_nan(lim) || lim == 0)
        {
            limit = 0;
        }
        else
        {
            if (lim > (double)INT64_MAX)
            {
                lim = (double)INT64_MAX;
            }
            if (lim < (double)INT64_MIN)
            {
                lim = (double)INT64_MIN;
            }
            int64_t int_val = (int64_t)lim;
            uint32_t uint_val = (uint32_t)((uint64_t)int_val);
            limit = (size_t)uint_val;
        }
    }

    if (limit == 0)
    {
        js_value_destroy(out);
        js_temp_string_release(&input_temp);
        free(pattern_copy);
        return js_value_make_array(out);
    }
    char *literal = NULL;
    size_t literal_len = pattern_len;
    if (js_regexp_build_literal(pattern, pattern_len, &literal, &literal_len) && literal)
    {
        pattern = literal;
        pattern_len = literal_len;
    }

    size_t out_index = 0;
    if (pattern_len == 0)
    {
        for (size_t i = 0; i < text_len && out_index < limit; ++i)
        {
            js_value_t part;
            if (!js_value_make_string(&part, text + i, 1))
            {
                js_value_destroy(out);
                free(literal);
                free(pattern_copy);
                js_temp_string_release(&input_temp);
                return false;
            }
            bool ok = js_value_array_set(out, out_index++, &part);
            js_value_destroy(&part);
            if (!ok)
            {
                js_value_destroy(out);
                free(literal);
                free(pattern_copy);
                js_temp_string_release(&input_temp);
                return false;
            }
        }
        free(literal);
        free(pattern_copy);
        js_temp_string_release(&input_temp);
        return true;
    }

    size_t start = 0;
    size_t i = 0;
    while (i + pattern_len <= text_len)
    {
        if (memcmp(text + i, pattern, pattern_len) == 0)
        {
            js_value_t part;
            if (!js_value_make_string(&part, text + start, i - start))
            {
                js_value_destroy(out);
                free(literal);
                free(pattern_copy);
                js_temp_string_release(&input_temp);
                return false;
            }
            bool ok = js_value_array_set(out, out_index++, &part);
            js_value_destroy(&part);
            if (!ok)
            {
                js_value_destroy(out);
                free(literal);
                free(pattern_copy);
                js_temp_string_release(&input_temp);
                return false;
            }
            if (out_index >= limit)
            {
                start = i + pattern_len;
                break;
            }
            i += pattern_len;
            start = i;
            continue;
        }
        ++i;
    }
    if (out_index < limit)
    {
        js_value_t tail;
        if (!js_value_make_string(&tail, text + start, text_len - start))
        {
            js_value_destroy(out);
            free(literal);
            free(pattern_copy);
            js_temp_string_release(&input_temp);
            return false;
        }
        bool ok = js_value_array_set(out, out_index++, &tail);
        js_value_destroy(&tail);
        if (!ok)
        {
            js_value_destroy(out);
            free(literal);
            free(pattern_copy);
            js_temp_string_release(&input_temp);
            return false;
        }
    }

    free(literal);
    free(pattern_copy);
    js_temp_string_release(&input_temp);
    return true;
}

static bool js_regexp_get(js_runtime_t *rt,
                          void *user_data,
                          const char *name,
                          js_value_t *out,
                          char **error_message)
{
    (void)rt;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    js_regexp_t *re = (js_regexp_t *)user_data;
    if (name && strcmp(name, "test") == 0)
    {
        memset(out, 0, sizeof(*out));
        out->type = JS_VALUE_NATIVE_FN;
        out->as.native.fn = js_regexp_test;
        out->as.native.user_data = user_data;
        return true;
    }
    if (name && strcmp(name, "exec") == 0)
    {
        memset(out, 0, sizeof(*out));
        out->type = JS_VALUE_NATIVE_FN;
        out->as.native.fn = js_regexp_exec;
        out->as.native.user_data = user_data;
        return true;
    }
    if (name && strcmp(name, "compile") == 0)
    {
        memset(out, 0, sizeof(*out));
        out->type = JS_VALUE_NATIVE_FN;
        out->as.native.fn = js_regexp_compile;
        out->as.native.user_data = user_data;
        return true;
    }
    if (name && strcmp(name, "toString") == 0)
    {
        memset(out, 0, sizeof(*out));
        out->type = JS_VALUE_NATIVE_FN;
        out->as.native.fn = js_regexp_to_string;
        out->as.native.user_data = user_data;
        return true;
    }
    if (name && strcmp(name, "lastIndex") == 0)
    {
        if (re && re->object && js_object_has_slot(re->object, "lastIndex"))
        {
            return js_object_get_slot(re->object, "lastIndex", out);
        }
        *out = js_value_make_number(0.0);
        return true;
    }
    if (name && strcmp(name, "Symbol.split") == 0)
    {
        memset(out, 0, sizeof(*out));
        out->type = JS_VALUE_NATIVE_FN;
        out->as.native.fn = js_regexp_split;
        out->as.native.user_data = user_data;
        return true;
    }
    if (name && strcmp(name, "Symbol.match") == 0)
    {
        memset(out, 0, sizeof(*out));
        out->type = JS_VALUE_NATIVE_FN;
        out->as.native.fn = js_regexp_test;
        out->as.native.user_data = user_data;
        return true;
    }
    if (name && strcmp(name, "source") == 0)
    {
        return js_value_make_string(out,
                                    re && re->pattern ? re->pattern : "",
                                    re ? re->pattern_len : 0);
    }
    if (name && strcmp(name, "flags") == 0)
    {
        return js_value_make_string(out,
                                    re && re->flags ? re->flags : "",
                                    re ? re->flags_len : 0);
    }
    if (name && strcmp(name, "global") == 0)
    {
        bool value = re && re->flags && strchr(re->flags, 'g') != NULL;
        *out = js_value_make_bool(value);
        return true;
    }
    if (name && strcmp(name, "ignoreCase") == 0)
    {
        bool value = re && re->flags && strchr(re->flags, 'i') != NULL;
        *out = js_value_make_bool(value);
        return true;
    }
    if (name && strcmp(name, "multiline") == 0)
    {
        bool value = re && re->flags && strchr(re->flags, 'm') != NULL;
        *out = js_value_make_bool(value);
        return true;
    }
    if (name && strcmp(name, "dotAll") == 0)
    {
        bool value = re && re->flags && strchr(re->flags, 's') != NULL;
        *out = js_value_make_bool(value);
        return true;
    }
    if (name && strcmp(name, "unicode") == 0)
    {
        bool value = re && re->flags && strchr(re->flags, 'u') != NULL;
        *out = js_value_make_bool(value);
        return true;
    }
    if (name && strcmp(name, "sticky") == 0)
    {
        bool value = re && re->flags && strchr(re->flags, 'y') != NULL;
        *out = js_value_make_bool(value);
        return true;
    }
    *out = js_value_make_undefined_internal();
    return true;
}

bool js_builtin_string_match(js_runtime_t *rt,
                             size_t argc,
                             const js_value_t *argv,
                             void *user_data,
                             js_value_t *out,
                             char **error_message)
{
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    const js_value_t *this_val = (const js_value_t *)user_data;
    if (!this_val || this_val->type != JS_VALUE_STRING)
    {
        *out = js_value_make_null();
        return true;
    }
    const char *text = this_val->as.string.data ? this_val->as.string.data : "";
    size_t text_len = this_val->as.string.len;

    const js_value_t *arg = (argc > 0 && argv) ? &argv[0] : NULL;
    js_value_t source = js_value_make_undefined_internal();
    bool have_source = false;
    const char *pattern = NULL;
    size_t pattern_len = 0;
    js_temp_string_t pattern_temp = {0};

    if (arg && arg->type == JS_VALUE_OBJECT)
    {
        if (js_builtin_object_get_value(rt, arg->as.object, "source", &source, error_message) &&
            source.type == JS_VALUE_STRING)
        {
            pattern = source.as.string.data ? source.as.string.data : "";
            pattern_len = source.as.string.len;
            have_source = true;
        }
        else
        {
            js_value_destroy(&source);
        }
    }
    if (!have_source)
    {
        if (!js_temp_string_from_value(rt, arg, &pattern_temp, error_message))
        {
            return false;
        }
        pattern = pattern_temp.data ? pattern_temp.data : "";
        pattern_len = pattern_temp.len;
    }

    char *literal = NULL;
    size_t literal_len = pattern_len;
    if (js_regexp_build_literal(pattern, pattern_len, &literal, &literal_len) && literal)
    {
        pattern = literal;
        pattern_len = literal_len;
    }

    size_t match_pos = (size_t)-1;
    if (pattern_len == 0)
    {
        match_pos = 0;
    }
    else if (pattern_len <= text_len)
    {
        for (size_t i = 0; i + pattern_len <= text_len; ++i)
        {
            if (memcmp(text + i, pattern, pattern_len) == 0)
            {
                match_pos = i;
                break;
            }
        }
    }

    if (literal)
    {
        free(literal);
    }
    js_temp_string_release(&pattern_temp);
    if (have_source)
    {
        js_value_destroy(&source);
    }

    if (match_pos == (size_t)-1)
    {
        *out = js_value_make_null();
        return true;
    }

    if (!js_value_make_array(out))
    {
        return false;
    }
    js_value_t match_value;
    if (!js_value_make_string(&match_value, text + match_pos, pattern_len))
    {
        js_value_destroy(out);
        return false;
    }
    bool ok = js_value_array_set(out, 0, &match_value);
    js_value_destroy(&match_value);
    if (!ok)
    {
        js_value_destroy(out);
        return false;
    }
    return true;
}

bool js_builtin_number_to_string(js_runtime_t *rt,
                                 size_t argc,
                                 const js_value_t *argv,
                                 void *user_data,
                                 js_value_t *out,
                                 char **error_message)
{
    (void)rt;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    const js_value_t *this_val = (const js_value_t *)user_data;
    if (!this_val || this_val->type != JS_VALUE_NUMBER)
    {
        if (error_message)
        {
            *error_message = js_strdup("TypeError: Number.prototype.toString called on non-number");
        }
        return false;
    }
    int radix = 10;
    if (argc > 0 && argv && argv[0].type != JS_VALUE_UNDEFINED)
    {
        bool ok = true;
        double r = js_value_to_number(&argv[0], &ok);
        if (ok && !js_is_nan(r))
        {
            radix = (int)r;
        }
        if (radix < 2 || radix > 36)
        {
            if (error_message)
            {
                *error_message = js_strdup("RangeError: invalid radix");
            }
            return false;
        }
    }
    double num = this_val->as.number;
    if (radix == 10 || js_is_nan(num) || num > 1.0e308 || num < -1.0e308)
    {
        js_temp_string_t temp = {0};
        if (!js_temp_string_from_value(rt, this_val, &temp, error_message))
        {
            return false;
        }
        bool ok = js_value_make_string(out, temp.data ? temp.data : "", temp.len);
        js_temp_string_release(&temp);
        return ok;
    }
    if (num == 0.0)
    {
        return js_value_make_string(out, "0", 1);
    }
    bool negative = num < 0.0;
    double abs_val = negative ? -num : num;
    unsigned long long int_part = (unsigned long long)abs_val;
    if (abs_val != (double)int_part)
    {
        js_temp_string_t temp = {0};
        if (!js_temp_string_from_value(rt, this_val, &temp, error_message))
        {
            return false;
        }
        bool ok = js_value_make_string(out, temp.data ? temp.data : "", temp.len);
        js_temp_string_release(&temp);
        return ok;
    }

    size_t cap = 70;
    char *buf = (char *)malloc(cap);
    if (!buf)
    {
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }
    const char *digits = "0123456789abcdefghijklmnopqrstuvwxyz";
    size_t len = 0;
    while (int_part > 0 && len + 1 < cap)
    {
        unsigned int digit = (unsigned int)(int_part % (unsigned long long)radix);
        buf[len++] = digits[digit];
        int_part /= (unsigned long long)radix;
    }
    if (negative)
    {
        buf[len++] = '-';
    }
    for (size_t i = 0; i < len / 2; ++i)
    {
        char tmp = buf[i];
        buf[i] = buf[len - 1 - i];
        buf[len - 1 - i] = tmp;
    }
    bool ok = js_value_make_string(out, buf, len);
    free(buf);
    if (!ok && error_message)
    {
        *error_message = js_strdup("allocation failed");
    }
    return ok;
}

bool js_builtin_define_property(js_runtime_t *rt,
                                size_t argc,
                                const js_value_t *argv,
                                void *user_data,
                                js_value_t *out,
                                char **error_message)
{
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    *out = js_value_make_undefined();
    if (argc < 3 || !argv)
    {
        return true;
    }
    const js_value_t *target = &argv[0];
    const js_value_t *key = &argv[1];
    const js_value_t *desc = &argv[2];
    if (target->type != JS_VALUE_OBJECT)
    {
        return true;
    }
    js_temp_string_t name_temp = {0};
    if (!js_temp_string_from_value(rt, key, &name_temp, error_message))
    {
        return false;
    }
    char *prop_name = js_strdup_len(name_temp.data ? name_temp.data : "", name_temp.len);
    js_temp_string_release(&name_temp);
    if (!prop_name)
    {
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }
    if (desc->type == JS_VALUE_OBJECT)
    {
        if (strcmp(prop_name, "lastIndex") == 0 && target->as.object &&
            target->as.object->get_fn == js_regexp_get)
        {
            if (js_object_has_slot(desc->as.object, "writable"))
            {
                js_value_t writable = js_value_make_undefined_internal();
                if (js_object_get_slot(desc->as.object, "writable", &writable))
                {
                    if (writable.type == JS_VALUE_BOOL)
                    {
                        js_value_t flag = js_value_make_bool(writable.as.boolean);
                        (void)js_object_set_slot(target->as.object, "__lastIndex_writable", &flag);
                    }
                    js_value_destroy(&writable);
                }
            }
        }
        if (js_object_has_slot(desc->as.object, "get"))
        {
            js_value_t getter = js_value_make_undefined_internal();
            if (js_object_get_slot(desc->as.object, "get", &getter))
            {
                if (getter.type == JS_VALUE_FUNCTION || getter.type == JS_VALUE_NATIVE_FN)
                {
                    char *get_slot = js_accessor_slot_name(js_accessor_get_prefix, prop_name);
                    if (!get_slot)
                    {
                        js_value_destroy(&getter);
                        free(prop_name);
                        if (error_message)
                        {
                            *error_message = js_strdup("allocation failed");
                        }
                        return false;
                    }
                    (void)js_object_set_slot(target->as.object, get_slot, &getter);
                    free(get_slot);
                }
                js_value_destroy(&getter);
            }
        }
        if (js_object_has_slot(desc->as.object, "value"))
        {
            js_value_t value = js_value_make_undefined_internal();
            if (js_object_get_slot(desc->as.object, "value", &value))
            {
                (void)js_object_set_slot(target->as.object, prop_name, &value);
                js_value_destroy(&value);
                free(prop_name);
                if (!js_value_copy(out, target))
                {
                    if (error_message)
                    {
                        *error_message = js_strdup("allocation failed");
                    }
                    return false;
                }
                return true;
            }
        }
    }
    js_value_t undef = js_value_make_undefined_internal();
    (void)js_object_set_slot(target->as.object, prop_name, &undef);
    free(prop_name);
    if (!js_value_copy(out, target))
    {
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }
    return true;
}

bool js_builtin_define_properties(js_runtime_t *rt,
                                  size_t argc,
                                  const js_value_t *argv,
                                  void *user_data,
                                  js_value_t *out,
                                  char **error_message)
{
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    *out = js_value_make_undefined();
    if (argc < 2 || !argv)
    {
        return true;
    }
    const js_value_t *target = &argv[0];
    const js_value_t *props = &argv[1];
    if (target->type != JS_VALUE_OBJECT || props->type != JS_VALUE_OBJECT)
    {
        return true;
    }
    for (js_property_t *prop = props->as.object->properties; prop; prop = prop->next)
    {
        if (!prop->name)
        {
            continue;
        }
        js_value_t key;
        if (!js_value_make_cstring(&key, prop->name))
        {
            if (error_message)
            {
                *error_message = js_strdup("allocation failed");
            }
            return false;
        }
        const js_value_t args[] = {*target, key, prop->value};
        js_value_t tmp = js_value_make_undefined_internal();
        char *err = NULL;
        bool ok = js_builtin_define_property(rt, 3, args, NULL, &tmp, &err);
        js_value_destroy(&tmp);
        js_value_destroy(&key);
        if (!ok)
        {
            if (err)
            {
                if (error_message)
                {
                    *error_message = err;
                }
                else
                {
                    free(err);
                }
            }
            return false;
        }
        free(err);
    }
    if (!js_value_copy(out, target))
    {
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }
    return true;
}

bool js_builtin_function_call(js_runtime_t *rt,
                              size_t argc,
                              const js_value_t *argv,
                              void *user_data,
                              js_value_t *out,
                              char **error_message)
{
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    const js_value_t *target = (const js_value_t *)user_data;
    if (!target)
    {
        if (error_message)
        {
            *error_message = js_strdup("invalid call");
        }
        return false;
    }
    return js_call_value(rt, target, argc, argv, out, error_message);
}

bool js_builtin_object(js_runtime_t *rt,
                       size_t argc,
                       const js_value_t *argv,
                       void *user_data,
                       js_value_t *out,
                       char **error_message)
{
    (void)rt;
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    if (argc > 0 && argv && argv[0].type == JS_VALUE_OBJECT)
    {
        return js_value_copy(out, &argv[0]);
    }
    return js_value_make_host_object(out, NULL, NULL, NULL, NULL);
}

bool js_builtin_regexp(js_runtime_t *rt,
                       size_t argc,
                       const js_value_t *argv,
                       void *user_data,
                       js_value_t *out,
                       char **error_message)
{
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    js_temp_string_t temp = {0};
    js_temp_string_t flags_temp = {0};
    bool have_flags = false;
    bool unicode = false;
    const js_value_t *pattern_val = (argc > 0 && argv) ? &argv[0] : NULL;
    if (pattern_val && pattern_val->type != JS_VALUE_UNDEFINED)
    {
        if (!js_temp_string_from_value(rt, pattern_val, &temp, error_message))
        {
            return false;
        }
        bool dup = false;
        if (!js_regexp_has_duplicate_named_groups(temp.data ? temp.data : "", temp.len, &dup))
        {
            js_temp_string_release(&temp);
            if (error_message)
            {
                *error_message = js_strdup("allocation failed");
            }
            return false;
        }
        if (dup)
        {
            js_temp_string_release(&temp);
            if (error_message)
            {
                *error_message = js_strdup("SyntaxError: duplicate named capturing group");
            }
            return false;
        }
    }
    if (argc > 1 && argv && argv[1].type != JS_VALUE_UNDEFINED)
    {
        if (!js_temp_string_from_value(rt, &argv[1], &flags_temp, error_message))
        {
            js_temp_string_release(&temp);
            return false;
        }
        have_flags = true;
        if (!js_regexp_flags_valid(flags_temp.data ? flags_temp.data : "", flags_temp.len))
        {
            js_temp_string_release(&temp);
            js_temp_string_release(&flags_temp);
            if (error_message)
            {
                *error_message = js_strdup("SyntaxError: invalid flags");
            }
            return false;
        }
        unicode = flags_temp.data && strchr(flags_temp.data, 'u') != NULL;
    }
    if (!js_regexp_pattern_valid(temp.data ? temp.data : "", temp.len, unicode))
    {
        js_temp_string_release(&temp);
        js_temp_string_release(&flags_temp);
        if (error_message)
        {
            *error_message = js_strdup("SyntaxError: invalid regular expression");
        }
        return false;
    }
    js_realm_t *realm = (js_realm_t *)user_data;
    js_regexp_t *re = (js_regexp_t *)calloc(1, sizeof(*re));
    if (!re)
    {
        js_temp_string_release(&temp);
        js_temp_string_release(&flags_temp);
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }
    re->realm_id = realm ? realm->id : js_default_realm.id;
    if (temp.data)
    {
        re->pattern = js_strdup_len(temp.data, temp.len);
        re->pattern_len = temp.len;
        if (!re->pattern)
        {
            free(re);
            js_temp_string_release(&temp);
            js_temp_string_release(&flags_temp);
            if (error_message)
            {
                *error_message = js_strdup("allocation failed");
            }
            return false;
        }
    }
    js_temp_string_release(&temp);
    if (have_flags)
    {
        bool ok = js_regexp_set_flags(re, flags_temp.data ? flags_temp.data : "", flags_temp.len);
        js_temp_string_release(&flags_temp);
        if (!ok)
        {
            if (error_message)
            {
                *error_message = js_strdup("allocation failed");
            }
            return false;
        }
    }
    if (!js_value_make_host_object(out, js_regexp_get, NULL, js_regexp_finalize, re))
    {
        js_regexp_finalize(re);
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }
    re->object = out->as.object;
    return true;
}

bool js_builtin_regexp_subclass(js_runtime_t *rt,
                                size_t argc,
                                const js_value_t *argv,
                                void *user_data,
                                js_value_t *out,
                                char **error_message)
{
    if (!js_builtin_regexp(rt, argc, argv, user_data, out, error_message))
    {
        return false;
    }
    if (out->type == JS_VALUE_OBJECT && out->as.object && out->as.object->get_fn == js_regexp_get)
    {
        js_regexp_t *re = (js_regexp_t *)out->as.object->user_data;
        if (re)
        {
            re->is_subclass = true;
        }
    }
    return true;
}

bool js_builtin_string(js_runtime_t *rt,
                       size_t argc,
                       const js_value_t *argv,
                       void *user_data,
                       js_value_t *out,
                       char **error_message)
{
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    if (argc == 0 || !argv)
    {
        return js_value_make_cstring(out, "");
    }
    js_temp_string_t temp = {0};
    if (!js_temp_string_from_value(rt, &argv[0], &temp, error_message))
    {
        return false;
    }
    bool ok = js_value_make_string(out, temp.data ? temp.data : "", temp.len);
    js_temp_string_release(&temp);
    return ok;
}

bool js_builtin_string_from_char_code(js_runtime_t *rt,
                                      size_t argc,
                                      const js_value_t *argv,
                                      void *user_data,
                                      js_value_t *out,
                                      char **error_message)
{
    (void)rt;
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    if (argc == 0 || !argv)
    {
        return js_value_make_cstring(out, "");
    }
    size_t cap = argc * 3;
    char *buf = (char *)malloc(cap ? cap : 1);
    if (!buf)
    {
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }
    size_t len = 0;
    for (size_t i = 0; i < argc; ++i)
    {
        bool ok_num = true;
        double num = js_value_to_number(&argv[i], &ok_num);
        if (!ok_num || js_is_nan(num))
        {
            num = 0.0;
        }
        uint16_t code = (uint16_t)((uint32_t)num);
        if (code < 0x80)
        {
            buf[len++] = (char)code;
        }
        else if (code < 0x800)
        {
            buf[len++] = (char)(0xC0 | (code >> 6));
            buf[len++] = (char)(0x80 | (code & 0x3F));
        }
        else
        {
            buf[len++] = (char)(0xE0 | (code >> 12));
            buf[len++] = (char)(0x80 | ((code >> 6) & 0x3F));
            buf[len++] = (char)(0x80 | (code & 0x3F));
        }
    }
    bool ok = js_value_make_string(out, buf, len);
    free(buf);
    return ok;
}

bool js_builtin_number(js_runtime_t *rt,
                       size_t argc,
                       const js_value_t *argv,
                       void *user_data,
                       js_value_t *out,
                       char **error_message)
{
    (void)rt;
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    if (argc == 0 || !argv)
    {
        *out = js_value_make_number(0.0);
        return true;
    }
    bool ok = true;
    double value = js_value_to_number(&argv[0], &ok);
    if (!ok)
    {
        value = js_nan();
    }
    *out = js_value_make_number(value);
    return true;
}

bool js_builtin_escape(js_runtime_t *rt,
                       size_t argc,
                       const js_value_t *argv,
                       void *user_data,
                       js_value_t *out,
                       char **error_message)
{
    (void)rt;
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    js_temp_string_t temp = {0};
    const js_value_t *value = (argc > 0 && argv) ? &argv[0] : NULL;
    if (!js_temp_string_from_value(rt, value, &temp, error_message))
    {
        return false;
    }

    size_t cap = temp.len * 6 + 1;
    char *buf = (char *)malloc(cap);
    if (!buf)
    {
        js_temp_string_release(&temp);
        return false;
    }
    size_t out_len = 0;
    size_t index = 0;
    while (index < temp.len)
    {
        unsigned int code = 0;
        if (!js_utf8_next(temp.data, temp.len, &index, &code))
        {
            free(buf);
            js_temp_string_release(&temp);
            return false;
        }
        if (code < 256 && js_is_unescaped_char(code))
        {
            if (out_len + 1 > cap)
            {
                free(buf);
                js_temp_string_release(&temp);
                return false;
            }
            buf[out_len++] = (char)code;
            continue;
        }
        if (code < 256)
        {
            if (!js_append_escape_hex(buf, cap, &out_len, code, false))
            {
                free(buf);
                js_temp_string_release(&temp);
                return false;
            }
            continue;
        }
        if (code <= 0xFFFF)
        {
            if (!js_append_escape_hex(buf, cap, &out_len, code, true))
            {
                free(buf);
                js_temp_string_release(&temp);
                return false;
            }
            continue;
        }
        unsigned int cp = code - 0x10000;
        unsigned int high = 0xD800 + (cp >> 10);
        unsigned int low = 0xDC00 + (cp & 0x3FF);
        if (!js_append_escape_hex(buf, cap, &out_len, high, true) ||
            !js_append_escape_hex(buf, cap, &out_len, low, true))
        {
            free(buf);
            js_temp_string_release(&temp);
            return false;
        }
    }
    buf[out_len] = '\0';

    bool ok = js_value_make_string(out, buf, out_len);
    free(buf);
    js_temp_string_release(&temp);
    return ok;
}

bool js_builtin_unescape(js_runtime_t *rt,
                         size_t argc,
                         const js_value_t *argv,
                         void *user_data,
                         js_value_t *out,
                         char **error_message)
{
    (void)rt;
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    js_temp_string_t temp = {0};
    const js_value_t *value = (argc > 0 && argv) ? &argv[0] : NULL;
    if (!js_temp_string_from_value(rt, value, &temp, error_message))
    {
        return false;
    }

    size_t cap = temp.len * 3 + 1;
    char *buf = (char *)malloc(cap);
    if (!buf)
    {
        js_temp_string_release(&temp);
        return false;
    }
    size_t out_len = 0;
    size_t i = 0;
    while (i < temp.len)
    {
        char c = temp.data ? temp.data[i] : '\0';
        if (c == '%' && i + 1 < temp.len)
        {
            if (temp.data[i + 1] == 'u')
            {
                if (i + 5 < temp.len)
                {
                    int h0 = js_hex_value(temp.data[i + 2]);
                    int h1 = js_hex_value(temp.data[i + 3]);
                    int h2 = js_hex_value(temp.data[i + 4]);
                    int h3 = js_hex_value(temp.data[i + 5]);
                    if (h0 >= 0 && h1 >= 0 && h2 >= 0 && h3 >= 0)
                    {
                        unsigned int code = (unsigned int)((h0 << 12) | (h1 << 8) | (h2 << 4) | h3);
                        if (!js_append_utf8(buf, cap, &out_len, code))
                        {
                            free(buf);
                            js_temp_string_release(&temp);
                            return false;
                        }
                        i += 6;
                        continue;
                    }
                }
            }
            else if (i + 2 < temp.len)
            {
                int h0 = js_hex_value(temp.data[i + 1]);
                int h1 = js_hex_value(temp.data[i + 2]);
                if (h0 >= 0 && h1 >= 0)
                {
                    unsigned int code = (unsigned int)((h0 << 4) | h1);
                    if (!js_append_utf8(buf, cap, &out_len, code))
                    {
                        free(buf);
                        js_temp_string_release(&temp);
                        return false;
                    }
                    i += 3;
                    continue;
                }
            }
        }
        if (out_len + 1 > cap)
        {
            free(buf);
            js_temp_string_release(&temp);
            return false;
        }
        buf[out_len++] = c;
        i++;
    }
    buf[out_len] = '\0';

    bool ok = js_value_make_string(out, buf, out_len);
    free(buf);
    js_temp_string_release(&temp);
    return ok;
}

bool js_builtin_eval(js_runtime_t *rt,
                     size_t argc,
                     const js_value_t *argv,
                     void *user_data,
                     js_value_t *out,
                     char **error_message)
{
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    if (argc == 0 || !argv)
    {
        *out = js_value_make_undefined();
        return true;
    }
    if (argv[0].type != JS_VALUE_STRING)
    {
        return js_value_copy(out, &argv[0]);
    }
    size_t len = argv[0].as.string.len;
    const char *src = argv[0].as.string.data ? argv[0].as.string.data : "";
    char *buf = (char *)malloc(len + 1);
    if (!buf)
    {
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }
    for (size_t i = 0; i < len; ++i)
    {
        unsigned char c = (unsigned char)src[i];
        buf[i] = (char)((c == '\0') ? JS_EVAL_NUL_SENTINEL : c);
    }
    buf[len] = '\0';
    js_exec_result_t res = js_eval(rt, buf);
    free(buf);
    if (res.ok)
    {
        *out = res.value;
        return true;
    }
    if (error_message)
    {
        *error_message = res.error_message ? res.error_message : js_strdup("error");
    }
    else
    {
        free(res.error_message);
    }
    js_value_destroy(&res.value);
    return false;
}

bool js_builtin_symbol(js_runtime_t *rt,
                       size_t argc,
                       const js_value_t *argv,
                       void *user_data,
                       js_value_t *out,
                       char **error_message)
{
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    const js_value_t *arg = (argc > 0 && argv) ? &argv[0] : NULL;
    if (!arg || arg->type == JS_VALUE_UNDEFINED)
    {
        if (!js_value_make_symbol(out, NULL))
        {
            if (error_message)
            {
                *error_message = js_strdup("allocation failed");
            }
            return false;
        }
        return true;
    }
    js_temp_string_t temp = {0};
    if (!js_temp_string_from_value(rt, arg, &temp, error_message))
    {
        return false;
    }
    bool ok = js_value_make_symbol(out, temp.data ? temp.data : "");
    js_temp_string_release(&temp);
    if (!ok && error_message)
    {
        *error_message = js_strdup("allocation failed");
    }
    return ok;
}

bool js_builtin_is_html_dda(js_runtime_t *rt,
                            size_t argc,
                            const js_value_t *argv,
                            void *user_data,
                            js_value_t *out,
                            char **error_message)
{
    (void)rt;
    (void)argc;
    (void)argv;
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    *out = js_value_make_undefined();
    return true;
}

bool js_builtin_test_with_typed_array_constructors(js_runtime_t *rt,
                                                   size_t argc,
                                                   const js_value_t *argv,
                                                   void *user_data,
                                                   js_value_t *out,
                                                   char **error_message)
{
    (void)rt;
    (void)argc;
    (void)argv;
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    *out = js_value_make_undefined();
    return true;
}

bool js_builtin_type_error(js_runtime_t *rt,
                           size_t argc,
                           const js_value_t *argv,
                           void *user_data,
                           js_value_t *out,
                           char **error_message)
{
    (void)rt;
    (void)argc;
    (void)argv;
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    *out = js_value_make_undefined();
    return true;
}

bool js_builtin_syntax_error(js_runtime_t *rt,
                             size_t argc,
                             const js_value_t *argv,
                             void *user_data,
                             js_value_t *out,
                             char **error_message)
{
    (void)rt;
    (void)argc;
    (void)argv;
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    *out = js_value_make_undefined();
    return true;
}

bool js_builtin_create_realm(js_runtime_t *rt,
                             size_t argc,
                             const js_value_t *argv,
                             void *user_data,
                             js_value_t *out,
                             char **error_message)
{
    (void)rt;
    (void)argc;
    (void)argv;
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    js_realm_t *realm = (js_realm_t *)calloc(1, sizeof(*realm));
    if (!realm)
    {
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }
    realm->id = js_realm_next_id++;

    js_value_t global_obj;
    if (!js_value_make_host_object(&global_obj, NULL, NULL, js_realm_finalize, realm))
    {
        free(realm);
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }

    js_value_t regexp_fn;
    memset(&regexp_fn, 0, sizeof(regexp_fn));
    regexp_fn.type = JS_VALUE_NATIVE_FN;
    regexp_fn.as.native.fn = js_builtin_regexp;
    regexp_fn.as.native.user_data = realm;
    if (!js_object_set_slot(global_obj.as.object, "RegExp", &regexp_fn))
    {
        js_value_destroy(&global_obj);
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }

    js_value_t type_error;
    memset(&type_error, 0, sizeof(type_error));
    type_error.type = JS_VALUE_NATIVE_FN;
    type_error.as.native.fn = js_builtin_type_error;
    type_error.as.native.user_data = NULL;
    if (!js_object_set_slot(global_obj.as.object, "TypeError", &type_error))
    {
        js_value_destroy(&global_obj);
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }

    js_value_t realm_obj;
    if (!js_value_make_host_object(&realm_obj, NULL, NULL, NULL, NULL))
    {
        js_value_destroy(&global_obj);
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }
    if (!js_object_set_slot(realm_obj.as.object, "global", &global_obj))
    {
        js_value_destroy(&realm_obj);
        js_value_destroy(&global_obj);
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }
    js_value_destroy(&global_obj);
    *out = realm_obj;
    return true;
}

static bool js_builtin_test262_error_to_string(js_runtime_t *rt,
                                               size_t argc,
                                               const js_value_t *argv,
                                               void *user_data,
                                               js_value_t *out,
                                               char **error_message)
{
    (void)rt;
    (void)argc;
    (void)argv;
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    return js_value_make_cstring(out, "Test262Error");
}

bool js_builtin_test262_error(js_runtime_t *rt,
                              size_t argc,
                              const js_value_t *argv,
                              void *user_data,
                              js_value_t *out,
                              char **error_message)
{
    (void)rt;
    (void)argc;
    (void)argv;
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!out)
    {
        return false;
    }
    js_value_t obj;
    if (!js_value_make_host_object(&obj, NULL, NULL, NULL, NULL))
    {
        return false;
    }
    js_value_t fn;
    memset(&fn, 0, sizeof(fn));
    fn.type = JS_VALUE_NATIVE_FN;
    fn.as.native.fn = js_builtin_test262_error_to_string;
    fn.as.native.user_data = NULL;
    if (!js_object_set_slot(obj.as.object, "toString", &fn))
    {
        js_value_destroy(&obj);
        return false;
    }
    *out = obj;
    return true;
}

bool js_builtin_verify_property(js_runtime_t *rt,
                                size_t argc,
                                const js_value_t *argv,
                                void *user_data,
                                js_value_t *out,
                                char **error_message)
{
    (void)user_data;
    if (error_message)
    {
        *error_message = NULL;
    }
    if (!rt || !out || argc < 3 || !argv)
    {
        if (error_message)
        {
            *error_message = js_strdup("verifyProperty missing arguments");
        }
        return false;
    }
    const js_value_t *obj = &argv[0];
    const js_value_t *name_val = &argv[1];
    const js_value_t *desc_val = &argv[2];

    js_temp_string_t name_temp = {0};
    char *name_err = NULL;
    if (!js_temp_string_from_value(rt, name_val, &name_temp, &name_err))
    {
        if (name_err)
        {
            if (error_message)
            {
                *error_message = name_err;
            }
            else
            {
                free(name_err);
            }
        }
        else if (error_message)
        {
            *error_message = js_strdup("invalid property name");
        }
        return false;
    }
    char *name = js_strdup_len(name_temp.data ? name_temp.data : "", name_temp.len);
    js_temp_string_release(&name_temp);
    if (!name)
    {
        if (error_message)
        {
            *error_message = js_strdup("allocation failed");
        }
        return false;
    }

    js_prop_desc_t actual;
    char *err = NULL;
    if (!js_builtin_get_prop_desc(rt, obj, name, &actual, &err))
    {
        free(name);
        if (err)
        {
            if (error_message)
            {
                *error_message = err;
            }
            else
            {
                free(err);
            }
        }
        return false;
    }

    if (desc_val->type == JS_VALUE_UNDEFINED)
    {
        if (actual.exists)
        {
            js_value_destroy(&actual.value);
            free(name);
            if (error_message)
            {
                *error_message = js_strdup("property should be undefined");
            }
            return false;
        }
        *out = js_value_make_bool(true);
        free(name);
        return true;
    }

    if (desc_val->type != JS_VALUE_OBJECT)
    {
        js_value_destroy(&actual.value);
        free(name);
        if (error_message)
        {
            *error_message = js_strdup("descriptor must be an object");
        }
        return false;
    }

    bool has_value = false;
    js_value_t expected_value = js_value_make_undefined_internal();
    if (!js_builtin_get_desc_value(desc_val->as.object, "value", &has_value, &expected_value, error_message))
    {
        js_value_destroy(&actual.value);
        free(name);
        return false;
    }

    if (has_value && !js_value_strict_equal(&actual.value, &expected_value))
    {
        js_value_destroy(&expected_value);
        js_value_destroy(&actual.value);
        free(name);
        if (error_message)
        {
            *error_message = js_strdup("property value mismatch");
        }
        return false;
    }
    js_value_destroy(&expected_value);

    bool has_writable = false;
    js_value_t expected_writable = js_value_make_undefined_internal();
    if (!js_builtin_get_desc_value(desc_val->as.object, "writable", &has_writable, &expected_writable, error_message))
    {
        js_value_destroy(&actual.value);
        free(name);
        return false;
    }
    if (has_writable && expected_writable.type != JS_VALUE_UNDEFINED)
    {
        bool expected = js_value_is_truthy(&expected_writable);
        if (expected != actual.writable)
        {
            js_value_destroy(&expected_writable);
            js_value_destroy(&actual.value);
            free(name);
            if (error_message)
            {
                *error_message = js_strdup("writable mismatch");
            }
            return false;
        }
    }
    js_value_destroy(&expected_writable);

    bool has_enumerable = false;
    js_value_t expected_enumerable = js_value_make_undefined_internal();
    if (!js_builtin_get_desc_value(desc_val->as.object, "enumerable", &has_enumerable, &expected_enumerable, error_message))
    {
        js_value_destroy(&actual.value);
        free(name);
        return false;
    }
    if (has_enumerable && expected_enumerable.type != JS_VALUE_UNDEFINED)
    {
        bool expected = js_value_is_truthy(&expected_enumerable);
        if (expected != actual.enumerable)
        {
            js_value_destroy(&expected_enumerable);
            js_value_destroy(&actual.value);
            free(name);
            if (error_message)
            {
                *error_message = js_strdup("enumerable mismatch");
            }
            return false;
        }
    }
    js_value_destroy(&expected_enumerable);

    bool has_configurable = false;
    js_value_t expected_configurable = js_value_make_undefined_internal();
    if (!js_builtin_get_desc_value(desc_val->as.object, "configurable", &has_configurable, &expected_configurable, error_message))
    {
        js_value_destroy(&actual.value);
        free(name);
        return false;
    }
    if (has_configurable && expected_configurable.type != JS_VALUE_UNDEFINED)
    {
        bool expected = js_value_is_truthy(&expected_configurable);
        if (expected != actual.configurable)
        {
            js_value_destroy(&expected_configurable);
            js_value_destroy(&actual.value);
            free(name);
            if (error_message)
            {
                *error_message = js_strdup("configurable mismatch");
            }
            return false;
        }
    }
    js_value_destroy(&expected_configurable);

    js_value_destroy(&actual.value);
    *out = js_value_make_bool(true);
    free(name);
    return true;
}
