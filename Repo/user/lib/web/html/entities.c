static char *html_strdup_range(const char *start, const char *end, bool to_lower)
{
    if (!start || !end || end < start)
    {
        return NULL;
    }
    size_t len = (size_t)(end - start);
    char *out = (char *)malloc(len + 1);
    if (!out)
    {
        return NULL;
    }
    for (size_t i = 0; i < len; ++i)
    {
        char c = start[i];
        out[i] = (char)(to_lower ? tolower((unsigned char)c) : c);
    }
    out[len] = '\0';
    return out;
}

static char html_decode_named_entity(const char *name, size_t len)
{
    if (!name || len == 0)
    {
        return '\0';
    }
    if (len == 3 && strncasecmp(name, "amp", 3) == 0)
    {
        return '&';
    }
    if (len == 2 && strncasecmp(name, "lt", 2) == 0)
    {
        return '<';
    }
    if (len == 2 && strncasecmp(name, "gt", 2) == 0)
    {
        return '>';
    }
    if (len == 4 && strncasecmp(name, "quot", 4) == 0)
    {
        return '"';
    }
    if (len == 4 && strncasecmp(name, "apos", 4) == 0)
    {
        return '\'';
    }
    if (len == 4 && strncasecmp(name, "nbsp", 4) == 0)
    {
        return ' ';
    }
    return '\0';
}

static bool html_decode_entity_one(const char *s, const char *end, size_t *consumed, char *out_ch)
{
    if (!s || !end || s >= end || !consumed || !out_ch)
    {
        return false;
    }
    if (*s != '&')
    {
        return false;
    }

    const char *semi = NULL;
    for (const char *p = s; p < end; ++p)
    {
        if (*p == ';')
        {
            semi = p;
            break;
        }
    }
    if (!semi)
    {
        return false;
    }
    size_t inner_len = (size_t)(semi - (s + 1));
    if (inner_len == 0)
    {
        return false;
    }

    const char *inner = s + 1;
    if (*inner == '#')
    {
        inner++;
        bool hex = false;
        if (inner < semi && (*inner == 'x' || *inner == 'X'))
        {
            hex = true;
            inner++;
        }

        uint32_t value = 0;
        bool have_digit = false;
        while (inner < semi)
        {
            unsigned char c = (unsigned char)*inner++;
            uint32_t digit = 0;
            if (hex)
            {
                if (c >= '0' && c <= '9')
                {
                    digit = (uint32_t)(c - '0');
                }
                else if (c >= 'a' && c <= 'f')
                {
                    digit = 10u + (uint32_t)(c - 'a');
                }
                else if (c >= 'A' && c <= 'F')
                {
                    digit = 10u + (uint32_t)(c - 'A');
                }
                else
                {
                    return false;
                }
                value = (value << 4) | digit;
            }
            else
            {
                if (c < '0' || c > '9')
                {
                    return false;
                }
                digit = (uint32_t)(c - '0');
                value = value * 10u + digit;
            }
            have_digit = true;
            if (value > 0x10FFFFu)
            {
                return false;
            }
        }

        if (!have_digit)
        {
            return false;
        }

        char out = '?';
        if (value == 160u)
        {
            out = ' ';
        }
        else if (value < 128u)
        {
            out = (char)value;
        }

        *out_ch = out;
        *consumed = (size_t)(semi - s) + 1;
        return true;
    }

    char named = html_decode_named_entity(inner, inner_len);
    if (!named)
    {
        return false;
    }

    *out_ch = named;
    *consumed = (size_t)(semi - s) + 1;
    return true;
}

static char *html_strdup_decoded_range(const char *start, const char *end)
{
    if (!start || !end || end < start)
    {
        return NULL;
    }

    size_t len = (size_t)(end - start);
    char *out = (char *)malloc(len + 1);
    if (!out)
    {
        return NULL;
    }

    size_t w = 0;
    const char *p = start;
    while (p < end)
    {
        if (*p == '&')
        {
            size_t consumed = 0;
            char decoded = '\0';
            if (html_decode_entity_one(p, end, &consumed, &decoded) && consumed > 0)
            {
                out[w++] = decoded;
                p += consumed;
                continue;
            }
        }
        out[w++] = *p++;
    }
    out[w] = '\0';
    return out;
}

