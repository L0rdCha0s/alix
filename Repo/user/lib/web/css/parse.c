#include "web/css/css_internal.h"

#include "libc.h"

static const char *css_scan_value_end(const char *p)
{
    if (!p)
    {
        return NULL;
    }
    char quote = 0;
    int paren_depth = 0;
    bool escape = false;
    while (*p)
    {
        char c = *p;
        if (escape)
        {
            escape = false;
            ++p;
            continue;
        }
        if (c == '\\')
        {
            escape = true;
            ++p;
            continue;
        }
        if (quote)
        {
            if (c == quote)
            {
                quote = 0;
            }
            ++p;
            continue;
        }
        if (c == '"' || c == '\'')
        {
            quote = c;
            ++p;
            continue;
        }
        if (c == '(')
        {
            ++paren_depth;
            ++p;
            continue;
        }
        if (c == ')' && paren_depth > 0)
        {
            --paren_depth;
            ++p;
            continue;
        }
        if ((c == ';' || c == '}') && paren_depth == 0)
        {
            break;
        }
        ++p;
    }
    return p;
}

static bool css_append_rule(css_stylesheet_t *sheet, const char *selector_start, const char *selector_end, const css_style_t *style)
{
    if (!sheet || !selector_start || !selector_end || selector_end <= selector_start || !style)
    {
        return false;
    }
    css_trim_range(&selector_start, &selector_end);
    if (selector_end <= selector_start)
    {
        return true;
    }

    css_rule_t *rule = (css_rule_t *)calloc(1, sizeof(*rule));
    if (!rule)
    {
        return false;
    }
    rule->selector = css_strdup_lower(selector_start, selector_end);
    if (!rule->selector)
    {
        free(rule);
        return false;
    }
    rule->style = *style;
    rule->next = NULL;

    if (!sheet->rules)
    {
        sheet->rules = rule;
        return true;
    }
    css_rule_t *tail = sheet->rules;
    while (tail->next)
    {
        tail = tail->next;
    }
    tail->next = rule;
    return true;
}

css_stylesheet_t *css_parse(const char *css_text)
{
    if (!css_text)
    {
        return NULL;
    }

    css_stylesheet_t *sheet = (css_stylesheet_t *)calloc(1, sizeof(*sheet));
    if (!sheet)
    {
        return NULL;
    }

    const char *p = css_text;
    while (*p)
    {
        css_skip_ws_and_comments(&p);
        if (*p == '\0')
        {
            break;
        }

        const char *sel_start = p;
        while (*p && *p != '{')
        {
            p++;
        }
        if (*p != '{')
        {
            break;
        }
        const char *sel_end = p;
        p++;

        css_style_t style = {0};
        while (*p)
        {
            css_skip_ws_and_comments(&p);
            if (*p == '\0' || *p == '}')
            {
                break;
            }

            const char *prop_start = p;
            while (*p && *p != ':' && *p != ';' && *p != '}')
            {
                p++;
            }
            const char *prop_end = p;
            if (*p != ':')
            {
                if (*p == ';')
                {
                    p++;
                }
                continue;
            }
            p++;

            const char *val_start = p;
            const char *val_end_scan = css_scan_value_end(p);
            if (!val_end_scan)
            {
                val_end_scan = p;
            }
            p = val_end_scan;
            const char *val_end = p;

            css_style_apply_property(&style, prop_start, prop_end, val_start, val_end);

            if (*p == ';')
            {
                p++;
            }
        }
        if (*p == '}')
        {
            p++;
        }

        const char *cur = sel_start;
        while (cur < sel_end)
        {
            const char *comma = cur;
            while (comma < sel_end && *comma != ',')
            {
                comma++;
            }
            if (!css_append_rule(sheet, cur, comma, &style))
            {
                css_stylesheet_destroy(sheet);
                return NULL;
            }
            cur = (comma < sel_end) ? comma + 1 : sel_end;
        }
    }

    return sheet;
}

void css_stylesheet_destroy(css_stylesheet_t *sheet)
{
    if (!sheet)
    {
        return;
    }
    css_rule_t *rule = sheet->rules;
    while (rule)
    {
        css_rule_t *next = rule->next;
        css_style_release(&rule->style);
        free(rule->selector);
        free(rule);
        rule = next;
    }
    free(sheet);
}
