#include "web/js/lexer.h"

#include "ctype.h"
#include "libc.h"

void js_token_destroy(js_token_t *tok)
{
    if (!tok)
    {
        return;
    }
    free(tok->text);
    tok->text = NULL;
    tok->length = 0;
}

char *js_token_take_text(js_token_t *tok)
{
    if (!tok)
    {
        return NULL;
    }
    char *text = tok->text;
    tok->text = NULL;
    tok->length = 0;
    return text;
}

void js_lexer_init(js_lexer_t *lex, const char *source)
{
    if (!lex)
    {
        return;
    }
    lex->source = source ? source : "";
    lex->cur = lex->source;
    lex->offset = 0;
}

static char js_lexer_peek(const js_lexer_t *lex)
{
    return (lex && lex->cur) ? *lex->cur : '\0';
}

static char js_lexer_peek_next(const js_lexer_t *lex)
{
    if (!lex || !lex->cur)
    {
        return '\0';
    }
    if (lex->cur[0] == '\0')
    {
        return '\0';
    }
    return lex->cur[1];
}

static char js_lexer_advance(js_lexer_t *lex)
{
    if (!lex || !lex->cur)
    {
        return '\0';
    }
    char c = *lex->cur;
    if (c != '\0')
    {
        lex->cur++;
        lex->offset++;
    }
    return c;
}

static bool js_is_ident_start(char c)
{
    return (c == '_' || c == '$' || isalpha((unsigned char)c) != 0);
}

static bool js_is_ident_part(char c)
{
    return js_is_ident_start(c) || isdigit((unsigned char)c) != 0;
}

static js_token_type_t js_keyword_type(const char *start, size_t len)
{
    if (!start)
    {
        return JS_TOKEN_IDENTIFIER;
    }
    if (len == 3 && strncmp(start, "var", len) == 0) return JS_TOKEN_KW_VAR;
    if (len == 3 && strncmp(start, "let", len) == 0) return JS_TOKEN_KW_LET;
    if (len == 5 && strncmp(start, "const", len) == 0) return JS_TOKEN_KW_CONST;
    if (len == 8 && strncmp(start, "function", len) == 0) return JS_TOKEN_KW_FUNCTION;
    if (len == 6 && strncmp(start, "return", len) == 0) return JS_TOKEN_KW_RETURN;
    if (len == 4 && strncmp(start, "true", len) == 0) return JS_TOKEN_KW_TRUE;
    if (len == 5 && strncmp(start, "false", len) == 0) return JS_TOKEN_KW_FALSE;
    if (len == 4 && strncmp(start, "null", len) == 0) return JS_TOKEN_KW_NULL;
    if (len == 9 && strncmp(start, "undefined", len) == 0) return JS_TOKEN_KW_UNDEFINED;
    if (len == 2 && strncmp(start, "if", len) == 0) return JS_TOKEN_KW_IF;
    if (len == 4 && strncmp(start, "else", len) == 0) return JS_TOKEN_KW_ELSE;
    if (len == 5 && strncmp(start, "while", len) == 0) return JS_TOKEN_KW_WHILE;
    if (len == 3 && strncmp(start, "for", len) == 0) return JS_TOKEN_KW_FOR;
    if (len == 5 && strncmp(start, "break", len) == 0) return JS_TOKEN_KW_BREAK;
    if (len == 8 && strncmp(start, "continue", len) == 0) return JS_TOKEN_KW_CONTINUE;
    if (len == 6 && strncmp(start, "switch", len) == 0) return JS_TOKEN_KW_SWITCH;
    if (len == 4 && strncmp(start, "case", len) == 0) return JS_TOKEN_KW_CASE;
    if (len == 7 && strncmp(start, "default", len) == 0) return JS_TOKEN_KW_DEFAULT;
    if (len == 2 && strncmp(start, "do", len) == 0) return JS_TOKEN_KW_DO;
    if (len == 3 && strncmp(start, "try", len) == 0) return JS_TOKEN_KW_TRY;
    if (len == 5 && strncmp(start, "catch", len) == 0) return JS_TOKEN_KW_CATCH;
    if (len == 3 && strncmp(start, "new", len) == 0) return JS_TOKEN_KW_NEW;
    return JS_TOKEN_IDENTIFIER;
}

static bool js_lexer_skip_ws_and_comments(js_lexer_t *lex, js_parse_error_t *error_out)
{
    for (;;)
    {
        char c = js_lexer_peek(lex);
        if (c == '\0')
        {
            return true;
        }
        if (isspace((unsigned char)c) != 0)
        {
            (void)js_lexer_advance(lex);
            continue;
        }
        if (c == '/')
        {
            char n = js_lexer_peek_next(lex);
            if (n == '/')
            {
                (void)js_lexer_advance(lex);
                (void)js_lexer_advance(lex);
                while ((c = js_lexer_peek(lex)) != '\0' && c != '\n')
                {
                    (void)js_lexer_advance(lex);
                }
                continue;
            }
            if (n == '*')
            {
                size_t start_offset = lex ? lex->offset : 0;
                (void)js_lexer_advance(lex);
                (void)js_lexer_advance(lex);
                for (;;)
                {
                    c = js_lexer_peek(lex);
                    if (c == '\0')
                    {
                        js_parse_error_set(error_out, start_offset, "unterminated comment");
                        return false;
                    }
                    if (c == '*' && js_lexer_peek_next(lex) == '/')
                    {
                        (void)js_lexer_advance(lex);
                        (void)js_lexer_advance(lex);
                        break;
                    }
                    (void)js_lexer_advance(lex);
                }
                continue;
            }
        }
        return true;
    }
}

static bool js_lexer_read_identifier(js_lexer_t *lex, js_token_t *out)
{
    const char *start = lex->cur;
    size_t start_offset = lex->offset;
    while (js_is_ident_part(js_lexer_peek(lex)))
    {
        (void)js_lexer_advance(lex);
    }
    size_t len = (size_t)(lex->cur - start);
    js_token_type_t kw = js_keyword_type(start, len);
    out->type = kw;
    out->offset = start_offset;
    out->number = 0.0;
    out->length = 0;
    out->text = NULL;
    if (kw == JS_TOKEN_IDENTIFIER)
    {
        out->text = js_strdup_len(start, len);
        out->length = out->text ? len : 0;
        if (!out->text)
        {
            return false;
        }
    }
    return true;
}

static bool js_lexer_read_number(js_lexer_t *lex, js_token_t *out, bool leading_dot, js_parse_error_t *error_out)
{
    size_t start_offset = lex->offset;
    const char *p = lex->cur;
    double value = 0.0;

    if (!leading_dot && p[0] == '0')
    {
        char next = p[1];
        if (next == 'x' || next == 'X')
        {
            p += 2;
            int digit = js_hex_value(*p);
            if (digit < 0)
            {
                js_parse_error_set(error_out, start_offset, "invalid hex literal");
                return false;
            }
            while (digit >= 0)
            {
                value = value * 16.0 + (double)digit;
                p++;
                digit = js_hex_value(*p);
            }
            lex->cur = p;
            lex->offset = (size_t)(p - lex->source);
            out->type = JS_TOKEN_NUMBER;
            out->offset = start_offset;
            out->number = value;
            out->text = NULL;
            out->length = 0;
            return true;
        }
        if (next == 'b' || next == 'B')
        {
            p += 2;
            if (*p != '0' && *p != '1')
            {
                js_parse_error_set(error_out, start_offset, "invalid binary literal");
                return false;
            }
            while (*p == '0' || *p == '1')
            {
                value = value * 2.0 + (double)(*p - '0');
                p++;
            }
            lex->cur = p;
            lex->offset = (size_t)(p - lex->source);
            out->type = JS_TOKEN_NUMBER;
            out->offset = start_offset;
            out->number = value;
            out->text = NULL;
            out->length = 0;
            return true;
        }
        if (next == 'o' || next == 'O')
        {
            p += 2;
            if (*p < '0' || *p > '7')
            {
                js_parse_error_set(error_out, start_offset, "invalid octal literal");
                return false;
            }
            while (*p >= '0' && *p <= '7')
            {
                value = value * 8.0 + (double)(*p - '0');
                p++;
            }
            lex->cur = p;
            lex->offset = (size_t)(p - lex->source);
            out->type = JS_TOKEN_NUMBER;
            out->offset = start_offset;
            out->number = value;
            out->text = NULL;
            out->length = 0;
            return true;
        }
    }

    bool had_digit = false;
    if (leading_dot)
    {
        p++;
        double scale = 0.1;
        while (isdigit((unsigned char)*p) != 0)
        {
            had_digit = true;
            value += (double)(*p - '0') * scale;
            scale *= 0.1;
            p++;
        }
    }
    else
    {
        while (isdigit((unsigned char)*p) != 0)
        {
            had_digit = true;
            value = value * 10.0 + (double)(*p - '0');
            p++;
        }

        if (*p == '.')
        {
            p++;
            double scale = 0.1;
            while (isdigit((unsigned char)*p) != 0)
            {
                had_digit = true;
                value += (double)(*p - '0') * scale;
                scale *= 0.1;
                p++;
            }
        }
    }

    if (!had_digit)
    {
        js_parse_error_set(error_out, start_offset, "invalid number literal");
        return false;
    }

    if (*p == 'e' || *p == 'E')
    {
        p++;
        int exp_sign = 1;
        if (*p == '+' || *p == '-')
        {
            if (*p == '-')
            {
                exp_sign = -1;
            }
            p++;
        }
        if (!isdigit((unsigned char)*p))
        {
            js_parse_error_set(error_out, start_offset, "invalid exponent");
            return false;
        }
        int exp = 0;
        while (isdigit((unsigned char)*p) != 0)
        {
            exp = exp * 10 + (*p - '0');
            p++;
        }
        exp *= exp_sign;

        double pow10 = 1.0;
        int e = exp < 0 ? -exp : exp;
        double base = 10.0;
        while (e)
        {
            if (e & 1)
            {
                pow10 *= base;
            }
            base *= base;
            e >>= 1;
        }
        if (exp < 0)
        {
            value /= pow10;
        }
        else
        {
            value *= pow10;
        }
    }

    lex->cur = p;
    lex->offset = (size_t)(p - lex->source);

    out->type = JS_TOKEN_NUMBER;
    out->offset = start_offset;
    out->number = value;
    out->text = NULL;
    out->length = 0;
    return true;
}

static bool js_lexer_read_string(js_lexer_t *lex, js_token_t *out, char quote, size_t start_offset, js_parse_error_t *error_out)
{
    const char *start = lex->cur;
    const char *p = start;
    for (;;)
    {
        char c = *p;
        if (c == '\0' || c == '\n' || c == '\r')
        {
            js_parse_error_set(error_out, start_offset, "unterminated string");
            return false;
        }
        if (c == quote)
        {
            break;
        }
        if (c == '\\' && p[1] != '\0')
        {
            p += 2;
            continue;
        }
        p++;
    }

    size_t raw_len = (size_t)(p - start);
    char *buf = (char *)malloc(raw_len + 1);
    if (!buf)
    {
        js_parse_error_set(error_out, start_offset, "allocation failed");
        return false;
    }
    if (raw_len == 0)
    {
        buf[0] = '\0';
    }

    size_t out_len = 0;
    const char *s = start;
    while (s < p)
    {
        char c = *s++;
        if (c == '\\' && s < p)
        {
            char esc = *s++;
            switch (esc)
            {
                case 'n': c = '\n'; break;
                case 'r': c = '\r'; break;
                case 't': c = '\t'; break;
                case 'b': c = '\b'; break;
                case 'f': c = '\f'; break;
                case 'v': c = '\v'; break;
                case '\\': c = '\\'; break;
                case '\"': c = '\"'; break;
                case '\'': c = '\''; break;
                case 'x':
                {
                    int hi = js_hex_value(s[0]);
                    int lo = js_hex_value(s[1]);
                    if (hi < 0 || lo < 0)
                    {
                        free(buf);
                        js_parse_error_set(error_out, start_offset, "invalid hex escape");
                        return false;
                    }
                    c = (char)((hi << 4) | lo);
                    s += 2;
                    break;
                }
                case 'u':
                {
                    int v0 = js_hex_value(s[0]);
                    int v1 = js_hex_value(s[1]);
                    int v2 = js_hex_value(s[2]);
                    int v3 = js_hex_value(s[3]);
                    if (v0 < 0 || v1 < 0 || v2 < 0 || v3 < 0)
                    {
                        free(buf);
                        js_parse_error_set(error_out, start_offset, "invalid unicode escape");
                        return false;
                    }
                    int value = (v0 << 12) | (v1 << 8) | (v2 << 4) | v3;
                    if (value < 0x20 || value > 0x7E)
                    {
                        c = '?';
                    }
                    else
                    {
                        c = (char)value;
                    }
                    s += 4;
                    break;
                }
                default: c = esc; break;
            }
        }
        buf[out_len++] = c;
    }
    buf[out_len] = '\0';

    lex->cur = p + 1;
    lex->offset = (size_t)(lex->cur - lex->source);

    out->type = JS_TOKEN_STRING;
    out->offset = start_offset;
    out->number = 0.0;
    out->text = buf;
    out->length = out_len;
    return true;
}

bool js_lexer_next(js_lexer_t *lex, js_token_t *out, js_parse_error_t *error_out)
{
    if (!out)
    {
        return false;
    }
    js_token_destroy(out);
    out->type = JS_TOKEN_EOF;
    out->offset = 0;
    out->number = 0.0;
    out->text = NULL;
    out->length = 0;

    if (!js_lexer_skip_ws_and_comments(lex, error_out))
    {
        return false;
    }

    char c = js_lexer_peek(lex);
    if (c == '\0')
    {
        out->type = JS_TOKEN_EOF;
        out->offset = lex ? lex->offset : 0;
        return true;
    }

    size_t start_offset = lex->offset;

    if (js_is_ident_start(c))
    {
        if (!js_lexer_read_identifier(lex, out))
        {
            js_parse_error_set(error_out, start_offset, "allocation failed");
            return false;
        }
        return true;
    }

    if (isdigit((unsigned char)c) != 0)
    {
        return js_lexer_read_number(lex, out, false, error_out);
    }

    if (c == '.' && isdigit((unsigned char)js_lexer_peek_next(lex)) != 0)
    {
        return js_lexer_read_number(lex, out, true, error_out);
    }

    (void)js_lexer_advance(lex);

    switch (c)
    {
        case ';': out->type = JS_TOKEN_SEMICOLON; out->offset = start_offset; return true;
        case '(': out->type = JS_TOKEN_LPAREN; out->offset = start_offset; return true;
        case ')': out->type = JS_TOKEN_RPAREN; out->offset = start_offset; return true;
        case '{': out->type = JS_TOKEN_LBRACE; out->offset = start_offset; return true;
        case '}': out->type = JS_TOKEN_RBRACE; out->offset = start_offset; return true;
        case '[': out->type = JS_TOKEN_LBRACKET; out->offset = start_offset; return true;
        case ']': out->type = JS_TOKEN_RBRACKET; out->offset = start_offset; return true;
        case ',': out->type = JS_TOKEN_COMMA; out->offset = start_offset; return true;
        case '.': out->type = JS_TOKEN_DOT; out->offset = start_offset; return true;
        case '?': out->type = JS_TOKEN_QUESTION; out->offset = start_offset; return true;
        case ':': out->type = JS_TOKEN_COLON; out->offset = start_offset; return true;
        case '+': out->type = JS_TOKEN_PLUS; out->offset = start_offset; return true;
        case '-': out->type = JS_TOKEN_MINUS; out->offset = start_offset; return true;
        case '*': out->type = JS_TOKEN_STAR; out->offset = start_offset; return true;
        case '%': out->type = JS_TOKEN_PERCENT; out->offset = start_offset; return true;
        case '/': out->type = JS_TOKEN_SLASH; out->offset = start_offset; return true;
        case '&':
            if (js_lexer_peek(lex) == '&')
            {
                (void)js_lexer_advance(lex);
                out->type = JS_TOKEN_AND_AND;
            }
            else
            {
                js_parse_error_set(error_out, start_offset, "unexpected '&'");
                return false;
            }
            out->offset = start_offset;
            return true;
        case '|':
            if (js_lexer_peek(lex) == '|')
            {
                (void)js_lexer_advance(lex);
                out->type = JS_TOKEN_OR_OR;
            }
            else
            {
                js_parse_error_set(error_out, start_offset, "unexpected '|'");
                return false;
            }
            out->offset = start_offset;
            return true;
        case '!':
            if (js_lexer_peek(lex) == '=')
            {
                (void)js_lexer_advance(lex);
                if (js_lexer_peek(lex) == '=')
                {
                    (void)js_lexer_advance(lex);
                    out->type = JS_TOKEN_BANG_EQUAL_EQUAL;
                }
                else
                {
                    out->type = JS_TOKEN_BANG_EQUAL;
                }
            }
            else
            {
                out->type = JS_TOKEN_BANG;
            }
            out->offset = start_offset;
            return true;
        case '=':
            if (js_lexer_peek(lex) == '>')
            {
                (void)js_lexer_advance(lex);
                out->type = JS_TOKEN_ARROW;
            }
            else if (js_lexer_peek(lex) == '=')
            {
                (void)js_lexer_advance(lex);
                if (js_lexer_peek(lex) == '=')
                {
                    (void)js_lexer_advance(lex);
                    out->type = JS_TOKEN_EQUAL_EQUAL_EQUAL;
                }
                else
                {
                    out->type = JS_TOKEN_EQUAL_EQUAL;
                }
            }
            else
            {
                out->type = JS_TOKEN_EQUAL;
            }
            out->offset = start_offset;
            return true;
        case '<':
            if (js_lexer_peek(lex) == '=')
            {
                (void)js_lexer_advance(lex);
                out->type = JS_TOKEN_LTE;
            }
            else
            {
                out->type = JS_TOKEN_LT;
            }
            out->offset = start_offset;
            return true;
        case '>':
            if (js_lexer_peek(lex) == '=')
            {
                (void)js_lexer_advance(lex);
                out->type = JS_TOKEN_GTE;
            }
            else
            {
                out->type = JS_TOKEN_GT;
            }
            out->offset = start_offset;
            return true;
        case '\"':
        case '\'':
            return js_lexer_read_string(lex, out, c, start_offset, error_out);
        default:
            js_parse_error_set(error_out, start_offset, "unexpected character");
            return false;
    }
}
