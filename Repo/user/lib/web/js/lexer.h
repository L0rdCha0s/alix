#ifndef WEB_JS_LEXER_H
#define WEB_JS_LEXER_H

#include "web/js/internal.h"

typedef enum
{
    JS_TOKEN_EOF = 0,
    JS_TOKEN_IDENTIFIER,
    JS_TOKEN_NUMBER,
    JS_TOKEN_BIGINT,
    JS_TOKEN_STRING,
    JS_TOKEN_BACKTICK,
    JS_TOKEN_SEMICOLON,
    JS_TOKEN_LPAREN,
    JS_TOKEN_RPAREN,
    JS_TOKEN_LBRACE,
    JS_TOKEN_RBRACE,
    JS_TOKEN_LBRACKET,
    JS_TOKEN_RBRACKET,
    JS_TOKEN_COMMA,
    JS_TOKEN_DOT,
    JS_TOKEN_ELLIPSIS,
    JS_TOKEN_QUESTION,
    JS_TOKEN_COLON,
    JS_TOKEN_PLUS,
    JS_TOKEN_PLUS_PLUS,
    JS_TOKEN_PLUS_EQUAL,
    JS_TOKEN_MINUS,
    JS_TOKEN_MINUS_MINUS,
    JS_TOKEN_STAR,
    JS_TOKEN_STAR_STAR,
    JS_TOKEN_SLASH,
    JS_TOKEN_PERCENT,
    JS_TOKEN_BANG,
    JS_TOKEN_BANG_EQUAL,
    JS_TOKEN_BANG_EQUAL_EQUAL,
    JS_TOKEN_EQUAL,
    JS_TOKEN_ARROW,
    JS_TOKEN_EQUAL_EQUAL,
    JS_TOKEN_EQUAL_EQUAL_EQUAL,
    JS_TOKEN_LT,
    JS_TOKEN_LTE,
    JS_TOKEN_GT,
    JS_TOKEN_GTE,
    JS_TOKEN_AND_AND,
    JS_TOKEN_OR_OR,
    JS_TOKEN_KW_VAR,
    JS_TOKEN_KW_LET,
    JS_TOKEN_KW_CONST,
    JS_TOKEN_KW_FUNCTION,
    JS_TOKEN_KW_RETURN,
    JS_TOKEN_KW_THROW,
    JS_TOKEN_KW_TRUE,
    JS_TOKEN_KW_FALSE,
    JS_TOKEN_KW_NULL,
    JS_TOKEN_KW_UNDEFINED,
    JS_TOKEN_KW_THIS,
    JS_TOKEN_KW_TYPEOF,
    JS_TOKEN_KW_INSTANCEOF,
    JS_TOKEN_KW_IF,
    JS_TOKEN_KW_ELSE,
    JS_TOKEN_KW_WHILE,
    JS_TOKEN_KW_FOR,
    JS_TOKEN_KW_BREAK,
    JS_TOKEN_KW_CONTINUE,
    JS_TOKEN_KW_SWITCH,
    JS_TOKEN_KW_CASE,
    JS_TOKEN_KW_DEFAULT,
    JS_TOKEN_KW_DO,
    JS_TOKEN_KW_TRY,
    JS_TOKEN_KW_CATCH,
    JS_TOKEN_KW_NEW
} js_token_type_t;

typedef struct
{
    js_token_type_t type;
    size_t offset;
    double number;
    char *text;
    size_t length;
    bool line_terminator;
} js_token_t;

typedef struct
{
    const char *source;
    const char *cur;
    size_t offset;
} js_lexer_t;

void js_token_destroy(js_token_t *tok);
char *js_token_take_text(js_token_t *tok);
void js_lexer_init(js_lexer_t *lex, const char *source);
bool js_lexer_next(js_lexer_t *lex, js_token_t *out, js_parse_error_t *error_out);

#endif /* WEB_JS_LEXER_H */
