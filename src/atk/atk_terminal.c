#include "atk/atk_terminal.h"

#include "atk_internal.h"
#include "video.h"
#include "libc.h"
#include "atk/atk_scrollbar.h"

#define ATK_TERMINAL_MAX_PARAMS 8
#define ATK_TERMINAL_TAB_WIDTH 8
#define ATK_TERMINAL_SCROLLBACK_LINES 500

typedef enum
{
    TERM_PARSE_NORMAL = 0,
    TERM_PARSE_ESC,
    TERM_PARSE_CSI
} term_parse_state_t;

typedef struct
{
    atk_list_node_t *list_node;
    atk_terminal_submit_t submit;
    void *submit_context;
    atk_terminal_control_t control_handler;
    void *control_context;

    int cols;
    int rows;
    char *cells;
    uint16_t *fg;
    uint16_t *bg;
    atk_widget_t *scrollbar;
    int scrollbar_width;
    int view_offset;
    int scrollback_capacity;
    int scrollback_count;
    int scrollback_start;
    char *scrollback_cells;
    uint16_t *scrollback_fg;
    uint16_t *scrollback_bg;

    int cursor_row;
    int cursor_col;
    int saved_row;
    int saved_col;
    bool show_cursor;
    bool focused;

    term_parse_state_t state;
    int params[ATK_TERMINAL_MAX_PARAMS];
    int param_count;
    bool param_active;
    bool param_question;
    bool attr_bold;

    uint16_t palette[16];
    uint16_t default_fg;
    uint16_t default_bg;
    uint16_t current_fg;
    uint16_t current_bg;

    char *input_buffer;
    size_t input_length;
    size_t input_capacity;
} atk_terminal_priv_t;

static const atk_widget_vtable_t terminal_vtable = { 0 };
const atk_class_t ATK_TERMINAL_CLASS = { "Terminal", &ATK_WIDGET_CLASS, &terminal_vtable, sizeof(atk_terminal_priv_t) };

static void terminal_invalidate(const atk_widget_t *terminal);
static bool terminal_allocate_buffers(atk_terminal_priv_t *priv);
static bool terminal_create_scrollbar(atk_widget_t *terminal, atk_terminal_priv_t *priv);
static void terminal_reset_state(atk_terminal_priv_t *priv);
static void terminal_apply_palette(atk_terminal_priv_t *priv);
static void terminal_set_cell(atk_terminal_priv_t *priv, int row, int col, char ch);
static void terminal_clear_range(atk_terminal_priv_t *priv, int row, int col_start, int col_end, bool entire_line);
static void terminal_scroll_up(atk_terminal_priv_t *priv, int lines);
static void terminal_line_feed(atk_terminal_priv_t *priv);
static void terminal_carriage_return(atk_terminal_priv_t *priv);
static void terminal_backspace(atk_terminal_priv_t *priv);
static void terminal_horizontal_tab(atk_terminal_priv_t *priv);
static void terminal_handle_printable(atk_terminal_priv_t *priv, char ch);
static void terminal_reset_params(atk_terminal_priv_t *priv);
static void terminal_csi_dispatch(atk_terminal_priv_t *priv, char command);
static int terminal_get_param(const atk_terminal_priv_t *priv, int index, int default_value);
static uint16_t terminal_color_from_code(atk_terminal_priv_t *priv, int code);
static bool terminal_ensure_input_capacity(atk_terminal_priv_t *priv, size_t extra);
static void terminal_store_scrollback_line(atk_terminal_priv_t *priv, int row);
static void terminal_clamp_view_offset(atk_terminal_priv_t *priv);
static void terminal_update_scrollbar(atk_terminal_priv_t *priv);
static void terminal_scrollbar_changed(atk_widget_t *scrollbar, void *context, int value);
static size_t terminal_scrollback_offset(const atk_terminal_priv_t *priv, int logical_index);

static atk_terminal_priv_t *terminal_priv_mut(atk_widget_t *terminal)
{
    return (atk_terminal_priv_t *)atk_widget_priv(terminal, &ATK_TERMINAL_CLASS);
}

static const atk_terminal_priv_t *terminal_priv(const atk_widget_t *terminal)
{
    return (const atk_terminal_priv_t *)atk_widget_priv(terminal, &ATK_TERMINAL_CLASS);
}

atk_widget_t *atk_window_add_terminal(atk_widget_t *window, int x, int y, int width, int height)
{
    if (!window || width <= 0 || height <= 0)
    {
        return NULL;
    }

    atk_window_priv_t *priv = (atk_window_priv_t *)atk_widget_priv(window, &ATK_WINDOW_CLASS);
    if (!priv)
    {
        return NULL;
    }

    atk_widget_t *terminal = atk_widget_create(&ATK_TERMINAL_CLASS);
    if (!terminal)
    {
        return NULL;
    }

    terminal->x = x;
    terminal->y = y;
    terminal->width = width;
    terminal->height = height;
    terminal->parent = window;
    terminal->used = true;

    atk_terminal_priv_t *term_priv = terminal_priv_mut(terminal);
    if (!term_priv)
    {
        atk_widget_destroy(terminal);
        return NULL;
    }

    term_priv->submit = NULL;
    term_priv->submit_context = NULL;
    term_priv->control_handler = NULL;
    term_priv->control_context = NULL;

    int scrollbar_width = ATK_TERMINAL_SCROLLBAR_WIDTH;
    if (width <= scrollbar_width)
    {
        atk_widget_destroy(terminal);
        return NULL;
    }

    int text_width = width - scrollbar_width;
    int cols = text_width / ATK_FONT_WIDTH;
    int line_height = ATK_FONT_HEIGHT + 2;
    int rows = height / line_height;
    if (cols <= 0 || rows <= 0)
    {
        atk_widget_destroy(terminal);
        return NULL;
    }
    term_priv->cols = cols;
    term_priv->rows = rows;
    term_priv->cells = NULL;
    term_priv->fg = NULL;
    term_priv->bg = NULL;
    term_priv->scrollbar = NULL;
    term_priv->scrollbar_width = scrollbar_width;
    term_priv->view_offset = 0;
    term_priv->scrollback_capacity = ATK_TERMINAL_SCROLLBACK_LINES;
    term_priv->scrollback_count = 0;
    term_priv->scrollback_start = 0;
    term_priv->scrollback_cells = NULL;
    term_priv->scrollback_fg = NULL;
    term_priv->scrollback_bg = NULL;
    term_priv->cursor_row = 0;
    term_priv->cursor_col = 0;
    term_priv->saved_row = 0;
    term_priv->saved_col = 0;
    term_priv->show_cursor = true;
    term_priv->focused = false;
    term_priv->input_buffer = NULL;
    term_priv->input_length = 0;
    term_priv->input_capacity = 0;

    if (!terminal_allocate_buffers(term_priv))
    {
        atk_terminal_destroy(terminal);
        atk_widget_destroy(terminal);
        return NULL;
    }

    atk_list_node_t *child_node = atk_list_push_back(&priv->children, terminal);
    if (!child_node)
    {
        atk_terminal_destroy(terminal);
        atk_widget_destroy(terminal);
        return NULL;
    }

    atk_list_node_t *term_node = atk_list_push_back(&priv->terminals, terminal);
    if (!term_node)
    {
        atk_list_remove(&priv->children, child_node);
        atk_terminal_destroy(terminal);
        atk_widget_destroy(terminal);
        return NULL;
    }

    term_priv->list_node = term_node;
    if (!terminal_create_scrollbar(terminal, term_priv))
    {
        atk_list_remove(&priv->terminals, term_node);
        atk_list_remove(&priv->children, child_node);
        atk_terminal_destroy(terminal);
        atk_widget_destroy(terminal);
        return NULL;
    }
    terminal_apply_palette(term_priv);
    terminal_reset_state(term_priv);
    return terminal;
}

void atk_terminal_reset(atk_widget_t *terminal)
{
    atk_terminal_priv_t *priv = terminal_priv_mut(terminal);
    if (!priv)
    {
        return;
    }
    terminal_reset_state(priv);
    terminal_invalidate(terminal);
}

static void terminal_write_internal(atk_terminal_priv_t *priv, const char *data, size_t len)
{
    for (size_t i = 0; i < len; ++i)
    {
        unsigned char ch = (unsigned char)data[i];
        if (priv->state == TERM_PARSE_ESC)
        {
            if (ch == '[')
            {
                priv->state = TERM_PARSE_CSI;
                terminal_reset_params(priv);
                continue;
            }
            else
            {
                /* Unsupported escape, ignore. */
                priv->state = TERM_PARSE_NORMAL;
                continue;
            }
        }
        else if (priv->state == TERM_PARSE_CSI)
        {
            if (ch == '?')
            {
                priv->param_question = true;
                continue;
            }
            else if (ch >= '0' && ch <= '9')
            {
                if (!priv->param_active)
                {
                    if (priv->param_count < ATK_TERMINAL_MAX_PARAMS)
                    {
                        priv->params[priv->param_count] = 0;
                        priv->param_active = true;
                    }
                    else
                    {
                        /* Ignore overflow */
                        continue;
                    }
                }
                priv->params[priv->param_count] = priv->params[priv->param_count] * 10 + (int)(ch - '0');
                continue;
            }
            else if (ch == ';')
            {
                if (!priv->param_active && priv->param_count < ATK_TERMINAL_MAX_PARAMS)
                {
                    priv->params[priv->param_count] = 0;
                }
                if (priv->param_count < ATK_TERMINAL_MAX_PARAMS - 1)
                {
                    priv->param_count++;
                }
                priv->param_active = false;
                continue;
            }
            else
            {
                if (priv->param_active)
                {
                    priv->param_count++;
                }
                else if (priv->param_count == 0)
                {
                    priv->params[0] = 0;
                    priv->param_count = 1;
                }
                terminal_csi_dispatch(priv, (char)ch);
                priv->state = TERM_PARSE_NORMAL;
                continue;
            }
        }

        if (ch == 0x1B)
        {
            priv->state = TERM_PARSE_ESC;
            continue;
        }

        switch (ch)
        {
            case '\r':
                terminal_carriage_return(priv);
                break;
            case '\n':
                terminal_line_feed(priv);
                terminal_carriage_return(priv);
                break;
            case '\b':
                terminal_backspace(priv);
                break;
            case '\t':
                terminal_horizontal_tab(priv);
                break;
            case '\a':
            case '\f':
            case '\v':
                /* Ignore */
                break;
            default:
                if (ch >= 32 || ch == '\0')
                {
                    terminal_handle_printable(priv, (char)ch);
                }
                break;
        }
    }
}

void atk_terminal_write(atk_widget_t *terminal, const char *data, size_t len)
{
    atk_terminal_priv_t *priv = terminal_priv_mut(terminal);
    if (!priv || !data || len == 0)
    {
        return;
    }
    terminal_write_internal(priv, data, len);
    terminal_invalidate(terminal);
}

bool atk_terminal_handle_char(atk_widget_t *terminal, char ch)
{
    atk_terminal_priv_t *priv = terminal_priv_mut(terminal);
    if (!priv)
    {
        return false;
    }

    if (ch == 0x03)
    {
        if (priv->control_handler &&
            priv->control_handler(terminal, priv->control_context, ch))
        {
            terminal_invalidate(terminal);
            return true;
        }
        return false;
    }

    if (ch == '\r')
    {
        ch = '\n';
    }

    if (ch == '\n')
    {
        terminal_write_internal(priv, "\r\n", 2);
        if (!terminal_ensure_input_capacity(priv, 1))
        {
            priv->input_length = 0;
        }
        priv->input_buffer[priv->input_length] = '\0';
        if (priv->submit)
        {
            priv->submit(terminal, priv->submit_context, priv->input_buffer ? priv->input_buffer : "");
        }
        priv->input_length = 0;
        terminal_invalidate(terminal);
        return true;
    }
    else if (ch == '\b' || ch == 0x7F)
    {
        if (priv->input_length > 0)
        {
            priv->input_length--;
            terminal_backspace(priv);
            terminal_invalidate(terminal);
            return true;
        }
        return false;
    }
    else if ((unsigned char)ch >= 32)
    {
        if (!terminal_ensure_input_capacity(priv, 1))
        {
            return false;
        }
        priv->input_buffer[priv->input_length++] = ch;
        terminal_handle_printable(priv, ch);
        terminal_invalidate(terminal);
        return true;
    }
    return false;
}

void atk_terminal_set_submit_handler(atk_widget_t *terminal, atk_terminal_submit_t handler, void *context)
{
    atk_terminal_priv_t *priv = terminal_priv_mut(terminal);
    if (!priv)
    {
        return;
    }
    priv->submit = handler;
    priv->submit_context = context;
}

void atk_terminal_set_control_handler(atk_widget_t *terminal,
                                      atk_terminal_control_t handler,
                                      void *context)
{
    atk_terminal_priv_t *priv = terminal_priv_mut(terminal);
    if (!priv)
    {
        return;
    }
    priv->control_handler = handler;
    priv->control_context = context;
}

void atk_terminal_clear_input(atk_widget_t *terminal)
{
    atk_terminal_priv_t *priv = terminal_priv_mut(terminal);
    if (!priv)
    {
        return;
    }
    priv->input_length = 0;
}

void atk_terminal_focus(atk_state_t *state, atk_widget_t *terminal)
{
    if (!state)
    {
        return;
    }

    if (state->focused_terminal == terminal)
    {
        return;
    }

    if (state->focused_terminal)
    {
        atk_terminal_priv_t *prev = terminal_priv_mut(state->focused_terminal);
        if (prev)
        {
            prev->focused = false;
            terminal_invalidate(state->focused_terminal);
        }
    }

    state->focused_terminal = terminal;

    if (terminal)
    {
        atk_terminal_priv_t *curr = terminal_priv_mut(terminal);
        if (curr)
        {
            curr->focused = true;
            terminal_invalidate(terminal);
        }
    }
}

bool atk_terminal_is_focused(const atk_state_t *state, const atk_widget_t *terminal)
{
    if (!state)
    {
        return false;
    }
    return state->focused_terminal == terminal;
}

void atk_terminal_mark_dirty(atk_widget_t *terminal)
{
    terminal_invalidate(terminal);
}

void atk_terminal_get_dimensions(const atk_widget_t *terminal, int *rows, int *cols)
{
    const atk_terminal_priv_t *priv = terminal_priv(terminal);
    if (!priv)
    {
        if (rows) *rows = 0;
        if (cols) *cols = 0;
        return;
    }
    if (rows) *rows = priv->rows;
    if (cols) *cols = priv->cols;
}

/* --------- Drawing & destruction --------- */

void atk_terminal_draw(const atk_state_t *state, const atk_widget_t *terminal)
{
    (void)state;
    const atk_terminal_priv_t *priv = terminal_priv(terminal);
    if (!terminal || !terminal->used || !priv)
    {
        return;
    }

    int origin_x = terminal->parent ? terminal->parent->x : 0;
    int origin_y = terminal->parent ? terminal->parent->y : 0;
    int x = origin_x + terminal->x;
    int y = origin_y + terminal->y;

    video_draw_rect(x, y, terminal->width, terminal->height, priv->default_bg);

    int line_height = ATK_FONT_HEIGHT + 2;
    int total_lines = priv->scrollback_count + priv->rows;
    if (total_lines < priv->rows)
    {
        total_lines = priv->rows;
    }
    int top_index = total_lines - priv->rows - priv->view_offset;
    if (top_index < 0)
    {
        top_index = 0;
    }
    bool cursor_visible = (priv->view_offset == 0);

    for (int row = 0; row < priv->rows; ++row)
    {
        int draw_y = y + row * line_height;
        int global_index = top_index + row;
        const char *line_cells = NULL;
        const uint16_t *line_fg = NULL;
        const uint16_t *line_bg = NULL;
        int screen_row = -1;

        if (global_index < priv->scrollback_count)
        {
            size_t offset = terminal_scrollback_offset(priv, global_index);
            line_cells = priv->scrollback_cells + offset;
            line_fg = priv->scrollback_fg + offset;
            line_bg = priv->scrollback_bg + offset;
        }
        else
        {
            screen_row = global_index - priv->scrollback_count;
            if (screen_row < 0) screen_row = 0;
            if (screen_row >= priv->rows) screen_row = priv->rows - 1;
            size_t offset = (size_t)screen_row * (size_t)priv->cols;
            line_cells = priv->cells + offset;
            line_fg = priv->fg + offset;
            line_bg = priv->bg + offset;
        }

        for (int col = 0; col < priv->cols; ++col)
        {
            char ch = line_cells[col];
            uint16_t fg = line_fg[col];
            uint16_t bg = line_bg[col];

            bool cursor_here = (cursor_visible &&
                                screen_row >= 0 &&
                                screen_row == priv->cursor_row &&
                                col == priv->cursor_col &&
                                priv->show_cursor &&
                                priv->focused);
            if (cursor_here)
            {
                uint16_t tmp = fg;
                fg = bg;
                bg = tmp;
            }

            int cell_x = x + col * ATK_FONT_WIDTH;
            video_draw_rect(cell_x, draw_y, ATK_FONT_WIDTH, line_height, bg);
            char buffer[2] = { ch ? ch : ' ', '\0' };
            video_draw_text(cell_x, draw_y, buffer, fg, bg);
        }
    }
}

void atk_terminal_destroy(atk_widget_t *terminal)
{
    atk_terminal_priv_t *priv = terminal_priv_mut(terminal);
    if (!priv)
    {
        return;
    }

    if (terminal && terminal->parent && priv->list_node)
    {
        atk_window_priv_t *wpriv = (atk_window_priv_t *)atk_widget_priv(terminal->parent, &ATK_WINDOW_CLASS);
        if (wpriv)
        {
            atk_list_remove(&wpriv->terminals, priv->list_node);
        }
    }

    if (priv->cells)
    {
        free(priv->cells);
        priv->cells = NULL;
    }
    if (priv->fg)
    {
        free(priv->fg);
        priv->fg = NULL;
    }
    if (priv->bg)
    {
        free(priv->bg);
        priv->bg = NULL;
    }
    if (priv->scrollback_cells)
    {
        free(priv->scrollback_cells);
        priv->scrollback_cells = NULL;
    }
    if (priv->scrollback_fg)
    {
        free(priv->scrollback_fg);
        priv->scrollback_fg = NULL;
    }
    if (priv->scrollback_bg)
    {
        free(priv->scrollback_bg);
        priv->scrollback_bg = NULL;
    }
    if (priv->input_buffer)
    {
        free(priv->input_buffer);
        priv->input_buffer = NULL;
    }

    priv->list_node = NULL;
    priv->submit = NULL;
    priv->submit_context = NULL;
    priv->focused = false;
}

/* --------- Internal helpers --------- */

static void terminal_invalidate(const atk_widget_t *terminal)
{
    if (!terminal || !terminal->parent)
    {
        return;
    }
    int origin_x = terminal->parent->x + terminal->x;
    int origin_y = terminal->parent->y + terminal->y;
    video_invalidate_rect(origin_x, origin_y, terminal->width, terminal->height);
    video_request_refresh_window(terminal->parent);
}

static bool terminal_allocate_buffers(atk_terminal_priv_t *priv)
{
    size_t count = (size_t)priv->rows * (size_t)priv->cols;
    priv->cells = (char *)malloc(count);
    priv->fg = (uint16_t *)malloc(sizeof(uint16_t) * count);
    priv->bg = (uint16_t *)malloc(sizeof(uint16_t) * count);
    size_t scrollback_total = (size_t)priv->scrollback_capacity * (size_t)priv->cols;
    if (priv->scrollback_capacity > 0 && priv->cols > 0)
    {
        priv->scrollback_cells = (char *)malloc(scrollback_total);
        priv->scrollback_fg = (uint16_t *)malloc(sizeof(uint16_t) * scrollback_total);
        priv->scrollback_bg = (uint16_t *)malloc(sizeof(uint16_t) * scrollback_total);
    }
    else
    {
        priv->scrollback_cells = NULL;
        priv->scrollback_fg = NULL;
        priv->scrollback_bg = NULL;
    }

    if (!priv->cells || !priv->fg || !priv->bg ||
        (priv->scrollback_capacity > 0 &&
         (!priv->scrollback_cells || !priv->scrollback_fg || !priv->scrollback_bg)))
    {
        return false;
    }
    return true;
}

static void terminal_apply_palette(atk_terminal_priv_t *priv)
{
    priv->palette[0]  = video_make_color(0x00, 0x00, 0x00);
    priv->palette[1]  = video_make_color(0xAA, 0x00, 0x00);
    priv->palette[2]  = video_make_color(0x00, 0xAA, 0x00);
    priv->palette[3]  = video_make_color(0xAA, 0x55, 0x00);
    priv->palette[4]  = video_make_color(0x00, 0x00, 0xAA);
    priv->palette[5]  = video_make_color(0xAA, 0x00, 0xAA);
    priv->palette[6]  = video_make_color(0x00, 0xAA, 0xAA);
    priv->palette[7]  = video_make_color(0xAA, 0xAA, 0xAA);
    priv->palette[8]  = video_make_color(0x55, 0x55, 0x55);
    priv->palette[9]  = video_make_color(0xFF, 0x55, 0x55);
    priv->palette[10] = video_make_color(0x55, 0xFF, 0x55);
    priv->palette[11] = video_make_color(0xFF, 0xFF, 0x55);
    priv->palette[12] = video_make_color(0x55, 0x55, 0xFF);
    priv->palette[13] = video_make_color(0xFF, 0x55, 0xFF);
    priv->palette[14] = video_make_color(0x55, 0xFF, 0xFF);
    priv->palette[15] = video_make_color(0xFF, 0xFF, 0xFF);

    priv->default_bg = priv->palette[0];
    priv->default_fg = priv->palette[15];
    priv->current_bg = priv->default_bg;
    priv->current_fg = priv->default_fg;
    priv->attr_bold = false;
}

static void terminal_reset_state(atk_terminal_priv_t *priv)
{
    priv->current_fg = priv->default_fg;
    priv->current_bg = priv->default_bg;
    priv->attr_bold = false;
    size_t count = (size_t)priv->rows * (size_t)priv->cols;
    for (size_t i = 0; i < count; ++i)
    {
        priv->cells[i] = ' ';
        priv->fg[i] = priv->current_fg;
        priv->bg[i] = priv->current_bg;
    }
    priv->cursor_row = 0;
    priv->cursor_col = 0;
    priv->saved_row = 0;
    priv->saved_col = 0;
    priv->show_cursor = true;
    priv->state = TERM_PARSE_NORMAL;
    priv->param_count = 0;
    priv->param_active = false;
    priv->param_question = false;
    priv->attr_bold = false;
    priv->input_length = 0;
    priv->scrollback_count = 0;
    priv->scrollback_start = 0;
    priv->view_offset = 0;
    terminal_update_scrollbar(priv);
}

static void terminal_set_cell(atk_terminal_priv_t *priv, int row, int col, char ch)
{
    if (row < 0 || row >= priv->rows || col < 0 || col >= priv->cols)
    {
        return;
    }
    int index = row * priv->cols + col;
    priv->cells[index] = ch ? ch : ' ';
    priv->fg[index] = priv->current_fg;
    priv->bg[index] = priv->current_bg;
}

static void terminal_clear_range(atk_terminal_priv_t *priv, int row, int col_start, int col_end, bool entire_line)
{
    if (row < 0 || row >= priv->rows)
    {
        return;
    }
    if (col_start < 0) col_start = 0;
    if (col_end > priv->cols) col_end = priv->cols;
    if (col_start >= col_end)
    {
        return;
    }

    for (int col = col_start; col < col_end; ++col)
    {
        int index = row * priv->cols + col;
        priv->cells[index] = ' ';
        priv->fg[index] = priv->current_fg;
        priv->bg[index] = entire_line ? priv->default_bg : priv->current_bg;
    }
}

static void terminal_scroll_up(atk_terminal_priv_t *priv, int lines)
{
    if (lines <= 0)
    {
        return;
    }
    if (lines > priv->rows)
    {
        lines = priv->rows;
    }

    for (int row = 0; row < lines; ++row)
    {
        terminal_store_scrollback_line(priv, row);
    }

    int cols = priv->cols;
    int rows = priv->rows;
    int remaining_rows = rows - lines;
    if (remaining_rows > 0)
    {
        size_t count = (size_t)cols * (size_t)remaining_rows;
        memmove(priv->cells, priv->cells + lines * cols, count);
        memmove(priv->fg, priv->fg + lines * cols, count * sizeof(uint16_t));
        memmove(priv->bg, priv->bg + lines * cols, count * sizeof(uint16_t));
    }

    for (int row = rows - lines; row < rows; ++row)
    {
        for (int col = 0; col < cols; ++col)
        {
            int index = row * cols + col;
            priv->cells[index] = ' ';
            priv->fg[index] = priv->current_fg;
            priv->bg[index] = priv->default_bg;
        }
    }
    priv->cursor_row -= lines;
    if (priv->cursor_row < 0)
    {
        priv->cursor_row = 0;
    }
    terminal_clamp_view_offset(priv);
    terminal_update_scrollbar(priv);
}

static void terminal_line_feed(atk_terminal_priv_t *priv)
{
    priv->cursor_row++;
    if (priv->cursor_row >= priv->rows)
    {
        terminal_scroll_up(priv, 1);
        priv->cursor_row = priv->rows - 1;
    }
}

static void terminal_carriage_return(atk_terminal_priv_t *priv)
{
    priv->cursor_col = 0;
}

static void terminal_backspace(atk_terminal_priv_t *priv)
{
    if (priv->cursor_col > 0)
    {
        priv->cursor_col--;
        terminal_set_cell(priv, priv->cursor_row, priv->cursor_col, ' ');
    }
}

static void terminal_horizontal_tab(atk_terminal_priv_t *priv)
{
    int next = ((priv->cursor_col / ATK_TERMINAL_TAB_WIDTH) + 1) * ATK_TERMINAL_TAB_WIDTH;
    if (next >= priv->cols)
    {
        next = priv->cols - 1;
    }
    while (priv->cursor_col < next)
    {
        terminal_handle_printable(priv, ' ');
    }
}

static void terminal_handle_printable(atk_terminal_priv_t *priv, char ch)
{
    terminal_set_cell(priv, priv->cursor_row, priv->cursor_col, ch);
    priv->cursor_col++;
    if (priv->cursor_col >= priv->cols)
    {
        priv->cursor_col = 0;
        terminal_line_feed(priv);
    }
}

static void terminal_reset_params(atk_terminal_priv_t *priv)
{
    for (int i = 0; i < ATK_TERMINAL_MAX_PARAMS; ++i)
    {
        priv->params[i] = 0;
    }
    priv->param_count = 0;
    priv->param_active = false;
    priv->param_question = false;
}

static int terminal_get_param(const atk_terminal_priv_t *priv, int index, int default_value)
{
    if (index < 0 || index >= priv->param_count)
    {
        return default_value;
    }
    return priv->params[index];
}

static uint16_t terminal_color_from_code(atk_terminal_priv_t *priv, int code)
{
    if (code < 0) code = 0;
    if (code > 15) code = 15;
    return priv->palette[code];
}

static void terminal_csi_dispatch(atk_terminal_priv_t *priv, char command)
{
    switch (command)
    {
        case 'A': /* Cursor up */
        {
            int amount = terminal_get_param(priv, 0, 1);
            priv->cursor_row -= amount;
            if (priv->cursor_row < 0) priv->cursor_row = 0;
            break;
        }
        case 'B': /* Cursor down */
        {
            int amount = terminal_get_param(priv, 0, 1);
            priv->cursor_row += amount;
            if (priv->cursor_row >= priv->rows) priv->cursor_row = priv->rows - 1;
            break;
        }
        case 'C': /* Cursor forward */
        {
            int amount = terminal_get_param(priv, 0, 1);
            priv->cursor_col += amount;
            if (priv->cursor_col >= priv->cols) priv->cursor_col = priv->cols - 1;
            break;
        }
        case 'D': /* Cursor backward */
        {
            int amount = terminal_get_param(priv, 0, 1);
            priv->cursor_col -= amount;
            if (priv->cursor_col < 0) priv->cursor_col = 0;
            break;
        }
        case 'H':
        case 'f':
        {
            int row = terminal_get_param(priv, 0, 1);
            int col = terminal_get_param(priv, 1, 1);
            if (row < 1) row = 1;
            if (col < 1) col = 1;
            priv->cursor_row = row - 1;
            priv->cursor_col = col - 1;
            if (priv->cursor_row >= priv->rows) priv->cursor_row = priv->rows - 1;
            if (priv->cursor_col >= priv->cols) priv->cursor_col = priv->cols - 1;
            break;
        }
        case 'J':
        {
            int mode = terminal_get_param(priv, 0, 0);
            if (mode == 2)
            {
                size_t count = (size_t)priv->rows * (size_t)priv->cols;
                for (size_t i = 0; i < count; ++i)
                {
                    priv->cells[i] = ' ';
                    priv->fg[i] = priv->current_fg;
                    priv->bg[i] = priv->default_bg;
                }
                priv->cursor_row = 0;
                priv->cursor_col = 0;
            }
            else if (mode == 1)
            {
                for (int row = 0; row <= priv->cursor_row; ++row)
                {
                    int end = (row == priv->cursor_row) ? priv->cursor_col + 1 : priv->cols;
                    terminal_clear_range(priv, row, 0, end, true);
                }
            }
            else /* mode 0 */
            {
                terminal_clear_range(priv, priv->cursor_row, priv->cursor_col, priv->cols, true);
                for (int row = priv->cursor_row + 1; row < priv->rows; ++row)
                {
                    terminal_clear_range(priv, row, 0, priv->cols, true);
                }
            }
            break;
        }
        case 'K':
        {
            int mode = terminal_get_param(priv, 0, 0);
            if (mode == 2)
            {
                terminal_clear_range(priv, priv->cursor_row, 0, priv->cols, true);
            }
            else if (mode == 1)
            {
                terminal_clear_range(priv, priv->cursor_row, 0, priv->cursor_col + 1, false);
            }
            else
            {
                terminal_clear_range(priv, priv->cursor_row, priv->cursor_col, priv->cols, false);
            }
            break;
        }
        case 's':
            priv->saved_row = priv->cursor_row;
            priv->saved_col = priv->cursor_col;
            break;
        case 'u':
            priv->cursor_row = priv->saved_row;
            priv->cursor_col = priv->saved_col;
            if (priv->cursor_row >= priv->rows) priv->cursor_row = priv->rows - 1;
            if (priv->cursor_col >= priv->cols) priv->cursor_col = priv->cols - 1;
            break;
        case 'm':
        {
            if (priv->param_count == 0)
            {
                priv->current_fg = priv->default_fg;
                priv->current_bg = priv->default_bg;
                priv->attr_bold = false;
                break;
            }
            for (int i = 0; i < priv->param_count; ++i)
            {
                int value = priv->params[i];
                if (value == 0)
                {
                    priv->current_fg = priv->default_fg;
                    priv->current_bg = priv->default_bg;
                    priv->attr_bold = false;
                }
                else if (value == 1)
                {
                    priv->attr_bold = true;
                }
                else if (value >= 30 && value <= 37)
                {
                    int color = value - 30;
                    if (priv->attr_bold) color += 8;
                    priv->current_fg = terminal_color_from_code(priv, color);
                }
                else if (value >= 40 && value <= 47)
                {
                    int color = value - 40;
                    priv->current_bg = terminal_color_from_code(priv, color);
                }
                else if (value >= 90 && value <= 97)
                {
                    int color = (value - 90) + 8;
                    priv->current_fg = terminal_color_from_code(priv, color);
                }
                else if (value >= 100 && value <= 107)
                {
                    int color = (value - 100) + 8;
                    priv->current_bg = terminal_color_from_code(priv, color);
                }
            }
            break;
        }
        case 'l':
        case 'h':
        {
            if (priv->param_question)
            {
                int mode = terminal_get_param(priv, 0, 0);
                if (mode == 25)
                {
                    priv->show_cursor = (command == 'h');
                }
            }
            break;
        }
        default:
            break;
    }
}

static bool terminal_ensure_input_capacity(atk_terminal_priv_t *priv, size_t extra)
{
    size_t needed = priv->input_length + extra + 1;
    if (needed <= priv->input_capacity)
    {
        return true;
    }
    size_t new_capacity = priv->input_capacity ? priv->input_capacity : 64;
    while (new_capacity < needed)
    {
        new_capacity *= 2;
    }
    char *buffer = (char *)realloc(priv->input_buffer, new_capacity);
    if (!buffer)
    {
        return false;
    }
    priv->input_buffer = buffer;
    priv->input_capacity = new_capacity;
    return true;
}

static bool terminal_create_scrollbar(atk_widget_t *terminal, atk_terminal_priv_t *priv)
{
    if (!terminal || !priv || !terminal->parent)
    {
        return false;
    }

    if (priv->scrollbar_width <= 0)
    {
        priv->scrollbar = NULL;
        return true;
    }

    int sb_x = terminal->x + terminal->width - priv->scrollbar_width;
    int sb_y = terminal->y;
    atk_widget_t *scrollbar = atk_window_add_scrollbar(terminal->parent,
                                                       sb_x,
                                                       sb_y,
                                                       priv->scrollbar_width,
                                                       terminal->height,
                                                       ATK_SCROLLBAR_VERTICAL);
    if (!scrollbar)
    {
        return false;
    }

    priv->scrollbar = scrollbar;
    atk_scrollbar_set_change_handler(scrollbar, terminal_scrollbar_changed, terminal);
    atk_scrollbar_set_range(scrollbar, 0, priv->scrollback_count, priv->rows);
    atk_scrollbar_set_value(scrollbar, priv->scrollback_count - priv->view_offset);
    return true;
}

static void terminal_store_scrollback_line(atk_terminal_priv_t *priv, int row)
{
    if (!priv || priv->scrollback_capacity <= 0 || priv->cols <= 0)
    {
        return;
    }
    if (row < 0 || row >= priv->rows)
    {
        return;
    }

    size_t line_offset = (size_t)row * (size_t)priv->cols;
    size_t insert_offset;
    if (priv->scrollback_count < priv->scrollback_capacity)
    {
        insert_offset = terminal_scrollback_offset(priv, priv->scrollback_count);
        priv->scrollback_count++;
    }
    else
    {
        insert_offset = terminal_scrollback_offset(priv, 0);
        priv->scrollback_start = (priv->scrollback_start + 1) % priv->scrollback_capacity;
    }

    memcpy(priv->scrollback_cells + insert_offset, priv->cells + line_offset, (size_t)priv->cols);
    memcpy(priv->scrollback_fg + insert_offset, priv->fg + line_offset, sizeof(uint16_t) * (size_t)priv->cols);
    memcpy(priv->scrollback_bg + insert_offset, priv->bg + line_offset, sizeof(uint16_t) * (size_t)priv->cols);
}

static void terminal_clamp_view_offset(atk_terminal_priv_t *priv)
{
    if (!priv)
    {
        return;
    }
    if (priv->view_offset < 0)
    {
        priv->view_offset = 0;
    }
    if (priv->view_offset > priv->scrollback_count)
    {
        priv->view_offset = priv->scrollback_count;
    }
}

static void terminal_update_scrollbar(atk_terminal_priv_t *priv)
{
    if (!priv || !priv->scrollbar)
    {
        return;
    }
    atk_scrollbar_set_range(priv->scrollbar, 0, priv->scrollback_count, priv->rows);
    int value = priv->scrollback_count - priv->view_offset;
    if (value < 0)
    {
        value = 0;
    }
    atk_scrollbar_set_value(priv->scrollbar, value);
    atk_scrollbar_mark_dirty(priv->scrollbar);
}

static void terminal_scrollbar_changed(atk_widget_t *scrollbar, void *context, int value)
{
    (void)scrollbar;
    atk_widget_t *terminal = (atk_widget_t *)context;
    atk_terminal_priv_t *priv = terminal_priv_mut(terminal);
    if (!priv)
    {
        return;
    }
    if (value < 0)
    {
        value = 0;
    }
    if (value > priv->scrollback_count)
    {
        value = priv->scrollback_count;
    }
    priv->view_offset = priv->scrollback_count - value;
    terminal_invalidate(terminal);
}

static size_t terminal_scrollback_offset(const atk_terminal_priv_t *priv, int logical_index)
{
    if (!priv || priv->scrollback_capacity <= 0 || priv->cols <= 0)
    {
        return 0;
    }
    int slot = logical_index % priv->scrollback_capacity;
    if (slot < 0)
    {
        slot += priv->scrollback_capacity;
    }
    slot = (priv->scrollback_start + slot) % priv->scrollback_capacity;
    return (size_t)slot * (size_t)priv->cols;
}
