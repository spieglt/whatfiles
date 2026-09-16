#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "wfstring.h"

// Grows the buffer so that it can hold at least `needed` bytes, NUL included.
static void grow(struct String *str, size_t needed)
{
    if (str->data && needed <= str->cap) return;
    size_t cap = str->cap ? str->cap : 64;
    while (cap < needed) {
        if (cap > (size_t)-1 / 2) {
            fprintf(stderr, "whatfiles: string grew past the addressable limit\n");
            exit(ENOMEM);
        }
        cap *= 2;
    }
    char *data = realloc(str->data, cap);
    if (!data) {
        perror("realloc() failed");
        exit(ENOMEM);
    }
    str->data = data;
    str->cap = cap;
}

void str_init(struct String *str, size_t initial_capacity)
{
    grow(str, initial_capacity < 1 ? 1 : initial_capacity);
    str->len = 0;
    str->data[0] = '\0';
}

void str_free(struct String *str)
{
    free(str->data);
    str->data = NULL;
    str->cap = 0;
    str->len = 0;
}

void str_clear(struct String *str)
{
    str->len = 0;
    if (str->data) str->data[0] = '\0';
}

void str_append(struct String *str, const char *data, size_t len)
{
    if (!len) {
        grow(str, str->len + 1);
        str->data[str->len] = '\0';
        return;
    }
    grow(str, str->len + len + 1);
    memcpy(str->data + str->len, data, len);
    str->len += len;
    str->data[str->len] = '\0';
}

void str_append_cstr(struct String *str, const char *cstr)
{
    str_append(str, cstr, strlen(cstr));
}

void str_append_char(struct String *str, char c)
{
    grow(str, str->len + 2);
    str->data[str->len++] = c;
    str->data[str->len] = '\0';
}

void str_appendf(struct String *str, const char *fmt, ...)
{
    va_list args, measure;
    va_start(args, fmt);
    va_copy(measure, args);
    int needed = vsnprintf(NULL, 0, fmt, measure);
    va_end(measure);
    if (needed > 0) {
        grow(str, str->len + (size_t)needed + 1);
        vsnprintf(str->data + str->len, (size_t)needed + 1, fmt, args);
        str->len += (size_t)needed;
    }
    va_end(args);
}

void str_append_escaped(struct String *str, const char *data, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)data[i];
        switch (c) {
        case '\\': str_append_cstr(str, "\\\\"); break;
        case '\n': str_append_cstr(str, "\\n"); break;
        case '\r': str_append_cstr(str, "\\r"); break;
        case '\t': str_append_cstr(str, "\\t"); break;
        default:
            if (c < 0x20 || c == 0x7F) str_appendf(str, "\\x%02X", c);
            else str_append_char(str, (char)c);
        }
    }
}
